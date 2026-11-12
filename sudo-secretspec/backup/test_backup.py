import contextlib
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

import backup


def audit_fixture(path):
    with sqlite3.connect(path) as db:
        db.executescript('''CREATE TABLE events (
          sequence INTEGER PRIMARY KEY, timestamp_ns INTEGER, transaction_id TEXT,
          phase TEXT, operation TEXT, actor INTEGER, client TEXT, reason_sha256 TEXT,
          command_basename TEXT, names_json TEXT, result_code INTEGER,
          previous_hash TEXT, event_hash TEXT);
          CREATE TABLE head (sequence INTEGER, event_hash TEXT);''')


def append_event(path, phase, transaction):
    with sqlite3.connect(path) as db:
        row = db.execute('SELECT sequence,event_hash FROM head').fetchone()
        seq, previous = (row[0] + 1, row[1]) if row else (1, '0' * 64)
        event = dict(actor=os.getuid(), client='unknown', command_basename=None,
                     names=['SYNTHETIC'], operation='set', phase=phase,
                     previous_hash=previous, reason_sha256='1' * 64,
                     result_code=None if phase == 'attempt' else 0,
                     sequence=seq, timestamp_ns=seq, transaction=transaction)
        h = hashlib.sha256((previous + '\n' + json.dumps(event, sort_keys=True,
                     separators=(',', ':'), ensure_ascii=False)).encode()).hexdigest()
        db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (seq, seq, transaction, phase, 'set', os.getuid(), 'unknown', '1'*64,
                    None, '["SYNTHETIC"]', event['result_code'], previous, h))
        db.execute('DELETE FROM head')
        db.execute('INSERT INTO head VALUES (?,?)', (seq, h))


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.vault = self.root / 'vault'
        self.vault.mkdir(mode=0o700)
        (self.vault / 'secretspec.toml').write_text('[profiles.default]\nSYNTHETIC = {}\n')
        with sqlite3.connect(self.vault / 'secrets.db') as db:
            db.execute('CREATE TABLE secrets (name TEXT,value TEXT)')
            db.execute('INSERT INTO secrets VALUES (?,?)', ('SYNTHETIC', 'fixture-only-secret'))
        audit_fixture(self.vault / 'broker-audit.sqlite3')
        self.transaction = str(uuid.uuid4())
        append_event(self.vault / 'broker-audit.sqlite3', 'attempt', self.transaction)
        append_event(self.vault / 'broker-audit.sqlite3', 'success', self.transaction)
        self.image = self.root / 'image'
        self.image.mkdir(mode=0o700)

    def tearDown(self):
        self.temp.cleanup()

    def test_capture_preserves_three_databases_and_files(self):
        with sqlite3.connect(self.vault / 'broker-history.sqlite3') as db:
            db.execute('CREATE TABLE history (manifest BLOB)')
        (self.vault / '.env.retired').write_text('fixture retained')
        result = backup.capture(self.vault, self.image)
        self.assertTrue(set(backup.DATABASES).issubset(result['files']))
        self.assertIn('.env.retired', result['files'])
        backup.verify_audit(self.image / 'broker-audit.sqlite3')

    def test_missing_vault_does_not_create_it(self):
        missing = self.root / 'missing'
        with self.assertRaisesRegex(backup.BackupError, 'VAULT_MISSING'):
            backup.capture(missing, self.image)
        self.assertFalse(missing.exists())

    def test_missing_database_refused(self):
        (self.vault / 'secrets.db').unlink()
        with self.assertRaisesRegex(backup.BackupError, 'VAULT_INCOMPLETE'):
            backup.capture(self.vault, self.image)

    def test_unresolved_attempt_refused_without_fabricating_terminal(self):
        append_event(self.vault / 'broker-audit.sqlite3', 'attempt', str(uuid.uuid4()))
        with self.assertRaisesRegex(backup.BackupError, 'AUDIT_UNFINISHED_OPERATION'):
            backup.capture(self.vault, self.image)
        self.assertEqual(backup.audit_state(self.vault / 'broker-audit.sqlite3')['pending'], 1)

    def test_tampered_chain_rejected(self):
        with sqlite3.connect(self.vault / 'broker-audit.sqlite3') as db:
            db.execute("UPDATE events SET client='tampered' WHERE sequence=1")
        with self.assertRaisesRegex(backup.BackupError, 'AUDIT_CHAIN_INVALID'):
            backup.capture(self.vault, self.image)

    def test_symlink_rejected(self):
        (self.vault / 'escape').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(backup.BackupError, 'VAULT_SPECIAL_FILE'):
            backup.capture(self.vault, self.image)

    def test_concurrent_atomic_replacement_rejected(self):
        real = backup.sqlite_copy
        def replace(*args):
            real(*args)
            temporary = self.vault / 'next'
            temporary.write_text('replacement')
            temporary.replace(self.vault / 'secretspec.toml')
        with patch.object(backup, 'sqlite_copy', replace):
            with self.assertRaisesRegex(backup.BackupError, 'VAULT_CHANGED_DURING_CAPTURE|SOURCE_REPLACED'):
                backup.capture(self.vault, self.image)

    def test_wal_committed_content_is_in_backup(self):
        db = sqlite3.connect(self.vault / 'secrets.db')
        try:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute("INSERT INTO secrets VALUES ('WAL','fixture-wal')")
            db.commit()
            # Prime read sidecars before measuring the stable capture.
            with contextlib.closing(backup.open_db(self.vault / 'secrets.db')) as read:
                read.execute('SELECT count(*) FROM secrets').fetchone()
            backup.capture(self.vault, self.image)
            with sqlite3.connect(self.image / 'secrets.db') as restored:
                self.assertEqual(restored.execute('SELECT count(*) FROM secrets').fetchone()[0], 2)
            self.assertFalse((self.image / 'secrets.db-wal').exists())
        finally:
            db.close()

    @unittest.skipUnless(hasattr(select, 'kqueue'), 'macOS vnode integration')
    def test_vnode_detects_file_replacement_and_vault_removal(self):
        watcher = backup.VnodeWatch(self.vault)
        try:
            (self.vault / 'new').write_text('change')
            self.assertTrue(watcher.poll(2))
            watcher.refresh()
            self.vault.rename(self.root / 'moved')
            self.assertTrue(watcher.poll(2))
            watcher.refresh()
            self.vault.mkdir(mode=0o700)
            self.assertTrue(watcher.poll(2))
        finally:
            watcher.close()


@unittest.skipUnless(shutil.which('age') and shutil.which('age-keygen'), 'age executables required')
class EncryptionHistoryTests(CaptureTests):
    def setUp(self):
        super().setUp()
        keys = self.root / 'keys'
        keys.mkdir(mode=0o700)
        self.key = keys / 'key'
        subprocess.run(['age-keygen', '-o', str(self.key)], check=True, capture_output=True)
        recipient = subprocess.check_output(['age-keygen', '-y', str(self.key)]).decode().strip()
        self.remote = self.root / 'remote.git'
        subprocess.run(['git', 'init', '--bare', str(self.remote)], check=True, capture_output=True)
        self.cfg = dict(vault=str(self.vault), state=str(self.root / 'state'), identity=str(self.key),
                        recipient=recipient, age=shutil.which('age'), git=shutil.which('git'),
                        remote=str(self.remote), min_free_bytes=0)
        self.b = backup.Backup(self.cfg)

    def test_competing_capture_preserves_owner_staging(self):
        stage = self.b.state / '.capture-active'
        stage.mkdir()
        (stage / 'plaintext').write_text('synthetic')
        with open(self.b.state / 'backup.lock', 'a') as lock:
            backup.fcntl.flock(lock, backup.fcntl.LOCK_EX | backup.fcntl.LOCK_NB)
            with patch.object(self.b, 'init_repo') as initialize:
                self.assertFalse(self.b.once())
                initialize.assert_not_called()
            self.assertEqual((stage / 'plaintext').read_text(), 'synthetic')

    def test_encrypted_history_old_new_local_remote_restore(self):
        self.assertTrue(self.b.once())
        old = self.b.status['commit']
        self.assertTrue(self.b.once())
        self.assertEqual(old, self.b.status['commit'])
        with sqlite3.connect(self.vault / 'secrets.db') as db:
            db.execute("UPDATE secrets SET value='second-fixture'")
        self.assertTrue(self.b.once())
        new = self.b.status['commit']
        self.assertNotEqual(old, new)
        self.assertEqual(new, self.b.status['mirrored_commit'])
        self.assertNotIn(b'fixture-only-secret', (self.b.repo / 'vault.tar.age').read_bytes())
        for source in (self.b.repo, self.remote):
            for revision, expected in ((old, 'fixture-only-secret'), (new, 'second-fixture')):
                dest = self.root / ('restore-' + source.name + '-' + revision)
                backup.restore(self.cfg, revision, dest, repo=source)
                with sqlite3.connect(dest / 'secrets.db') as db:
                    self.assertEqual(db.execute('SELECT value FROM secrets').fetchone()[0], expected)

    def test_remote_outage_keeps_local_snapshot_and_retries(self):
        self.b.cfg['remote'] = str(self.root / 'unavailable.git')
        self.assertTrue(self.b.once())
        self.assertEqual(self.b.status['mirror_error'], 'MIRROR_FAILED')
        self.assertTrue((self.b.repo / 'vault.tar.age').exists())
        subprocess.run(['git', 'init', '--bare', self.b.cfg['remote']], check=True, capture_output=True)
        self.b.replicate()
        self.assertIsNone(self.b.status['mirror_error'])

    def test_missing_vault_preserves_last_good_history(self):
        self.assertTrue(self.b.once())
        old = self.b.status['commit']
        self.vault.rename(self.root / 'gone')
        self.assertFalse(self.b.once())
        self.assertEqual(old, self.b.status['commit'])
        self.assertEqual(self.b.status['capture_error'], 'VAULT_MISSING')

    def test_low_disk_never_commits(self):
        self.b.cfg['min_free_bytes'] = 2**63
        self.assertFalse(self.b.once())
        self.assertNotIn('commit', self.b.status)

    def test_restore_refuses_existing_destination_and_live_vault(self):
        with self.assertRaisesRegex(backup.BackupError, 'DESTINATION_EXISTS'):
            backup.restore(self.cfg, 'a'*40, self.vault)

    def test_interrupted_encryption_preserves_previous_commit(self):
        self.assertTrue(self.b.once())
        old = self.b.status['commit']
        (self.vault / 'secretspec.toml').write_text('changed')
        self.b.age = '/usr/bin/false'
        with patch.object(backup.time, 'sleep'):
            self.assertFalse(self.b.once())
        self.assertEqual(old, self.b.status['commit'])

    def test_stale_instance_replication_reloads_committed_state(self):
        stale = backup.Backup(self.cfg)
        self.assertTrue(self.b.once())
        stale.replicate()
        self.assertEqual(stale.status['commit'], self.b.status['commit'])
        self.assertEqual(stale.status['mirrored_commit'], self.b.status['commit'])

    def test_empty_interrupted_repository_initialization_recovers(self):
        self.b.repo.mkdir(mode=0o700)
        self.assertTrue(self.b.once())

    def test_missing_established_history_is_not_accepted(self):
        self.b.cfg['expected_databases'] = list(backup.DATABASES)
        with patch.object(backup.time, 'sleep'):
            self.assertFalse(self.b.once())
        self.assertEqual(self.b.status['capture_error'], 'ESTABLISHED_DATABASE_MISSING')

    def test_restore_rejects_live_path_through_parent_alias(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        self.vault.rename(self.root / 'moved')
        with self.assertRaisesRegex(backup.BackupError, 'ISOLATED'):
            backup.restore(self.cfg, 'a' * 40, alias / 'vault')


if __name__ == '__main__':
    unittest.main()
