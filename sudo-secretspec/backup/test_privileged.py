#!/usr/bin/python3
"""Explicit root-only smoke: synthetic service-owned WAL vault, no live secrets."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import sqlite3
import tempfile
import unittest

import backup
from test_backup import audit_fixture, append_event


@unittest.skipUnless(os.geteuid() == 0 and os.uname().sysname == 'Darwin', 'explicit privileged macOS fixture')
class PrivilegedCaptureTests(unittest.TestCase):
    def test_root_staging_and_service_uid_source_access(self):
        user = pwd.getpwnam('_sudo_secretspec')
        # Parent /var/db is traversable; only the service UID owns this fixture.
        vault = Path(tempfile.mkdtemp(prefix='sudo-secretspec-fixture-', dir='/var/db'))
        try:
            (vault / 'secretspec.toml').write_text('[profiles.default]\nSYNTHETIC = {}\n')
            db = sqlite3.connect(vault / 'secrets.db')
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE secrets (value TEXT)')
            db.execute("INSERT INTO secrets VALUES ('synthetic-only')")
            db.commit()
            audit_fixture(vault / 'broker-audit.sqlite3')
            for path in [vault] + list(vault.iterdir()):
                os.chown(path, user.pw_uid, user.pw_gid)
                os.chmod(path, 0o700 if path.is_dir() else 0o600)
            with tempfile.TemporaryDirectory(prefix='root-only-backup-', dir='/var/db') as tmp:
                image = Path(tmp) / 'image'
                image.mkdir(mode=0o700)
                result = backup.restricted_capture(dict(vault=str(vault), vault_uid=user.pw_uid,
                                                       vault_gid=user.pw_gid), image)
                self.assertIn('secrets.db', result['files'])
                self.assertEqual(image.stat().st_uid, 0)
                self.assertEqual(os.geteuid(), 0)
                with contextlib.closing(sqlite3.connect(image / 'secrets.db')) as restored:
                    self.assertEqual(restored.execute('SELECT count(*) FROM secrets').fetchone()[0], 1)
                # Service cannot read a root-only target even if the live path
                # is swapped. No source SQLite connection is opened as root.
                (vault / 'secrets.db').unlink()
                (vault / 'secrets.db').symlink_to(image / 'secrets.db')
                with self.assertRaises(backup.BackupError):
                    backup.inventory(vault)
            db.close()
        finally:
            shutil.rmtree(vault)


if __name__ == '__main__':
    unittest.main()
