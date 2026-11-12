#!/usr/bin/python3
"""Independent, encrypted, append-only vault backups. No secret output."""
from __future__ import annotations

import argparse
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import syslog
import tarfile
import tempfile
import time
import uuid

DATABASES = ('secrets.db', 'broker-audit.sqlite3', 'broker-history.sqlite3')
REQUIRED = ('secretspec.toml', 'secrets.db', 'broker-audit.sqlite3')
DEFAULT_CONFIG = '/usr/local/etc/sudo-secretspec-backup.json'


class BackupError(Exception):
    pass


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def atomic_json(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(value, out, sort_keys=True)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def run(argv, *, cwd=None, input=None, timeout=120, env=None):
    # Command errors can contain secret material (age, SQLite, restore input).
    # Return only the command basename and exit code; never raw subprocess output.
    try:
        result = subprocess.run(argv, cwd=cwd, input=input, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        raise BackupError('command timed out: ' + Path(argv[0]).name) from None
    if result.returncode:
        raise BackupError('command failed: %s (exit %s)' %
                          (Path(argv[0]).name, result.returncode))
    return result.stdout


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as src:
        for chunk in iter(lambda: src.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def secure_dir(path):
    path = Path(path)
    if not path.exists():
        path.mkdir(mode=0o700, parents=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise BackupError('backup state must be an owner-only directory owned by the executing user')


def inventory(vault):
    """Capture metadata without following symlinks; reject special files."""
    vault = Path(vault)
    if not vault.exists():
        raise BackupError('VAULT_MISSING')
    root = vault.lstat()
    if not stat.S_ISDIR(root.st_mode) or root.st_mode & 0o077:
        raise BackupError('VAULT_METADATA_INVALID')
    result = {'.': metadata(root)}
    for directory, dirs, files in os.walk(vault, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            info = path.lstat()
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise BackupError('VAULT_SPECIAL_FILE')
            result[str(path.relative_to(vault))] = metadata(info)
    if 'backup-manifest.json' in result:
        raise BackupError('RESERVED_BACKUP_METADATA_NAME')
    for name in REQUIRED:
        if name not in result or result[name]['kind'] != 'file':
            raise BackupError('VAULT_INCOMPLETE')
    return result


def metadata(s):
    return dict(uid=s.st_uid, gid=s.st_gid, mode=stat.S_IMODE(s.st_mode),
                size=s.st_size, mtime_ns=s.st_mtime_ns, ctime_ns=s.st_ctime_ns,
                inode=s.st_ino, device=s.st_dev, kind='dir' if stat.S_ISDIR(s.st_mode) else 'file')


@contextlib.contextmanager
def source_access(credentials):
    """Temporarily drop privilege for source access in this single-threaded helper.

    Outputs stay root-only, opened before this scope. Never launch subprocesses
    or execute callbacks supplied by configuration while privileges are lowered.
    """
    if credentials is None:
        yield
        return
    uid, gid = credentials
    old_uid, old_gid = os.geteuid(), os.getegid()
    try:
        os.setgroups([])
        os.setegid(gid)
        os.seteuid(uid)
        yield
    finally:
        os.seteuid(old_uid)
        os.setegid(old_gid)
        # getgroups() on macOS includes dynamically resolved memberships and
        # cannot be round-tripped through setgroups(). This dedicated root
        # helper deliberately retains no supplementary groups.
        os.setgroups([])


def open_db(path):
    # mode=ro honors WAL/journals. Never immutable=1 on a live SQLite database.
    conn = sqlite3.connect(Path(path).absolute().as_uri() + '?mode=ro', uri=True, timeout=2)
    conn.execute('PRAGMA query_only=ON')
    return conn


def audit_state(path, credentials=None):
    with source_access(credentials), contextlib.closing(open_db(path)) as db:
        # Filled from the product's actual schema; explicit columns fail closed
        # if a future version changes the recovery contract.
        heads = db.execute('SELECT sequence, event_hash FROM head').fetchall()
        if len(heads) > 1:
            raise BackupError('AUDIT_HEAD_INVALID')
        head = heads[0] if heads else None
        pending = db.execute("SELECT count(*) FROM events a WHERE a.phase = 'attempt' "
                             "AND NOT EXISTS (SELECT 1 FROM events t "
                             "WHERE t.transaction_id = a.transaction_id "
                             "AND t.phase IN ('success','failure','unknown'))").fetchone()[0]
        return {'head': list(head) if head else None, 'pending': pending}


def verify_audit(path):
    previous, sequence = '0' * 64, 0
    with contextlib.closing(open_db(path)) as db:
        db.row_factory = sqlite3.Row
        for row in db.execute('SELECT * FROM events ORDER BY sequence'):
            r = dict(row)
            if r['previous_hash'] != previous or r['sequence'] != sequence + 1:
                raise BackupError('AUDIT_CHAIN_INVALID')
            event = {k: r[k] for k in ('actor', 'client', 'command_basename', 'operation',
                     'phase', 'previous_hash', 'reason_sha256', 'result_code', 'sequence', 'timestamp_ns')}
            event['names'] = json.loads(r['names_json'])
            event['transaction'] = str(uuid.UUID(r['transaction_id']))
            canonical = json.dumps(event, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
            expected = hashlib.sha256((previous + '\n' + canonical).encode()).hexdigest()
            if expected != r['event_hash']:
                raise BackupError('AUDIT_CHAIN_INVALID')
            previous, sequence = expected, r['sequence']
    head = audit_state(path)['head']
    if head != ([sequence, previous] if sequence else None):
        raise BackupError('AUDIT_HEAD_INVALID')


def sqlite_copy(source, destination, deadline, credentials=None, memory_limit=512 * 1024 * 1024):
    page_size = 0
    def progress(status, remaining, total):
        if time.monotonic() > deadline:
            raise BackupError('SNAPSHOT_TIMEOUT')
        if credentials is not None and total * page_size > memory_limit:
            raise BackupError('DATABASE_EXCEEDS_MEMORY_SNAPSHOT_LIMIT')
    # SQLite may reopen its destination while backing up. A service-UID source
    # cannot back up directly into a root-only path, even with preopened FDs.
    # Materialize one bounded in-memory image as that UID, then write the image
    # as root. No plaintext scratch is ever exposed outside root-only staging.
    if credentials is not None:
        size = Path(source).stat().st_size
        wal = Path(str(source) + '-wal')
        if wal.exists():
            size += wal.stat().st_size
        if size > memory_limit:
            raise BackupError('DATABASE_EXCEEDS_MEMORY_SNAPSHOT_LIMIT')
        with contextlib.closing(sqlite3.connect(':memory:')) as image:
            with source_access(credentials), contextlib.closing(open_db(source)) as src:
                page_size = src.execute('PRAGMA page_size').fetchone()[0]
                progress(0, 0, src.execute('PRAGMA page_count').fetchone()[0])
                src.backup(image, pages=256, progress=progress, sleep=0.05)
            with contextlib.closing(sqlite3.connect(str(destination))) as dst:
                image.backup(dst, pages=256, progress=progress, sleep=0.05)
                dst.execute('PRAGMA journal_mode=DELETE')
                if dst.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                    raise BackupError('DATABASE_INTEGRITY_FAILED')
        return
    with contextlib.closing(sqlite3.connect(str(destination))) as dst:
        dst.execute('PRAGMA journal_mode=OFF')
        with source_access(credentials), contextlib.closing(open_db(source)) as src:
            src.backup(dst, pages=256, progress=progress, sleep=0.05)
        dst.execute('PRAGMA journal_mode=DELETE')
        if dst.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise BackupError('DATABASE_INTEGRITY_FAILED')


def capture(vault, destination, credentials=None, memory_limit=512 * 1024 * 1024):
    """Stable capture across all DBs and files; interrupted operations fail closed."""
    vault, destination = Path(vault), Path(destination)
    before = inventory(vault)
    audit_before = audit_state(vault / 'broker-audit.sqlite3', credentials)
    if audit_before['pending']:
        raise BackupError('AUDIT_UNFINISHED_OPERATION')
    deadline = time.monotonic() + 20
    records = {}
    for name, info in before.items():
        if name == '.':
            continue
        path = destination / name
        if info['kind'] == 'dir':
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            records[name] = info
            continue
        # SQLite sidecars belong to the live connection, not to a standalone
        # backup. They are folded into the DB by SQLite's backup API.
        if any(name == db + suffix for db in DATABASES for suffix in ('-wal', '-shm', '-journal')):
            continue
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if name in DATABASES:
            sqlite_copy(vault / name, path, deadline, credentials, memory_limit)
        else:
            with source_access(credentials):
                fd = os.open(vault / name, os.O_RDONLY | os.O_NOFOLLOW)
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info['device'], info['inode']):
                os.close(fd)
                raise BackupError('SOURCE_REPLACED')
            with os.fdopen(fd, 'rb') as src, open(path, 'xb') as dst:
                shutil.copyfileobj(src, dst)
        os.chmod(path, 0o600)
        records[name] = dict(info, sha256=digest(path))
    after = inventory(vault)
    audit_after = audit_state(vault / 'broker-audit.sqlite3', credentials)
    if before != after or audit_before != audit_after:
        raise BackupError('VAULT_CHANGED_DURING_CAPTURE')
    # SQLite backup image must carry the same audit tip as the live stable view.
    if audit_state(destination / 'broker-audit.sqlite3') != audit_before:
        raise BackupError('AUDIT_SNAPSHOT_MISMATCH')
    verify_audit(destination / 'broker-audit.sqlite3')
    stable = {name: {k: v for k, v in info.items()
                     if k in ('uid', 'gid', 'mode', 'kind', 'sha256')}
              for name, info in records.items()}
    fingerprint = hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()
    manifest = dict(format=1, captured_at=utc(), root=before['.'], files=records,
                    audit=audit_before, fingerprint=fingerprint)
    atomic_json(destination / 'backup-manifest.json', manifest)
    manifest['_source_inventory'] = before
    return manifest


def restricted_capture(cfg, image):
    credentials = None
    if os.geteuid() == 0:
        # A sudo-launched process can inherit more directory-service groups
        # than macOS setgroups permits restoring. This dedicated helper needs
        # none of them; discard them before entering temporary source scopes.
        os.setgroups([])
        uid, gid = cfg['vault_uid'], cfg['vault_gid']
        try:
            root = Path(cfg['vault']).lstat()
        except FileNotFoundError:
            raise BackupError('VAULT_MISSING') from None
        if root.st_uid != uid or root.st_gid != gid or uid == 0:
            raise BackupError('VAULT_OWNER_MISMATCH')
        credentials = (uid, gid)
    return capture(cfg['vault'], image, credentials, cfg.get('snapshot_memory_limit_bytes', 512 * 1024 * 1024))


class Backup:
    def __init__(self, cfg):
        self.cfg = cfg
        self.state = Path(cfg['state'])
        secure_dir(self.state)
        self.repo = self.state / 'history'
        self.status_path = self.state / 'status.json'
        self.status = json.loads(self.status_path.read_text()) if self.status_path.exists() else {'format': 1}
        self.capture_inventory = None
        self.git = cfg.get('git', '/usr/bin/git')
        self.age = cfg.get('age', '/usr/local/libexec/sudo-secretspec-backup/age')
        self.git_env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                            GIT_TERMINAL_PROMPT='0')
        for key in list(self.git_env):
            if key.startswith('GIT_') and key not in ('GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_GLOBAL', 'GIT_TERMINAL_PROMPT'):
                del self.git_env[key]
        if cfg.get('ssh_command'):
            self.git_env['GIT_SSH_COMMAND'] = cfg['ssh_command']

    def git_run(self, *args, timeout=120):
        return run([self.git, '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
                    '-c', 'gc.auto=0', '-c', 'maintenance.auto=false', *args],
                   cwd=self.repo, env=self.git_env, timeout=timeout)

    def save_status(self, **fields):
        self.status.update(fields, updated_at=utc())
        atomic_json(self.status_path, self.status)
        # Public health contains no hashes of plaintext, names, or credentials.
        if self.cfg.get('health_file'):
            public = {k: v for k, v in self.status.items() if k != 'fingerprint'}
            atomic_json(self.cfg['health_file'], public)
            os.chmod(self.cfg['health_file'], 0o644)

    def event(self, code):
        record = {'at': utc(), 'code': code}
        with open(self.state / 'incidents.jsonl', 'a') as out:
            out.write(json.dumps(record) + '\n')
        print(json.dumps(record), flush=True)
        syslog.syslog(syslog.LOG_ERR, 'sudo-secretspec backup: ' + code)
        notify = self.cfg.get('notify_argv')
        if notify:
            try:
                run(notify + ['sudo-secretspec backup: ' + code], timeout=15)
            except (BackupError, OSError):
                print(json.dumps({'at': utc(), 'code': 'ALERT_DELIVERY_FAILED'}), flush=True)

    def init_repo(self):
        if not self.repo.exists():
            self.repo.mkdir(mode=0o700)
        if not (self.repo / '.git').exists():
            if any(self.repo.iterdir()) or self.status.get('commit'):
                raise BackupError('REPOSITORY_MISSING_OR_INCOMPLETE')
            self.git_run('init', '--initial-branch=main')
        if Path(self.git_run('rev-parse', '--show-toplevel').decode().strip()).resolve() != self.repo.resolve():
            raise BackupError('REPOSITORY_LOCATION_MISMATCH')
        self.git_run('config', 'user.name', 'sudo-secretspec backup')
        self.git_run('config', 'user.email', 'backup@localhost')
        if self.cfg.get('remote'):
            existing = self.git_run('remote').decode().splitlines()
            if 'mirror' not in existing:
                self.git_run('remote', 'add', 'mirror', self.cfg['remote'])
            elif self.git_run('remote', 'get-url', 'mirror').decode().strip() != self.cfg['remote']:
                raise BackupError('REMOTE_CONFIG_MISMATCH')

    def replicate(self):
        with open(self.state / 'backup.lock', 'a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return
            self.status = json.loads(self.status_path.read_text()) if self.status_path.exists() else {'format': 1}
            self._replicate_locked()

    def _replicate_locked(self):
        if not self.status.get('commit') or not self.cfg.get('remote'):
            return
        try:
            current = self.git_run('rev-parse', 'HEAD').decode().strip()
            if current != self.status['commit']:
                self.save_status(commit=current, fingerprint=None)
            self.git_run('push', 'mirror', 'HEAD:refs/heads/main', timeout=60)
            refs = self.git_run('ls-remote', 'mirror', 'refs/heads/main', timeout=30).decode().split()
            if not refs or refs[0] != self.status['commit']:
                raise BackupError('MIRROR_HEAD_MISMATCH')
            self.save_status(last_mirror_at=utc(), mirrored_commit=refs[0], mirror_error=None)
        except (BackupError, OSError):
            if not self.status.get('mirror_error'):
                self.event('MIRROR_FAILED')
            self.save_status(mirror_error='MIRROR_FAILED')

    def once(self):
        lock = open(self.state / 'backup.lock', 'a')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            lock.close()
            return False
        try:
            self.status = json.loads(self.status_path.read_text()) if self.status_path.exists() else {'format': 1}
            self.init_repo()
            # Only this lock holder can capture; stale private staging from a
            # killed predecessor must not accumulate plaintext indefinitely.
            for abandoned in self.state.glob('.capture-*'):
                info = abandoned.lstat()
                if stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid():
                    shutil.rmtree(abandoned)
            if shutil.disk_usage(self.state).free < self.cfg.get('min_free_bytes', 1024 ** 3):
                raise BackupError('LOW_DISK_SPACE')
            last_error = None
            for delay in (0, 1, 3):
                if delay:
                    time.sleep(delay)
                try:
                    with tempfile.TemporaryDirectory(prefix='.capture-', dir=self.state) as tmp:
                        stage = Path(tmp)
                        image = stage / 'vault'
                        image.mkdir(mode=0o700)
                        manifest = restricted_capture(self.cfg, image)
                        self.capture_inventory = manifest.pop('_source_inventory')
                        expected = set(self.status.get('established_databases', self.cfg.get('expected_databases', [])))
                        present = set(manifest['files']).intersection(DATABASES)
                        if not expected.issubset(present):
                            raise BackupError('ESTABLISHED_DATABASE_MISSING')
                        if manifest['fingerprint'] != self.status.get('fingerprint'):
                            archive = stage / 'vault.tar'
                            with tarfile.open(archive, 'w:gz') as tar:
                                tar.add(image, arcname='vault')
                            encrypted = stage / 'vault.tar.age'
                            run([self.age, '-r', self.cfg['recipient'], '-o', str(encrypted), str(archive)])
                            os.replace(encrypted, self.repo / 'vault.tar.age')
                            self.git_run('add', '--', 'vault.tar.age')
                            self.git_run('commit', '-m', 'Vault snapshot ' + utc())
                            commit = self.git_run('rev-parse', 'HEAD').decode().strip()
                            self.save_status(commit=commit, fingerprint=manifest['fingerprint'],
                                             last_snapshot_at=manifest['captured_at'])
                        self.save_status(last_check_at=utc(), capture_error=None,
                                         established_databases=sorted(present))
                        last_error = None
                        break
                except (BackupError, sqlite3.Error, OSError) as exc:
                    last_error = exc
                    if isinstance(exc, BackupError) and str(exc) in ('VAULT_MISSING', 'VAULT_INCOMPLETE'):
                        break
            if last_error:
                raise last_error
            self._replicate_locked()
            return True
        except (BackupError, sqlite3.Error, OSError, ValueError) as exc:
            code = str(exc) if isinstance(exc, BackupError) else type(exc).__name__
            if self.status.get('capture_error') != code:
                self.event(code)
            self.save_status(last_check_at=utc(), capture_error=code)
            self._replicate_locked()
            return False
        finally:
            lock.close()


class VnodeWatch:
    """Watch file content as well as directory entries, and retain parent watch."""
    def __init__(self, vault):
        self.vault = Path(vault)
        self.queue = select.kqueue()
        self.fds = []
        self.parent_fd = None
        self.identity = None
        self.refresh()

    def vault_identity(self):
        try:
            info = self.vault.lstat()
            return info.st_dev, info.st_ino
        except FileNotFoundError:
            return None

    def refresh(self):
        for fd in self.fds:
            os.close(fd)
        self.fds = []
        self.parent_fd = None
        self.identity = self.vault_identity()
        paths = [self.vault.parent]
        if self.vault.is_dir() and not self.vault.is_symlink():
            paths += [self.vault] + list(self.vault.rglob('*'))
        for path in paths:
            try:
                fd = os.open(path, getattr(os, 'O_EVTONLY', os.O_RDONLY) | os.O_NOFOLLOW)
                self.queue.control([select.kevent(fd, filter=select.KQ_FILTER_VNODE,
                    flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                    fflags=select.KQ_NOTE_WRITE | select.KQ_NOTE_DELETE | select.KQ_NOTE_RENAME |
                           select.KQ_NOTE_ATTRIB | select.KQ_NOTE_EXTEND | select.KQ_NOTE_REVOKE)], 0)
                self.fds.append(fd)
                if path == self.vault.parent:
                    self.parent_fd = fd
            except FileNotFoundError:
                pass

    def poll(self, timeout):
        events = self.queue.control(None, max(1, len(self.fds)), timeout)
        # /var/db is busy. Parent changes matter only if our vault's identity
        # changed; file/directory events inside the vault always trigger.
        return any(e.ident != self.parent_fd for e in events) or (
            bool(events) and self.vault_identity() != self.identity)

    def close(self):
        for fd in self.fds:
            os.close(fd)
        self.queue.close()


def watch(backup):
    if not hasattr(select, 'kqueue'):
        raise BackupError('VNODE_WATCH_UNAVAILABLE')
    watcher = VnodeWatch(backup.cfg['vault'])
    running = True
    def stop(*args):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    next_hour = 0.0
    next_mirror = 0.0
    first_event = last_event = None
    try:
        while running:
            now = time.monotonic()
            due = first_event is not None and (now - last_event >= 2 or now - first_event >= 30)
            if now >= next_hour or due:
                success = backup.once()
                dirty = watcher.poll(0)
                watcher.refresh()
                if success:
                    try:
                        dirty = dirty or inventory(backup.cfg['vault']) != backup.capture_inventory
                    except (BackupError, OSError):
                        dirty = True
                next_hour = time.monotonic() + 3600
                next_mirror = time.monotonic() + 300
                first_event = last_event = time.monotonic() if dirty else None
            elif now >= next_mirror:
                backup.replicate()
                next_mirror = time.monotonic() + 300
            if watcher.poll(1):
                last_event = time.monotonic()
                if first_event is None:
                    first_event = last_event
    finally:
        watcher.close()


def restore(cfg, revision, destination, *, repo=None):
    """Restore to a NEW isolated directory only, never overwrite the live vault."""
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise BackupError('RESTORE_DESTINATION_EXISTS')
    resolved = destination.resolve()
    live = Path(cfg['vault']).resolve()
    protected = [live, Path(cfg['state']).resolve(), Path(cfg['identity']).resolve().parent]
    if not destination.is_absolute() or any(
            resolved == p or p in resolved.parents or resolved in p.parents for p in protected):
        raise BackupError('RESTORE_REQUIRES_ISOLATED_ABSOLUTE_DESTINATION')
    if not revision or any(c not in '0123456789abcdef' for c in revision) or len(revision) != 40:
        raise BackupError('RESTORE_REQUIRES_FULL_COMMIT_SHA')
    state = Path(cfg['state'])
    secure_dir(state)
    with tempfile.TemporaryDirectory(prefix='.restore-', dir=state) as tmp:
        tmp = Path(tmp)
        encrypted = tmp / 'vault.tar.age'
        # Binary ciphertext goes to a file, never console output.
        encrypted.write_bytes(run([cfg.get('git', '/usr/bin/git'), '-C', str(repo or state / 'history'),
                                   'show', revision + ':vault.tar.age']))
        archive = tmp / 'vault.tar'
        run([cfg.get('age', '/usr/local/libexec/sudo-secretspec-backup/age'), '-d',
             '-i', cfg['identity'], '-o', str(archive), str(encrypted)])
        extracted = tmp / 'extracted'
        extracted.mkdir(mode=0o700)
        with tarfile.open(archive, 'r:*') as tar:
            members = tar.getmembers()
            for member in members:
                p = Path(member.name)
                if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0] != 'vault':
                    raise BackupError('UNSAFE_ARCHIVE_PATH')
                if not (member.isfile() or member.isdir()):
                    raise BackupError('UNSAFE_ARCHIVE_MEMBER')
            # All members are regular files/directories rooted at vault.
            for member in members:
                target = extracted / member.name
                if member.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    with tar.extractfile(member) as src, open(target, 'xb') as dst:
                        shutil.copyfileobj(src, dst)
        image = extracted / 'vault'
        manifest = json.loads((image / 'backup-manifest.json').read_text())
        if manifest.get('format') != 1:
            raise BackupError('UNKNOWN_BACKUP_FORMAT')
        names = set(manifest['files'])
        actual = {str(p.relative_to(image)) for p in image.rglob('*')}
        if not set(REQUIRED).issubset(names) or names | {'backup-manifest.json'} != actual:
            raise BackupError('RESTORE_INVENTORY_MISMATCH')
        if 'backup-manifest.json' in names:
            raise BackupError('RESERVED_BACKUP_METADATA_NAME')
        for name, info in manifest['files'].items():
            p = Path(name)
            if p.is_absolute() or '..' in p.parts:
                raise BackupError('UNSAFE_MANIFEST_PATH')
            path = image / name
            if info['kind'] not in ('file', 'dir') or (info['kind'] == 'dir') != path.is_dir():
                raise BackupError('RESTORE_KIND_INVALID')
            if any(type(info[k]) is not int or info[k] < 0 for k in ('uid', 'gid', 'mode')) or info['mode'] > 0o777:
                raise BackupError('RESTORE_METADATA_INVALID')
            if info['kind'] == 'file' and digest(path) != info['sha256']:
                raise BackupError('RESTORE_CHECKSUM_FAILED')
            if name in DATABASES:
                with contextlib.closing(open_db(path)) as db:
                    if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                        raise BackupError('RESTORE_DATABASE_INVALID')
        if audit_state(image / 'broker-audit.sqlite3') != manifest['audit']:
            raise BackupError('RESTORE_AUDIT_MISMATCH')
        verify_audit(image / 'broker-audit.sqlite3')
        (image / 'backup-manifest.json').unlink()
        # All validation precedes ownership changes; directories are applied
        # deepest first while staging remains hidden by its protected parent.
        for name in sorted(names, key=lambda n: len(Path(n).parts), reverse=True):
            info = manifest['files'][name]
            os.chmod(image / name, info['mode'])
            if os.geteuid() == 0:
                os.chown(image / name, info['uid'], info['gid'])
        os.chmod(image, manifest['root']['mode'])
        if os.geteuid() == 0:
            os.chown(image, manifest['root']['uid'], manifest['root']['gid'])
        # Destination must be on the same filesystem: no partial cross-device copy.
        parent = resolved.parent.stat()
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
            raise BackupError('RESTORE_PARENT_NOT_PROTECTED')
        destination = resolved
        # mkdir is exclusive. Never replace a directory created by another
        # process since the initial check; this reserved target is ours only.
        destination.mkdir(mode=0o700)
        try:
            os.rename(image, destination)
        except BaseException:
            destination.rmdir()
            raise
    return {'restored': True, 'commit': revision, 'destination': str(destination)}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default=DEFAULT_CONFIG)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('once')
    sub.add_parser('watch')
    sub.add_parser('status')
    p = sub.add_parser('restore')
    p.add_argument('revision')
    p.add_argument('destination')
    p.add_argument('--repo')
    args = parser.parse_args()
    try:
        cfg = json.loads(Path(args.config).read_text())
        if args.command == 'restore':
            print(json.dumps(restore(cfg, args.revision, args.destination, repo=args.repo)))
            return 0
        backup = Backup(cfg)
        if args.command == 'status':
            print(json.dumps({k: v for k, v in backup.status.items() if k != 'fingerprint'}, sort_keys=True))
        elif args.command == 'watch':
            watch(backup)
        else:
            return 0 if backup.once() else 1
    except (BackupError, sqlite3.Error, OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, BackupError) else type(exc).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
