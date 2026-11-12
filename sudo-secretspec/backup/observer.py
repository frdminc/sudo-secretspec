#!/usr/bin/env python3
"""Best-effort Endpoint Security attribution, independent of vault backups.

Requires root and Full Disk Access for /usr/bin/eslogger. eslogger is not a
stable API: unknown schemas, sequence loss and startup failures are explicit
health failures. Raw events, stderr, argv and environments are never persisted.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid

DEFAULT_STATE = Path('/var/db/sudo-secretspec-backup/observer')
MAX_LINE = 2 * 1024 * 1024
ROTATE_BYTES = 4 * 1024 * 1024
EVENTS = ('unlink', 'rename')  # macOS eslogger exposes directory removal as unlink.
SUPPORTED_SCHEMAS = {1}


class ObserverError(Exception):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def secure_directory(path: Path) -> None:
    """Never follow a planted state-dir symlink, including an ancestor."""
    absolute = path.absolute()
    for parent in reversed((absolute, *absolute.parents)):
        if parent.exists() or parent.is_symlink():
            if stat.S_ISLNK(parent.lstat().st_mode):
                if parent == Path('/var') and os.path.realpath(parent) == '/private/var':
                    continue  # The standard macOS /var alias, never an arbitrary symlink.
                raise ObserverError('state_path_symlink')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    meta = path.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.geteuid():
        raise ObserverError('state_directory_owner')
    if stat.S_IMODE(meta.st_mode) != 0o700:
        raise ObserverError('state_directory_permissions')


def atomic_json(path: Path, value: dict) -> None:
    tmp = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def normal_path(value: object) -> str:
    if not isinstance(value, str) or not value.startswith('/') or '\x00' in value:
        raise ObserverError('event_path_invalid')
    return os.path.normpath(value)


class EventFilter:
    def __init__(self, vault: str):
        self.vaults = {normal_path(vault), os.path.realpath(vault)}
        self.ancestors = {str(p) for v in self.vaults for p in Path(v).parents}
        self.sequences: dict[str, int] = {}
        self.global_sequence: int | None = None
        self.events_seen = 0
        self.event_loss = 0

    def relevant(self, path: str) -> bool:
        return path in self.ancestors or any(
            path == v or path.startswith(v + '/') for v in self.vaults)

    def parse(self, value: dict) -> dict | None:
        if not isinstance(value, dict) or type(value.get('schema_version')) is not int or value.get('schema_version') not in SUPPORTED_SCHEMAS:
            raise ObserverError('unsupported_schema')
        event_type = value.get('event_type')
        if not isinstance(event_type, str):
            raise ObserverError('event_type_missing')
        event_type = event_type.lower().removeprefix('es_event_type_').removeprefix('notify_')
        if event_type not in EVENTS:
            raise ObserverError('unexpected_event_type')
        seq = value.get('seq_num')
        if type(seq) is not int or seq < 0:
            raise ObserverError('event_sequence_missing')
        previous = self.sequences.get(event_type)
        if previous is not None and seq != previous + 1:
            self.event_loss += max(1, seq - previous - 1)
        self.sequences[event_type] = seq
        # global_seq_num is not emitted on every supported macOS release.
        global_seq = value.get('global_seq_num')
        if global_seq is not None:
            if type(global_seq) is not int or global_seq < 0:
                raise ObserverError('event_sequence_invalid')
            if self.global_sequence is not None and global_seq != self.global_sequence + 1:
                self.event_loss += max(1, global_seq - self.global_sequence - 1)
            self.global_sequence = global_seq
        event = value.get('event', {}).get(event_type)
        if not isinstance(event, dict):
            raise ObserverError('event_payload_missing')
        if event_type == 'unlink':
            paths = [normal_path(event.get('target', {}).get('path'))]
        else:
            paths = [normal_path(event.get('source', {}).get('path'))]
            destination = event.get('destination')
            if not isinstance(destination, dict):
                raise ObserverError('rename_destination_missing')
            if 'existing_file' in destination:
                paths.append(normal_path(destination['existing_file'].get('path')))
            elif 'new_path' in destination:
                new = destination['new_path']
                directory = normal_path(new.get('dir', {}).get('path'))
                filename = new.get('filename')
                if not isinstance(filename, str) or not filename or '/' in filename or filename in ('.', '..'):
                    raise ObserverError('rename_filename_invalid')
                paths.append(normal_path(directory + '/' + filename))
            else:
                raise ObserverError('rename_destination_unsupported')
        self.events_seen += 1
        if not any(self.relevant(p) for p in paths):
            return None
        process = value.get('process')
        if not isinstance(process, dict):
            raise ObserverError('process_missing')
        token = process.get('audit_token', {})
        pid, uid = token.get('pid'), token.get('euid')
        if type(pid) is not int or type(uid) is not int:
            raise ObserverError('process_identity_missing')
        executable = normal_path(process.get('executable', {}).get('path'))
        record = {'observed_at': utc_now(), 'event': event_type,
                  'paths': paths, 'pid': pid, 'uid': uid, 'executable': executable}
        # Copy only a strict whitelist, never the raw process object or event.
        if isinstance(value.get('time'), str):
            record['event_time'] = value['time'][:128]
        for name in ('signing_id', 'team_id', 'cdhash'):
            if isinstance(process.get(name), str):
                record[name] = process[name][:512]
        return record


def append_incident(state: Path, record: dict, limit: int = ROTATE_BYTES) -> None:
    path = state / 'incidents.jsonl'
    if path.exists() or path.is_symlink():
        meta = path.lstat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.geteuid() or stat.S_IMODE(meta.st_mode) != 0o600:
            raise ObserverError('incident_file_permissions')
        if meta.st_size >= limit:
            # Retain archives forever; only the current writable file rotates.
            path.rename(state / ('incidents.' + str(time.time_ns()) + '.' + uuid.uuid4().hex + '.jsonl'))
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as stream:
        stream.write(json.dumps(record, sort_keys=True) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


def cpu_seconds(value: str) -> float:
    parts = value.split(':')
    result = 0.0
    for part in parts:
        result = result * 60 + float(part)
    return result


def process_tree_metrics(root_pid: int, own_pid: int) -> tuple[float, int]:
    result = subprocess.run(['/bin/ps', '-axo', 'pid=,ppid=,time=,rss='],
                            capture_output=True, text=True, timeout=5, check=True)
    rows = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 4:
            rows[int(fields[0])] = (int(fields[1]), cpu_seconds(fields[2]), int(fields[3]) * 1024)
    if root_pid not in rows or own_pid not in rows:
        raise ObserverError('metrics_process_missing')
    pids = {root_pid}
    changed = True
    while changed:
        new = {pid for pid, (parent, _, _) in rows.items() if parent in pids}
        changed = bool(new - pids)
        pids |= new
    return (sum(rows[p][1] for p in pids if p in rows),
            sum(rows[p][2] for p in pids | {own_pid} if p in rows))


def run_observer(state: Path, vault: str, benchmark_seconds: float | None = None) -> int:
    secure_directory(state)
    filt = EventFilter(vault)
    started = time.monotonic()
    start_cpu = time.process_time()
    health = {'schema': 1, 'started_at': utc_now(), 'status': 'starting',
              'coverage_verified': False, 'events_seen': 0, 'matching_events': 0,
              'event_loss': 0, 'errors': []}
    stop = False
    def stopping(_signum, _frame):
        nonlocal stop
        stop = True
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, stopping)
    atomic_json(state / 'health.json', health)
    if sys.platform != 'darwin' or os.geteuid() != 0:
        health.update(status='unavailable', errors=['requires_macos_root_and_full_disk_access'], updated_at=utc_now())
        atomic_json(state / 'health.json', health)
        if benchmark_seconds is not None:
            report = {'schema': 1, 'passed': False, 'duration_seconds': 0,
                      'requested_seconds': benchmark_seconds, 'coverage_verified': False,
                      'errors': health['errors'], 'measured_at': utc_now()}
            atomic_json(state / 'benchmark.json', report)
            print(json.dumps(report, sort_keys=True))
        return 1
    try:
        child = subprocess.Popen(['/usr/bin/eslogger', *EVENTS], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True)
    except OSError:
        health.update(status='failed', errors=['eslogger_launch_failed'], updated_at=utc_now())
        atomic_json(state / 'health.json', health)
        return 1
    selector = selectors.DefaultSelector()
    for stream, name in ((child.stdout, 'stdout'), (child.stderr, 'stderr')):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    buffer = b''
    next_sample = started
    max_rss, child_cpu = 0, 0.0
    metrics_samples = 0
    fatal = False
    try:
        while not stop:
            now = time.monotonic()
            if benchmark_seconds is not None and now - started >= benchmark_seconds:
                break
            for key, _ in selector.select(timeout=0.5):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == 'stderr':
                    # eslogger errors may include paths; keep only a classification.
                    lowered = data.lower()
                    reason = ('permission_or_full_disk_access' if any(
                        x in lowered for x in (b'permission', b'not permitted', b'not_permitted', b'not_entitled', b'not authorized', b'full disk', b'failed to create'))
                        else 'eslogger_stderr')
                    if reason not in health['errors']:
                        health['errors'].append(reason)
                    fatal = True
                    break
                buffer += data
                if len(buffer) > MAX_LINE and b'\n' not in buffer:
                    raise ObserverError('event_line_too_large')
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    if len(line) > MAX_LINE:
                        raise ObserverError('event_line_too_large')
                    if not line.strip():
                        continue
                    try:
                        record = filt.parse(json.loads(line))
                    except (ValueError, AttributeError, TypeError, KeyError):
                        raise ObserverError('event_schema_invalid') from None
                    if record is not None:
                        append_incident(state, record)
                        health['matching_events'] += 1
                        health['coverage_verified'] = True
            if fatal:
                break
            if now >= next_sample:
                cpu, rss = process_tree_metrics(child.pid, os.getpid())
                child_cpu = max(child_cpu, cpu)
                max_rss = max(max_rss, rss)
                metrics_samples += 1
                health.update(updated_at=utc_now(), events_seen=filt.events_seen,
                              event_loss=filt.event_loss, max_rss_bytes=max_rss,
                              status='degraded' if filt.event_loss else ('observing' if filt.events_seen else 'waiting_for_events'))
                if filt.event_loss and 'event_loss' not in health['errors']:
                    health['errors'].append('event_loss')
                atomic_json(state / 'health.json', health)
                next_sample = now + 10
            if child.poll() is not None:
                health['errors'].append('eslogger_exited')
                health['eslogger_exit'] = child.returncode
                fatal = True
                break
    except (ObserverError, OSError, subprocess.SubprocessError) as exc:
        # OSError messages may contain sensitive unrelated paths; use class only.
        health['errors'].append(str(exc) if isinstance(exc, ObserverError) else type(exc).__name__)
        fatal = True
    finally:
        if child.poll() is None:
            try:
                cpu, rss = process_tree_metrics(child.pid, os.getpid())
                child_cpu = max(child_cpu, cpu)
                max_rss = max(max_rss, rss)
            except (ObserverError, OSError, subprocess.SubprocessError, ValueError):
                health['errors'].append('final_metrics_unavailable')
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        selector.close()
        child.stdout.close()
        child.stderr.close()
    elapsed = time.monotonic() - started
    health.update(updated_at=utc_now(), events_seen=filt.events_seen,
                  event_loss=filt.event_loss, status='failed' if fatal else 'stopped')
    atomic_json(state / 'health.json', health)
    if benchmark_seconds is not None:
        cpu_percent = 100 * (time.process_time() - start_cpu + child_cpu) / max(elapsed, 0.001)
        if benchmark_seconds < 600:
            health['errors'].append('benchmark_too_short_for_acceptance')
        passed = (not fatal and not stop and not health['errors'] and
                  elapsed >= benchmark_seconds and metrics_samples >= 2 and
                  filt.events_seen > 0 and cpu_percent <= 1.0 and max_rss <= 100 * 1024 * 1024)
        report = {'schema': 1, 'passed': passed, 'duration_seconds': elapsed,
                  'requested_seconds': benchmark_seconds, 'cpu_percent_one_core': cpu_percent,
                  'max_rss_bytes': max_rss, 'events_seen': filt.events_seen,
                  'matching_events': health['matching_events'],
                  'coverage_verified': health['coverage_verified'], 'errors': health['errors'],
                  'measured_at': utc_now()}
        atomic_json(state / 'benchmark.json', report)
        print(json.dumps(report, sort_keys=True))
        return 0 if passed else 1
    return 1 if fatal or health['errors'] else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['observe', 'benchmark'])
    parser.add_argument('--state', type=Path, default=DEFAULT_STATE)
    parser.add_argument('--vault', default='/var/db/sudo-secretspec')
    parser.add_argument('--seconds', type=float, default=600,
                        help='benchmark duration; production acceptance requires at least 600 seconds')
    args = parser.parse_args()
    if args.seconds <= 0:
        parser.error('--seconds must be positive')
    os.umask(0o077)
    try:
        return run_observer(args.state, args.vault, args.seconds if args.mode == 'benchmark' else None)
    except (ObserverError, OSError) as exc:
        print('observer: ' + (str(exc) if isinstance(exc, ObserverError) else type(exc).__name__), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
