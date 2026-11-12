"""Synthetic events only; no Endpoint Security permission or real secret access."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('observer', Path(__file__).with_name('observer.py'))
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


def unlink(path='/private/var/db/sudo-secretspec/secrets.db', seq=0):
    return {
        'schema_version': 1, 'event_type': 'ES_EVENT_TYPE_NOTIFY_UNLINK',
        'seq_num': seq, 'global_seq_num': seq, 'time': '2026-11-12T12:00:00Z',
        'event': {'unlink': {'target': {'path': path}}},
        'process': {'audit_token': {'pid': 12, 'euid': 0},
                    'executable': {'path': '/bin/rm'}, 'signing_id': 'com.apple.rm',
                    'team_id': 'APPLE', 'cdhash': '012345',
                    'argv': ['secret argument'], 'env': ['SECRET=do not persist']},
    }


def rename(source, destination, seq=0):
    event = unlink(seq=seq)
    event['event_type'] = 'ES_EVENT_TYPE_NOTIFY_RENAME'
    event['event'] = {'rename': {'source': {'path': source}, 'destination': destination}}
    return event


class FilterTests(unittest.TestCase):
    def setUp(self):
        self.filter = observer.EventFilter('/private/var/db/sudo-secretspec')

    def test_unlink_has_process_attribution_without_secrets(self):
        record = self.filter.parse(unlink())
        self.assertEqual(record['pid'], 12)
        self.assertEqual(record['uid'], 0)
        self.assertEqual(record['executable'], '/bin/rm')
        self.assertEqual(record['signing_id'], 'com.apple.rm')
        encoded = json.dumps(record)
        self.assertNotIn('secret argument', encoded)
        self.assertNotIn('SECRET=', encoded)
        self.assertNotIn('argv', encoded)
        self.assertNotIn('env', encoded)

    def test_outside_vault_and_similar_prefix_are_discarded(self):
        for seq, path in enumerate(['/tmp/unrelated', '/private/var/db/sudo-secretspec-copy/secrets.db']):
            self.assertIsNone(self.filter.parse(unlink(path, seq)))
        self.assertEqual(self.filter.events_seen, 2)

    def test_directory_and_ancestor_removals_are_attributed(self):
        for seq, path in enumerate(['/private/var/db/sudo-secretspec', '/private/var/db', '/private/var']):
            self.assertIsNotNone(self.filter.parse(unlink(path, seq)))

    def test_var_alias_matches_on_macos(self):
        with patch.object(observer.os.path, 'realpath', return_value='/private/var/db/sudo-secretspec'):
            filt = observer.EventFilter('/var/db/sudo-secretspec')
        self.assertIsNotNone(filt.parse(unlink('/var/db/sudo-secretspec/secrets.db')))
        self.assertIsNotNone(filt.parse(unlink('/private/var/db/sudo-secretspec/secrets.db', 1)))

    def test_rename_away_of_vault_matches(self):
        record = self.filter.parse(rename('/private/var/db/sudo-secretspec', {
            'new_path': {'dir': {'path': '/tmp'}, 'filename': 'moved'}}))
        self.assertEqual(record['paths'], ['/private/var/db/sudo-secretspec', '/tmp/moved'])

    def test_rename_over_vault_file_matches(self):
        record = self.filter.parse(rename('/tmp/new', {
            'existing_file': {'path': '/private/var/db/sudo-secretspec/secrets.db'}}))
        self.assertIsNotNone(record)

    def test_rename_filename_traversal_refused(self):
        with self.assertRaisesRegex(observer.ObserverError, 'rename_filename_invalid'):
            self.filter.parse(rename('/tmp/new', {
                'new_path': {'dir': {'path': '/tmp'}, 'filename': '../secret'}}))

    def test_unknown_schema_fails_closed(self):
        event = unlink()
        event['schema_version'] = 999
        with self.assertRaisesRegex(observer.ObserverError, 'unsupported_schema'):
            self.filter.parse(event)

    def test_missing_sequences_cannot_silently_disable_loss_detection(self):
        event = unlink()
        del event['seq_num']
        with self.assertRaisesRegex(observer.ObserverError, 'event_sequence_missing'):
            self.filter.parse(event)

    def test_sequence_gap_is_reported_even_on_unrelated_events(self):
        self.filter.parse(unlink('/tmp/unrelated', 2))
        self.filter.parse(unlink('/tmp/unrelated', 4))
        self.assertGreater(self.filter.event_loss, 0)

    def test_optional_global_sequence(self):
        event = unlink()
        del event['global_seq_num']
        self.assertIsNotNone(self.filter.parse(event))

    def test_per_event_sequences_are_independent(self):
        a = unlink(seq=0)
        b = rename('/tmp/new', {'existing_file': {'path': '/tmp/old'}}, seq=0)
        b['global_seq_num'] = 1
        self.filter.parse(a)
        self.filter.parse(b)
        self.assertEqual(self.filter.event_loss, 0)

    def test_missing_process_identity_is_not_an_attributed_event(self):
        event = unlink()
        del event['process']['audit_token']['pid']
        with self.assertRaisesRegex(observer.ObserverError, 'process_identity_missing'):
            self.filter.parse(event)

    def test_unknown_event_fails_closed(self):
        event = unlink()
        event['event_type'] = 'ES_EVENT_TYPE_NOTIFY_SOMETHING_NEW'
        with self.assertRaisesRegex(observer.ObserverError, 'unexpected_event_type'):
            self.filter.parse(event)


class StorageTests(unittest.TestCase):
    def test_rotation_retains_incidents_and_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            observer.append_incident(state, {'event': 'first'}, limit=1)
            observer.append_incident(state, {'event': 'second'}, limit=1)
            logs = list(state.glob('incidents*.jsonl'))
            self.assertEqual(len(logs), 2)
            self.assertEqual({json.loads(p.read_text())['event'] for p in logs}, {'first', 'second'})
            for p in logs:
                self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_symlink_log_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            target = state / 'elsewhere'
            target.write_text('unchanged')
            (state / 'incidents.jsonl').symlink_to(target)
            with self.assertRaisesRegex(observer.ObserverError, 'incident_file_permissions'):
                observer.append_incident(state, {'event': 'bad'})
            self.assertEqual(target.read_text(), 'unchanged')

    def test_insecure_existing_state_directory_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / 'state'
            state.mkdir(mode=0o755)
            state.chmod(0o755)
            with self.assertRaisesRegex(observer.ObserverError, 'state_directory_permissions'):
                observer.secure_directory(state)

    def test_symlink_state_directory_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            (parent / 'actual').mkdir()
            (parent / 'state').symlink_to(parent / 'actual')
            with self.assertRaisesRegex(observer.ObserverError, 'state_path_symlink'):
                observer.secure_directory(parent / 'state')

    def test_atomic_health_file_is_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'health.json'
            observer.atomic_json(path, {'status': 'waiting_for_events'})
            observer.atomic_json(path, {'status': 'failed'})
            self.assertEqual(json.loads(path.read_text())['status'], 'failed')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(list(Path(tmp).iterdir())), 1)

    def test_unprivileged_run_explicitly_reports_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            with patch.object(observer.os, 'geteuid', return_value=os.getuid()), patch.object(observer.sys, 'platform', 'linux'):
                self.assertEqual(observer.run_observer(state, '/tmp/fixture', 0.01), 1)
            health = json.loads((state / 'health.json').read_text())
            self.assertEqual(health['status'], 'unavailable')
            self.assertFalse(health['coverage_verified'])


class MetricsTests(unittest.TestCase):
    def test_cpu_time_parses_minutes_hours_and_fraction(self):
        self.assertEqual(observer.cpu_seconds('01:02.50'), 62.5)
        self.assertEqual(observer.cpu_seconds('02:01:02'), 7262)

    def test_resource_measurement_includes_descendants_and_observer(self):
        result = type('Result', (), {'stdout': '10 1 00:00.20 100\n20 10 00:01.00 200\n21 20 00:00.50 50\n30 1 00:10.00 900\n'})()
        with patch.object(observer.subprocess, 'run', return_value=result):
            cpu, rss = observer.process_tree_metrics(20, 10)
        self.assertEqual(cpu, 1.5)
        self.assertEqual(rss, 350 * 1024)

    def test_missing_measurement_process_fails_closed(self):
        result = type('Result', (), {'stdout': '10 1 00:00.20 100\n'})()
        with patch.object(observer.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(observer.ObserverError, 'metrics_process_missing'):
                observer.process_tree_metrics(20, 10)


if __name__ == '__main__':
    unittest.main()
