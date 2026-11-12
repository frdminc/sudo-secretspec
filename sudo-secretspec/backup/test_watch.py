"""Deterministic scheduler acceptance: no sleeps, real signals, or live vault."""
import signal
import unittest
from unittest.mock import patch

import backup


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now


class FakeVnodeWatch:
    """poll(1) advances virtual time; poll(0) drains events queued in once()."""
    def __init__(self, clock, events, stop_at, handlers):
        self.clock = clock
        self.events = sorted(events)
        self.stop_at = stop_at
        self.handlers = handlers
        self.refreshes = 0
        self.closed = False
        self.polls = 0

    def poll(self, timeout):
        self.polls += 1
        if self.polls > 20000:
            raise AssertionError('scheduler did not stop')
        self.clock.now += timeout
        changed = False
        while self.events and self.events[0] <= self.clock.now:
            self.events.pop(0)
            changed = True
        if self.clock.now >= self.stop_at:
            self.handlers[signal.SIGTERM](signal.SIGTERM, None)
        return changed

    def refresh(self):
        self.refreshes += 1

    def close(self):
        self.closed = True


class FakeBackup:
    def __init__(self, clock, live_inventory, on_capture=None, succeeds=True):
        self.clock = clock
        self.live_inventory = live_inventory
        self.cfg = {'vault': '/synthetic-vault'}
        self.capture_inventory = None
        self.captures = []
        self.replications = []
        self.on_capture = on_capture
        self.succeeds = succeeds

    def once(self):
        self.captures.append(self.clock.now)
        self.capture_inventory = dict(self.live_inventory)
        if self.on_capture:
            self.on_capture(self)
        return self.succeeds

    def replicate(self):
        self.replications.append(self.clock.now)


class WatchSchedulerTests(unittest.TestCase):
    def run_scheduler(self, *, events=(), stop_at=1, on_capture=None,
                      succeeds=True, inventory_reader=None):
        clock = Clock()
        handlers = {}
        live_inventory = {'generation': 0}
        worker = FakeBackup(clock, live_inventory, on_capture, succeeds)
        watcher = FakeVnodeWatch(clock, events, stop_at, handlers)
        self.watcher = watcher
        if inventory_reader is None:
            inventory_reader = lambda path: dict(live_inventory)
        with patch.object(backup.select, 'kqueue', object(), create=True), \
                patch.object(backup, 'VnodeWatch', return_value=watcher) as construct, \
                patch.object(backup.time, 'monotonic', clock.monotonic), \
                patch.object(backup.signal, 'signal', side_effect=lambda sig, fn: handlers.update({sig: fn})), \
                patch.object(backup, 'inventory', side_effect=inventory_reader):
            backup.watch(worker)
        construct.assert_called_once_with('/synthetic-vault')
        self.assertTrue(watcher.closed)
        self.assertEqual(watcher.refreshes, len(worker.captures))
        return worker

    def test_startup_captures_without_an_event(self):
        worker = self.run_scheduler()
        self.assertEqual(worker.captures, [0])
        self.assertEqual(worker.replications, [])

    def test_hourly_capture_recurs_without_filesystem_events(self):
        worker = self.run_scheduler(stop_at=7201)
        self.assertEqual(worker.captures, [0, 3600, 7200])

    def test_replication_retries_every_300_seconds_without_recapturing(self):
        worker = self.run_scheduler(stop_at=901)
        self.assertEqual(worker.captures, [0])
        self.assertEqual(worker.replications, [300, 600, 900])

    def test_failed_capture_does_not_disable_replication_or_hourly_retry(self):
        worker = self.run_scheduler(stop_at=3601, succeeds=False)
        self.assertEqual(worker.captures, [0, 3600])
        self.assertEqual(worker.replications, list(range(300, 3600, 300)))

    def test_burst_debounces_two_seconds_from_last_event(self):
        worker = self.run_scheduler(events=[1, 2, 3], stop_at=8)
        self.assertEqual(worker.captures, [0, 5])

    def test_continuous_events_cannot_delay_capture_beyond_30_seconds(self):
        worker = self.run_scheduler(events=range(1, 35), stop_at=35)
        # First event at 1; continuous writes force a capture by 31.
        self.assertEqual(worker.captures, [0, 31])

    def test_events_queued_during_capture_force_followup(self):
        def slow_first_capture(worker):
            if len(worker.captures) == 1:
                worker.clock.now += 5
        worker = self.run_scheduler(events=[3], stop_at=9,
                                    on_capture=slow_first_capture)
        self.assertEqual(worker.captures, [0, 7])

    def test_inventory_change_without_queued_event_forces_followup(self):
        def change_after_first_snapshot(worker):
            if len(worker.captures) == 1:
                worker.live_inventory['generation'] += 1
        worker = self.run_scheduler(stop_at=4, on_capture=change_after_first_snapshot)
        self.assertEqual(worker.captures, [0, 2])

    def test_inventory_read_failure_forces_followup(self):
        calls = []
        def inventory_reader(path):
            calls.append(path)
            if len(calls) == 1:
                raise OSError('synthetic disappearance after capture')
            return {'generation': 0}
        worker = self.run_scheduler(stop_at=4, inventory_reader=inventory_reader)
        self.assertEqual(worker.captures, [0, 2])

    def test_watcher_closes_when_capture_raises(self):
        def fail_capture(worker):
            raise RuntimeError('synthetic fatal capture error')
        with self.assertRaisesRegex(RuntimeError, 'synthetic fatal'):
            self.run_scheduler(on_capture=fail_capture)
        self.assertTrue(self.watcher.closed)


if __name__ == '__main__':
    unittest.main()
