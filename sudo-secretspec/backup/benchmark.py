#!/usr/bin/python3
"""Measure attribution for ten minutes and prove it with disposable events."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


def main():
    if os.geteuid() != 0 or sys.platform != 'darwin':
        raise SystemExit('macOS root required')
    state = Path('/var/db/sudo-secretspec-backup/observer')
    fixture = Path(tempfile.mkdtemp(prefix='sudo-secretspec-attribution-', dir='/var/db'))
    process = None
    try:
        process = subprocess.Popen(['/usr/bin/python3', '-I', str(Path(__file__).with_name('observer.py')),
                    'benchmark', '--seconds', '600', '--state', str(state), '--vault', str(fixture)])
        time.sleep(3)
        if process.poll() is None:
            item = fixture / 'synthetic-event'
            item.write_text('synthetic only')
            item.rename(fixture / 'renamed-event')
            (fixture / 'renamed-event').unlink()
        result = process.wait(timeout=640)
        report = json.loads((state / 'benchmark.json').read_text())
        # A small CPU number without a known matching event is not coverage.
        if result or not report.get('passed') or not report.get('coverage_verified'):
            raise SystemExit('Attribution not enabled: benchmark or fixture coverage failed')
        print('Attribution benchmark and disposable-event coverage passed')
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        shutil.rmtree(fixture)


if __name__ == '__main__':
    main()
