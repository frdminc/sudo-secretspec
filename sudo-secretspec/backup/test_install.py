import ast
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

import install


class RemoteSetupTests(unittest.TestCase):
    def test_remote_setup_idempotency_and_forced_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            repo = home / 'repository with spaces.git'
            data = json.dumps(dict(repo=str(repo), recovery_key='synthetic-recovery-key\n',
                                   ssh_public='ssh-ed25519 synthetic-public-key fixture')).encode()
            env = dict(os.environ, HOME=tmp)
            for _ in range(2):
                r = subprocess.run([sys.executable, '-c', install.REMOTE_SETUP], input=data,
                                   capture_output=True, env=env)
                self.assertEqual(r.returncode, 0, r.stderr.decode())
                self.assertNotIn(b'synthetic-recovery-key', r.stdout + r.stderr)
            wrapper = home / '.config/sudo-secretspec-backup/git-only'
            ast.parse(wrapper.read_text())
            auth = (home / '.ssh/authorized_keys').read_text().splitlines()
            self.assertEqual(len(auth), 1)
            self.assertTrue(auth[0].startswith('restrict,command='))
            self.assertEqual(subprocess.check_output(['/usr/bin/git', '--git-dir', str(repo),
                    'config', 'receive.denyDeletes']).strip(), b'true')
            denied = subprocess.run([sys.executable, str(wrapper)], env=dict(env, SSH_ORIGINAL_COMMAND='rm -rf /'),
                                    capture_output=True)
            self.assertEqual(denied.returncode, 126)
            allowed = subprocess.run([sys.executable, str(wrapper)], input=b'', capture_output=True,
                      env=dict(env, SSH_ORIGINAL_COMMAND=shlex.join(['git-upload-pack', str(repo)])))
            # No client protocol arrives; Git can terminate unsuccessfully after
            # advertising refs. The wrapper must have allowed Git, not exit 126.
            self.assertNotEqual(allowed.returncode, 126)
            self.assertTrue(allowed.stdout)


if __name__ == '__main__':
    unittest.main()
