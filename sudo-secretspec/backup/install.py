#!/usr/bin/python3
"""Explicit privileged installation; package installation never invokes this."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
PREFIX = Path('/usr/local/libexec/sudo-secretspec-backup')
STATE = Path('/var/db/sudo-secretspec-backup')
KEYS = Path('/var/root/.config/sudo-secretspec-backup')
CONFIG = Path('/usr/local/etc/sudo-secretspec-backup.json')


def command(argv, data=None, timeout=60):
    r = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if r.returncode:
        raise RuntimeError('%s exited %s' % (Path(argv[0]).name, r.returncode))
    return r.stdout


def activate(label, target):
    loaded = subprocess.run(['/bin/launchctl', 'print', 'system/' + label],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    if loaded:
        command(['/bin/launchctl', 'bootout', 'system/' + label])
    # bootout returns before launchd finishes removing an old service. Bootstrap
    # may transiently return EIO during that interval; retry boundedly.
    for attempt in range(10):
        result = subprocess.run(['/bin/launchctl', 'bootstrap', 'system', str(target)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            return
        if result.returncode != 5 or attempt == 9:
            raise RuntimeError('launchctl bootstrap exited %s' % result.returncode)
        time.sleep(1)


def verify_observer_health(path, previous_mtime):
    # An interactive benchmark may inherit Full Disk Access that launchd lacks.
    # Require a fresh daemon health record before reporting activation success.
    time.sleep(2)
    for _ in range(10):
        if path.exists() and path.stat().st_mtime_ns != previous_mtime:
            report = json.loads(path.read_text())
            if report.get('errors') or report.get('status') in ('failed', 'unavailable', 'stopped', 'degraded'):
                raise RuntimeError('observer unavailable in launchd context; check Full Disk Access and observer health')
            if report.get('status') in ('observing', 'waiting_for_events'):
                return
        time.sleep(1)
    raise RuntimeError('observer did not publish fresh running health')


def write(path, data, mode=0o600):
    if path.is_symlink():
        raise RuntimeError('refusing symlink destination')
    fd, name = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(name, mode)
        os.chown(name, 0, 0)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def directory(path, mode=0o700):
    if path.is_symlink():
        raise RuntimeError('refusing symlink directory')
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    os.chown(path, 0, 0)
    os.chmod(path, mode)


def validate_key(path):
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o077:
        raise RuntimeError('unsafe existing key')


REMOTE_SETUP = r'''
import json,sys,os,pathlib,subprocess,shlex,stat
d=json.load(sys.stdin)
os.umask(0o077)
home=pathlib.Path.home()
keys=home/'.config/sudo-secretspec-backup'
for p in (home/'.config',keys):
    if p.is_symlink(): raise SystemExit('key directory symlink refused')
keys.mkdir(parents=True,exist_ok=True,mode=0o700)
os.chmod(keys,0o700)
identity=keys/'recovery.agekey'
if identity.exists():
    s=identity.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077:
        raise SystemExit('unsafe existing recovery key')
    if identity.read_text()!=d['recovery_key']: raise SystemExit('existing recovery key differs')
else:
    fd=os.open(identity,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f: f.write(d['recovery_key'])
repo=pathlib.Path(d['repo'])
if not repo.exists():
    subprocess.run(['/usr/bin/git','init','--bare',str(repo)],check=True,stdout=subprocess.DEVNULL)
if repo.is_symlink(): raise SystemExit('repository symlink refused')
subprocess.run(['/usr/bin/git','--git-dir',str(repo),'symbolic-ref','HEAD','refs/heads/main'],check=True)
os.chmod(repo,0o700)
for k,v in [('receive.denyDeletes','true'),('receive.denyNonFastForwards','true'),('gc.auto','0')]:
    subprocess.run(['/usr/bin/git','--git-dir',str(repo),'config',k,v],check=True)
wrapper=keys/'git-only'
if wrapper.is_symlink(): raise SystemExit('wrapper symlink refused')
allowed={shlex.join(['git-receive-pack',str(repo)]):'git-receive-pack',shlex.join(['git-upload-pack',str(repo)]):'git-upload-pack'}
script='#!/usr/bin/python3\nimport os,sys\ncommands='+repr(allowed)+'\ncmd=commands.get(os.environ.get("SSH_ORIGINAL_COMMAND", ""))\nif not cmd: sys.exit(126)\nos.execv("/usr/bin/git", ["git",cmd[4:],'+repr(str(repo))+'])\n'
wrapper.write_text(script);os.chmod(wrapper,0o700)
ssh=home/'.ssh';ssh.mkdir(exist_ok=True,mode=0o700)
auth=ssh/'authorized_keys'
if ssh.is_symlink() or auth.is_symlink(): raise SystemExit('SSH symlink refused')
line='restrict,command="'+str(wrapper)+'" '+d['ssh_public'].strip()+'\n'
old=auth.read_text() if auth.exists() else ''
if line.strip() not in old.splitlines():
    with open(auth,'a') as f:
        if old and not old.endswith('\n'):f.write('\n')
        f.write(line)
os.chmod(auth,0o600)
print(json.dumps({'identity':str(identity)}))
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--operator', required=True)
    p.add_argument('--remote-host', required=True)
    p.add_argument('--remote-repo', required=True)
    p.add_argument('--age', default=shutil.which('age') or '/opt/homebrew/bin/age')
    p.add_argument('--age-keygen', default=shutil.which('age-keygen') or '/opt/homebrew/bin/age-keygen')
    p.add_argument('--activate', action='store_true')
    p.add_argument('--enable-observer', action='store_true',
                   help='enable attribution only after benchmark.py passed on this host')
    args = p.parse_args()
    if sys.platform != 'darwin':
        p.error('automated backup installation currently supports macOS only')
    if args.remote_host.startswith('-') or any(c.isspace() for c in args.remote_host):
        p.error('remote host must be a hostname or configured SSH alias')
    if not args.remote_repo.startswith('/') or '\n' in args.remote_repo or '\r' in args.remote_repo:
        p.error('remote repo must be an absolute single-line path')
    if os.geteuid() != 0:
        p.error('run this installer with sudo-ask')
    os.umask(0o077)
    user = pwd.getpwnam(args.operator)
    for path in (PREFIX, STATE, KEYS):
        directory(path)
    print('Installing protected helpers and independent keys', flush=True)
    for name in ('backup.py', 'observer.py', 'benchmark.py'):
        write(PREFIX / name, (HERE / name).read_bytes(), 0o700)
    write(PREFIX / 'age', Path(args.age).resolve().read_bytes(), 0o700)
    write(PREFIX / 'age-keygen', Path(args.age_keygen).resolve().read_bytes(), 0o700)
    identity = KEYS / 'recovery.agekey'
    if not identity.exists():
        command([str(PREFIX / 'age-keygen'), '-o', str(identity)])
    validate_key(identity)
    recipient = command([str(PREFIX / 'age-keygen'), '-y', str(identity)]).decode().strip()
    sshkey = KEYS / 'mirror_ed25519'
    if not sshkey.exists():
        command(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(sshkey),
                 '-C', 'sudo-secretspec-backup'])
    validate_key(sshkey)
    derived = command(['/usr/bin/ssh-keygen', '-y', '-f', str(sshkey)]).decode().split()
    if derived[:2] != Path(str(sshkey) + '.pub').read_text().split()[:2]:
        raise RuntimeError('SSH public key mismatch')
    remote = args.operator + '@' + args.remote_host
    # Bootstrap uses the operator's existing SSH identity, not the broken vault.
    ssh = ['/usr/bin/sudo', '-u', args.operator, '/usr/bin/ssh', '-o', 'BatchMode=yes',
           '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=yes', remote]
    payload = dict(repo=args.remote_repo, recovery_key=identity.read_text(),
                   ssh_public=Path(str(sshkey) + '.pub').read_text())
    remote_cmd = shlex.join(['/usr/bin/python3', '-c', REMOTE_SETUP])
    print('Configuring remote append-only repository and protected recovery key', flush=True)
    remote_info = json.loads(command(ssh + [remote_cmd], json.dumps(payload).encode()))
    # Verify the independently stored key by actually decrypting a challenge
    # using the remote copy. Never display key bytes or put them in argv.
    remote_identity = remote_info['identity']
    remote_key = command(ssh + [shlex.join(['/bin/cat', remote_identity])])
    with tempfile.TemporaryDirectory(prefix='.key-test-', dir=STATE) as tmp:
        tmp = Path(tmp)
        key = tmp / 'remote.agekey'
        key.write_bytes(remote_key)
        challenge = os.urandom(32)
        encrypted = command([str(PREFIX / 'age'), '-r', recipient], challenge)
        for candidate in (identity, key):
            if command([str(PREFIX / 'age'), '-d', '-i', str(candidate)], encrypted) != challenge:
                raise RuntimeError('recovery key verification failed')
    print('Both recovery key copies passed the decryption challenge', flush=True)
    known = Path(user.pw_dir) / '.ssh/known_hosts'
    write(KEYS / 'known_hosts', known.read_bytes())
    ssh_command = shlex.join(['/usr/bin/ssh', '-i', str(sshkey), '-o', 'IdentitiesOnly=yes',
         '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=yes',
         '-o', 'UserKnownHostsFile=' + str(KEYS / 'known_hosts')])
    health_dir = Path('/usr/local/var/run/sudo-secretspec-backup')
    directory(Path('/usr/local/var'), 0o755)
    directory(Path('/usr/local/var/run'), 0o755)
    directory(health_dir, 0o755)
    vault_user = pwd.getpwnam('_sudo_secretspec')
    cfg = dict(vault='/var/db/sudo-secretspec', state=str(STATE), identity=str(identity),
               recipient=recipient, age=str(PREFIX / 'age'), git='/usr/bin/git',
               remote=remote + ':' + args.remote_repo, ssh_command=ssh_command,
               health_file=str(health_dir / 'status.json'), min_free_bytes=1024 ** 3,
               vault_uid=vault_user.pw_uid, vault_gid=vault_user.pw_gid,
               expected_databases=['secrets.db','broker-audit.sqlite3','broker-history.sqlite3'],
               notify_argv=['/bin/launchctl','asuser',str(user.pw_uid),'/usr/bin/sudo','-u',args.operator,
                   '/usr/bin/osascript','-e','on run argv\ndisplay notification (item 1 of argv) with title "Vault backup"\nend run'])
    if CONFIG.exists():
        validate_key(CONFIG)
        prior_config = json.loads(CONFIG.read_text())
        # Explicit offline-recovery evidence must survive service upgrades.
        # Never derive or advance this acknowledgement from the live vault.
        if 'audit_anchor' in prior_config:
            cfg['audit_anchor'] = prior_config['audit_anchor']
    write(CONFIG, (json.dumps(cfg, indent=2) + '\n').encode())
    logs = STATE / 'logs'
    directory(logs)
    label = 'com.djbclark.sudo-secretspec-backup'
    plist = dict(Label=label, ProgramArguments=['/usr/bin/python3', '-I', str(PREFIX / 'backup.py'), 'watch'],
                 RunAtLoad=True, KeepAlive=True, ThrottleInterval=30, Umask=0o077,
                 StandardOutPath=str(logs / 'backup.log'), StandardErrorPath=str(logs / 'backup-error.log'))
    target = Path('/Library/LaunchDaemons') / (label + '.plist')
    write(target, plistlib.dumps(plist), 0o644)
    command(['/usr/bin/plutil', '-lint', str(target)])
    if args.activate:
        activate(label, target)
    if args.enable_observer:
        benchmark = STATE / 'observer/benchmark.json'
        validate_key(benchmark)
        report = json.loads(benchmark.read_text())
        if not (report.get('passed') and report.get('coverage_verified') and
                report.get('duration_seconds', 0) >= 600 and
                report.get('cpu_percent_one_core', 100) <= 1 and
                report.get('max_rss_bytes', 2**63) <= 100 * 1024**2):
            raise RuntimeError('observer benchmark/coverage gate has not passed')
        observer_label = label + '-observer'
        observer_plist = dict(plist, Label=observer_label,
            ProgramArguments=['/usr/bin/python3', '-I', str(PREFIX / 'observer.py'), 'observe'],
            StandardOutPath=str(logs / 'observer.log'), StandardErrorPath=str(logs / 'observer-error.log'))
        observer_target = Path('/Library/LaunchDaemons') / (observer_label + '.plist')
        write(observer_target, plistlib.dumps(observer_plist), 0o644)
        health = STATE / 'observer/health.json'
        previous_mtime = health.stat().st_mtime_ns if health.exists() else None
        activate(observer_label, observer_target)
        try:
            verify_observer_health(health, previous_mtime)
        except (RuntimeError, OSError, ValueError):
            subprocess.run(['/bin/launchctl', 'bootout', 'system/' + observer_label],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            observer_target.unlink()
            raise
    print(json.dumps({'installed': True, 'activated': args.activate, 'remote_key_decryption_verified': True,
                      'observer': 'enabled' if args.enable_observer else 'not enabled: benchmark and Full Disk Access required'}))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # No exception payloads: external programs may include secret bytes.
        print('installation failed: ' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__))
        raise SystemExit(1)
