"""secrets-collect.py with stub `sudo-secretspec` and `pbpaste` on PATH; no real vault."""
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "skills/sudo-secretspec/scripts/secrets-collect.py"
VALUE = "s3cretVALUE0123"


@pytest.fixture
def env(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls.log"
    clip = tmp_path / "clip"
    clip.write_text(VALUE)

    def stub(name, body):
        p = bindir / name
        p.write_text("#!/bin/sh\n" + body)
        p.chmod(p.stat().st_mode | stat.S_IXUSR)

    stub("sudo-secretspec", f'echo "ARGV: $*" >> {log}\ncat >> {log}\necho >> {log}\n')
    stub("pbpaste", f"cat {clip}\n")
    e = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
    return e, log, clip


def run(env, args, stdin="\n"):
    e, _, _ = env
    return subprocess.run([sys.executable, str(SCRIPT), *args], input=stdin, text=True,
                          capture_output=True, env=e)


def calls(log):
    return log.read_text() if log.exists() else ""


def test_yes_stores_via_stdin_not_argv(env):
    _, log, _ = env
    r = run(env, ["--secret", "A=a", "--literal", "--clipboard", "--yes"], stdin="")
    assert r.returncode == 0, r.stderr
    text = calls(log)
    assert f"ARGV: set A --reason" in text
    assert VALUE in text.replace(next(l for l in text.splitlines() if l.startswith("ARGV")), "")
    assert VALUE not in next(l for l in text.splitlines() if l.startswith("ARGV"))
    assert VALUE not in r.stdout + r.stderr


def test_no_yes_and_no_tty_stores_nothing(env):
    _, log, _ = env
    r = run(env, ["--secret", "A=a", "--literal", "--clipboard"], stdin="\n")
    assert r.returncode == 1
    assert calls(log) == ""


def test_bad_shape_stores_nothing(env):
    _, log, clip = env
    clip.write_text("not alnum !!")
    r = run(env, ["--secret", "A=a", "--clipboard", "--yes"], stdin="")
    assert r.returncode == 1
    assert calls(log) == ""


def test_multi_secret_clipboard_without_tty_refused(env):
    _, log, _ = env
    r = run(env, ["--secret", "A=a", "--secret", "B=b", "--literal", "--clipboard", "--yes"], stdin="")
    assert r.returncode == 2
    assert calls(log) == ""
