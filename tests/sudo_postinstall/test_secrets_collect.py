"""secrets-collect.py with stub `sudo-secretspec`, `pbpaste`, `pbcopy` on PATH; no real vault or clipboard.

Every subprocess has a hard timeout: a mutant that loops must fail, not hang CI.
"""
import os
import pty
import signal
import stat
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "skills/sudo-secretspec/scripts/secrets-collect.py"
VALUE = "s3cretVALUE0123"
LEN = len(VALUE)
MARK = "secrets-collect: clipboard cleared, copy the value again"
TIMEOUT = 10


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

    stub("sudo-secretspec", f'echo "ARGV: $*" >> {log}\n'
         f'if [ "$2" = "$FAIL_NAME" ]; then echo boom >&2; exit 1; fi\n'
         f'if [ "$2" = "$INT_NAME" ]; then kill -INT $PPID; sleep 5; fi\n'
         f'cat >> {log}\necho >> {log}\n')
    stub("pbpaste", f"cat {clip}\n")
    stub("pbcopy", f"cat > {clip}\n")
    e = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
    e.pop("FAIL_NAME", None)
    e.pop("INT_NAME", None)
    return e, log, clip, bindir


def _sigint_default():
    signal.signal(signal.SIGINT, signal.SIG_DFL)  # so python installs its KeyboardInterrupt handler


def run(env, args, stdin="", extra_env=None):
    e = dict(env[0], **(extra_env or {}))
    return subprocess.run([sys.executable, str(SCRIPT), *args], input=stdin, text=True,
                          capture_output=True, env=e, timeout=TIMEOUT, preexec_fn=_sigint_default)


def calls(log):
    return log.read_text() if log.exists() else ""


def yes_args(spec=f"A=a:{LEN}", *more):
    return ["--secret", spec, "--clipboard", "--yes", *more]


def out(r):
    return r.stdout + r.stderr


# --- the accepted path -------------------------------------------------------------------

def test_yes_stores_via_stdin_not_argv(env):
    _, log, clip, _ = env
    r = run(env, yes_args())
    assert r.returncode == 0, r.stderr
    text = calls(log)
    argv = next(l for l in text.splitlines() if l.startswith("ARGV"))
    assert argv == "ARGV: set A --reason store values supplied by the operator"
    assert VALUE in text.replace(argv, "")
    assert VALUE not in out(r)


def test_literal_with_matching_length_stores(env):
    _, log, _, _ = env
    r = run(env, ["--secret", f"A=a:{LEN}", "--literal", "--clipboard", "--yes"])
    assert r.returncode == 0, r.stderr
    assert VALUE in calls(log)


# --- finding 1: stale clipboard, sentinel -------------------------------------------------

def test_clipboard_is_cleared_after_a_successful_read(env):
    _, _, clip, _ = env
    assert run(env, yes_args()).returncode == 0
    assert clip.read_text() == MARK


def test_second_run_without_a_fresh_copy_stores_nothing(env):
    _, log, clip, _ = env
    assert run(env, yes_args("A=a:%d" % LEN)).returncode == 0
    log.unlink()
    r = run(env, yes_args("B=b:%d" % len(MARK), "--literal"))  # even a spec that fits the sentinel
    assert r.returncode == 1
    assert calls(log) == ""
    assert "sentinel" in out(r)


@pytest.mark.parametrize("stale", ["cleared", MARK])
def test_sentinels_refused_even_when_length_and_literal_fit(env, stale):
    _, log, clip, _ = env
    clip.write_text(stale)
    r = run(env, ["--secret", f"A=a:{len(stale)}", "--literal", "--clipboard", "--yes"])
    assert r.returncode == 1
    assert calls(log) == ""


def test_no_terminal_mode_requires_length_or_regex(env):
    _, log, clip, _ = env
    r = run(env, ["--secret", "A=a", "--clipboard", "--yes"])
    assert r.returncode == 2
    assert calls(log) == ""
    assert clip.read_text() == VALUE  # refused before touching the clipboard


def test_regex_spec_satisfies_the_requirement(env):
    _, log, _, _ = env
    r = run(env, ["--secret", "A=a:s3cret[A-Za-z0-9]+", "--clipboard", "--yes"])
    assert r.returncode == 0, out(r)
    assert VALUE in calls(log)


def test_clipboard_cleared_on_every_failure_path_after_the_read(env):
    _, log, clip, _ = env
    clip.write_text("not alnum !!")
    assert run(env, yes_args("A=a:12")).returncode == 1
    assert clip.read_text() == MARK
    clip.write_text(VALUE)
    assert run(env, yes_args("A=a:99")).returncode == 1  # length mismatch
    assert clip.read_text() == MARK
    clip.write_text(VALUE)
    r = run(env, yes_args(), extra_env={"FAIL_NAME": "A"})  # store failure
    assert r.returncode == 1
    assert clip.read_text() == MARK


def test_pbcopy_failure_is_loud(env):
    _, _, clip, bindir = env
    (bindir / "pbcopy").write_text("#!/bin/sh\nexit 1\n")
    r = run(env, yes_args())
    assert "NOT cleared" in r.stderr
    assert clip.read_text() == VALUE


# --- finding 2/12a: --yes only skips the confirmation, Enter wait is consumed w/o --yes ---

def test_no_yes_and_no_tty_waits_for_enter_and_stores_nothing(env):
    _, log, clip, _ = env
    r = run(env, ["--secret", f"A=a:{LEN}", "--clipboard"], stdin="\n")
    assert r.returncode == 1
    assert "[Enter when copied]" in r.stdout
    assert calls(log) == ""
    assert clip.read_text() == VALUE  # interactive mode does not clear


# --- findings 3, 4: partial stores ---------------------------------------------------------

TWO = ["--secret", "A=a", "--secret", "B=b"]


def test_partial_store_failure_names_stored_and_not_stored(env):
    _, log, _, _ = env
    r = run(env, TWO, stdin="v1\nv2\ny\n", extra_env={"FAIL_NAME": "B"})
    assert r.returncode == 1
    assert "stored=[A] not_stored=[B]" in r.stderr
    assert "PARTIAL" in r.stderr
    assert "ARGV: set A" in calls(log)
    assert "nothing was stored" not in r.stderr


def test_first_store_failure_says_nothing_stored(env):
    r = run(env, TWO, stdin="v1\nv2\ny\n", extra_env={"FAIL_NAME": "A"})
    assert r.returncode == 1
    assert "stored=[] not_stored=[A, B]" in r.stderr


def test_ctrl_c_during_store_is_not_reported_as_nothing_stored(env):
    _, log, _, _ = env
    r = run(env, TWO + ["--secret", "C=c"], stdin="v1\nv2\nv3\ny\n", extra_env={"INT_NAME": "B"})
    assert r.returncode == 130
    assert "nothing was stored" not in out(r)
    assert "stored=[A] not_stored=[C] unknown=[B]" in r.stderr


def test_eof_at_confirmation_says_nothing_stored(env):
    r = run(env, ["--secret", "A=a"], stdin="v1\n")
    assert r.returncode == 1
    assert "nothing was stored" in out(r)


# --- finding 5: no value characters in the agent's transcript -------------------------------

def test_bad_shape_stores_nothing_and_echoes_no_characters(env):
    _, log, clip, _ = env
    clip.write_text("ab!#$ cd")
    r = run(env, yes_args("A=a:8"))
    assert r.returncode == 1
    assert calls(log) == ""
    o = out(r)
    for leaked in ("!", "#", "$", "ab", "cd"):
        assert leaked not in o.replace("Aborted", "").replace("abort", ""), leaked
    assert "punctuation" in o and "whitespace" in o


def test_non_utf8_clipboard_aborts_without_the_byte(env):
    _, log, _, bindir = env
    (bindir / "pbpaste").write_text("#!/bin/sh\nprintf 'ab\\351cd'\n")
    r = run(env, yes_args("A=a:5"))
    assert r.returncode == 1
    assert calls(log) == ""
    assert "0xe9" not in out(r) and "position" not in out(r)


# --- finding 6: pty / identical values -------------------------------------------------------

def test_same_clipboard_for_two_names_is_refused_on_a_tty(env, tmp_path):
    _, log, clip, bindir = env
    (tmp_path / "clip2").write_text("fresh2VALUE0123")
    (bindir / "pbpaste").write_text(
        f"#!/bin/sh\nn=$(cat {tmp_path}/cnt 2>/dev/null || echo 0); n=$((n+1)); echo $n > {tmp_path}/cnt\n"
        f"if [ $n -ge 3 ]; then cat {tmp_path}/clip2; else cat {clip}; fi\n")
    master, slave = pty.openpty()
    p = subprocess.Popen([sys.executable, str(SCRIPT), "--secret", f"A=a:{LEN}", "--secret", f"B=b:{LEN}",
                          "--clipboard", "--yes"], stdin=slave, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, env=env[0], preexec_fn=_sigint_default)
    os.close(slave)
    os.write(master, b"\n\n\n")  # A; B (same clipboard: refused); B again (fresh copy)
    try:
        so, se = p.communicate(timeout=TIMEOUT)
    finally:
        os.close(master)
        if p.poll() is None:
            p.kill()
    assert p.returncode == 0, se
    assert "identical to a value already collected" in so
    text = calls(log)
    assert text.count(VALUE) == 1  # the stale read never became B
    assert text.index(VALUE) < text.index("fresh2VALUE0123")


# --- finding 7 ---------------------------------------------------------------------------

def test_yes_without_clipboard_and_piped_stdin_refused(env):
    _, log, _, _ = env
    r = run(env, ["--secret", "A=a", "--yes"], stdin="pipedVALUE\n")
    assert r.returncode == 2
    assert calls(log) == ""


# --- finding 8 -----------------------------------------------------------------------------

def test_length_mismatch_aborts_without_reading_stdin(env):
    _, log, _, _ = env
    r = run(env, yes_args("A=a:32"), stdin="y\n")
    assert r.returncode == 1
    assert calls(log) == ""
    assert "Use it anyway" not in r.stdout
    assert "expected length is 32" in r.stdout


def test_literal_does_not_waive_the_length_in_no_terminal_mode(env):
    _, log, _, _ = env
    r = run(env, ["--secret", "A=a:32", "--literal", "--clipboard", "--yes"], stdin="y\n")
    assert r.returncode == 1
    assert calls(log) == ""


def test_interactive_length_mismatch_still_asks(env):
    _, log, _, _ = env
    r = run(env, ["--secret", "A=a:32", "--clipboard"], stdin="\ny\ny\n")
    assert r.returncode == 0
    assert "Use it anyway" in r.stdout
    assert VALUE in calls(log)


# --- findings 5/12b: other aborts -------------------------------------------------------------

def test_empty_clipboard_aborts_not_loops(env):
    _, log, clip, _ = env
    clip.write_text("  \n")
    r = run(env, yes_args())
    assert r.returncode == 1
    assert calls(log) == ""
    assert "empty" in r.stderr


def test_pbpaste_failure_aborts(env):
    _, log, _, bindir = env
    (bindir / "pbpaste").write_text("#!/bin/sh\nexit 1\n")
    r = run(env, yes_args())
    assert r.returncode == 1
    assert calls(log) == ""


def test_multi_secret_clipboard_without_tty_refused_with_and_without_yes(env):
    _, log, _, _ = env
    for extra in (["--yes"], []):
        r = run(env, ["--secret", "A=a:15", "--secret", "B=b:15", "--clipboard", *extra])
        assert r.returncode == 2
        assert calls(log) == ""


# --- finding 10 --------------------------------------------------------------------------

def test_banner_does_not_promise_a_confirmation_under_yes(env):
    r = run(env, yes_args())
    assert "until you confirm" not in r.stdout
    r = run(env, ["--secret", "A=a:15", "--clipboard"], stdin="\n")
    assert "until you confirm" in r.stdout
