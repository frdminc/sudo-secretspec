"""secrets-collect.py with stub `sudo-secretspec`, `pbpaste`, `pbcopy` on PATH; no real vault or clipboard.

Every subprocess has a hard timeout: a mutant that loops must fail, not hang CI.
"""
import calendar
import importlib.util
import os
import pty
import re
import signal
import stat
import subprocess
import sys
import time
import types
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "skills/sudo-secretspec/scripts/secrets-collect.py"
VALUE = "s3cretVALUE0123"
LEN = len(VALUE)
OLD_MARK = "secrets-collect: clipboard cleared, copy the value again"  # round 1/2 sentinel
CLEARED = re.compile(r"secrets-collect: clipboard cleared by the run for (\w+) at "
                     r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d{4}, copy the value again")
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
         f'cat {clip} > {tmp_path}/clip_at_store\n'
         f'if [ "$2" = "$FAIL_NAME" ]; then echo boom >&2; exit 1; fi\n'
         f'if [ "$2" = "$INT_NAME" ]; then kill -INT $PPID; sleep 5; fi\n'
         f'if [ "$2" = "$TERM_NAME" ]; then kill -TERM $PPID; sleep 5; fi\n'
         f'if [ "$2" = "$BURST_NAME" ]; then kill -INT $PPID; kill -TERM $PPID; '
         f'kill -HUP $PPID; sleep 5; fi\n'
         f'cat >> {log}\necho >> {log}\n')
    stub("pbpaste", f"cat {clip}\n")
    stub("pbcopy", f"cat > {clip}\n")
    e = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", TMPDIR=str(tmp_path),
             SECRETS_COLLECT_LOCK_DIR=str(tmp_path / "lock"))
    for k in ("FAIL_NAME", "INT_NAME", "TERM_NAME", "BURST_NAME"):
        e.pop(k, None)
    return e, log, clip, bindir


def _sigint_default():
    signal.signal(signal.SIGINT, signal.SIG_DFL)  # so python installs its KeyboardInterrupt handler


def cleared_by(text):
    """The NAME the clipboard's sentinel says consumed the copy, or None if it is not one."""
    m = CLEARED.fullmatch(text)
    return m.group(1) if m else None


def run(env, args, stdin="", extra_env=None):
    e = dict(env[0], **(extra_env or {}))
    # own session: no controlling tty, so getpass reads the piped stdin even under a terminal
    return subprocess.run([sys.executable, str(SCRIPT), *args], input=stdin, text=True,
                          capture_output=True, env=e, timeout=TIMEOUT, preexec_fn=_sigint_default,
                          start_new_session=True)


def calls(log):
    return log.read_text() if log.exists() else ""


def run_pty(env, args, keys):
    """Run with a real terminal on stdin; `keys` is what the 'operator' types. Returns (rc, out, err)."""
    master, slave = pty.openpty()
    p = subprocess.Popen([sys.executable, str(SCRIPT), *args], stdin=slave, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, env=env[0], preexec_fn=_sigint_default)
    os.close(slave)
    if keys:
        os.write(master, keys)
    try:
        so, se = p.communicate(timeout=TIMEOUT)
    finally:
        os.close(master)
        if p.poll() is None:
            p.kill()
    return p.returncode, so, se


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
    assert cleared_by(clip.read_text()) == "A"
    # cleared BEFORE the store, not after: the store's own view of the clipboard is the sentinel
    assert cleared_by((clip.parent / "clip_at_store").read_text()) == "A"


def test_second_run_without_a_fresh_copy_stores_nothing(env):
    _, log, clip, _ = env
    assert run(env, yes_args("A=a:%d" % LEN)).returncode == 0
    log.unlink()
    # even a spec that fits the sentinel
    r = run(env, yes_args("B=b:%d" % len(clip.read_text()), "--literal"))
    assert r.returncode == 1
    assert calls(log) == ""
    assert "sentinel" in out(r)
    # it names the run that consumed the copy, since that run may have taken B's value
    assert re.search(r"the run for A consumed this copy at "
                     r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d{4} \(\d+ s ago\)", out(r))
    assert "re-collect A too" in out(r)
    assert "leftover" not in out(r)
    assert "nothing was copied" not in out(r)


def test_second_run_for_the_same_name_says_so(env):
    _, log, clip, _ = env
    assert run(env, yes_args("A=a:%d" % LEN)).returncode == 0
    r = run(env, yes_args("A=a:%d" % len(clip.read_text()), "--literal"))
    assert r.returncode == 1
    assert "an earlier run for A consumed the copy at" in out(r)
    assert "re-collect" not in out(r)


@pytest.mark.parametrize("stale", [
    "cleared", OLD_MARK,
    "secrets-collect: clipboard cleared by the run for Z at 01:02:03, copy the value again",
    "secrets-collect: clipboard cleared by the run for Z at 2020-01-02T03:04:05+0000, "
    "copy the value again"])
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


def test_regex_only_spec_is_refused_without_touching_the_clipboard(env):
    _, log, clip, _ = env
    r = run(env, ["--secret", "A=a:s3cret[A-Za-z0-9]+", "--clipboard", "--yes"])
    assert r.returncode == 2
    assert "length" in r.stderr
    assert calls(log) == ""
    assert clip.read_text() == VALUE


def test_malformed_regex_fails_before_the_clipboard_is_read(env):
    _, log, clip, _ = env
    r = run(env, ["--secret", "A=a:[unclosed", "--clipboard", "--yes"])
    assert r.returncode != 0
    assert "Traceback" not in r.stderr and "bad regex" in r.stderr
    assert clip.read_text() == VALUE
    assert calls(log) == ""


def _load_module():
    spec = importlib.util.spec_from_file_location("secrets_collect_under_test", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _check_fn():
    return _load_module().check


def test_regex_must_match_the_whole_value_and_keeps_the_shape_check():
    check = _check_fn()
    pat = "s3cret[A-Za-z0-9]+"
    assert check(VALUE, None, pat, False) is None
    assert check("xx" + VALUE + "!!", None, pat, False) is not None  # fullmatch, not search
    assert check("xx" + VALUE, None, pat, False) is not None
    # a regex alone does not waive the alphanumeric shape check; --literal does
    assert check("see https://example.com/x", None, ".+", False) is not None
    assert check("see https://example.com/x", None, ".+", True) is None


def test_clipboard_cleared_on_every_failure_path_after_the_read(env):
    _, log, clip, _ = env
    clip.write_text("not alnum !!")
    assert run(env, yes_args("A=a:12")).returncode == 1
    assert cleared_by(clip.read_text()) == "A"
    clip.write_text(VALUE)
    assert run(env, yes_args("A=a:99")).returncode == 1  # length mismatch
    assert cleared_by(clip.read_text()) == "A"
    clip.write_text(VALUE)
    r = run(env, yes_args(), extra_env={"FAIL_NAME": "A"})  # store failure
    assert r.returncode == 1
    assert cleared_by(clip.read_text()) == "A"


def test_pbcopy_failure_is_loud(env):
    _, _, clip, bindir = env
    (bindir / "pbcopy").write_text("#!/bin/sh\nexit 1\n")
    r = run(env, yes_args())
    assert "NOT cleared" in r.stderr
    assert clip.read_text() == VALUE


# --- the sentinel carries a date: a race and a leftover read differently -------------------------

def _stamp(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(epoch))


def _mark(who, stamp):
    return f"secrets-collect: clipboard cleared by the run for {who} at {stamp}, copy the value again"


@pytest.mark.parametrize("who", ["A", "Z"])
def test_an_old_sentinel_is_a_leftover_not_a_race(env, who):
    _, log, clip, _ = env
    mark = _mark(who, _stamp(time.time() - 600))
    clip.write_text(mark)
    r = run(env, yes_args(f"A=a:{len(mark)}", "--literal"))
    o = out(r)
    assert r.returncode == 1 and calls(log) == ""
    assert "10 min ago" in o
    assert "a leftover from an earlier run, not a race" in o and "no other run is involved" in o
    assert "re-collect Z too" not in o and "re-collect A too" not in o
    assert "Traceback" not in o


def test_sentinel_error_threshold_and_fallbacks(monkeypatch):
    m = _load_module()
    base = calendar.timegm((2026, 10, 26, 12, 0, 0))

    def err(stamp, delta, name="A"):
        monkeypatch.setattr(m, "time", types.SimpleNamespace(time=lambda: base + delta))
        return m.sentinel_error(_mark("Z", stamp), name)

    dated = "2026-10-26T12:00:00+0000"
    e = err(dated, 59)
    assert "(59 s ago)" in e and "re-collect Z too" in e and "leftover" not in e
    e = err(dated, 60)  # exactly STALE_AFTER is still a race
    assert "(1 min ago)" in e and "re-collect Z too" in e and "leftover" not in e
    e = err(dated, 61)
    assert "(1 min ago)" in e and "a leftover from an earlier run, not a race" in e
    assert "re-collect Z too" not in e
    e = err(dated, 7200)
    assert "(120 min ago)" in e and "leftover" in e
    e = err(dated, 7200, name="Z")  # the same name: leftover too, never "an earlier run for Z"
    assert "leftover" in e and "an earlier run for Z" not in e
    e = err(dated, 30, name="Z")
    assert "an earlier run for Z consumed the copy at" in e and "(30 s ago)" in e
    # not usable as an age: the old wording, no crash
    for stamp, delta in [(dated, -30), ("2026-13-45T99:99:99+0000", 100), ("01:02:03", 100000)]:
        e = err(stamp, delta)
        assert "re-collect Z too" in e and "ago" not in e and "leftover" not in e, stamp


# --- a failed clear is loud: exit 3 --------------------------------------------------------

def _break_pbcopy(bindir):
    (bindir / "pbcopy").write_text("#!/bin/sh\nexit 1\n")


def test_failed_clear_after_a_store_exits_3_and_says_so(env):
    _, log, clip, bindir = env
    _break_pbcopy(bindir)
    r = run(env, yes_args())
    assert r.returncode == 3, out(r)
    assert VALUE in calls(log)  # stored all the same
    assert "NOT cleared" in r.stderr
    assert r.stdout.splitlines()[-1] == ("stored, but the clipboard was NOT cleared: "
                                         "overwrite it yourself, exit 3")
    assert clip.read_text() == VALUE


def test_failed_clear_on_a_dry_run_exits_3_with_nothing_stored(env):
    _, log, clip, bindir = env
    _break_pbcopy(bindir)
    r = run(env, yes_args(f"A=a:{LEN}", "--dry-run"))
    assert r.returncode == 3, out(r)
    assert calls(log) == ""
    assert r.stdout.splitlines()[-1] == ("dry run, nothing stored, but the clipboard was NOT "
                                         "cleared: overwrite it yourself, exit 3")


@pytest.mark.parametrize("spec, extra_env", [(f"A=a:{LEN + 1}", None), (f"A=a:{LEN}", {"FAIL_NAME": "A"})])
def test_failed_clear_does_not_change_another_failures_code(env, spec, extra_env):
    _, log, _, bindir = env
    _break_pbcopy(bindir)
    r = run(env, yes_args(spec), extra_env=extra_env)  # a rejected value / a failed store
    assert r.returncode == 1, out(r)
    assert "NOT cleared" in r.stderr and "exit 3" not in out(r)


def test_a_working_clear_exits_0_and_the_failed_flag_does_not_leak_between_calls(
        env, monkeypatch, capsys):
    e, log, clip, bindir = env
    m = _load_module()
    for k in ("PATH", "TMPDIR", "SECRETS_COLLECT_LOCK_DIR"):
        monkeypatch.setenv(k, e[k])
    monkeypatch.setattr(sys, "argv", ["secrets-collect", *yes_args()])
    # main() installs SIGTERM/SIGHUP handlers on the pytest process: put them back afterwards
    old = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGHUP)}
    try:
        good = (bindir / "pbcopy").read_text()
        _break_pbcopy(bindir)
        assert m.main() == 3
        (bindir / "pbcopy").write_text(good)
        clip.write_text(VALUE)
        assert m.main() == 0  # a fresh call starts clean
        assert cleared_by(clip.read_text()) == "A"
    finally:
        for sig, h in old.items():
            signal.signal(sig, h)
    capsys.readouterr()


# --- findings 2/12a/3: piped answers are not the operator ------------------------------------

def test_clipboard_with_piped_stdin_and_no_yes_is_refused(env):
    _, log, clip, _ = env
    r = run(env, ["--secret", f"A=a:{LEN}", "--clipboard"], stdin="\ny\n")
    assert r.returncode == 2
    assert "use --yes" in r.stderr
    assert calls(log) == ""
    assert clip.read_text() == VALUE  # refused before the clipboard was read


def test_interactive_clipboard_without_yes_waits_for_enter_and_does_not_clear(env):
    _, log, clip, _ = env
    r, so, se = run_pty(env, ["--secret", f"A=a:{LEN}", "--clipboard"], b"\ny\n")
    assert r == 0, se
    assert "[Enter when copied]" in so
    assert VALUE in calls(log)
    assert clip.read_text() == VALUE  # a human at the keyboard: no self-clear


def test_yes_on_a_pty_gets_the_no_terminal_protections(env):
    _, log, clip, _ = env
    # no LEN: refused before the clipboard is touched, even though stdin is a terminal
    r, so, se = run_pty(env, ["--secret", "A=a", "--clipboard", "--yes"], b"")
    assert r == 2, se
    assert clip.read_text() == VALUE
    assert calls(log) == ""
    # with LEN: stores without any Enter being sent, and clears
    r, so, se = run_pty(env, yes_args(), b"")
    assert r == 0, se
    assert VALUE in calls(log)
    assert cleared_by(clip.read_text()) == "A"
    # a second run on the pty fails closed on the sentinel instead of waiting for input forever
    log.unlink()
    r, so, se = run_pty(env, yes_args("B=b:%d" % LEN), b"")
    assert r == 1
    assert calls(log) == ""


@pytest.mark.parametrize("own_tmpdirs", [False, True])
def test_parallel_runs_store_the_copy_at_most_once(env, tmp_path, own_tmpdirs):
    _, log, clip, bindir = env
    # a slow pbpaste holds the first run between its read and its clear, and a slow pbcopy
    # makes the clear itself long enough that a clear outside the lock lets run 2 read the value
    (bindir / "pbpaste").write_text(f"#!/bin/sh\ncat {clip}\nsleep 1\n")
    (bindir / "pbcopy").write_text(f"#!/bin/sh\nsleep 1\ncat > {clip}\n")
    names = ("A", "B")
    procs = []
    for n in names:
        e = dict(env[0])
        if own_tmpdirs:  # two harnesses with their own TMPDIR still share one pasteboard
            (tmp_path / f"tmp{n}").mkdir()
            e["TMPDIR"] = str(tmp_path / f"tmp{n}")
        procs.append(subprocess.Popen(
            [sys.executable, str(SCRIPT), *yes_args(f"{n}=x:{LEN}")], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=e,
            preexec_fn=_sigint_default, start_new_session=True))
    try:
        res = [(p.communicate(timeout=TIMEOUT), p.returncode) for p in procs]
    finally:
        for p in procs:
            if p.poll() is None:
                p.kill()
    rcs = sorted(rc for _, rc in res)
    assert rcs == [0, 1], res
    assert calls(log).count("ARGV: set") == 1
    winner = names[[rc for _, rc in res].index(0)]
    loser_out = res[1 - names.index(winner)][0]
    assert cleared_by(clip.read_text()) == winner
    assert f"the run for {winner} consumed this copy" in "".join(loser_out)
    assert f"re-collect {winner} too" in "".join(loser_out)


def test_group_signal_during_the_clear_cannot_leave_the_secret(env, tmp_path):
    _, log, clip, bindir = env
    started = tmp_path / "pbcopy_started"
    (bindir / "pbcopy").write_text(f"#!/bin/sh\ntouch {started}\nsleep 1\ncat > {clip}\n")
    p = subprocess.Popen([sys.executable, str(SCRIPT), *yes_args()], stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env[0],
                         preexec_fn=_sigint_default, start_new_session=True)
    try:
        deadline = time.monotonic() + 5
        while not started.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert started.exists()
        os.killpg(p.pid, signal.SIGTERM)  # a harness cancel, or Ctrl-C, hits pbcopy too
        so, se = p.communicate(timeout=TIMEOUT)
    finally:
        if p.poll() is None:
            p.kill()
    assert p.returncode == 130, se
    assert cleared_by(clip.read_text()) == "A"  # pbcopy finished: the signal waited for it
    assert "NOT cleared" not in se
    assert calls(log) == ""  # and the run still stops: the signal is delivered after the clear


@pytest.mark.parametrize("sig", ["TERM", "HUP"])
def test_signal_between_the_read_and_the_clear_still_clears(env, sig):
    _, log, clip, bindir = env
    (bindir / "pbpaste").write_text(f"#!/bin/sh\ncat {clip}\nkill -{sig} $PPID\nsleep 1\n")
    r = run(env, yes_args())
    assert r.returncode == 130, out(r)
    assert cleared_by(clip.read_text()) == "A"
    assert calls(log) == ""


def test_lock_contention_exits_with_a_message_after_the_wait(tmp_path, monkeypatch, capsys):
    m = _load_module()
    monkeypatch.setenv("SECRETS_COLLECT_LOCK_DIR", str(tmp_path))
    monkeypatch.setattr(m, "LOCK_WAIT", 0.3)
    with m.clipboard_lock():
        t0 = time.monotonic()
        with pytest.raises(SystemExit) as ei:
            with m.clipboard_lock():
                pytest.fail("got a lock that another holder has")
        assert ei.value.code == 1
        assert time.monotonic() - t0 >= 0.3  # it retried, it did not give up at once
    assert "another secrets-collect run holds the clipboard lock" in capsys.readouterr().err
    with m.clipboard_lock():  # and the lock is released when the holder leaves
        pass


@pytest.mark.skipif(os.geteuid() == 0, reason="root opens a mode-000 file")
def test_unopenable_lock_file_is_reported_as_the_lock(env, tmp_path):
    _, log, clip, _ = env
    (tmp_path / "lock").mkdir()
    f = tmp_path / "lock" / "secrets-collect.lock"
    f.write_text("")
    f.chmod(0)
    r = run(env, yes_args())
    assert r.returncode == 1
    assert f"could not open the lock file {f}" in r.stderr
    assert "could not read the clipboard" not in r.stderr
    assert clip.read_text() == VALUE and calls(log) == ""


def test_default_lock_path_is_under_the_users_home_not_tmpdir(tmp_path, monkeypatch):
    m = _load_module()
    other = tmp_path / "other_tmpdir"
    other.mkdir()
    monkeypatch.delenv("SECRETS_COLLECT_LOCK_DIR", raising=False)
    monkeypatch.setenv("TMPDIR", str(other))
    monkeypatch.setattr(m, "pwd", types.SimpleNamespace(
        getpwuid=lambda uid: types.SimpleNamespace(pw_dir=str(tmp_path))))
    caches = tmp_path / "Library" / "Caches"
    assert m.lock_path() == str(caches / "secrets-collect.lock")
    assert stat.S_IMODE(caches.stat().st_mode) == 0o700
    assert list(other.iterdir()) == []  # nothing went under TMPDIR


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
    assert "nothing was stored" in r.stderr and "PARTIAL" not in r.stderr


def test_ctrl_c_during_store_is_not_reported_as_nothing_stored(env):
    _, log, _, _ = env
    r = run(env, TWO + ["--secret", "C=c"], stdin="v1\nv2\nv3\ny\n", extra_env={"INT_NAME": "B"})
    assert r.returncode == 130
    assert "nothing was stored" not in out(r)
    assert "stored=[A] not_stored=[C] unknown=[B]" in r.stderr


def test_sigterm_during_store_gets_the_partial_report(env):
    r = run(env, TWO + ["--secret", "C=c"], stdin="v1\nv2\nv3\ny\n", extra_env={"TERM_NAME": "B"})
    assert r.returncode == 130
    assert "stored=[A] not_stored=[C] unknown=[B]" in r.stderr


def test_a_burst_of_signals_does_not_cut_the_partial_report_short(env):
    r = run(env, TWO + ["--secret", "C=c"], stdin="v1\nv2\nv3\ny\n", extra_env={"BURST_NAME": "B"})
    assert r.returncode == 130
    assert "Traceback" not in r.stderr
    assert "stored=[A] not_stored=[C] unknown=[B]" in r.stderr


def test_interrupt_during_notify_says_so_and_not_storing(env):
    _, log, _, bindir = env
    (bindir / "python3").write_text("#!/bin/sh\nkill -INT $PPID\nsleep 5\n")
    (bindir / "python3").chmod(0o755)
    r = run(env, TWO + ["--notify-to", "x"], stdin="v1\nv2\ny\n")
    assert r.returncode == 130
    assert "Interrupted while notifying" in r.stderr
    assert "while storing" not in r.stderr and "PARTIAL" not in r.stderr
    assert "ARGV: set A" in calls(log) and "ARGV: set B" in calls(log)


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
    _, log, clip, bindir = env
    (bindir / "pbpaste").write_text("#!/bin/sh\nprintf 'ab\\351cd'\n")
    r = run(env, yes_args("A=a:5"))
    assert r.returncode == 1
    assert calls(log) == ""
    o = out(r)
    assert "0xe9" not in o and "position" not in o
    assert "ab" not in o and "\\xe9" not in o and "cd" not in o
    assert cleared_by(clip.read_text()) == "A"  # the decode-failure path cleared it too


def test_pbpaste_gets_the_utf8_locale_like_pbcopy(env):
    _, log, clip, bindir = env
    (bindir / "pbpaste").write_text(f'#!/bin/sh\necho "$LC_CTYPE" > {clip}.lc\ncat {clip}\n')
    r = run(env, yes_args(), extra_env={"LC_CTYPE": "C"})
    assert r.returncode == 0, out(r)
    assert Path(f"{clip}.lc").read_text().strip() == "UTF-8"


# --- finding 6: pty / identical values -------------------------------------------------------

def test_same_clipboard_for_two_names_is_refused_on_a_tty(env, tmp_path):
    _, log, clip, bindir = env
    (tmp_path / "clip2").write_text("fresh2VALUE0123")
    (bindir / "pbpaste").write_text(
        f"#!/bin/sh\nn=$(cat {tmp_path}/cnt 2>/dev/null || echo 0); n=$((n+1)); echo $n > {tmp_path}/cnt\n"
        f"if [ $n -ge 3 ]; then cat {tmp_path}/clip2; else cat {clip}; fi\n")
    # interactive (no --yes): Enter for A; Enter for B (same clipboard: refused); Enter again
    # (fresh copy); then the final confirmation
    rc, so, se = run_pty(env, ["--secret", f"A=a:{LEN}", "--secret", f"B=b:{LEN}", "--clipboard"],
                         b"\n\n\ny\n")
    assert rc == 0, se
    assert "identical to a value already collected" in so
    text = calls(log)
    assert text.count(VALUE) == 1  # the stale read never became B
    assert text.index(VALUE) < text.index("fresh2VALUE0123")


def test_yes_with_two_secrets_is_refused_even_on_a_tty(env):
    _, log, clip, _ = env
    rc, so, se = run_pty(env, ["--secret", f"A=a:{LEN}", "--secret", f"B=b:{LEN}",
                               "--clipboard", "--yes"], b"")
    assert rc == 2, se
    assert calls(log) == ""
    assert clip.read_text() == VALUE


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
    rc, so, se = run_pty(env, ["--secret", "A=a:32", "--clipboard"], b"\ny\ny\n")
    assert rc == 0, se
    assert "Use it anyway" in so
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
    _, log, clip, bindir = env
    (bindir / "pbpaste").write_text("#!/bin/sh\nexit 1\n")
    r = run(env, yes_args())
    assert r.returncode == 1
    assert calls(log) == ""
    assert clip.read_text() == VALUE  # nothing was read, so nothing is overwritten


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
    env[2].write_text(VALUE)  # the first run cleared it
    rc, so, se = run_pty(env, ["--secret", "A=a:15", "--clipboard"], b"\ny\n")
    assert "until you confirm" in so
