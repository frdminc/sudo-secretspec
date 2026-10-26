#!/usr/bin/env python3
"""Collect several secret values interactively, validate each, store them in one pass.

Any agent, any provider. The operator runs it; the agent reads the result from the store.

    # one secret
    secrets-collect.py --secret 'FOO_API_KEY=the API key' --notify-to dann

    # several, with expected lengths (a mismatch warns rather than blocks)
    secrets-collect.py \
      --secret 'OVH_APPLICATION_KEY=Application Key (AK):16' \
      --secret 'OVH_APPLICATION_SECRET=Application Secret (AS):32' \
      --secret 'OVH_CONSUMER_KEY=Consumer Key (CK):32' \
      --notify-to dann

    # a non-secret constant stored alongside (e.g. an endpoint)
    secrets-collect.py --secret 'OVH_ENDPOINT=API endpoint:ovh-us' --literal

    secrets-collect.py ... --dry-run      # validate only; store nothing, notify nobody
    secrets-collect.py ... --clipboard    # read each value from pbpaste instead of typing

    # no terminal (an agent): ONE secret per run, no prompts, LEN REQUIRED. Run it only after the
    # operator says the value is copied, and never two at once (a lock makes a second one fail)
    secrets-collect.py --secret 'NAME=desc:32' --clipboard --yes

Why this exists: an agent that needs values from a human must never ask the human to paste them
into a chat. That puts the value in a transcript, which is the one thing the house rules forbid.
This script is the safe path: the human types into a hidden prompt, the value goes straight to
the secret store, and the agent is told only the NAMES and LENGTHS.

Properties, each deliberate:
  1. Input is hidden (getpass) — not echoed, so not in the scrollback, and not in shell history.
  2. Nothing is stored until every value is collected and checked (and, without --yes, confirmed),
     so an abort (Ctrl-C, closed stdin) before that leaves the store exactly as it was. Once the
     store loop starts it is NOT atomic: a failure or Ctrl-C mid-loop prints
     `stored=[...] not_stored=[...]` (and `unknown=[...]` for the one in flight), exit non-zero.
     Nothing is rolled back, because an overwritten old value is gone.
  3. Values reach sudo-secretspec on stdin, never in argv (so not in the process table).
  4. Only names and lengths are ever printed. In the no-terminal mode (an agent's transcript) a
     rejected value is described by a count and character classes, never the characters.
  5. The notification message carries names and lengths, never values.
  6. EOF is treated as "no", never a crash.
  7. --clipboard --yes (tty or not) cannot tell a fresh copy from a stale clipboard by looking
     at it, so it (a) requires an expected LEN in the spec (a regex does not count) and aborts on
     a mismatch without prompting, (b) refuses the sentinels `cleared` and CLEARED_MARK, (c)
     overwrites the clipboard with CLEARED_MARK itself, in a `finally` right after the read
     (stored, rejected, or interrupted by an exception or SIGINT/SIGTERM/SIGHUP), and (d) holds an
     exclusive per-user lock from before pbpaste until after that overwrite, so two parallel runs
     cannot both read one copy: the second reads the sentinel and fails. A SIGKILL or power loss
     between the read and the clear still leaves the value on the pasteboard. A clipboard that was
     stale before the FIRST run and happens to have the same shape and length is not detectable;
     --dry-run reads and clears too, so it consumes the operator's copy.
     --clipboard with a non-tty stdin and no --yes is refused: piped answers are not the operator.
  8. A clipboard value identical to one already collected in the same run is refused (the
     clipboard did not change between secrets), so a pty cannot read one value into N names.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import getpass
import os
import re
import signal
import subprocess
import sys
import tempfile
import unicodedata

CLEARED_MARK = "secrets-collect: clipboard cleared, copy the value again"
SENTINELS = {"cleared", CLEARED_MARK}


class StoreError(Exception):
    pass


def ask(prompt: str, default: bool = False) -> bool:
    """A y/N prompt that treats EOF (piped input, closed stdin) as 'no' rather than crashing."""
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        print("  (no input available — taking that as 'no')")
        return default


def parse_spec(spec: str) -> tuple[str, str, int | None, str | None]:
    """'NAME=description[:length|:regex]' -> (name, description, length, regex)."""
    if "=" not in spec:
        raise SystemExit(f"bad --secret {spec!r}: expected NAME=description[:length]")
    name, rest = spec.split("=", 1)
    name = name.strip()
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
        raise SystemExit(f"bad secret name {name!r}: use UPPER_SNAKE_CASE")
    length: int | None = None
    pattern: str | None = None
    desc = rest
    if ":" in rest:
        desc, tail = rest.rsplit(":", 1)
        tail = tail.strip()
        if tail.isdigit():
            length = int(tail)
        elif tail:
            pattern = tail
    if pattern:
        try:
            re.compile(pattern)
        except re.error as e:
            raise SystemExit(f"bad regex in --secret {name!r}: {e}") from None
    return name, desc.strip() or name, length, pattern


def _pb_env() -> dict[str, str]:
    """pbcopy and pbpaste both need this: an agent shell's LC_CTYPE=C mangles non-ASCII text."""
    return dict(os.environ, LC_CTYPE="UTF-8")


def clear_clipboard() -> None:
    """Overwrite the pasteboard with CLEARED_MARK so a later run cannot read this secret again."""
    try:
        subprocess.run(["pbcopy"], input=CLEARED_MARK, text=True, check=True,
                       capture_output=True, env=_pb_env())
    except Exception as e:  # noqa: BLE001
        print(f"  WARNING: the clipboard was NOT cleared ({type(e).__name__}); "
              "overwrite it yourself", file=sys.stderr)


@contextlib.contextmanager
def clipboard_lock():
    """Per-user exclusive lock held from before pbpaste until after the clear, so two parallel
    no-terminal runs cannot both read the same copy: the loser reads CLEARED_MARK and fails."""
    path = os.path.join(tempfile.gettempdir(), f"secrets-collect-{os.getuid()}.lock")
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)  # closing releases the flock


def read_and_clear() -> bytes:
    """pbpaste, then overwrite the clipboard in a finally, so an interrupt right after the read
    still clears. A pbpaste that failed read nothing, so it leaves the clipboard alone."""
    failed = False
    try:
        return subprocess.run(["pbpaste"], capture_output=True, check=True,
                              env=_pb_env()).stdout
    except (subprocess.CalledProcessError, OSError):
        failed = True
        raise
    finally:
        if not failed:
            clear_clipboard()


def read_value(label: str, from_clipboard: bool, no_wait: bool = False) -> str:
    """One value, hidden if from the terminal. Retries on an empty read.

    no_wait (clipboard, no terminal): read pbpaste once, no Enter wait, no retry -- the
    clipboard cannot change, so an empty read or a retry would only loop forever -- and
    overwrite the clipboard at once. Error text never carries clipboard bytes."""
    while True:
        if from_clipboard:
            try:
                if no_wait:
                    print(f"  Reading {label} from the clipboard (no terminal, no wait).")
                    with clipboard_lock():
                        data = read_and_clear()
                else:
                    print(f"  Copy {label} to the clipboard, then press Enter.")
                    input("  [Enter when copied] ")
                    data = subprocess.run(["pbpaste"], capture_output=True, check=True,
                                          env=_pb_env()).stdout
                try:
                    raw = data.decode("utf-8")
                except UnicodeDecodeError:
                    print("  the clipboard is not valid UTF-8 text", file=sys.stderr)
                    if no_wait:
                        raise SystemExit(1)
                    continue
            except EOFError:
                print("  no input available — aborting rather than guessing", file=sys.stderr)
                raise SystemExit(1)
            except Exception as e:  # noqa: BLE001
                print(f"  could not read the clipboard: {type(e).__name__}", file=sys.stderr)
                if no_wait:
                    raise SystemExit(1)
                continue
        else:
            try:
                raw = getpass.getpass(f"  {label}: ")
            except EOFError:
                print("  no input available — aborting rather than guessing", file=sys.stderr)
                raise SystemExit(1)
        value = raw.strip()
        if value:
            return value
        if no_wait:
            print("  the clipboard is empty — aborting, nothing stored", file=sys.stderr)
            raise SystemExit(1)
        print("  empty — try again (Ctrl-C to abort)")


def _classes(bad: set[str]) -> str:
    out = set()
    for c in bad:
        if c.isspace():
            out.add("whitespace")
        elif ord(c) > 127:
            out.add("non-ASCII")
        elif unicodedata.category(c).startswith("C"):
            out.add("control")
        else:
            out.add("punctuation")
    return ", ".join(sorted(out))


def check(value: str, length: int | None, pattern: str | None, literal: bool,
          no_wait: bool = False) -> str | None:
    """Return an error string, or None if acceptable.

    A length mismatch warns (asks) interactively; with no_wait there is nobody to ask and the
    length is the freshness check, so it blocks."""
    if pattern and not re.fullmatch(pattern, value):
        return f"does not match the required pattern {pattern!r}"
    if not literal:
        # API keys are alphanumeric (plus - and _); punctuation is the signature of a mis-copied
        # UI rendering — a masked box or a copied label — which passes a length check and is not a key.
        if not re.fullmatch(r"[A-Za-z0-9_\-]+", value):
            bad = {c for c in value if not re.match(r"[A-Za-z0-9_\-]", c)}
            if no_wait:
                return (f"{len(bad)} distinct character(s) of class [{_classes(bad)}] that API keys "
                        f"do not have — usually a mis-copied UI rendering or a stale clipboard")
            return (f"contains characters {sorted(bad)!r} that API keys do not have — that is usually "
                    f"a mis-copied UI rendering (a masked box, a label), not a key")
    if length is not None and len(value) != length:
        if no_wait:
            return f"{len(value)} characters; the expected length is {length} (stale clipboard?)"
        print(f"  ⚠ {len(value)} characters; the expected length is {length}.")
        print("    Not necessarily wrong, but check you copied the whole value.")
        if not ask("    Use it anyway? [y/N] "):
            return "not confirmed by the operator"
    return None


def store(name: str, value: str, reason: str) -> None:
    """Store one value via sudo-secretspec, on stdin, never argv."""
    try:
        proc = subprocess.run(
            ["sudo-secretspec", "set", name, "--reason", reason],
            input=value, text=True, capture_output=True,
        )
    except OSError as e:
        raise StoreError(f"FAILED to store {name}: {type(e).__name__}") from None
    if proc.returncode != 0:
        raise StoreError(f"FAILED to store {name}: {proc.stderr.strip()}")


def report_partial(stored: list[str], rest: list[str], unknown: str | None = None) -> None:
    """The store loop is not atomic; say exactly what was and was not stored."""
    msg = f"stored=[{', '.join(stored)}] not_stored=[{', '.join(rest)}]"
    if unknown:
        msg += f" unknown=[{unknown}] (in flight)"
    print(f"PARTIAL STORE: {msg}" if stored or unknown else f"nothing was stored: {msg}",
          file=sys.stderr)


def notify(role: str, names: list[tuple[str, int]], reason: str) -> None:
    """Tell a peer. Best-effort: a failure here does not undo a successful store."""
    mail = os.path.expanduser(
        "~/src/techno-euphora/projects/hiwymi/spec/composite-individual/tools/peer-comms/peer_mail.py"
    )
    body = [f"Values stored in sudo-secretspec ({reason}).", "",
            "Names and lengths only — read them with `sudo-secretspec run`, never `get`:", ""]
    body += [f"  {n}  (len={ln})" for n, ln in names]
    proc = subprocess.run(
        ["python3", mail, "send", "--from", os.environ.get("PEER_MAIL_FROM", "dann"),
         "--to", role, "--subject", "secret values stored - you may proceed",
         "--text", "\n".join(body)],
        text=True, capture_output=True,
    )
    if proc.returncode == 0:
        lines = [ln for ln in proc.stdout.strip().splitlines() if ln]
        print(f"  notified {role}: {lines[-1] if lines else 'sent'}")
    else:
        print(f"  could NOT notify {role} ({proc.returncode}): {proc.stderr.strip()}", file=sys.stderr)
        print("  The values ARE stored; tell the agent in the chat instead.", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description="Collect and store secret values (see the module docstring).")
    ap.add_argument("--secret", action="append", required=True, metavar="NAME=DESC[:LEN]",
                    help="repeatable; LEN is an expected character count (warns on mismatch; "
                         "REQUIRED, with a mismatch aborting, under --clipboard --yes)")
    ap.add_argument("--reason", default="store values supplied by the operator",
                    help="the reason recorded in the audit ledger")
    ap.add_argument("--notify-to", metavar="ROLE",
                    help="tell this peer-role when done (names and lengths only)")
    ap.add_argument("--literal", action="store_true",
                    help="values are not API keys (no alphanumeric check) — endpoints, URLs only; "
                         "an agent must not use it for a key")
    ap.add_argument("--dry-run", action="store_true",
                    help="validate but store nothing and notify nobody")
    ap.add_argument("--clipboard", action="store_true",
                    help="read each value from pbpaste instead of typing it")
    ap.add_argument("--yes", action="store_true",
                    help="skip the final 'Store these?' prompt. With --clipboard it also skips the "
                         "Enter wait (tty or not): ONE secret per run, LEN required, the clipboard is "
                         "cleared after the read, and a lock stops two runs at once. Needed for any "
                         "--clipboard run with a non-tty stdin. Without --clipboard it needs a "
                         "terminal (hidden prompt)")
    a = ap.parse_args()

    tty = sys.stdin.isatty()
    if a.yes and not a.clipboard and not tty:
        print("refusing: --yes without --clipboard needs a terminal; a value piped on stdin "
              "went through the caller's command line", file=sys.stderr)
        return 2
    if a.clipboard and not a.yes and not tty:
        print("refusing: a non-tty stdin is not the operator; use --yes (with LEN) for "
              "--clipboard without a terminal", file=sys.stderr)
        return 2
    no_wait = a.clipboard and a.yes
    if a.clipboard and (no_wait or not tty) and len(a.secret) > 1:
        print("refusing: --clipboard --yes (or a non-tty stdin) takes ONE --secret per run "
              "(the clipboard cannot change between secrets)", file=sys.stderr)
        return 2

    specs = [parse_spec(s) for s in a.secret]
    if no_wait and any(length is None for _, _, length, _ in specs):
        print("refusing: --clipboard --yes needs an expected length in the spec "
              "(--secret 'NAME=desc:32'; a regex does not count, the spec cannot carry both) — "
              "the length is the check that the clipboard is fresh", file=sys.stderr)
        return 2

    def _cancel(signum, frame):  # a harness cancel (SIGTERM/SIGHUP) gets the same report as Ctrl-C
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _cancel)
    signal.signal(signal.SIGHUP, _cancel)

    print(f"{len(specs)} value(s) to collect, stored in sudo-secretspec")
    if a.yes:
        print("Input is hidden; nothing is echoed. --yes: there is no final confirmation; every "
              "check still applies before anything is stored.")
    else:
        print("Input is hidden; nothing is echoed. Nothing is stored until you confirm at the end.")
    if a.dry_run:
        print("\n*** DRY RUN — nothing will be stored and nobody will be notified ***")
    print()

    collected: list[tuple[str, str]] = []
    stored: list[str] = []
    inflight: str | None = None
    storing = False
    notifying = False
    try:
        for i, (name, desc, length, pattern) in enumerate(specs, 1):
            print(f"[{i}/{len(specs)}] {name}")
            while True:
                value = read_value(desc, a.clipboard, no_wait)
                err = None
                if a.clipboard and value in SENTINELS:
                    err = "the clipboard holds the cleared-clipboard sentinel — nothing was copied"
                elif a.clipboard and any(value == v for _, v in collected):
                    err = "identical to a value already collected — the clipboard did not change"
                else:
                    err = check(value, length, pattern, a.literal, no_wait)
                if err is None:
                    break
                print(f"  ✗ {err}")
                if no_wait:
                    print("Aborted — nothing was stored.", file=sys.stderr)
                    return 1
            collected.append((name, value))
            print(f"  ✓ {name} accepted ({len(value)} characters)\n")

        print("Ready to store:")
        for name, value in collected:
            print(f"  {name}  (len={len(value)})")
        if not a.yes and not ask("\nStore these? [y/N] "):
            print("Aborted — nothing was stored.")
            return 1

        if a.dry_run:
            print("\nDRY RUN: skipping the store and the notification.")
            return 0

        storing = True
        for name, value in collected:
            inflight = name
            try:
                store(name, value, a.reason)
            except StoreError as e:
                print(str(e), file=sys.stderr)
                report_partial(stored, [n for n, _ in collected if n not in stored])
                return 1
            stored.append(name)
            inflight = None
            print(f"  stored {name}")

        notifying = True
        if a.notify_to:
            notify(a.notify_to, [(n, len(v)) for n, v in collected], a.reason)
        print("\nDone.")
        return 0
    except KeyboardInterrupt:
        if notifying:
            print("\nInterrupted while notifying; every value IS stored.", file=sys.stderr)
        elif storing:
            print("\nInterrupted while storing.", file=sys.stderr)
            report_partial(stored, [n for n, _ in collected if n not in stored and n != inflight],
                           inflight)
        else:
            print("\nAborted — nothing was stored.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
