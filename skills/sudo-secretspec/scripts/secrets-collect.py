#!/usr/bin/env python3
"""Collect several secret values interactively, validate each, store them all-or-nothing.

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
    secrets-collect.py ... --clipboard --yes   # no terminal (agent): one secret per run, no prompts

Why this exists: an agent that needs values from a human must never ask the human to paste them
into a chat. That puts the value in a transcript, which is the one thing the house rules forbid.
This script is the safe path: the human types into a hidden prompt, the value goes straight to
the secret store, and the agent is told only the NAMES and LENGTHS.

Properties, each deliberate:
  1. Input is hidden (getpass) — not echoed, so not in the scrollback, and not in shell history.
  2. All-or-nothing — nothing is stored until every value is collected and confirmed, so an
     abort (Ctrl-C, closed stdin) leaves the store exactly as it was, never half-populated.
  3. Values reach sudo-secretspec on stdin, never in argv (so not in the process table).
  4. Only names and lengths are ever printed.
  5. The notification message carries names and lengths, never values.
  6. EOF is treated as "no", never a crash.
"""
from __future__ import annotations

import argparse
import getpass
import os
import re
import subprocess
import sys


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
    return name, desc.strip() or name, length, pattern


def read_value(label: str, from_clipboard: bool, no_wait: bool = False) -> str:
    """One value, hidden if from the terminal. Retries on an empty read.

    no_wait (clipboard, no terminal): read pbpaste once, no Enter wait, no retry -- the
    clipboard cannot change, so an empty read or a retry would only loop forever."""
    while True:
        if from_clipboard:
            try:
                if no_wait:
                    print(f"  Reading {label} from the clipboard (no terminal, no wait).")
                else:
                    print(f"  Copy {label} to the clipboard, then press Enter.")
                    input("  [Enter when copied] ")
                raw = subprocess.run(["pbpaste"], capture_output=True, text=True, check=True).stdout
            except EOFError:
                print("  no input available — aborting rather than guessing", file=sys.stderr)
                raise SystemExit(1)
            except Exception as e:  # noqa: BLE001
                print(f"  could not read the clipboard: {e}", file=sys.stderr)
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


def check(value: str, length: int | None, pattern: str | None, literal: bool) -> str | None:
    """Return an error string, or None if acceptable. A length mismatch warns, not blocks."""
    if pattern and not re.fullmatch(pattern, value):
        return f"does not match the required pattern {pattern!r}"
    if literal or pattern:
        return None
    # API keys are alphanumeric (plus - and _); punctuation is the signature of a mis-copied
    # UI rendering — a masked box or a copied label — which passes a length check and is not a key.
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", value):
        bad = sorted({c for c in value if not re.match(r"[A-Za-z0-9_\-]", c)})
        return (f"contains characters {bad!r} that API keys do not have — that is usually a "
                f"mis-copied UI rendering (a masked box, a label), not a key")
    if length is not None and len(value) != length:
        print(f"  ⚠ {len(value)} characters; the expected length is {length}.")
        print("    Not necessarily wrong, but check you copied the whole value.")
        if not ask("    Use it anyway? [y/N] "):
            return "not confirmed by the operator"
    return None


def store(name: str, value: str, reason: str) -> None:
    """Store one value via sudo-secretspec, on stdin, never argv."""
    proc = subprocess.run(
        ["sudo-secretspec", "set", name, "--reason", reason],
        input=value, text=True, capture_output=True,
    )
    if proc.returncode != 0:
        raise SystemExit(f"FAILED to store {name}: {proc.stderr.strip()}")


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

        print("  empty — try again (Ctrl-C to abort)")


def main() -> int:
    ap = argparse.ArgumentParser(description="Collect and store secret values, all-or-nothing.")
    ap.add_argument("--secret", action="append", required=True, metavar="NAME=DESC[:LEN]",
                    help="repeatable; LEN is an expected character count (warns on mismatch)")
    ap.add_argument("--reason", default="store values supplied by the operator",
                    help="the reason recorded in the audit ledger")
    ap.add_argument("--notify-to", metavar="ROLE",
                    help="tell this peer-role when done (names and lengths only)")
    ap.add_argument("--literal", action="store_true",
                    help="values are not API keys (no alphanumeric check) — endpoints, URLs")
    ap.add_argument("--dry-run", action="store_true",
                    help="validate but store nothing and notify nobody")
    ap.add_argument("--clipboard", action="store_true",
                    help="read each value from pbpaste instead of typing it")
    ap.add_argument("--yes", action="store_true",
                    help="skip only the final 'Store these?' prompt (for an agent with no terminal); "
                         "with --clipboard and a non-tty stdin, also skip the Enter wait: one secret per run")
    a = ap.parse_args()

    no_wait = a.clipboard and a.yes and not sys.stdin.isatty()
    if a.clipboard and not sys.stdin.isatty() and len(a.secret) > 1:
        print("refusing: --clipboard with a non-tty stdin takes ONE --secret per run "
              "(the clipboard cannot change between secrets)", file=sys.stderr)
        return 2

    specs = [parse_spec(s) for s in a.secret]

    print(f"{len(specs)} value(s) to collect, stored in sudo-secretspec")
    print("Input is hidden; nothing is echoed. Nothing is stored until you confirm at the end.")
    if a.dry_run:
        print("\n*** DRY RUN — nothing will be stored and nobody will be notified ***")
    print()

    collected: list[tuple[str, str]] = []
    try:
        for i, (name, desc, length, pattern) in enumerate(specs, 1):
            print(f"[{i}/{len(specs)}] {name}")
            while True:
                value = read_value(desc, a.clipboard, no_wait)
                err = check(value, length, pattern, a.literal)
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

        for name, value in collected:
            store(name, value, a.reason)
            print(f"  stored {name}")

        if a.notify_to:
            notify(a.notify_to, [(n, len(v)) for n, v in collected], a.reason)
        print("\nDone.")
        return 0
    except KeyboardInterrupt:
        print("\nAborted — nothing was stored.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())

