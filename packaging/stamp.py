#!/usr/bin/env python3
"""Stamp the workspace onto a downstream version, deterministically.

The version sites are counted, not discovered: every file below must contain
exactly the pinned number of downstream-version references, so adding a new
site fails this script loudly instead of shipping a half-stamped workspace.
Validation (version grammar, the downstream-version regex) is imported from
``release.py`` rather than duplicated — one spelling of the rules.

Idempotent: re-running with the already-stamped version reports success and
changes nothing, so a release interrupted after stamping can resume with the
same command.

After rewriting, the lockfile is synchronized (``cargo metadata`` writes it
without compiling) and then verified with ``--locked`` — the exact check
``release.py`` preflight repeats, because a stale Cargo.lock is how
v0.19.1-sudo.4 shipped a tag that ``cargo install --locked`` refused.
"""

from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Relative path -> exact number of downstream-version references it carries.
STAMP_SITES = {
    Path("Cargo.toml"): 5,
    Path("secretspec-derive/Cargo.toml"): 1,
    Path("sudo-secretspec-cli/Cargo.toml"): 1,
}


def load_release_module():
    spec = importlib.util.spec_from_file_location(
        "sudo_secretspec_release", ROOT / "packaging" / "release.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version",
        required=True,
        help="full downstream version to stamp, e.g. 0.19.1-sudo.16",
    )
    args = parser.parse_args(argv)
    release = load_release_module()
    target = release.parse_release(args.version).version

    changed: list[str] = []
    for relpath, expected in STAMP_SITES.items():
        path = ROOT / relpath
        text = path.read_text(encoding="utf-8")
        found = release.ANY_VERSION_RE.findall(text)
        if len(found) != expected:
            raise release.ReleaseError(
                f"expected {expected} downstream version references in "
                f"{relpath}, found {len(found)}; update STAMP_SITES if a "
                "site was legitimately added or removed"
            )
        if all(value == target for value in found):
            continue
        path.write_text(release.ANY_VERSION_RE.sub(target, text), encoding="utf-8")
        changed.append(str(relpath))

    subprocess.run(
        ["cargo", "metadata", "--format-version", "1"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )

    if changed:
        print(f"stamped {target}: {', '.join(changed)} (+ Cargo.lock)")
    else:
        print(f"already stamped {target}; nothing to do")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as error:
        raise SystemExit(str(error)) from error
