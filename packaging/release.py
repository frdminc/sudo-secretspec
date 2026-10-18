#!/usr/bin/env python3
"""Release a sudo-secretspec downstream version and its tap.

The release descends from a pinned upstream tag and stamps the whole workspace
with a downstream version such as ``0.19.1-djbclark.2``. Which one is a
command-line argument::

    packaging/release.py --version 0.19.1-djbclark.2 --dry-run

The upstream base stays a constant in this file. Rebasing onto a newer upstream
tag is a different and much larger decision than cutting the next downstream
patch, and ``preflight`` verifies the pinned base really is an ancestor of what
is being released.

``--dry-run`` prints all mutating commands. The live path validates fork
lineage, creates an annotated tag and GitHub Release, rewrites the formula
version and checksum, synchronizes the tap, and performs a live Homebrew
readback test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_VERSION = "0.19.1"
UPSTREAM_TAG = f"v{UPSTREAM_VERSION}"
FORK_REPO = "frdminc/sudo-secretspec"
UPSTREAM_REPO = "cachix/secretspec"
ORIGIN_URL = f"https://github.com/{FORK_REPO}.git"
UPSTREAM_URL = f"https://github.com/{UPSTREAM_REPO}.git"
FORMULA_REL = Path("packaging/homebrew/sudo-secretspec.rb")
FORMULA = ROOT / FORMULA_REL
DEFAULT_TAP = Path.home() / "src" / "homebrew-sudo-secretspec"
# The Homebrew tap is named after the fork's owner and repo, so both derive from
# FORK_REPO. Moving the fork to another org then means editing one constant --
# the 2026-08-15 djbclark -> frdminc move had to touch three.
TAP_NAME = FORK_REPO
FORMULA_NAME = f"{TAP_NAME}/sudo-secretspec"
# The downstream serial's prefix. Releases through 0.19.1-djbclark.3 used
# "djbclark"; everything from 0.19.1-sudo.4 on uses "sudo".
DOWNSTREAM_SUFFIX = "sudo"
VERSION_RE = re.compile(
    rf"^{re.escape(UPSTREAM_VERSION)}-{DOWNSTREAM_SUFFIX}\.([1-9][0-9]*)$"
)
# Any downstream version, anywhere in a file. Used to restamp the formula.
# Both spellings, because a formula carried over from before the rename still
# names the old one and has to be restamped rather than silently left behind.
ANY_VERSION_RE = re.compile(
    rf"{re.escape(UPSTREAM_VERSION)}-(?:{DOWNSTREAM_SUFFIX}|djbclark)\.[0-9]+"
)
# Places the formula names its own version: the source `url`, the explicit
# `version` stanza, and both `brew test` assertions. Pinned as a count so that
# adding a fifth site fails this script loudly instead of shipping a formula
# that is only half restamped.
FORMULA_VERSION_SITES = 4
# GitHub generates the source tarball for a tag on first request, so the fetch
# in `archive_sha256` can 404 or time out for a few seconds after the Release is
# created. That fetch happens *after* the tag and Release are published, which
# are the irreversible steps -- a transient failure there drops the operator
# into the justfile's "do NOT re-run, finish by hand" path for no reason. Retry
# instead. Delays double from the first: 3s, 6s, 12s, 24s.
ARCHIVE_ATTEMPTS = 5
ARCHIVE_BACKOFF_SECONDS = 3
# The release gate is GitHub CI (2026-10-18): free runners, not a cold cargo
# build on the maintainer's Mac. Actions can take a few seconds to register a
# push, so look for the run a few times before giving up.
CI_WRAPPER = ROOT / "scripts" / "github-ci-run"
CI_RUN_LOOKUPS = 12
CI_RUN_LOOKUP_SECONDS = 5


class ReleaseError(RuntimeError):
    """Release invariant failed."""


@dataclass(frozen=True)
class Release:
    """Every version-derived value for one downstream release.

    Built from the serial so that cutting the next release is an argument
    rather than an edit to this file — which is what it was through
    ``0.19.1-djbclark.1``, when the version was a module constant guarded by a
    regex that refused every other value.
    """

    serial: int

    @property
    def version(self) -> str:
        return f"{UPSTREAM_VERSION}-{DOWNSTREAM_SUFFIX}.{self.serial}"

    @property
    def tag(self) -> str:
        return f"v{self.version}"

    @property
    def title(self) -> str:
        return (
            f"SecretSpec {UPSTREAM_VERSION} — sudo-secretspec downstream {self.serial}"
        )

    @property
    def archive_url(self) -> str:
        return f"https://github.com/{FORK_REPO}/archive/refs/tags/{self.tag}.tar.gz"


def log(message: str) -> None:
    print(message, flush=True)


def run(
    argv: list[str],
    *,
    cwd: Path = ROOT,
    capture: bool = True,
    check: bool = True,
    dry_run: bool = False,
) -> subprocess.CompletedProcess[str]:
    if dry_run:
        log("[dry-run] " + " ".join(str(value) for value in argv))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
    log("+ " + " ".join(str(value) for value in argv))
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=capture, check=check)


def output(argv: list[str], **kwargs: object) -> str:
    return (run(argv, **kwargs).stdout or "").strip()


def parse_release(version: str) -> Release:
    """Build a [`Release`] from a full downstream version string.

    The full string rather than a bare serial: it is what appears in the tag,
    the formula, and the changelog, so there is one spelling to get right and
    no way to cut ``djbclark.2`` while believing you asked for ``0.20.0``.
    """
    match = VERSION_RE.fullmatch(version)
    if not match:
        raise ReleaseError(
            f"downstream version must be {UPSTREAM_VERSION}-{DOWNSTREAM_SUFFIX}.N "
            f"with N >= 1, got {version!r}"
        )
    return Release(serial=int(match.group(1)))


def validate_release_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        raise ReleaseError(f"refuse non-GitHub HTTPS release URL: {url!r}")


def parent_slug(repo: dict) -> str | None:
    """Return the fork parent's ``owner/name`` slug, or None if absent.

    ``gh repo view --json parent`` does not put ``nameWithOwner`` inside the
    parent object on every gh version -- 2.97 returns ``id``/``name``/``owner``
    instead -- so compose the slug from its parts when that key is missing.
    """
    parent = repo.get("parent")
    if not isinstance(parent, dict):
        return None
    slug = parent.get("nameWithOwner")
    if isinstance(slug, str) and slug:
        return slug
    owner = parent.get("owner")
    login = owner.get("login") if isinstance(owner, dict) else None
    name = parent.get("name")
    if isinstance(login, str) and login and isinstance(name, str) and name:
        return f"{login}/{name}"
    return None


def _require(value: bool, message: str) -> None:
    if not value:
        raise ReleaseError(message)


def preflight(release: Release, *, allow_dirty: bool) -> None:
    status = output(["git", "status", "--porcelain"])
    _require(
        allow_dirty or not status,
        "working tree is dirty; commit/stash first or pass --allow-dirty",
    )
    branch = output(["git", "branch", "--show-current"])
    _require(branch == "sudo-main", "downstream release must run from sudo-main")
    _require(
        output(["git", "remote", "get-url", "origin"]) == ORIGIN_URL,
        f"origin must be {ORIGIN_URL}",
    )
    _require(
        output(["git", "remote", "get-url", "upstream"]) == UPSTREAM_URL,
        f"upstream must be {UPSTREAM_URL}",
    )
    output(["git", "rev-parse", f"{UPSTREAM_TAG}^{{commit}}"])
    run(["git", "merge-base", "--is-ancestor", UPSTREAM_TAG, "HEAD"])
    manifest = output(["git", "show", f"{UPSTREAM_TAG}:Cargo.toml"])
    _require(
        f'version = "{UPSTREAM_VERSION}"' in manifest,
        f"{UPSTREAM_TAG} is not upstream workspace version {UPSTREAM_VERSION}",
    )
    _require(
        f'version = "{release.version}"'
        in (ROOT / "Cargo.toml").read_text(encoding="utf-8"),
        f"workspace is not stamped {release.version}; bump Cargo.toml first",
    )
    # Cargo.lock records every workspace member's version, so bumping Cargo.toml
    # without regenerating the lock leaves the two disagreeing. The formula
    # builds with `cargo install --locked`, which refuses that tree outright, so
    # the tag installs nowhere. This is exactly how v0.19.1-sudo.4 shipped
    # broken; catch it here, before a tag exists to be un-published.
    _require(
        run(
            ["cargo", "metadata", "--locked", "--format-version", "1"],
            check=False,
        ).returncode
        == 0,
        f"Cargo.lock is out of date for {release.version}; run `cargo check` to "
        "regenerate it and commit the result, or the published tag will fail "
        "`cargo install --locked`",
    )
    # Catch a re-used serial here rather than after the test suite has run and
    # a local tag already exists. The remote is the authority: a serial can be
    # published from another checkout.
    _require(
        not output(["git", "ls-remote", "--tags", "origin", release.tag]),
        f"{release.tag} is already published on origin; pick the next serial",
    )
    repo = json.loads(
        output(
            [
                "gh",
                "repo",
                "view",
                FORK_REPO,
                "--json",
                "nameWithOwner,parent,defaultBranchRef",
            ]
        )
    )
    _require(repo.get("nameWithOwner") == FORK_REPO, f"gh target is not {FORK_REPO}")
    _require(
        (repo.get("defaultBranchRef") or {}).get("name") == branch,
        "current branch is not the fork default branch",
    )
    parent = parent_slug(repo)
    _require(
        parent == UPSTREAM_REPO, f"fork parent must be {UPSTREAM_REPO}, got {parent!r}"
    )


def ci_gate(*, dry_run: bool) -> None:
    """Gate the release on GitHub CI for HEAD rather than building it here.

    ``scripts/github-ci-run`` overlays ``ci/base`` onto HEAD and pushes
    ``ci/run/<slug>``; that workflow runs the Linux engine job and the macOS
    job carrying ``run_tests``'s suites (companion crate, this helper, the
    formula). Its own watch gives up after 8 minutes and a run takes about 15,
    so the run is found and watched here, until the jobs' 60-minute limit.
    """
    run(["git", "fetch", "origin", "ci/base"], dry_run=dry_run)
    # The wrapper prefers a local ci/base over origin's, and a fetch does not
    # move it: a stale one would gate the release on an old workflow.
    local = run(
        ["git", "rev-parse", "--verify", "--quiet", "refs/heads/ci/base"],
        check=False,
        dry_run=dry_run,
    )
    if local.returncode == 0 and local.stdout.strip():
        _require(
            local.stdout.strip() == output(["git", "rev-parse", "origin/ci/base"]),
            "local ci/base differs from origin/ci/base; update or delete it first",
        )
    pushed = output([str(CI_WRAPPER), "--no-wait", "HEAD"], dry_run=dry_run)
    if dry_run:
        return
    match = re.search(
        r"^overlay ([0-9a-f]{40}) for [0-9a-f]{40} -> \S+ (ci/run/\S+)$",
        pushed,
        re.MULTILINE,
    )
    if match is None:
        raise ReleaseError(f"github-ci-run printed no overlay line:\n{pushed}")
    overlay, branch = match.groups()
    run_id = None
    for attempt in range(CI_RUN_LOOKUPS):
        if attempt:
            time.sleep(CI_RUN_LOOKUP_SECONDS)
        runs = json.loads(
            output(
                [
                    "gh",
                    "run",
                    "list",
                    "-R",
                    FORK_REPO,
                    "--branch",
                    branch,
                    "--json",
                    "databaseId,headSha",
                ]
            )
            or "[]"
        )
        ids = [r["databaseId"] for r in runs if r.get("headSha") == overlay]
        if ids:
            run_id = ids[0]
            break
    _require(run_id is not None, f"no GitHub Actions run appeared for {branch}")
    url = f"https://github.com/{FORK_REPO}/actions/runs/{run_id}"
    log(f"CI: {url}")
    watched = run(
        ["gh", "run", "watch", str(run_id), "-R", FORK_REPO, "--exit-status"],
        capture=False,
        check=False,
    )
    _require(watched.returncode == 0, f"CI did not pass: {url}")


def run_tests(*, dry_run: bool) -> None:
    run(["pytest", "tests/sudo_packaging", "-q"], dry_run=dry_run, capture=False)
    # The companion is the crate that carries privilege, so its suite is the one
    # that has to gate a release. Building the engine proves nothing about the
    # broker, the audit ledger, or the sudoers policy this project installs.
    run(
        ["cargo", "test", "-p", "sudo-secretspec-cli", "--locked"],
        dry_run=dry_run,
        capture=False,
    )
    # Core is unchanged; compile the pinned upstream engine without invoking
    # provider integration tests that depend on optional host CLIs (for example sops).
    run(
        ["cargo", "build", "-p", "secretspec", "--locked"],
        dry_run=dry_run,
        capture=False,
    )


def rewrite_formula(path: Path, release: Release, sha256: str) -> None:
    """Restamp the formula onto `release`.

    Every place the formula names a downstream version is rewritten, not just
    the source `url`. The explicit `version` stanza and the `brew test`
    assertions were added to the formula after this function was first written,
    and rewriting the url alone published a formula that fetched the new
    tarball while declaring — and asserting — the previous version.
    """
    text = path.read_text(encoding="utf-8")
    text, versions = ANY_VERSION_RE.subn(release.version, text)
    if versions != FORMULA_VERSION_SITES:
        raise ReleaseError(
            f"expected {FORMULA_VERSION_SITES} downstream version references in {path}, "
            f"rewrote {versions}"
        )
    text, hashes = re.subn(
        r'sha256 "[0-9a-f]{64}"', f'sha256 "{sha256}"', text, count=1
    )
    if hashes != 1:
        raise ReleaseError(f"failed to rewrite exactly one checksum in {path}")
    # The version substitution above is textual; confirm it actually produced
    # the archive URL this release will publish.
    if f'url "{release.archive_url}"' not in text:
        raise ReleaseError(f"formula url is not {release.archive_url}")
    path.write_text(text, encoding="utf-8")


def archive_sha256(release: Release, *, dry_run: bool) -> str:
    validate_release_url(release.archive_url)
    if dry_run:
        log(f"[dry-run] hash {release.archive_url}")
        return "0" * 64
    request = urllib.request.Request(
        release.archive_url, headers={"User-Agent": "sudo-secretspec-release"}
    )
    delay = ARCHIVE_BACKOFF_SECONDS
    last_error: Exception | None = None
    for attempt in range(1, ARCHIVE_ATTEMPTS + 1):
        # Fresh digest per attempt: a stream that failed part way through has
        # already fed bytes to the hasher, and reusing it would hash the partial
        # body and the retry together.
        digest = hashlib.sha256()
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                while chunk := response.read(1024 * 1024):
                    digest.update(chunk)
            return digest.hexdigest()
        except (urllib.error.URLError, OSError) as error:
            last_error = error
            if attempt == ARCHIVE_ATTEMPTS:
                break
            log(
                f"archive not ready ({error}); attempt {attempt}/{ARCHIVE_ATTEMPTS}, "
                f"retrying in {delay}s"
            )
            time.sleep(delay)
            delay *= 2
    raise ReleaseError(
        f"could not fetch {release.archive_url} after {ARCHIVE_ATTEMPTS} attempts: "
        f"{last_error}. The tag and Release are already published -- do not re-run "
        "`just release`; finish by hand per the justfile RESUME RULES."
    )


def create_tag_and_release(
    release: Release, notes: str, state: CleanupState, *, dry_run: bool
) -> None:
    if output(["git", "tag", "--list", release.tag]) and not dry_run:
        raise ReleaseError(f"local tag already exists: {release.tag}")
    run(["git", "tag", "-a", release.tag, "-m", release.title], dry_run=dry_run)
    state.tag_created = not dry_run
    run(["git", "push", "origin", release.tag], dry_run=dry_run)
    state.tag_pushed = not dry_run
    if dry_run:
        run(
            [
                "gh",
                "release",
                "create",
                release.tag,
                "--repo",
                FORK_REPO,
                "--title",
                release.title,
                "--notes-file",
                "<temporary-notes>",
            ],
            dry_run=True,
        )
        return
    with tempfile.NamedTemporaryFile("w", suffix=".md", encoding="utf-8") as notes_file:
        notes_file.write(notes)
        notes_file.flush()
        run(
            [
                "gh",
                "release",
                "create",
                release.tag,
                "--repo",
                FORK_REPO,
                "--title",
                release.title,
                "--notes-file",
                notes_file.name,
            ]
        )


def update_formula_commit(
    release: Release, *, dry_run: bool, state: CleanupState
) -> None:
    sha = archive_sha256(release, dry_run=dry_run)
    if dry_run:
        log(f"[dry-run] rewrite {FORMULA_REL} for {release.tag} sha256={sha}")
        run(["git", "add", str(FORMULA_REL)], dry_run=True)
        run(
            ["git", "commit", "-m", f"Update Homebrew formula for {release.tag}"],
            dry_run=True,
        )
        run(["git", "push", "origin", "HEAD"], dry_run=True)
        return
    rewrite_formula(FORMULA, release, sha)
    state.formula_changed = True
    run(["git", "add", str(FORMULA_REL)])
    run(["git", "commit", "-m", f"Update Homebrew formula for {release.tag}"])
    state.formula_changed = False
    run(["git", "push", "origin", "HEAD"])


def sync_tap(release: Release, tap_path: Path, *, dry_run: bool) -> None:
    destination = tap_path / "Formula" / "sudo-secretspec.rb"
    if dry_run:
        log(f"[dry-run] copy {FORMULA_REL} -> {destination}")
        run(["git", "add", "Formula/sudo-secretspec.rb"], cwd=tap_path, dry_run=True)
        run(
            ["git", "commit", "-m", f"sudo-secretspec {release.version}"],
            cwd=tap_path,
            dry_run=True,
        )
        run(["git", "push", "origin", "HEAD"], cwd=tap_path, dry_run=True)
        return
    _require((tap_path / ".git").exists(), f"tap clone missing or not Git: {tap_path}")
    _require(
        not output(["git", "status", "--porcelain"], cwd=tap_path),
        f"tap working tree is dirty: {tap_path}",
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(FORMULA, destination)
    run(["git", "add", "Formula/sudo-secretspec.rb"], cwd=tap_path)
    if output(["git", "diff", "--cached", "--name-only"], cwd=tap_path):
        run(["git", "commit", "-m", f"sudo-secretspec {release.version}"], cwd=tap_path)
        run(["git", "push", "origin", "HEAD"], cwd=tap_path)


def brew_refresh_and_test(release: Release, *, dry_run: bool) -> str:
    run(["brew", "update", "--force"], dry_run=dry_run, capture=False)
    tap_repo = output(["brew", "--repository", TAP_NAME], dry_run=dry_run)
    if not dry_run:
        tap = Path(tap_repo)
        _require(tap.is_dir(), "Homebrew did not return the tap checkout")
        run(["git", "fetch", "origin", "main"], cwd=tap, capture=False)
        run(["git", "merge", "--ff-only", "origin/main"], cwd=tap, capture=False)
        _require(
            release.tag
            in (tap / "Formula/sudo-secretspec.rb").read_text(encoding="utf-8"),
            "live tap formula is stale",
        )
    run(["brew", "reinstall", FORMULA_NAME], dry_run=dry_run, capture=False)
    prefix = (
        output(["brew", "--prefix", FORMULA_NAME], dry_run=dry_run)
        or "/opt/homebrew/opt/sudo-secretspec"
    )
    run(["brew", "test", FORMULA_NAME], dry_run=dry_run, capture=False)
    return prefix


def verify_readback(release: Release, prefix: str) -> None:
    repo = json.loads(
        output(["gh", "repo", "view", FORK_REPO, "--json", "nameWithOwner,parent"])
    )
    _require(repo.get("nameWithOwner") == FORK_REPO, "repository readback mismatch")
    _require(
        parent_slug(repo) == UPSTREAM_REPO,
        "fork lineage readback mismatch",
    )
    ref = json.loads(
        output(["gh", "api", f"repos/{FORK_REPO}/git/ref/tags/{release.tag}"])
    )
    _require(ref.get("ref") == f"refs/tags/{release.tag}", "tag readback mismatch")
    published = json.loads(
        output(
            [
                "gh",
                "release",
                "view",
                release.tag,
                "--repo",
                FORK_REPO,
                "--json",
                "tagName,name,isDraft",
            ]
        )
    )
    _require(
        published == {"tagName": release.tag, "name": release.title, "isDraft": False},
        "release readback mismatch",
    )
    version = output([str(Path(prefix) / "bin" / "secretspec"), "--version"])
    _require(
        release.version in version, f"installed engine version mismatch: {version!r}"
    )


@dataclass
class CleanupState:
    tag_created: bool = False
    tag_pushed: bool = False
    formula_changed: bool = False


def cleanup_interrupted(release: Release, state: CleanupState) -> None:
    if state.tag_created and not state.tag_pushed:
        run(["git", "tag", "-d", release.tag])
    if state.formula_changed:
        run(["git", "restore", "--staged", "--worktree", "--", str(FORMULA_REL)])


@contextmanager
def interrupt_cleanup(release: Release, state: CleanupState) -> Iterator[None]:
    previous = {
        number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)
    }

    def handler(number: int, _frame: object) -> None:
        cleanup_interrupted(release, state)
        raise ReleaseError(f"interrupted by {signal.Signals(number).name}")

    for number in previous:
        signal.signal(number, handler)
    try:
        yield
    finally:
        for number, old_handler in previous.items():
            signal.signal(number, old_handler)


def default_notes() -> str:
    return (
        f"Downstream packaging release based on upstream SecretSpec {UPSTREAM_VERSION}.\n\n"
        "Adds the opt-in `sudo-secretspec` privilege-boundary companion. Homebrew installs files only; "
        "run `sudo-secretspec install` explicitly to configure privileged state.\n"
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version",
        required=True,
        help=f"downstream version to cut, e.g. {UPSTREAM_VERSION}-{DOWNSTREAM_SUFFIX}.5",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--skip-tests", action="store_true")
    parser.add_argument(
        "--local-tests",
        action="store_true",
        help="run the gating suites on this machine instead of GitHub CI",
    )
    parser.add_argument("--skip-homebrew", action="store_true")
    parser.add_argument("--notes-file", type=Path)
    parser.add_argument("--tap-path", type=Path, default=DEFAULT_TAP)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    release = parse_release(args.version)
    # Preflight is read-only, so it runs on the dry-run path too: a rehearsal
    # that skips validation hides exactly the failures it exists to surface.
    preflight(release, allow_dirty=args.allow_dirty)
    if args.skip_tests:
        pass
    elif args.local_tests:
        run_tests(dry_run=args.dry_run)
    else:
        ci_gate(dry_run=args.dry_run)
    notes = (
        args.notes_file.read_text(encoding="utf-8")
        if args.notes_file
        else default_notes()
    )
    state = CleanupState()
    with interrupt_cleanup(release, state):
        create_tag_and_release(release, notes, state, dry_run=args.dry_run)
        if not args.skip_homebrew:
            update_formula_commit(release, dry_run=args.dry_run, state=state)
            sync_tap(release, args.tap_path, dry_run=args.dry_run)
            prefix = brew_refresh_and_test(release, dry_run=args.dry_run)
            if not args.dry_run:
                verify_readback(release, prefix)
    log(f"done: {release.title} ({release.tag})")
    return 0


def describe(error: subprocess.CalledProcessError) -> str:
    """Render a failed command with the output it actually produced.

    Every command here runs with `capture=True`, so `str(error)` alone reports
    the exit status and nothing else -- the reason git, gh or brew refused is
    captured and then discarded. A release that dies mid-flight is expensive and
    often has to be finished by hand, so the operator needs the message.
    """
    command = " ".join(str(value) for value in error.cmd)
    detail = (error.stderr or "").strip() or (error.stdout or "").strip()
    return f"command failed (exit {error.returncode}): {command}" + (
        f"\n{detail}" if detail else ""
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as error:
        raise SystemExit(str(error)) from error
    except subprocess.CalledProcessError as error:
        raise SystemExit(describe(error)) from error
