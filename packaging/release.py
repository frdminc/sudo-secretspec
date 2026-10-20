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
import os
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
from typing import Any
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
BOTTLE_FORMULA_BASENAME = "sudo-secretspec"
FORMULA_NAME = f"{TAP_NAME}/{BOTTLE_FORMULA_BASENAME}"
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
# Deadlines for `watch_run`. `timeout-minutes` in the workflow caps a job's
# EXECUTION; neither it nor `gh run watch` bounds the time a job sits queued,
# and GitHub cancels a job waiting on a label nothing matches only after about
# 24 hours. Each value is the job's own limit plus slack for queueing: the CI
# gate's jobs cap at 60 minutes, the bottle job at 90 (sudo-release.yml).
CI_WATCH_SECONDS = 75 * 60
BOTTLE_WATCH_SECONDS = 110 * 60
# The macOS bottle is built by `sudo-release.yml` on the tag push (2026-10-18),
# so `brew reinstall` pours it instead of compiling the crate graph on this Mac.
# The workflow uploads the bottle and its JSON as this artifact on every run.
BOTTLE_WORKFLOW = "sudo-release.yml"
BOTTLE_ARTIFACT = "sudo-secretspec-bottle"
# The sha256 of the source archive the CI build compiled, shipped in the artifact
# so it can be compared with the archive hashed here for the formula.
SOURCE_SHA_FILE = "source.sha256"
TAP_FORMULA_REL = Path("Formula/sudo-secretspec.rb")
# What `brew bottle --json` writes for this tap's formula (the throwaway tap
# `brew tap-new` makes in the bottle job has the same name as the real one).
# `brew bottle --merge --write` opens that path under Homebrew's repository, so
# anything else in the JSON is refused.
_TAP_OWNER, _TAP_REPO = TAP_NAME.split("/")
BOTTLE_FORMULA_PATH = (
    f"Library/Taps/{_TAP_OWNER}/homebrew-{_TAP_REPO}/{TAP_FORMULA_REL}"
)
# The JSON's strings reach Ruby source in the tap formula (Homebrew writes the
# cellar and the tag between quotes without escaping), so each is held to the
# few values a real bottle has.
BOTTLE_TAG_RE = re.compile(r"(arm64_|x86_64_)?[a-z0-9_]+")
BOTTLE_CELLARS = (
    "any",
    "any_skip_relocation",
    "/opt/homebrew/Cellar",
    "/usr/local/Cellar",
)
# Homebrew omits `cellar:` for these two, and writes the relocatable ones as symbols.
BOTTLE_DEFAULT_CELLARS = ("/opt/homebrew/Cellar", "/usr/local/Cellar")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
# Install the tap formula, never Homebrew's API copy of a formula.
BREW_ENV = {"HOMEBREW_NO_INSTALL_FROM_API": "1"}
# The one place that names the escape hatch; every bottle failure repeats it.
BOTTLE_FALLBACK_HINT = (
    "The tag and Release are already published, so re-running release.py is "
    "refused. To install on this Mac anyway, run `brew reinstall "
    f"--build-from-source {FORMULA_NAME}` (what `release.py --build-from-source` "
    "runs); that compiles the whole crate graph locally."
)


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
    env: dict[str, str] | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    if dry_run:
        log("[dry-run] " + " ".join(str(value) for value in argv))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
    log("+ " + " ".join(str(value) for value in argv))
    return subprocess.run(
        argv,
        cwd=cwd,
        text=True,
        capture_output=capture,
        check=check,
        env={**os.environ, **env} if env else None,
        timeout=timeout,
    )


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


def find_run(branch: str, sha: str, *, workflow: str | None = None) -> int:
    """Return the id of the run on `branch` whose head is exactly `sha`.

    Matching the head matters: a force-pushed ``ci/run`` branch keeps its name,
    so the newest run on it may belong to the previous push. With a `workflow`
    the run must also be a push, and exactly one run may match: a
    ``workflow_dispatch`` on the same tag ref or a second run for the same commit
    is ambiguous, and picking the newest would watch (and trust) the wrong one.
    """
    argv = ["gh", "run", "list", "-R", FORK_REPO, "--branch", branch]
    if workflow:
        argv += ["--workflow", workflow, "--event", "push"]
    argv += ["--json", "databaseId,headSha"]
    for attempt in range(CI_RUN_LOOKUPS):
        if attempt:
            time.sleep(CI_RUN_LOOKUP_SECONDS)
        runs = json.loads(output(argv) or "[]")
        ids = [r["databaseId"] for r in runs if r.get("headSha") == sha]
        if workflow and len(ids) > 1:
            raise ReleaseError(
                f"{len(ids)} {workflow} push runs match {branch} at {sha[:12]} "
                f"({', '.join(map(str, ids))}); refusing to guess which one built it"
            )
        if ids:
            return ids[0]
    raise ReleaseError(f"no GitHub Actions run appeared for {branch}")


def watch_run(run_id: int, failure: str, *, timeout_s: float = CI_WATCH_SECONDS) -> str:
    """Block until the run finishes; raise `failure` plus its URL unless green.

    The wait is bounded. A `runs-on` label that matches nothing leaves the job
    queued rather than failing, and an unbounded watch would then block here
    for about a day -- for the bottle, *after* the tag and Release are already
    public, which is the one state release.py refuses to re-enter (2026-10-20:
    moving the bottle job to `xcode-27` is exactly the kind of edit that can
    mistype a label).
    """
    url = f"https://github.com/{FORK_REPO}/actions/runs/{run_id}"
    log(f"CI: {url}")
    try:
        watched = run(
            ["gh", "run", "watch", str(run_id), "-R", FORK_REPO, "--exit-status"],
            capture=False,
            check=False,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        raise ReleaseError(
            f"{failure}: no verdict after {timeout_s / 60:.0f} minutes, so the "
            "run is queued or stuck rather than red (a runs-on label that "
            f"matches no runner looks exactly like this): {url}"
        ) from None
    _require(watched.returncode == 0, f"{failure}: {url}")
    return url


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
    run_id = find_run(branch, overlay)
    watch_run(run_id, "CI did not pass")


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


def tap_checkout(*, dry_run: bool) -> Path:
    """Homebrew's own checkout of the tap, which is not the maintainer's clone."""
    repo = output(["brew", "--repository", TAP_NAME], dry_run=dry_run)
    return Path(repo) if repo else Path("<brew-tap-checkout>")


def brew_refresh(release: Release, *, dry_run: bool) -> Path:
    """Force-refresh Homebrew and fast-forward its tap checkout to origin."""
    run(["brew", "update", "--force"], dry_run=dry_run, capture=False)
    tap = tap_checkout(dry_run=dry_run)
    if not dry_run:
        _require(tap.is_dir(), "Homebrew did not return the tap checkout")
        run(["git", "fetch", "origin", "main"], cwd=tap, capture=False)
        run(["git", "merge", "--ff-only", "origin/main"], cwd=tap, capture=False)
        _require(
            release.tag in (tap / TAP_FORMULA_REL).read_text(encoding="utf-8"),
            "live tap formula is stale",
        )
    return tap


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def bottle_entry(release: Release, path: Path) -> dict[str, Any]:
    """The one formula entry of a ``brew bottle --json`` file, checked.

    The file must hold exactly one formula, ours, at this release's version and
    at the path ``brew bottle --merge`` opens, pointing at this release's
    download URL, with a tag, cellar, rebuild and sha256 of the shapes a real
    bottle has, and name every tarball by a bare file name (``dest / "../x"``
    would otherwise pass an ``is_file`` check). Homebrew pastes several of these
    strings into the tap's Ruby source unescaped.
    """
    document = json.loads(path.read_text(encoding="utf-8"))
    _require(
        isinstance(document, dict) and list(document) == [FORMULA_NAME],
        f"{path.name}: must hold exactly one entry, named {FORMULA_NAME}",
    )
    entry = document[FORMULA_NAME]
    formula = entry["formula"]
    _require(
        formula["name"] == BOTTLE_FORMULA_BASENAME,
        f"{path.name}: formula is {formula['name']!r}, not {BOTTLE_FORMULA_BASENAME}",
    )
    _require(
        formula["path"] == BOTTLE_FORMULA_PATH,
        f"{path.name}: formula path {formula['path']!r} is not {BOTTLE_FORMULA_PATH}",
    )
    pkg_version = formula["pkg_version"]
    _require(
        pkg_version == release.version,
        f"{path.name}: bottle is for {pkg_version}, not {release.version}",
    )
    bottle = entry["bottle"]
    root_url = f"https://github.com/{FORK_REPO}/releases/download/{release.tag}"
    _require(bottle["root_url"] == root_url, f"{path.name}: wrong root_url")
    _require(
        bottle["cellar"] in BOTTLE_CELLARS,
        f"{path.name}: unexpected cellar {bottle['cellar']!r}",
    )
    rebuild = bottle["rebuild"]
    _require(
        type(rebuild) is int and rebuild >= 0,
        f"{path.name}: rebuild {rebuild!r} is not a non-negative integer",
    )
    tags = bottle["tags"]
    _require(
        isinstance(tags, dict) and bool(tags), f"{path.name}: lists no bottle tags"
    )
    for tag, spec in tags.items():
        _require(
            isinstance(tag, str) and BOTTLE_TAG_RE.fullmatch(tag) is not None,
            f"{path.name}: unexpected bottle tag {tag!r}",
        )
        sha = spec["sha256"]
        _require(
            isinstance(sha, str) and SHA256_RE.fullmatch(sha) is not None,
            f"{path.name}: {tag} sha256 {sha!r} is not 64 lowercase hex digits",
        )
        name = spec["filename"]
        _require(
            isinstance(name, str)
            and bool(name)
            and name not in (".", "..")
            and not {"/", "\\"} & set(name),
            f"{path.name}: unsafe bottle file name {name!r}",
        )
    return entry


def bottle_specs(release: Release, path: Path) -> list[dict[str, Any]]:
    """The checked bottle entries (one per tag) of one ``brew bottle --json`` file."""
    return list(bottle_entry(release, path)["bottle"]["tags"].values())


def bottle_block_lines(release: Release, jsons: list[Path]) -> list[str]:
    """The ``bottle do`` block Homebrew writes for these JSON files, from the
    validated fields only, one whitespace-normalised line each (sha256 lines
    sorted, since the order and column padding are Homebrew's business).
    """
    rows: dict[str, str] = {}
    rebuilds: set[int] = set()
    for path in jsons:
        bottle = bottle_entry(release, path)["bottle"]
        rebuilds.add(bottle["rebuild"])
        cellar = bottle["cellar"]
        if cellar in BOTTLE_DEFAULT_CELLARS:
            prefix = ""
        elif cellar.startswith("/"):
            prefix = f'cellar: "{cellar}", '
        else:
            prefix = f"cellar: :{cellar}, "
        for tag, spec in bottle["tags"].items():
            _require(tag not in rows, f"bottle tag {tag} appears in two JSON files")
            rows[tag] = f'sha256 {prefix}{tag}: "{spec["sha256"]}"'
    _require(
        len(rebuilds) == 1, f"the bottle JSON files disagree on rebuild: {rebuilds}"
    )
    (rebuild,) = rebuilds
    lines = [
        "bottle do",
        f'root_url "https://github.com/{FORK_REPO}/releases/download/{release.tag}"',
    ]
    if rebuild:
        lines.append(f"rebuild {rebuild}")
    return [*lines, *sorted(rows.values()), "end"]


def written_bottle_block(formula: str) -> list[str]:
    """The formula's single ``bottle do`` block, normalised like the expected one."""
    blocks = re.findall(
        r"^  bottle do\n(.*?)^  end$", formula, re.MULTILINE | re.DOTALL
    )
    _require(len(blocks) == 1, f"the merged formula has {len(blocks)} bottle blocks")
    body = [" ".join(line.split()) for line in blocks[0].splitlines() if line.strip()]
    shas = sorted(line for line in body if line.startswith("sha256 "))
    return ["bottle do", *(line for line in body if line not in shas), *shas, "end"]


def verify_attestation(artifact: Path, *, source_ref: str, source_digest: str) -> None:
    """Check the signed build provenance of a bottle tarball or its JSON.

    ``gh attestation verify`` exits non-zero unless the Sigstore bundle GitHub
    holds for the file's digest was signed by exactly ``sudo-release.yml`` of
    this repository at the given ref (``--cert-identity`` is an exact match of
    the certificate's workflow identity on every gh version, unlike
    ``--signer-workflow``'s prefix match before gh 2.102), on a GitHub-hosted
    runner, at the given commit. The exit status decides; the output is only
    quoted in the refusal.
    """
    identity = (
        f"https://github.com/{FORK_REPO}/.github/workflows/{BOTTLE_WORKFLOW}"
        f"@{source_ref}"
    )
    try:
        run(
            ["gh", "attestation", "verify", str(artifact), "--repo", FORK_REPO]
            + ["--cert-identity", identity]
            + ["--source-ref", source_ref, "--source-digest", source_digest]
            + ["--deny-self-hosted-runners"]
        )
    except subprocess.CalledProcessError as error:
        raise ReleaseError(
            f"build provenance check failed for {artifact.name}: it is not "
            f"attested as built by {BOTTLE_WORKFLOW} at {source_ref} "
            f"({source_digest})\n{describe(error)}"
        ) from error


def fetch_bottle(release: Release, dest: Path, *, dry_run: bool) -> list[Path]:
    """Wait for the tag's bottle job and download its JSON into `dest`.

    The run is the ``sudo-release.yml`` push run for the tag commit itself,
    found by head SHA like ``ci_gate`` finds its own. Every JSON and every
    tarball must carry a signed build provenance from this workflow at the tag
    commit, and every tarball must hash to the sha256 its JSON records (the tap
    block is written from that JSON), and
    the source archive the runner compiled must be the one hashed here. Anything
    missing, mismatched or red is an error that names ``--build-from-source``;
    the caller never compiles on its own.
    """
    if dry_run:
        log(f"[dry-run] wait for {BOTTLE_WORKFLOW} on {release.tag}")
        run(
            ["gh", "run", "download", "<run-id>", "-n", BOTTLE_ARTIFACT],
            dry_run=True,
        )
        return []
    sha = output(["git", "rev-parse", f"{release.tag}^{{commit}}"])
    try:
        run_id = find_run(release.tag, sha, workflow=BOTTLE_WORKFLOW)
        watch_run(
            run_id,
            "the bottle run did not pass",
            timeout_s=BOTTLE_WATCH_SECONDS,
        )
        run(
            ["gh", "run", "download", str(run_id), "-R", FORK_REPO]
            + ["-n", BOTTLE_ARTIFACT, "-D", str(dest)]
        )
        jsons = sorted(dest.glob("*.bottle.json"))
        _require(bool(jsons), f"artifact {BOTTLE_ARTIFACT} holds no bottle JSON")
        ref = f"refs/tags/{release.tag}"
        for path in jsons:
            # The JSON is parsed by Homebrew into the tap formula's Ruby, so it
            # needs the provenance the tarball has, and before it is trusted.
            verify_attestation(path, source_ref=ref, source_digest=sha)
            for spec in bottle_specs(release, path):
                tarball = dest / spec["filename"]
                _require(
                    tarball.is_file(),
                    f"{path.name}: {spec['filename']} missing from the artifact",
                )
                _require(
                    file_sha256(tarball) == spec["sha256"],
                    f"{path.name}: {spec['filename']} does not hash to the sha256 "
                    "its JSON records",
                )
                verify_attestation(tarball, source_ref=ref, source_digest=sha)
        source = dest / SOURCE_SHA_FILE
        _require(
            source.is_file(), f"artifact {BOTTLE_ARTIFACT} lacks {SOURCE_SHA_FILE}"
        )
        _require(
            source.read_text(encoding="utf-8").strip()
            == archive_sha256(release, dry_run=False),
            "the CI build compiled a different source archive than the one the "
            "formula will pin",
        )
    except (
        ReleaseError,
        subprocess.CalledProcessError,
        KeyError,
        TypeError,
        ValueError,
        OSError,
    ) as error:
        detail = (
            describe(error)
            if isinstance(error, subprocess.CalledProcessError)
            else error
        )
        raise ReleaseError(
            f"no usable macOS bottle for {release.tag}: {detail}\n{BOTTLE_FALLBACK_HINT}"
        ) from error
    return jsons


def verify_release_assets(
    release: Release, jsons: list[Path], *, dry_run: bool
) -> None:
    """Check the bottles published on the GitHub Release against the JSON.

    The tap's ``bottle do`` block records the artifact's sha256, so an asset that
    differs (replaced, or attached by another run) would fail every install of
    the release. Catch it before the tap is pushed.
    """
    if dry_run:
        log(f"[dry-run] compare the {release.tag} release assets with the artifact")
        run(["gh", "release", "download", release.tag, "-R", FORK_REPO], dry_run=True)
        return
    with tempfile.TemporaryDirectory(prefix="sudo-secretspec-assets-") as work:
        for path in jsons:
            for spec in bottle_specs(release, path):
                name = spec["filename"]
                try:
                    run(
                        ["gh", "release", "download", release.tag, "-R", FORK_REPO]
                        + ["--pattern", name, "-D", work]
                    )
                except subprocess.CalledProcessError as error:
                    raise ReleaseError(
                        f"cannot download release asset {name}: {describe(error)}\n"
                        + BOTTLE_FALLBACK_HINT
                    ) from error
                actual = file_sha256(Path(work) / name)
                _require(
                    actual == spec["sha256"],
                    f"release asset {name} hashes to {actual}, but the CI artifact "
                    f"recorded {spec['sha256']}; the tap was not touched\n"
                    + BOTTLE_FALLBACK_HINT,
                )


def merge_bottle(
    release: Release, tap_path: Path, jsons: list[Path], *, dry_run: bool
) -> None:
    """Write the `bottle do` block into the tap formula and push the tap.

    ``brew bottle --merge --write`` edits Homebrew's tap checkout, where the
    JSON's formula path points, not the maintainer's clone. Run it without a
    commit, carry the edited file into the clone (the repository that is
    pushed), put the checkout back, and let the next refresh fast-forward it.
    """
    verify_release_assets(release, jsons, dry_run=dry_run)
    tap = brew_refresh(release, dry_run=dry_run)
    checkout_formula = tap / TAP_FORMULA_REL
    run(
        ["brew", "bottle", "--merge", "--write", "--no-commit", *map(str, jsons)],
        env=BREW_ENV,
        capture=False,
        dry_run=dry_run,
    )
    if dry_run:
        log(f"[dry-run] copy {checkout_formula} -> {tap_path / TAP_FORMULA_REL}")
        run(["git", "add", str(TAP_FORMULA_REL)], cwd=tap_path, dry_run=True)
        run(
            ["git", "commit", "-m", f"sudo-secretspec {release.version} bottle"],
            cwd=tap_path,
            dry_run=True,
        )
        run(["git", "push", "origin", "HEAD"], cwd=tap_path, dry_run=True)
        return
    merged = checkout_formula.read_text(encoding="utf-8")
    try:
        _require(
            "bottle do" in merged
            and f"releases/download/{release.tag}" in merged
            and release.tag in merged,
            f"brew bottle --merge wrote no bottle block for {release.tag}\n"
            + BOTTLE_FALLBACK_HINT,
        )
        # Homebrew pastes the JSON's strings into Ruby source; nothing but the
        # block the validated fields make may reach a commit.
        _require(
            written_bottle_block(merged) == bottle_block_lines(release, jsons),
            "the bottle block brew bottle --merge wrote differs from the one the "
            "validated JSON fields make; nothing was committed or pushed\n"
            + BOTTLE_FALLBACK_HINT,
        )
    except ReleaseError:
        run(["git", "checkout", "--", str(TAP_FORMULA_REL)], cwd=tap)
        raise
    shutil.copy2(checkout_formula, tap_path / TAP_FORMULA_REL)
    run(["git", "checkout", "--", str(TAP_FORMULA_REL)], cwd=tap)
    run(["git", "add", str(TAP_FORMULA_REL)], cwd=tap_path)
    run(
        ["git", "commit", "-m", f"sudo-secretspec {release.version} bottle"],
        cwd=tap_path,
    )
    run(["git", "push", "origin", "HEAD"], cwd=tap_path)


def install_from_source(*, dry_run: bool) -> None:
    """The explicit fallback: compile the formula here, one job at a time.

    Run through ``bg``, which gates on machine load. ``just release`` is
    normally started under ``bg`` itself, so this is bg inside bg. That cannot
    wait on the parent's slot: ``bg`` takes machine-wide slots only for gradle
    and test runners (pytest, swift, xcodebuild), and neither ``just``,
    ``release.py`` nor ``brew`` is one, so the inner call only re-reads the load
    gate the outer one already passed. It runs from ``$HOME`` because ``bg``
    refuses any build whose cwd is a CI-first repo such as this one, and the
    brew build never touches the checkout.
    """
    bg = Path.home() / "ops" / "site-private" / "bin" / "bg"
    argv = ["brew", "reinstall", "--build-from-source", FORMULA_NAME]
    if bg.is_file() or dry_run:
        argv = [str(bg), *argv]
    else:
        log(f"{bg} not found; compiling without the load gate")
    run(
        argv,
        cwd=Path.home(),
        env={**BREW_ENV, "HOMEBREW_MAKE_JOBS": "1"},
        capture=False,
        dry_run=dry_run,
    )


def brew_install_and_test(*, build_from_source: bool, dry_run: bool) -> str:
    if build_from_source:
        install_from_source(dry_run=dry_run)
    else:
        # --force-bottle makes brew refuse rather than quietly compile when it
        # finds no bottle it can pour; the cause is named, not hidden.
        result = run(
            ["brew", "reinstall", "--force-bottle", FORMULA_NAME],
            env=BREW_ENV,
            capture=False,
            check=False,
            dry_run=dry_run,
        )
        _require(
            result.returncode == 0,
            f"brew could not pour a bottle for {FORMULA_NAME}.\n"
            + BOTTLE_FALLBACK_HINT,
        )
    prefix = (
        output(["brew", "--prefix", FORMULA_NAME], dry_run=dry_run)
        or "/opt/homebrew/opt/sudo-secretspec"
    )
    run(["brew", "test", FORMULA_NAME], env=BREW_ENV, dry_run=dry_run, capture=False)
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
    parser.add_argument(
        "--build-from-source",
        action="store_true",
        help="compile the formula on this Mac instead of pouring the CI-built "
        "bottle (slow; the explicit fallback when the bottle job fails)",
    )
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
            with tempfile.TemporaryDirectory(prefix="sudo-secretspec-bottle-") as work:
                # Wait for the bottle before the tap moves: a failed bottle then
                # leaves the tap on the previous release instead of half-updated.
                jsons = (
                    []
                    if args.build_from_source
                    else fetch_bottle(release, Path(work), dry_run=args.dry_run)
                )
                update_formula_commit(release, dry_run=args.dry_run, state=state)
                sync_tap(release, args.tap_path, dry_run=args.dry_run)
                if not args.build_from_source:
                    merge_bottle(release, args.tap_path, jsons, dry_run=args.dry_run)
                brew_refresh(release, dry_run=args.dry_run)
                prefix = brew_install_and_test(
                    build_from_source=args.build_from_source, dry_run=args.dry_run
                )
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
