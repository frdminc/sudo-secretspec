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
import tarfile
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
# in `archive_facts` can 404 or time out for a few seconds after the Release is
# created. That fetch happens *after* the tag and Release are published, which
# are the irreversible steps -- a transient failure there drops the operator
# into the justfile's "do NOT re-run, finish by hand" path for no reason. Retry
# instead. Delays double from the first: 3s, 6s, 12s, 24s.
ARCHIVE_ATTEMPTS = 5
ARCHIVE_BACKOFF_SECONDS = 3
# Every host allowed to serve archive bytes. github.com 302s a tag archive to
# codeload.github.com, so the redirect target needs naming rather than
# refusing (see `PinnedRedirectHandler`).
ARCHIVE_HOSTS = ("github.com", "codeload.github.com")
# Every failure raised after `create_tag_and_release` repeats this, because the
# irreversible steps are already done by then and a re-run is refused.
RESUME_BY_HAND_HINT = (
    "The tag and Release are already published -- do not re-run `just release`; "
    "finish by hand per the justfile RESUME RULES."
)
# The tag push and the Release creation are two steps, and `tag_pushed` is set
# between them, so a failure in `gh release create` used to be told "the tag
# AND Release are already published" -- half false, and the justfile's
# hand-finish needs a Release that does not exist (adversary F4, 2026-10-23).
# Worded as uncertainty, not fact: the flag records only that release.py did
# not SEE `gh release create` return. A signal in that window, or a dropped
# connection after the API accepted the create, leaves the Release in place
# with the flag False -- so telling the operator to run `gh release create`
# outright would send them at a command that refuses (adversary F2,
# 2026-10-23). It branches on what `gh release view` reports instead, and says
# what the RESUME RULES assume: in the state that selects this hint there is no
# Release, no formula commit and no synced tap, so the rules' `brew reinstall`
# repairs none of them and would pour the PREVIOUS release's bottle. An
# uncertain hint that dead-ends is no better than a false one that does not
# (adversary F5, 2026-10-23).
RESUME_TAG_ONLY_HINT = (
    "The tag is pushed, but release.py did not see `gh release create` succeed "
    "-- do not re-run `just release`. Check `gh release view <tag> --repo "
    f"{FORK_REPO}` first: if the Release is there, finish by hand per the "
    "justfile RESUME RULES. If it is not, create it (`gh release create <tag> "
    f"--repo {FORK_REPO} --title <title> --notes-file <notes>`), then follow "
    "those rules -- they assume the Release, the formula commit and the tap are "
    "all public already, which is why the tag-only state has its own rule."
)
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
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
# A bottle file name reaches `gh release download --pattern`, which is a glob,
# and argv. Allow only what Homebrew actually writes, so a name carrying glob
# metacharacters or shaped like an option is refused before it is used at all
# (adversary N7, 2026-10-20).
BOTTLE_FILENAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
# The single workflow `ci/base` carries. Naming it makes `find_run` apply its
# `--event push` filter and its one-match refusal to the gate too: the
# wrapper's overlay_paths already lists agent-ci.yml, so the day ci/base
# grows it two runs would share the overlay SHA and the release would be
# gated on whichever gh listed first (adversary F3.3, 2026-10-20).
CI_GATE_WORKFLOW = "linux-ci.yml"
# Install the tap formula, never Homebrew's API copy of a formula.
BREW_ENV = {"HOMEBREW_NO_INSTALL_FROM_API": "1"}
# The one place that names the escape hatch; every bottle failure repeats it.
BOTTLE_FALLBACK_HINT = (
    "The tag and Release are already published, so re-running release.py is "
    "refused. To install on this Mac anyway, run `brew reinstall "
    f"--build-from-source {FORMULA_NAME}` (what `release.py --build-from-source` "
    "runs); that compiles the whole crate graph locally."
)
# A HEAD keg is a different failure with a different remedy, so it gets its
# own hint: compiling the crate graph would not help, because `brew reinstall`
# would still resolve the HEAD spec, which by definition carries no bottle.
HEAD_KEG_HINT = (
    "A HEAD keg is linked ({keg}), and `brew reinstall` reuses the spec of the "
    "linked keg, so it resolves HEAD -- which has no bottle at any version. The "
    "bottle this release published is fine; the install is what cannot take it. "
    f"To move this Mac onto the stable spec: `brew unlink {FORMULA_NAME} && brew "
    f"install --force-bottle {FORMULA_NAME}`; to go back, `brew link --overwrite "
    "{keg}`. Upgrading the privileged boundary is a separate, explicit step "
    "(see the formula's caveats)."
)
# Every hint above is SELF-SUFFICIENT: it already says how far the release got
# and names the one recovery route for its own failure. Two places wrap an
# error and append a hint of their own (`fetch_bottle` and `main`), so an
# error that already carries one must pass through untouched -- otherwise the
# operator reads the claim twice with two CONFLICTING routes. That is what
# shipped in 0c19acb: the guard knew only RESUME_BY_HAND_HINT, so every
# BOTTLE_FALLBACK_HINT failure (five functions, eight raise sites, all
# post-publication) stated "The tag and Release are already published" twice,
# joined by "..", offering both `brew reinstall --build-from-source` and the
# justfile's pour-the-bottle recipe -- the thing that had just failed to exist
# (adversary F1, 2026-10-23).
#
# The carrier is a FLAG ON THE EXCEPTION, not a substring of its message.
# Three heads were spent patching a substring heuristic and each left a hole:
# first it knew one hint of three, then -- once the guard reached inside
# `fetch_bottle` -- a fragment match fired on messages that merely QUOTED a
# hint, because `bottle_entry` reports a rejected field by echoing its value,
# so a JSON field carrying "finish by hand per the justfile RESUME RULES" had
# BOTTLE_FALLBACK_HINT and the "no usable macOS bottle" framing stripped from
# its failure. Bottle JSON is attacker-reachable by this file's own threat
# model (see `fetch_bottle`), so that let the content choose which recovery
# route the operator was shown (adversary F1, ninth review, 2026-10-23). A
# flag cannot be forged by message text, needs no marker/hint coupling test,
# and states the property at the raise site, where the author knows the answer.


class ReleaseError(RuntimeError):
    """Release invariant failed.

    `self_sufficient` marks a message that already says how far the release got
    and names its own recovery route, so the two wrapping handlers re-raise it
    untouched instead of appending a second, conflicting one. Set it at every
    raise site whose message carries one of the hints above; the test
    `test_every_hint_carrying_raise_site_declares_itself_self_sufficient`
    walks this file's AST and fails on one that forgets.
    """

    def __init__(self, *args: object, self_sufficient: bool = False) -> None:
        super().__init__(*args)
        self.self_sufficient = self_sufficient


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

    @property
    def archive_prefix(self) -> str:
        """The single directory GitHub puts inside its generated archive.

        Repo name plus the tag with its leading `v` stripped -- verified
        against the real v0.19.1-sudo.28 archive, whose only top-level entry
        is `sudo-secretspec-0.19.1-sudo.28`. Computed locally, never read out
        of the archive, so it is a requirement the bytes must meet rather
        than a value they get to choose.
        """
        return f"{FORK_REPO.split('/')[-1]}-{self.version}"


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


class PinnedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-check scheme and host on every redirect hop.

    `validate_release_url` sees only the URL release.py built; urllib then
    follows redirects wherever they point, and its default handler permits a
    hop to plain `http`. So the host check did not constrain who actually
    served the bytes (adversary, 2026-10-20). The hop cannot simply be
    refused: GitHub's archive URL does redirect, to codeload.github.com.

    `ReleaseError` is a RuntimeError, so it is not swallowed by
    `archive_facts`'s `(URLError, OSError)` retry -- a redirect off GitHub is
    not a transient failure and must not be retried into.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlsplit(newurl)
        if parsed.scheme != "https" or parsed.hostname not in ARCHIVE_HOSTS:
            raise ReleaseError(
                f"refuse redirect off GitHub HTTPS: {newurl!r}. {RESUME_BY_HAND_HINT}",
                self_sufficient=True,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# Private, not `install_opener`: the global opener is process state, and
# `sudo-release.yml` imports this module inside the bottle job, which has no
# business having its redirect policy changed by importing a formula rewriter.
# Keeping it here also gives the test something to assert the fetch goes
# through (adversary, 2026-10-20). `build_opener` replaces the default
# `HTTPRedirectHandler` rather than stacking beside it, which is what the pin
# depends on.
_OPENER = urllib.request.build_opener(PinnedRedirectHandler)


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


def _require(value: bool, message: str, *, self_sufficient: bool = False) -> None:
    if not value:
        raise ReleaseError(message, self_sufficient=self_sufficient)


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
    run_id = find_run(branch, overlay, workflow=CI_GATE_WORKFLOW)
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


# (digest, commit) per archive URL. One download fills both: hashing one body
# and reading the commit out of another meant the number pinned into the
# formula was never the body whose commit was checked (adversary, 2026-10-20).
_ARCHIVE_FACTS: dict[
    str, tuple[str, str | None, dict[str, tuple[str, str]] | None]
] = {}


def archive_commit(path: Path) -> str | None:
    """The commit id GitHub embedded in a generated tag archive, or None.

    GitHub writes it as the `comment` record of the tar's global pax header,
    which is exactly what CI's `git get-tar-commit-id` reads
    (`sudo-release.yml`). Reading it with `tarfile` keeps the check in process:
    no gzip pipe, no temp tar, nothing that needs a shell.

    The record is data *inside* the archive, so anyone who can produce the
    bytes can choose it. This identifies which archive GitHub generated; it is
    not evidence about the tree, and nothing here should be read as a defence
    against a forged archive.
    """
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            comment = (archive.pax_headers or {}).get("comment")
    except (tarfile.TarError, OSError, EOFError):
        return None
    if isinstance(comment, str) and COMMIT_RE.fullmatch(comment.strip()):
        return comment.strip()
    return None


def tree_entries(root: Path) -> dict[str, tuple[str, str]]:
    """Every fact git tracks about a source tree, and nothing else.

    git records a path, whether it is executable, whether it is a symlink,
    and content. Not mtimes, not uid/gid, not directories -- a directory
    exists only as a side effect of the files under it. Fingerprinting
    exactly that set is what makes the comparison meaningful in both
    directions: a reported difference is always a real difference to the
    tree, and an irrelevant one is never reported.

    `followlinks=False` so a symlinked directory is recorded as a symlink
    rather than walked into (and cannot make the walk cyclic).

    `onerror` raises, because `os.walk`'s default silently *discards* a
    directory it cannot list -- and since directories are not entries here,
    an unlistable directory would vanish from the fingerprint along with
    everything under it. That is a hiding primitive: a hostile archive adds
    a traversable-but-unlistable directory (mode 0o111) holding, say, a
    `.cargo/config.toml` with `rustc-wrapper`, which cargo opens by exact
    name at build time. Today the data filter normalises directory modes to
    0o755 so the walk descends and the extra path is reported -- but that is
    a CPython implementation detail, not a guarantee, and it is the only
    thing standing between a fail-open walk and a silent forgery (adversary
    F4, 2026-10-23). Raising makes the refusal ours.
    """
    entries: dict[str, tuple[str, str]] = {}

    def refuse(error: OSError) -> None:
        raise error

    for dirpath, dirnames, filenames in os.walk(
        root, followlinks=False, onerror=refuse
    ):
        for name in filenames + dirnames:
            path = Path(dirpath) / name
            relative = path.relative_to(root).as_posix()
            # Order matters: `is_file` follows symlinks, so a symlink to a
            # file would otherwise be recorded as its target's content.
            if path.is_symlink():
                target = os.readlink(path).encode()
                entries[relative] = ("120000", hashlib.sha256(target).hexdigest())
            elif path.is_file():
                mode = "100755" if path.stat().st_mode & 0o111 else "100644"
                entries[relative] = (mode, file_sha256(path))
    return entries


def extracted_tree(tarball: Path, *, prefix: str) -> dict[str, tuple[str, str]] | None:
    """Fingerprint a tar's single prefixed root, or None if it is not one.

    This is the one place release.py writes bytes it does not trust to the
    filesystem, and the whole premise of the caller is that the archive may
    not be the tag's tree.

    What `filter="data"` *refuses*, raising `FilterError` (a `TarError`): an
    absolute path, `..` traversal, a device or other special file, a symlink
    or hardlink whose target escapes the destination. What it instead
    *normalises*, silently and without raising: setuid, setgid and sticky
    bits, group/other write bits on files, and directory and symlink modes
    altogether. Probed on 3.13.14 and 3.14.7 (adversary F3, 2026-10-23):
    0o4755 and 0o2755 members both land as 0o755, 0o666 as 0o644, a 0o111
    directory as 0o755. So the fingerprint below compares *post-filter*
    modes, and a mode-only divergence in those bits is invisible to it --
    which is harmless here only because git cannot express them either, so
    the `git archive` side is always 0o100644 or 0o100755.

    Passing the argument explicitly is not redundant, and the reason is not
    any particular interpreter: never depend on a default that changes under
    you. It does change -- probed 2026-10-20, confirmed 2026-10-23: 3.13
    still writes a `../../escaped.txt` member *outside* the destination with
    only a DeprecationWarning, while 3.14 refuses with
    `OutsideDestinationError`. The release driver runs under
    `#!/usr/bin/env python3`, whatever that resolves to on the operator's
    machine; 3.13 is what `sudo-release.yml`'s packaging job pins for the
    tests, which is a different thing (adversary F2, 2026-10-23).
    """
    with tempfile.TemporaryDirectory() as workspace:
        destination = Path(workspace)
        # Everything that touches the extracted bytes is inside the `try`,
        # not just `extractall`: `iterdir`, `is_dir` and `tree_entries` all
        # stat, readlink and read files, and `tree_entries` now raises on an
        # unlistable directory by design. An OSError escaping here would
        # reach the operator as a bare traceback with no resume path, after
        # the tag and the Release are already public -- the exact shape of
        # the defect 9e1312e was written to fix (adversary F5, 2026-10-23).
        try:
            with tarfile.open(tarball, mode="r:*") as archive:
                archive.extractall(destination, filter="data")
            roots = list(destination.iterdir())
            if len(roots) != 1 or roots[0].name != prefix or not roots[0].is_dir():
                return None
            return tree_entries(roots[0])
        except (tarfile.TarError, OSError, EOFError, ValueError) as error:
            # Logged, because the caller's `_require` can only say "not a
            # single prefixed directory, or a refused member, or could not be
            # fingerprinted" -- three causes, attack first and accident last.
            # On a post-publication failure the operator has to choose between
            # finishing by hand and opening a compromise investigation, and an
            # ENOSPC that reads as "carries a member the tar data filter
            # refuses" sends them the wrong way. v0.19.1-sudo.15 ran out of
            # disk after publishing; that is why `preflight_disk` exists
            # (adversary F2, 2026-10-23).
            log(f"cannot fingerprint {tarball}: {error!r}")
            return None


def tag_tree(release: Release) -> dict[str, tuple[str, str]] | None:
    """Fingerprint the tag's own tree, straight out of git.

    Via `git archive` with GitHub's own prefix rather than a worktree
    checkout, so both sides of the comparison are built the same way and
    both have `.gitattributes` applied identically (this repo sets
    `text eol=lf` on the sops fixtures, which would otherwise be a
    difference that means nothing). `-o` rather than a pipe: a result read
    through a pipe is the pipe's.
    """
    with tempfile.TemporaryDirectory() as workspace:
        tarball = Path(workspace) / "tag.tar"
        try:
            run(
                [
                    "git",
                    "archive",
                    "--format=tar",
                    f"--prefix={release.archive_prefix}/",
                    "-o",
                    str(tarball),
                    f"refs/tags/{release.tag}",
                ],
                dry_run=False,
            )
        except (subprocess.CalledProcessError, OSError):
            # None rather than a raise, so the caller's `_require` reports it
            # with the resume path. `run` has check=True, and a bare
            # CalledProcessError out of here would be the one failure on this
            # path that reaches the operator without it.
            return None
        return extracted_tree(tarball, prefix=release.archive_prefix)


def archive_facts(
    release: Release, *, dry_run: bool
) -> tuple[str, str | None, dict[str, tuple[str, str]] | None]:
    """The tag archive's sha256, embedded commit id and tree, from one download.

    Memoised per URL, because the digest compared with CI's `source.sha256`
    has to be the digest written into the formula, and the commit checked has
    to belong to those same bytes. Each extra download was a window of its
    own: GitHub's generated archives are not contractually byte-stable -- the
    2023 gzip change moved every one of them (adversary N6b, 2026-10-20).
    The module is re-executed per test, so the memo is per process.
    """
    validate_release_url(release.archive_url)
    if dry_run:
        log(f"[dry-run] fetch {release.archive_url}")
        return "0" * 64, None, None
    cached = _ARCHIVE_FACTS.get(release.archive_url)
    if cached is not None:
        return cached
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
            with tempfile.NamedTemporaryFile(suffix=".tar.gz") as body:
                written = 0
                with _OPENER.open(request, timeout=60) as response:
                    while chunk := response.read(1024 * 1024):
                        digest.update(chunk)
                        body.write(chunk)
                        written += len(chunk)
                    # `response.length` is what `http.client` itself
                    # believed, counted down by the reads above. It is None
                    # whenever the raw header must not be trusted: absent,
                    # malformed (`Content-Length: ` or a proxy's folded
                    # `40, 40` -- `http.client` tolerates both and reads to
                    # close), or overridden by chunked encoding, which wins
                    # while the raw header stays in `headers`. Comparing
                    # against the raw string instead raised an uncaught
                    # ValueError on the first two and wasted five attempts on
                    # the third (adversary, 2026-10-20).
                    declared = (
                        response.headers.get("Content-Length")
                        if response.length is not None
                        else None
                    )
                # `http.client` does not raise on a body shorter than its
                # Content-Length: `read` returns b"" and closes. Without this
                # the attempt looks complete, the memo takes the digest of the
                # truncated bytes, and the tar carries no pax header -- so a
                # transient cut surfaced as the permanent-sounding "not an
                # archive GitHub generated for this tag" and burned the
                # release into finish-by-hand instead of retrying (adversary,
                # 2026-10-20). An OSError is what the loop below retries.
                if declared is not None and written != int(declared):
                    raise OSError(f"truncated download: {written} of {declared} bytes")
                body.flush()
                facts = (
                    digest.hexdigest(),
                    archive_commit(Path(body.name)),
                    extracted_tree(Path(body.name), prefix=release.archive_prefix),
                )
            _ARCHIVE_FACTS[release.archive_url] = facts
            return facts
        except (urllib.error.URLError, OSError, ValueError) as error:
            # ValueError is belt and braces: the gate above means no header is
            # parsed unless `http.client` already parsed it, but this loop is
            # the only thing standing between a malformed response and a raw
            # traceback after the tag and Release are published.
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
        f"{last_error}. {RESUME_BY_HAND_HINT}",
        self_sufficient=True,
    )


def require_archive_matches_tag(release: Release, *, dry_run: bool) -> None:
    """Bind the published archive to the tag's tree, not to a label it carries.

    GitHub serves an archive by tag *name*, and nothing local used to tie
    those bytes to the commit the tag points at: the binding existed only in
    CI, and only transitively, through a `source.sha256` that carried no
    attestation.

    Two checks, and only the second is a binding. The commit id in the tar's
    pax header is data *inside* the archive, so whoever produces the bytes
    chooses it -- it is an accident check that gives a precise diagnosis for
    the common cases (a stale tag, a regenerated archive of another tree, a
    fetch for the wrong ref). The tree comparison is the real one: every path,
    executable bit, symlink target and content digest in the archive, against
    `git archive` of the tag built with the same prefix. A forged archive
    passes the first and cannot pass the second (adversary 1b, 2026-10-20).

    Both read the bytes `archive_facts` hashed, so the digest pinned into the
    formula is the digest of the tree that was checked.

    This binds *the source the formula will pin* to the tag, locally,
    trusting CI for none of it. It does NOT bind the source the runner
    compiled: the bottle job fetches the archive itself, by URL, with its
    own curl (`sudo-release.yml:177`). Tying those two together is the
    `source.sha256` comparison in `fetch_bottle`, and nothing else does it.
    Both checks are load-bearing and neither subsumes the other; only on
    `--build-from-source`, where there is no bottle and `fetch_bottle` never
    runs, is this one the whole binding (adversary F1, 2026-10-23).
    """
    if dry_run:
        log(f"[dry-run] bind {release.archive_url} to {release.tag}")
        return
    # `output` runs with check=True and `git rev-parse` exits 128 on an
    # unknown tag, so the real failure here is a CalledProcessError, not the
    # guard below -- which made the guard reachable only under a monkeypatch
    # (adversary, 2026-10-20). Both now carry the resume path.
    try:
        expected = output(["git", "rev-parse", f"{release.tag}^{{commit}}"])
    except subprocess.CalledProcessError as error:
        raise ReleaseError(
            f"cannot resolve {release.tag} to a local commit, so the archive "
            f"cannot be checked against it: {describe(error)}. "
            f"{RESUME_BY_HAND_HINT}",
            self_sufficient=True,
        ) from error
    _require(
        COMMIT_RE.fullmatch(expected) is not None,
        f"cannot resolve {release.tag} to a local commit, so the archive "
        f"cannot be checked against it: got {expected!r}. {RESUME_BY_HAND_HINT}",
        self_sufficient=True,
    )
    found, archive = archive_facts(release, dry_run=dry_run)[1:]
    _require(
        found is not None,
        f"{release.archive_url} carries no commit id in its tar header, so it "
        f"is not an archive GitHub generated for this tag. {RESUME_BY_HAND_HINT}",
        self_sufficient=True,
    )
    _require(
        found == expected,
        f"{release.archive_url} names commit {found}, but {release.tag} is "
        f"{expected}: the archive is not this tag's. {RESUME_BY_HAND_HINT}",
        self_sufficient=True,
    )
    _require(
        archive is not None,
        f"{release.archive_url} is not a single `{release.archive_prefix}/` "
        "directory of ordinary files, or carries a member the tar data filter "
        "refuses (an absolute path, `..`, a special file, or an escaping "
        "symlink or hardlink), or could not be fingerprinted. "
        f"{RESUME_BY_HAND_HINT}",
        self_sufficient=True,
    )
    expected_tree = tag_tree(release)
    _require(
        expected_tree is not None,
        f"cannot fingerprint {release.tag}'s own tree with `git archive`, so "
        f"the archive has nothing to be checked against. {RESUME_BY_HAND_HINT}",
        self_sufficient=True,
    )
    _require(
        archive == expected_tree,
        f"{release.archive_url} is not {release.tag}'s tree: "
        f"{describe_tree_mismatch(archive, expected_tree)}. {RESUME_BY_HAND_HINT}",
        self_sufficient=True,
    )
    log(
        f"archive of {release.tag} is commit {found} and matches its tree "
        f"({len(expected_tree)} entries)"
    )


def describe_tree_mismatch(
    archive: dict[str, tuple[str, str]], tag: dict[str, tuple[str, str]]
) -> str:
    """Name the first few differing paths, by kind.

    A bare "trees differ" on a 601-entry tree is not actionable, and this
    failure arrives after the tag and Release are published, when the operator
    has to decide between a resume by hand and a real compromise.
    """
    extra = sorted(set(archive) - set(tag))
    missing = sorted(set(tag) - set(archive))
    changed = sorted(
        path for path in set(archive) & set(tag) if archive[path] != tag[path]
    )
    parts = []
    for label, paths in (
        ("not in the tag", extra),
        ("missing", missing),
        ("different", changed),
    ):
        if paths:
            shown = ", ".join(paths[:5])
            more = f" and {len(paths) - 5} more" if len(paths) > 5 else ""
            parts.append(f"{len(paths)} {label} ({shown}{more})")
    return "; ".join(parts) or "same paths, same content -- compare the walk itself"


def archive_sha256(release: Release, *, dry_run: bool) -> str:
    """The sha256 of the tag's source archive, downloaded at most once."""
    return archive_facts(release, dry_run=dry_run)[0]


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
        # Inside the `with`, immediately after the call that earns it: an
        # OSError out of __exit__ would otherwise leave the flag False after a
        # fully successful `gh release create`, and the tag-only hint would
        # then send the operator looking for a Release that exists (adversary
        # F2c, 2026-10-23). What can actually propagate from here is an EIO or
        # ENOSPC from the final `close()`, or an `unlink` failing with
        # something other than FileNotFoundError: `tempfile`'s own closer
        # wraps that one in `except FileNotFoundError: pass`, so a $TMPDIR
        # reaper deleting the file cannot raise at all -- an earlier version of
        # this comment named exactly that (adversary F4, ninth review).
        state.release_created = True


def update_formula_commit(
    release: Release, *, dry_run: bool, state: CleanupState
) -> None:
    require_archive_matches_tag(release, dry_run=dry_run)
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
            and BOTTLE_FILENAME_RE.fullmatch(name) is not None
            and name not in (".", ".."),
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
        # Exactly one: every line of the merged block comes from a validated,
        # attested JSON, but nothing said how many there should be, so a run
        # that produced a second OS tag would add a `sha256 <tag>:` line for a
        # bottle nobody meant to ship -- and an image transition is exactly
        # when that happens (adversary F3.2, 2026-10-20). Shipping a second
        # platform should be an edit here.
        _require(
            len(jsons) == 1,
            f"artifact {BOTTLE_ARTIFACT} holds {len(jsons)} bottle JSON files "
            f"({', '.join(p.name for p in jsons) or 'none'}); expected exactly one",
        )
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
        # Attested like the tarball and the JSON. It used to be the only input
        # trusted here with no provenance at all (adversary N6a, 2026-10-20);
        # the workflow now signs it and writes it from a step output recorded
        # before `brew install --build-bottle` runs, which stops the obvious
        # attack of a build.rs overwriting the file the next step copies.
        #
        # What an attestation proves is "this workflow produced these bytes",
        # never "these bytes predate the third-party code". The bottle job's
        # filesystem stays writable between the build step and the attest
        # step, so a process the build left behind could still rewrite this
        # file and have it signed (adversary F3.1, 2026-10-20).
        #
        # It is nevertheless LOAD-BEARING, and an earlier version of this
        # comment was wrong to call it belt-and-braces (adversary F1,
        # 2026-10-23). `require_archive_matches_tag` binds the source the
        # formula pins to the tag, but it only ever sees the operator's own
        # download; the bottle job curls the archive itself
        # (`sudo-release.yml:177`) and compiles whatever it got. The bottle's
        # attestation says "sudo-release.yml at this tag produced these
        # bytes" and carries no statement about the source behind them. So
        # the comparison below is the only thing in the whole release tying
        # the shipped, attested binary to the tree that was verified against
        # the tag. Serve codeload's two fetches different bytes -- cache
        # poisoning, a hostile resolver on the runner's egress, or GitHub
        # simply regenerating the archive in between, which this repo already
        # records as possible (N6b, `archive_facts`) -- and every other check
        # still passes. Do not remove it, and do not weaken it to a warning.
        #
        # The review's escalation of F3.1 -- move the digest into a job that
        # runs no cargo and no brew and verify *that job's* attestation --
        # cannot be enforced, which is why it is not built. The only identity
        # `verify_attestation` can pin is the certificate identity, and that
        # names the workflow FILE, not the job. Checked against the real .28
        # predicate rather than inferred: `runDetails.builder.id`, the
        # workflow `externalParameters`, and the certificate's SAN,
        # `buildSignerURI` and `buildConfigURI` all read `sudo-release.yml`
        # and nothing finer, while `metadata.invocationId` names the run,
        # which two jobs share. A second job here would mint attestations
        # indistinguishable from this one's. A separate workflow file would
        # have a distinct identity; the operator chose to make 1b the real
        # check instead (2026-10-23).
        verify_attestation(source, source_ref=ref, source_digest=sha)
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
        # The inner error may already carry a hint of its own, and the one that
        # does is reachable: the `source.sha256` comparison above is the run's
        # FIRST archive download (fetch_bottle precedes update_formula_commit),
        # so `archive_facts` exhausting its attempts raises a ReleaseError
        # ending in RESUME_BY_HAND_HINT. Wrapping that and appending
        # BOTTLE_FALLBACK_HINT states "already published" twice with two
        # conflicting routes -- and here the bottle route is the MORE wrong of
        # the two, because what failed was a source download, not the bottle.
        #
        # `main`'s guard cannot help: by the time it sees this the composition
        # has already happened, so it correctly re-raises untouched. The guard
        # has to be here too (adversary F1, 2026-10-23).
        #
        # It reads the FLAG, never the message. The validation errors from
        # `bottle_entry` echo the rejected field value, so a substring test
        # here fired on bottle JSON that merely quoted a hint and stripped the
        # bottle route from a bottle failure (adversary F1, ninth review).
        # `isinstance` is load-bearing: the other five caught types have no
        # such attribute, and reading one off them would be an AttributeError
        # inside an exception handler.
        if isinstance(error, ReleaseError) and error.self_sufficient:
            raise
        detail = (
            describe(error)
            if isinstance(error, subprocess.CalledProcessError)
            else error
        )
        raise ReleaseError(
            f"no usable macOS bottle for {release.tag}: {detail}\n"
            f"{BOTTLE_FALLBACK_HINT}",
            self_sufficient=True,
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
                # One asset per download directory: `--pattern` is a glob, and
                # the point of this step is to hash the asset Homebrew will
                # fetch by exact name. A pattern that matched several would
                # make the set checked here differ from the set installed, and
                # one that matched none left `file_sha256` to raise
                # FileNotFoundError outside any handler that names the
                # fallback (adversary N7, 2026-10-20).
                asset_dir = Path(work) / name
                try:
                    asset_dir.mkdir(parents=True)
                    run(
                        ["gh", "release", "download", release.tag, "-R", FORK_REPO]
                        + ["--pattern", name, "-D", str(asset_dir)]
                    )
                    landed = sorted(p.name for p in asset_dir.iterdir())
                    _require(
                        landed == [name],
                        f"downloading release asset {name} produced "
                        f"{landed or 'no files'}; expected exactly that one name\n"
                        + BOTTLE_FALLBACK_HINT,
                        self_sufficient=True,
                    )
                    actual = file_sha256(asset_dir / name)
                except (subprocess.CalledProcessError, OSError) as error:
                    detail = (
                        describe(error)
                        if isinstance(error, subprocess.CalledProcessError)
                        else error
                    )
                    raise ReleaseError(
                        f"cannot download release asset {name}: {detail}\n"
                        + BOTTLE_FALLBACK_HINT,
                        self_sufficient=True,
                    ) from error
                _require(
                    actual == spec["sha256"],
                    f"release asset {name} hashes to {actual}, but the CI artifact "
                    f"recorded {spec['sha256']}; the tap was not touched\n"
                    + BOTTLE_FALLBACK_HINT,
                    self_sufficient=True,
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
            self_sufficient=True,
        )
        # Homebrew pastes the JSON's strings into Ruby source; nothing but the
        # block the validated fields make may reach a commit.
        _require(
            written_bottle_block(merged) == bottle_block_lines(release, jsons),
            "the bottle block brew bottle --merge wrote differs from the one the "
            "validated JSON fields make; nothing was committed or pushed\n"
            + BOTTLE_FALLBACK_HINT,
            self_sufficient=True,
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


def linked_head_keg(*, dry_run: bool) -> str | None:
    """The linked keg's name when it is a HEAD keg, else None.

    `brew reinstall` reuses the spec of the keg that is linked. A HEAD keg
    therefore makes `--force-bottle` fail with "has no bottle" however good
    the published bottle is, and the build-from-source hint is wrong for it:
    a HEAD build is exactly what is already installed. Unreadable or absent
    `brew info` output means "not a HEAD keg": this check only ever turns one
    confusing message into a precise one, so it must never be the thing that
    fails a release.
    """
    if dry_run:
        return None
    try:
        info = json.loads(
            output(
                ["brew", "info", "--json=v2", FORMULA_NAME],
                env=BREW_ENV,
                check=False,
            )
            or "{}"
        )
        linked = (info.get("formulae") or [{}])[0].get("linked_keg")
    except (json.JSONDecodeError, OSError, AttributeError, IndexError, TypeError):
        return None
    if isinstance(linked, str) and linked.upper().startswith("HEAD"):
        return linked
    return None


def brew_install_and_test(*, build_from_source: bool, dry_run: bool) -> str:
    if build_from_source:
        install_from_source(dry_run=dry_run)
    else:
        head_keg = linked_head_keg(dry_run=dry_run)
        _require(
            head_keg is None,
            HEAD_KEG_HINT.format(keg=head_keg),
            self_sufficient=True,
        )
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
            self_sufficient=True,
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
    # Set only once `gh release create` has returned, so the resume hint can
    # claim the Release exists only when it does (adversary F4, 2026-10-23).
    release_created: bool = False
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
    try:
        _release_body(release, args, notes, state)
    except Exception as error:
        # The real last resort for the post-publication path: anything nobody
        # enumerated, including a ValueError such as `verify_readback`'s
        # `json.loads` on a `gh` that exits 0 with non-JSON (adversary F3,
        # 2026-10-23 -- the previous version of this handler caught only
        # OSError while its comment claimed to catch everything).
        #
        # Scoped to `state.tag_pushed`, because RESUME_BY_HAND_HINT is a
        # factual CLAIM -- "the tag and Release are already published" -- and
        # a directive not to re-run, not a generic apology. Appended to a
        # PRE-publication failure (`git`, `cargo` or `gh` missing from PATH in
        # preflight, a mistyped `--notes-file`) it tells the operator not to
        # re-run when re-running is exactly right, and the justfile's RESUME
        # RULES make those two cases opposite. That is what the first version
        # of this guard did, unconditionally, from `__main__` (adversary F1,
        # 2026-10-23). Before the tag is pushed, the error is re-raised
        # untouched.
        if not state.tag_pushed:
            raise
        message = str(error)
        # The flag, never the message: an error whose text merely QUOTES a hint
        # (a `_require` echoing a rejected field value, a CalledProcessError
        # whose stderr contains one) still needs the resume path appended.
        # `isinstance` is load-bearing -- an arbitrary Exception has no such
        # attribute (adversary F2, ninth review, 2026-10-23).
        if isinstance(error, ReleaseError) and error.self_sufficient:
            raise
        if isinstance(error, subprocess.CalledProcessError):
            # `describe` carries the failed command's own stderr, and since
            # this handler now intercepts the CalledProcessError, __main__'s
            # `except subprocess.CalledProcessError` can no longer fire for
            # anything inside `_release_body`. Without this branch "Error:
            # the `brew link` step did not complete successfully" -- the whole
            # reason brew refused -- is lost (adversary F3.1, 2026-10-23).
            detail = describe(error)
        elif isinstance(error, ReleaseError):
            # Our own errors carry curated operator-facing prose; the type
            # name would only add noise.
            detail = message
        else:
            # Anything nobody enumerated. __main__ turns this into a
            # string-valued SystemExit, and CPython prints such a SystemExit's
            # argument ALONE -- no traceback, no type, no __cause__ chain -- so
            # without the type name the operator cannot tell a ValueError from
            # an OSError (adversary F2, 2026-10-23).
            detail = f"{type(error).__name__}: {error}"
        hint = RESUME_BY_HAND_HINT if state.release_created else RESUME_TAG_ONLY_HINT
        raise ReleaseError(f"{detail}. {hint}", self_sufficient=True) from error
    log(f"done: {release.title} ({release.tag})")
    return 0


def _release_body(
    release: Release, args: argparse.Namespace, notes: str, state: CleanupState
) -> None:
    """Everything from the tag push onward, so `main` can wrap it in one place.

    Split out only so the publication-state guard in `main` has a single
    statement to wrap; `preflight` and the notes read stay outside it, where
    nothing can yet be published.
    """
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
