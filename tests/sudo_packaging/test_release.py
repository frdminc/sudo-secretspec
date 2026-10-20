"""Focused tests for the downstream release helper; never touch the network."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import re
import subprocess
import sys
import tarfile
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


def _tag_archive(path, commit):
    """A gzipped tar carrying `commit` the way GitHub's generated archives do."""
    headers = {"comment": commit} if commit else {}
    with tarfile.open(
        path, "w:gz", format=tarfile.PAX_FORMAT, pax_headers=headers
    ) as tf:
        member = tarfile.TarInfo("sudo-secretspec/README.md")
        member.size = 0
        tf.addfile(member, io.BytesIO(b""))
    return path


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


def test_the_archive_must_be_the_tag_commits_tree(monkeypatch, release, cut, tmp_path):
    """N6c: nothing local used to check the archive bytes against the tag.

    GitHub serves an archive by tag *name*; the check existed only in CI, and
    only transitively, through a source.sha256 that carried no attestation.
    """
    wanted, other = "a" * 40, "b" * 40
    monkeypatch.setattr(release, "output", lambda *_a, **_k: wanted)

    for body, expected in (
        (_tag_archive(tmp_path / "ok.tar.gz", wanted), None),
        (_tag_archive(tmp_path / "no.tar.gz", other), "is not the tag's tree"),
        (_tag_archive(tmp_path / "bare.tar.gz", None), "carries no commit id"),
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
    for name, commit in (("bare", None), ("other", "b" * 40)):
        release._ARCHIVE_FACTS.clear()
        body = _tag_archive(tmp_path / f"{name}.tar.gz", commit).read_bytes()
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
    body = _tag_archive(tmp_path / "full.tar.gz", commit).read_bytes()
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

    digest, found = release.archive_facts(cut, dry_run=False)
    assert responses == []  # the short body was retried, not accepted
    assert found == commit
    assert digest == hashlib.sha256(body).hexdigest()


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
    body = _tag_archive(tmp_path / "once.tar.gz", commit).read_bytes()
    downloads = []

    def opener(*_a, **_k):
        downloads.append(1)
        return _ByteResponse(body)

    monkeypatch.setattr(release._OPENER, "open", opener)
    monkeypatch.setattr(release, "output", lambda *_a, **_k: commit)

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
    with pytest.raises(release.ReleaseError, match="different source archive"):
        release.fetch_bottle(cut, tmp_path, dry_run=False)


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
