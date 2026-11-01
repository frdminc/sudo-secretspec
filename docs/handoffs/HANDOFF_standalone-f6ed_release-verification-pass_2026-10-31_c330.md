---
schema_version: 1
handoff_id: c330
parent_handoff_ids: [7882]
lineage: deterministic
chain: [standalone-f6ed]
repo: sudo-secretspec
workspace: sudo-secretspec
branch: sudo-main
head_sha: 8ece97b98292509e3a162f0bd4bd5dacff23b718
created_at: 2026-10-31T20:50:00-04:00
writer: omp
---
# Handoff — Release verification pass after v0.21.1-sudo.3

## The Goal
Work down the open items from handoff 7882: prove v0.21.1-sudo.3 on real machines (macOS rollback, Debian), fix the `ci/base` overlay, close the harness-bug relay, and settle the sqlite PR #487 follow-up.

## Where We Are
No source change in this repo this stretch (`sudo-main` clean, equal to `origin/sudo-main`, HEAD `8ece97b9`). Done:
- **macOS rollback, live.** `sudo-secretspec rollback /usr/local/libexec/sudo-secretspec-rollback-1793482277` restored 0.19.1-sudo.30 (doctor OK, advisory UPGRADE_AVAILABLE only); `libexec/sudo-secretspec install` from the Homebrew path returned the Mac to 0.21.1-sudo.3 (new snapshot `...-1793484123`, one pruned). `check --reason ...` afterwards: 104 found, 0 missing. Rollback takes a **required snapshot path**; bare `rollback` exits 2.
- **Debian 13 real host (pastebin, x86_64).** Tarball downloaded by `gh release download`, sha256 OK and `gh attestation verify` exit 0. Operator ran the install (`--declarations` with a one-secret smoke file) on pastebin: `doctor: OK`, `/usr/bin/sudo-secretspec` and `/usr/libexec/sudo-secretspec` present, sudoers parsed, service user created. `set`, `check`, `run` worked without a password. Operator then ran `uninstall`: all 8 artifacts removed, vault preserved. Not exercised: rollback and upgrade-over-existing on Linux (first install has no snapshot).
- **`ci/base` overlay fix.** `d79aacb3` on `origin/ci/base`: the overlay's Python borrows PyYAML through `uv run --with pyyaml` when the interpreter lacks it. Proven by a real overlay run: `scripts/github-ci-run --no-wait origin/sudo-main` pushed `ci/run/origin-sudo-main-8ece97b9` with 24 workflow files kept (non-CI workflows, e.g. `sudo-release.yml`, survived) and only `Linux CI` fired (run 41258970954; its four jobs were still in progress when this was written, so the **conclusion is not yet known**).
- **Harness relay `ss-harness-bugs-2` closed.** Lead 1e61c979 answered: H-1 (dropped `GIT_CONFIG_KEY_n`) was Codex's `shell_environment_policy` name filter, fixed in djbclark-ade by `85634ba0` (PR 156); H-2 (pre-commit ran clippy) is this repo's own untracked `.git/hooks/pre-commit`, already patched by an earlier session (skips clippy when `ACP_RUN_AGENT` is set or `load-watch ci check` says ci; `SKIP_CLIPPY=0` forces it). No new commits needed.
- **sqlite PR #487.** Pushed `pr487-rebase` (`599c3529`, rebased on upstream main plus the schema-setup serialization fix) to `djbclark/secretspec-sqlite` as branch `sqlite-provider-rebased`. The PR's own head branch `sqlite-provider` (`50d3e2b2`) is untouched because the rebase diverges and updating it needs a force-push. Posted and then edited a comment on the PR (https://github.com/cachix/secretspec/pull/487#issuecomment-6551397861) linking both branches and offering a prepared handoff version to anyone who wants to pick it up.

## What We Tried
- Bare `sudo-secretspec rollback` and `check`: both need arguments (`<SNAPSHOT>`, `--reason`). Not a defect, but the 7882 Quick Start did not say so.
- Running the overlay through `bg`: refused (exit 3, "full suites run on CI"); run `scripts/github-ci-run` directly.
- Looking for "the person interested in sqlite via an issue": none exists in `cachix/secretspec`. The only expressed interest is domenkozar's comment on PR 487 itself (2026-10-28).

## Key Decisions
Pushed the rebased branch under a new name rather than force-pushing the PR head, so the maintainer's PR does not change underneath him. Left the pastebin vault (with a smoke secret) in place because `uninstall` preserves it by design and nobody asked to purge it.

## Decisions
- [decision] Push the rebased sqlite work as `sqlite-provider-rebased`; rejected: force-push over `sqlite-provider`; because it rewrites an open upstream PR's history without the operator saying so.
- [decision] Uninstall pastebin without `--purge-vault` or `--remove-service-user`; rejected: purging; because AI-GUIDANCE says not to pass either.
- [ruling] "Yes, post that." (djbclark, 2026-10-31)
- [ruling] "You can go ahead and push that branch and then update the issue" (djbclark, 2026-10-31)

## Relations
- continues [[HANDOFF_standalone-f6ed_first-linux-release-v0-21-1-sudo-3_2026-10-31_7882]]
- decided_in [[HANDOFF_standalone-f6ed_release-verification-pass_2026-10-31_c330]]

## Evidence & Data
- Tarball: `sudo-secretspec-0.21.1-sudo.3-x86_64-unknown-linux-gnu.tar.gz`, 6155460 bytes, attestation verified for `frdminc/sudo-secretspec`.
- Linux paths: client `/usr/bin/sudo-secretspec`, broker `/usr/libexec/sudo-secretspec`, config `/etc/sudo-secretspec.toml`, sudoers `/etc/sudoers.d/sudo-secretspec`, vault `/var/lib/sudo-secretspec`.
- Overlay commit `0ae6c0e9` for `8ece97b9`; CI run 41258970954.

## Operator Feedback
Said pastebin is Debian 13 and that agents may ssh to machines to check things themselves. Wants the final test, at about 99% confidence, to be installing the latest sudo-secretspec on all hosts. Asked whether a podman microvm with a Debian image would be a good choice: answer is it would mostly repeat the `debian:12` CI job and cannot test real sudo, tty or systemd; it is useful only for covering Debian 13 in CI.

## Where We're Going
1. Read the result of CI run 41258970954 (`gh run view 41258970954 --repo frdminc/sudo-secretspec --json status,conclusion,jobs`); if a job is red, fix it before the next tag.
2. Leftover on pastebin: the vault under `/var/lib/sudo-secretspec` with a `SMOKE_TEST` secret and the `sudo-secretspec` service user. Remove with `sudo rm -rf /var/lib/sudo-secretspec` only if the operator wants it gone.
3. Next release: install it over an existing install on a Debian host to exercise rollback and upgrade on Linux, then the final latest-version install on all hosts (operator's word).
4. PR #487 stays on hold; only act if upstream replies. To make the PR show the rebased work, force-push `sqlite-provider` (needs the operator's yes).
5. Next upstream merge: `git fetch upstream && git merge-tree --write-tree --name-only HEAD upstream/main`.

## Detached jobs
none.

## Quick Start
```bash
cd ~/src/sudo-secretspec && git status -sb
gh run view 41258970954 --repo frdminc/sudo-secretspec --json status,conclusion
sudo-secretspec doctor
sudo-secretspec rollback /usr/local/libexec/sudo-secretspec-rollback-<timestamp>   # snapshot path required
sudo-secretspec check --reason "why"                                                # --reason required
```
