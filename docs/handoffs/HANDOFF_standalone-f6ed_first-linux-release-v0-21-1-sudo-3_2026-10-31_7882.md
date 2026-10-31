---
schema_version: 1
handoff_id: 7882
parent_handoff_ids: [f6ed]
lineage: deterministic
chain: [standalone-f6ed]
repo: sudo-secretspec
workspace: sudo-secretspec
branch: sudo-main
head_sha: 34f635d94b8a5f6112a658e0cacdcad4d6457659
created_at: 2026-10-31T16:50:00-04:00
writer: omp
---
# Handoff — first real release v0.21.1-sudo.3 (Linux artifact + bottle), installed on this Mac

## The Goal
Continue from handoff f6ed (upstream 0.21.1 merge, Debian installer, release tooling). Goal of this stretch: finish the open follow-ups, then cut the first real `0.21.1-sudo.N` release and prove the Linux release path on a real tag. Done. What remains is verification on a real Debian host and a few deferred items.

## Where We Are
- `sudo-main` = `origin/sudo-main` = `34f635d9`, clean. Tap `~/src/homebrew-sudo-secretspec` clean and equal to origin.
- **Released `v0.21.1-sudo.3`** (Latest): Linux x86_64 tarball + `.sha256` (both attested, verified), macOS bottle in the tap, formula commit `eb26d730`. `brew reinstall --force-bottle` poured it and `brew test` passed.
- **djbclark ran the macOS install** (`sudo .../libexec/sudo-secretspec install`). `/usr/local/bin/sudo-secretspec --version` = `0.21.1-sudo.3`; `sudo-secretspec doctor` = `doctor: OK` (read this session).
- `v0.21.1-sudo.1` and `.2` are orphan tags from failed attempts; both Releases are now marked pre-release with a "superseded by .3" note. Tags left in place on purpose (release.py refuses a published serial; deleting would free the serial).
- Upstream: merged `cachix/secretspec` main again (our #519/#520 fixes landed upstream as PRs #522/#521, both merged by domenkozar; both issues closed). Took upstream's versions of `add --optional/--required` and the SecretNotFound/`SecretNotDefined` change; dropped our duplicate code and tests.
- Code changes this stretch (all on `sudo-main`): `release.py` `watch_jobs` polls per-job conclusions (30 s, `CI_JOB_POLL_SECONDS`) and names the failed job before unfinished ones; pytest that every non-sudo workflow with a `tags:` trigger carries `'!v*-sudo.*'` (skips when the CI overlay stripped the workflows); sqlite provider `set` now uses `BEGIN IMMEDIATE` (a deferred transaction failed intermittently with "database is locked" under concurrent writers; CHANGELOG entry added); `sudo-release.yml` linux-artifact: `git config --global --add safe.directory "$GITHUB_WORKSPACE"`, and the tarball and `.sha256` are attested in separate steps; `AGENTS.md` CI section updated.
- Tests run: targeted `tests/sudo_packaging/test_release.py -k ...` (64 + 2 passed); full CI on the release commits all green (linux, macos incl. the whole packaging suite, debian incl. smoke, nix). The full local `test_release.py` run never finished (bg slot wait), so full-suite proof is CI's.

## What We Tried
- **sudo.1 failed:** the `linux-artifact` job died on git "dubious ownership" in the `debian:12` container (`git rev-parse HEAD`). Fixed with `safe.directory`. The first `watch_jobs` reported `'packaging' concluded ''` instead of the red job, because it checked jobs in list order; fixed by ordering failures first.
- **sudo.2 failed:** one `attest-build-provenance` step with two globs in `subject-path` attested only the `.tar.gz`; `release.py` rejected the unattested `.sha256` (HTTP 404 on its digest). Fixed by one step per file. Proven with `gh workflow run sudo-release.yml --ref sudo-main -f tag=v0.21.1-sudo.2` (dispatch uploads an artifact only), then `gh attestation verify` on both files (rc=0), before cutting `.3`.
- The first live attempt at sudo.1 was also gated out by CI: the new tag-exclusion test failed in the `ci/run/*` overlay because `scripts/github-ci-run` deletes other workflows when PyYAML is missing (it is, under `bg`). Fixed by skipping the test when the workflows are gone.
- sudo.2 gate failed once on the flaky sqlite concurrent-write test (real bug, fixed, see above) and once on a transient nix API 403 (re-run).
- `just release` refused at 20 GiB free (guard is 25). Freed ~7.7 GB: `npm cache clean --force`, `~/.cache/pre-commit`, `~/.cargo/target-shared` (4.3 GB). 32 GiB free after the release.

## Key Decisions
Ran the release despite the earlier "hold" because djbclark said nobody but them uses it and a real publish is the easiest test of the update path. Left orphan tags public but marked pre-release. Took upstream's code for features upstream merged rather than keeping a fork copy. Fixed the failed-release problems by cutting new serials rather than deleting tags.

## Decisions
- [decision] Mark v0.21.1-sudo.1 and .2 as pre-release with a superseded note; rejected: deleting the tags and Releases; because release.py would then accept re-cutting the serial and published tags should stay immutable.
- [decision] Attest the Linux tarball and checksum in separate steps; rejected: one step with two globs; because it attested only the tarball.
- [decision] sqlite `set` uses an IMMEDIATE transaction; rejected: raising busy_timeout; because a deferred read-to-write upgrade fails at once and ignores busy_timeout.
- [decision] Skip the sudo-tag exclusion test when the CI overlay stripped workflows; rejected: installing PyYAML under bg; because the overlay script's behaviour is a separate bug on ci/base.
- [ruling] "We can do 2; no one but us uses it now, and this is the easiest way for us to test the new install in a way that will be almost the same as for when we do updates. So no big deal if we publish something that doesn't work." (djbclark, 2026-10-31)
- [ruling] "I don't think secretspec-sqlite is ready for upstream yet, for the moment the only things we should consider upstream issues or PRs or DPRs for are sudo-secretspec fixes/features that are applicable to upstream." (djbclark, 2026-10-30)

## Relations
- continues [[HANDOFF_standalone-f6ed_linux-installer-upstream-merge_2026-10-31_f6ed]]
- decided_in [[HANDOFF_standalone-f6ed_first-linux-release-v0-21-1-sudo-3_2026-10-31_7882]]

## Evidence & Data
- Release: https://github.com/frdminc/sudo-secretspec/releases/tag/v0.21.1-sudo.3 (assets: Linux tarball + .sha256, bottle tar.gz + json). Tag run 41235171144 was sudo.2; sudo.3's tag run green end to end. Dispatch proof run 41235617596.
- Failed tag runs: sudo.1 run 41230246435 (dubious ownership); sudo.2 run 41235171144 (unattested checksum).
- Disk: 20 GiB free before cache clear, 27 after, 32 at release end.
- Always pass `--repo frdminc/sudo-secretspec` to `gh`; bare `gh` answers about upstream.
- Local branch `pr487-rebase` (599c3529) unpushed on purpose. Relay expectation `ss-harness-bugs-1` is `acked` (not overdue); the djbclark-ade lead's commit shas for the two harness items were never seen by me.

## Operator Feedback
Asked why sudo-secretspec "uses 5GB": the repo is 103 MB; the 5 GB was the shared `~/.cargo/target-shared` plus npm/pre-commit caches I cleared to pass the release disk guard. Wanted the release cut for real as the test of the update path. Chose the orphan-release pre-release marking.

## Where We're Going
1. Run the installer on a real Debian host (nothing has proved it outside the CI container): download `sudo-secretspec-0.21.1-sudo.3-x86_64-unknown-linux-gnu.tar.gz` from the release, verify with `gh attestation verify FILE --repo frdminc/sudo-secretspec`, then follow `sudo-secretspec/AI-GUIDANCE.md` (install, doctor, a set/get/run, rollback, uninstall). Report findings.
2. Check the macOS rollback ownership live (unit-tested only): on this Mac `sudo-secretspec rollback` then `doctor`.
3. Fix `scripts/github-ci-run` on `origin/ci/base` so an overlay keeps non-firing workflows when PyYAML is missing (currently deletes every non-CI workflow; a release-gate overlay differs from a hand-run one). It lives in the `ci/base` worktree `~/src/sudo-secretspec-ci-base`; a change needs a push to `origin/ci/base` and a local fast-forward (stale local `ci/base` makes the overlay use an old workflow).
4. Watch upstream PR #487 (sqlite, our draft, on hold with a holding comment): `gh pr view 487 --repo cachix/secretspec --comments`. Do not push `pr487-rebase` without the operator's yes.
5. When the djbclark-ade lead reports commit shas for the two harness items, check them and close the relay expectation: `python3 -I ~/src/djbclark-ade/skills/session-finder/relay.py --pending`.
6. Next upstream merge: `git fetch upstream && git merge-tree --write-tree --name-only HEAD upstream/main`; take upstream's versions of anything we re-expressed.

## Detached jobs
none (no bigteam job records are owned by this session; no `run_in_background` task is expected to survive).

## Quick Start
```bash
cd ~/src/sudo-secretspec && git status -sb && git log --oneline -5
gh release list --repo frdminc/sudo-secretspec --limit 4
sudo-secretspec doctor
uvx ruff check packaging tests/sudo_packaging && uvx ruff format --check packaging tests/sudo_packaging
scripts/github-ci-run --no-wait origin/sudo-main   # CI is the only place Rust builds here
```
