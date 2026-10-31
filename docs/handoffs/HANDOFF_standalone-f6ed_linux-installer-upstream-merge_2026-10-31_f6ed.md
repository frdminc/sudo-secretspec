---
schema_version: 1
handoff_id: f6ed
parent_handoff_ids: []
lineage: none
chain: [standalone-f6ed]
repo: sudo-secretspec
workspace: sudo-secretspec
branch: sudo-main
head_sha: 05fad72797115f30999060c382399f40c8877e33
created_at: 2026-10-31T10:55:00-04:00
writer: omp
---
# Handoff — upstream 0.21.1 merge, Linux installer, release tooling for 0.21.1-sudo.N

## The Goal
Operator task (`/tmp/s-s.txt`, copy at `~/.local/state/bigteam/linux-installer/task.txt`): an imperative installer for non-NixOS Linux (Debian) beside the unchanged NixOS module; runtime NixOS detection; a Linux x86_64 release artifact. Mid-session the operator added: first merge current upstream `cachix/secretspec`, then file upstream issues/PRs for fork fixes that apply upstream. All of that is done and on `sudo-main`. What remains is the first real release and a few follow-ups.

## Where We Are
- `sudo-main` = `origin/sudo-main` = `05fad727`, clean. Workspace stamped `0.21.1-sudo.1` (scheme moved from `0.19.1-sudo.N`). CI on that content: `linux`, `macos`, `nix`, `debian` all green (run 41166556081, overlay 559b184b).
- Upstream merged: `upstream/main` a3e6cbeb (0.21.1 + 47 commits). Took upstream's versions of `check`-to-stdout, `SpecBuilder` manifest edits, ETXTBSY test fixes, schema API. Kept and re-expressed on upstream APIs: `add --optional/--required`, `SecretNotFound` display fix, sqlite provider with opt-in history (base = our PR 487 code, plus `BEGIN IMMEDIATE` fix and a legacy TEXT value-column write path). Companion crate adapted in `sudo-secretspec-cli/src/broker.rs`.
- Linux installer: `Host {MacOs, NixOs, Linux}` in `platform.rs`, decided at run time (`/run/current-system` or `/etc/NIXOS`, dangling counts). Debian layout: client `/usr/bin/sudo-secretspec`, broker `/usr/libexec/sudo-secretspec`, config `/etc/sudo-secretspec.toml`, sudoers `/etc/sudoers.d/sudo-secretspec` (staged, `visudo -c -f` validated, 0440), vault `/var/lib/sudo-secretspec` 0700, user and group `sudo-secretspec`. NOPASSWD only for broker path + the 11 broker verbs; `timestamp_timeout=0` on the client. `install`/`uninstall`/`rollback`/`doctor` work on Debian and refuse on NixOS; a binary with a baked `SUDO_SECRETSPEC_BROKER_PATH` refuses everywhere. NixOS policy text unchanged (`nixos_sudoers_text`, pinned by a test).
- Proof: `scripts/debian-smoke.sh` runs the whole lifecycle as root in `debian:12` in the `debian` CI job (44 PASS markers read in the round-7 log: real broker add/set/get/check/run as an unprivileged operator, doctor, rollback then doctor, uninstall retention, adopt/purge refusal, both NixOS markers).
- Release tooling: `sudo-release.yml` builds the Linux artifact (`linux-artifact`, read-only token, `debian:12`) and publishes with `publish-linux` (write token, no cargo); tag regexes derive the base from `UPSTREAM_VERSION` in `packaging/release.py`; `release.py` verifies the Linux and bottle jobs per platform (`watch_jobs`, `LINUX_JOBS`, `BOTTLE_JOBS`). `release.py --version 0.21.1-sudo.1 --dry-run` passes.
- Upstream actions taken: issues [#519](https://github.com/cachix/secretspec/issues/519) (SecretNotFound double-wrapped) and [#520](https://github.com/cachix/secretspec/issues/520) (`add --optional/--required`); a holding comment on [#487](https://github.com/cachix/secretspec/pull/487) (sqlite, our draft) saying we may not finish it.
- Harness: two bugs handed to the djbclark-ade lead (relay expectation `ss-harness-bugs-1`, brief `~/.local/state/bigteam/linux-installer/harness-bugs-for-ade-lead.md`). It reports H-1 (`GIT_CONFIG_KEY_n` dropped) was Codex's own `shell_environment_policy` name filter, already fixed in djbclark-ade by 85634ba0; H-2 was the untracked `.git/hooks/pre-commit` of THIS repo, which I patched (clippy skipped when `ACP_RUN_AGENT` is set or `load-watch ci check` says `ci`; `SKIP_CLIPPY=0` forces it).

## What We Tried
- Slices S1-S4 (codex/omp) wrote the first installer pass with no local build (this Mac sends builds to CI via `bg`); the first review (`review-1.md`) returned BLOCK: smoke script contradicted the installer on ownership, its `! cmd` negatives never failed under `set -e`, adopted purge was refused, `/usr/local` is `root:staff` 2775 on stock Debian so the installer's root-only ancestor check refused every install, rollback restored root-owned files so `doctor` failed. Fixed by F1 over 7 CI rounds (the six-round cap was extended to ten for the smoke).
- Client first placed at `/usr/local/bin` (operator said fine); moved to `/usr/bin` because of the `/usr/local` finding above.
- M1 merge needed 4 CI rounds: `yyjson.h` missing in the `linux` job (fixed in `ci/base`), engine API test fixtures (`set(.., Some)` to `set_text`), `Config` shape in the SecretNotFound regression test. Local `ci/base` was stale and `scripts/github-ci-run` prefers a local `ci/base` over `origin/ci/base`; this bit twice (M1 and my last CI round: re-run after fast-forwarding).
- I ran `ruff format` but not `ruff check` on a new test: macOS CI failed PLW1510. Use `uvx ruff check packaging tests/sudo_packaging` before every push.
- A throwaway-tag `workflow_dispatch` to prove the release build jobs is NOT possible: dispatch needs an existing tag, and a pushed tag fires the real publish jobs.
- Review 2 (BLOCK on bcce5512) caught that `build-linux-artifact.sh` still pinned `0.19.1-sudo.N` (every 0.21.1 tag would have failed with no Linux asset), that upstream `jvm-package.yml` and `elixir-package.yml` would fire on `v*-sudo.N` tags (jvm publishes to Maven), and the rollback chown identity trust. All fixed. Review 3 (delta): APPROVE; its MED (a bad snapshot config fell back to the live service-writable config) fixed in `rollback.rs` `restore_identity` with two tests.

## Key Decisions
Chosen: runtime host detection over `target_os`; client at `/usr/bin`; merge upstream before finishing the installer; version scheme `0.21.1-sudo.1`; take upstream's reimplementations, keep fork features; formula left at `0.19.1-sudo.30` until the first release restamps it (`ANY_VERSION_RE` accepts any base). Rejected: loosening the Codex env excludes; chmod'ing `/usr/local`; re-adding hidden engine accessors (companion adapted to `Spec`/`SpecBuilder` instead). L5 (build jobs hold `id-token`/`attestations: write` while compiling) accepted as inherited and documented in `packaging/README.md`.

## Decisions
- [decision] Debian client path is /usr/bin/sudo-secretspec; rejected: /usr/local/bin; because stock Debian ships /usr/local as root:staff 2775 and the installer must not chmod system directories.
- [decision] NixOS detected at run time (/run/current-system or /etc/NIXOS); rejected: target_os = "linux"; because a Debian-built binary can run on NixOS and the NixOS build sandbox has no /run/current-system.
- [decision] Merge upstream cachix/secretspec main before finishing the installer; rejected: installer first; because the engine API the companion calls changed and verification should happen once on the final base.
- [decision] Downstream version scheme restarts at 0.21.1-sudo.1; rejected: deciding at merge time; because release.py, stamp.py and workflow regexes all pin the base.
- [decision] Rollback chown identity comes from the verified snapshot config and a bad snapshot config is fatal; rejected: falling back to the live config; because the live config is service-user-writable.
- [decision] Accept review finding L5 (attestation permissions held while compiling); rejected: a separate no-cargo attestation job; because it matches the shipped bottle job and release.py verifies provenance against the exact tag and commit.
- [ruling] "I don't think secretspec-sqlite is ready for upstream yet, for the moment the only things we should consider upstream issues or PRs or DPRs for are sudo-secretspec fixes/features that are applicable to upstream." (djbclark, 2026-10-30)
- [ruling] "Merge first, then finish installer" and scheme "0.21.1-sudo.1" (djbclark, 2026-10-30)
- [ruling] "File both" for upstream issues 519 and 520 (djbclark, 2026-10-30)

## Relations
- decided_in [[HANDOFF_standalone-f6ed_linux-installer-upstream-merge_2026-10-31_f6ed]]

## Evidence & Data
- Work dir with briefs, reports, both reviews, CI logs: `~/.local/state/bigteam/linux-installer/` (`review-1.md`, `review-2-status.md`, `f1-installer-finish-report.md`, `m1-merge-report.md`, `f1-ci-round-7-smoke.log`, `u1-pr487-report.md`, `u2-*-issue-draft.md`). Third review verdict (APPROVE at 4d6c8b78) was only in the task result; its MED/LOW are in this section and fixed or documented.
- CI: run 40982346719 (bb75595d, all green), 41166556081 (05fad727 content, all green). Round 7 Debian: https://github.com/frdminc/sudo-secretspec/actions/runs/40974543129 (282 tests, clippy `-D warnings`, smoke).
- Always pass `--repo frdminc/sudo-secretspec` to `gh`; bare `gh` answers about upstream.
- Local branch `pr487-rebase` (599c3529, 3 commits on upstream a3e6cbeb, never pushed) is kept on purpose for the on-hold sqlite PR.
- Remote branches of this session were deleted; 21 older `ci/run/*` branches belong to earlier sessions.

## Operator Feedback
- Wanted this pushed to upstream where it applies, and the sqlite PR held with an honest "may not finish" note (posted).
- Wanted drafts shown as wrapped markdown and copied to the clipboard before anything is posted.

## Where We're Going
1. Decide whether to cut `v0.21.1-sudo.1` (nothing is tagged). Preconditions: `git -C ~/src/sudo-secretspec status -sb` clean and equal to origin; `git rev-parse refs/heads/ci/base origin/ci/base` equal (stale local `ci/base` makes the overlay use an old workflow); `gh repo set-default frdminc/sudo-secretspec`. Then `~/ops/site-private/bin/bg python3 packaging/release.py --version 0.21.1-sudo.1` (live). The first tag is the first proof of `linux-artifact`, `publish-linux`, `fetch_linux` and the tag regexes; `release.py` refuses to redo a published tag, so read the dry-run output first and watch the run (`gh run watch <id> --repo frdminc/sudo-secretspec --exit-status`).
2. When the djbclark-ade lead reports commit shas for the two harness items (relay expectation `ss-harness-bugs-1`), check them and close the expectation: `python3 -I ~/src/djbclark-ade/skills/session-finder/relay.py --pending`.
3. Watch upstream #519, #520 and #487 for maintainer replies (`gh issue view 519 --repo cachix/secretspec --comments`). Offer small PRs only after an ack (#519 fix shape in `u2-secretnotfound-issue-draft.md`; #520 patch is our commits 1139f1af, 13dbd543 re-expressed in `spec_edit.rs`).
4. Optional hardening: poll per-job status in `watch_jobs` so a macOS job stuck queued cannot delay Linux verification; a pytest asserting every non-`sudo-release.yml` workflow with a `tags:` trigger carries `'!v*-sudo.*'`.
5. Not proven and worth a real run: macOS rollback ownership live (unit-tested only), and a first install on a real Debian host by the operator.

## Detached jobs
none (all bigteam job records under `~/.local/state/bigteam/linux-installer/jobs/` are closed; no `run_in_background` task is expected to survive this session).

## Quick Start
```bash
cd ~/src/sudo-secretspec && git status -sb && git log --oneline -5
~/ops/site-private/bin/bg python3 packaging/release.py --version 0.21.1-sudo.1 --dry-run
gh run list --repo frdminc/sudo-secretspec --limit 5
uvx ruff check packaging tests/sudo_packaging && uvx ruff format --check packaging tests/sudo_packaging
scripts/github-ci-run --no-wait origin/sudo-main   # CI is the only place Rust builds here
```
