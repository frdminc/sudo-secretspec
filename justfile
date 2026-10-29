# Deterministic release cutting for the sudo-secretspec fork.
#
# `just release 0.21.1-sudo.N` is the whole ceremony: disk guard, version
# stamp, stamp commit, push, then packaging/release.py (which runs the gating
# tests and publishes tag + GitHub Release + formula + tap + brew reinstall).
# The full version string is deliberate — same principle as release.py: one
# spelling to get right, no way to cut serial N while believing you asked for
# something else.
#
# RESUME RULES after a failure:
# - Failed before or during tests: fix, then re-run `just release <version>`.
#   Stamping and the stamp commit are idempotent no-ops the second time.
# - Failed AFTER "git push origin <tag>" and release.py says "The tag is pushed,
#   but release.py did not see `gh release create` succeed" (the 'no formula
#   commit yet' rule): do NOT re-run -- preflight will refuse the published
#   serial. The tag, and possibly the Release, are public; the formula commit,
#   tap sync and bottle merge have NOT happened, and release.py has no resume
#   mode for them. The rule below does NOT cover this state: its `brew
#   reinstall` would pour the PREVIOUS release's bottle. In order:
#   1. `gh release view <tag> --repo frdminc/sudo-secretspec`. A Release can
#      exist although release.py never saw it return. "release not found"
#      names no repository, so check the --repo before believing it.
#   2. If it is missing, write the notes file (the one passed to `just
#      release`, else `python3 -B -c 'import sys; sys.path.insert(0,
#      "packaging"); import release; sys.stdout.write(release.default_notes())'
#      > <notes>`, from the repo root), then read the title and create the
#      Release in ONE chain, so an empty title stops it: `title=$(git tag -l
#      --format='%(contents:subject)' <tag>) && test -n "$title" && gh release
#      create <tag> --verify-tag --repo frdminc/sudo-secretspec --title
#      "$title" --notes-file <notes>`. An empty title means the tag is not in
#      THIS clone (run `git fetch --tags origin` and repeat), and `gh release
#      create` would accept `--title ""`. --verify-tag makes a mistyped <tag>
#      abort instead of creating a NEW public tag at the branch head.
#   3. `publish-bottle` polls only about ten minutes for the Release, then
#      fails; its upload has no --clobber. If it failed for want of the
#      Release, find the tag's run with `gh run list --repo
#      frdminc/sudo-secretspec --branch <tag>` (always --repo), and once the
#      bottle job is green re-run it: `gh run rerun <run-id> --failed --repo
#      frdminc/sudo-secretspec`. Never upload assets by hand: step 4's
#      verify_release_assets hashes the job's files by name. If a partial
#      upload is on the Release, remove those assets (`gh release delete-asset
#      <tag> <name> --repo frdminc/sudo-secretspec`) before the re-run.
#   4. This is the step release.py cannot do for you, and a hand version is
#      only as safe as your copy of what it does. In `_release_body` order,
#      read and reproduce `fetch_bottle` (gh attestation verify with the
#      workflow identity, source ref and tag commit on the bottle JSON, every
#      tarball and source.sha256; field validation; the tarball-hash check),
#      `update_formula_commit` (which starts with `require_archive_matches_tag`),
#      `sync_tap`, and `merge_bottle` (which starts with
#      `verify_release_assets`). ONE download of the tag's archive must feed
#      the tree check, the source.sha256 comparison and the formula sha256
#      (`archive_facts` memoises it for exactly that reason); a fresh download
#      per step lets the three disagree unseen. The source.sha256 comparison is
#      the only check tying the shipped binary to the verified tree, so it is
#      not optional. The next slice is a `--resume-after-release` mode so
#      this is code, not prose.
#   5. Then follow the rule below, and finish with `verify_readback`: it
#      checks the NEW engine version is installed, so in `_release_body` it
#      comes after the install, never before.
# - Failed AFTER "git push origin <tag>" (tag/Release/formula/tap already
#   public): do NOT re-run — release.py preflight will refuse the published
#   serial. Finish by hand: `brew update --force && brew reinstall
#   frdminc/sudo-secretspec/sudo-secretspec && brew test ...`. This is exactly
#   how the v0.19.1-sudo.15 release died (disk hit 100% mid-brew).

# Recipe arguments also arrive as $1, $2, ...; `release` hands its flags to
# release.py as "${@:2}" rather than splicing `{{flags}}` into the script text.
set positional-arguments

# The .15 release ran out of disk AFTER publishing; refuse to start low.
min_free_gi := "25"

default:
    @just --list

# Refuse to begin a release without headroom for the cold cargo build.
preflight-disk:
    #!/usr/bin/env bash
    set -euo pipefail
    free_gi=$(df -g /System/Volumes/Data | awk 'NR==2 {print $4}')
    if [ "${free_gi}" -lt {{min_free_gi}} ]; then
        echo "refusing: ${free_gi}Gi free on /System/Volumes/Data < {{min_free_gi}}Gi minimum" >&2
        echo "the v0.19.1-sudo.15 release died at 100% disk after publishing; free space first" >&2
        exit 1
    fi
    echo "disk ok: ${free_gi}Gi free"

# Rehearse: stamp the workspace, then dry-run the release (prints every
# mutating command, publishes nothing). Leaves the stamp in the working tree
# for the real run; tests are skipped here because the live run gates on them.
release-dry version: preflight-disk
    #!/usr/bin/env bash
    set -euo pipefail
    # "$1", never `{{version}}`: just splices a recipe parameter into the script
    # text before bash parses it, so a spliced value is shell source, not a word
    # (adversary I1, 2026-10-20). The version is validated downstream by
    # VERSION_RE, which is too late to stop a splice.
    packaging/stamp.py --version "$1"
    packaging/release.py --version "$1" --dry-run --allow-dirty --skip-tests

# Cut the release end to end. Extra flags reach release.py, e.g.
# `just release 0.21.1-sudo.N --build-from-source` to compile on this Mac
# instead of pouring the CI-built bottle.
release version *flags: preflight-disk
    #!/usr/bin/env bash
    set -euo pipefail
    packaging/stamp.py --version "$1"
    git add Cargo.toml Cargo.lock secretspec-derive/Cargo.toml sudo-secretspec-cli/Cargo.toml
    if ! git diff --cached --quiet; then
        git commit -m "chore: stamp workspace $1"
    fi
    git push origin sudo-main
    packaging/release.py --version "$1" "${@:2}"
    echo
    echo "Published. The INSTALLED boundary is still the previous version until:"
    echo "  sudo \"$(brew --prefix sudo-secretspec)/libexec/sudo-secretspec\" install"
    echo "Upgrading adopts the vault the installed config records, so no flag is"
    echo "needed. --adopt-existing is still required for a vault found only by"
    echo "path scan, which includes the retired wrapper's store."
