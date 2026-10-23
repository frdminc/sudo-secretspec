# Deterministic release cutting for the sudo-secretspec fork.
#
# `just release 0.19.1-sudo.N` is the whole ceremony: disk guard, version
# stamp, stamp commit, push, then packaging/release.py (which runs the gating
# tests and publishes tag + GitHub Release + formula + tap + brew reinstall).
# The full version string is deliberate — same principle as release.py: one
# spelling to get right, no way to cut serial N while believing you asked for
# something else.
#
# RESUME RULES after a failure:
# - Failed before or during tests: fix, then re-run `just release <version>`.
#   Stamping and the stamp commit are idempotent no-ops the second time.
# - Failed AFTER "git push origin <tag>" but with NO GitHub Release yet (the
#   tag push and `gh release create` are two steps, and release.py says so:
#   "release.py did not see `gh release create` succeed"): do NOT re-run —
#   preflight will refuse the published serial. Check `gh release view <tag>
#   --repo frdminc/sudo-secretspec` first, because a signal or a dropped
#   connection can leave the Release in place while release.py never saw it
#   return. If it is missing, `gh release create <tag> --repo
#   frdminc/sudo-secretspec --title <title> --notes-file <notes>`, then follow
#   the rule below. The rule below does NOT cover this state on its own: its
#   `brew reinstall` would pour the previous release's bottle.
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
# `just release 0.19.1-sudo.N --build-from-source` to compile on this Mac
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
