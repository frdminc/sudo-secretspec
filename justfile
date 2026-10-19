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
# - Failed AFTER "git push origin <tag>" (tag/Release/formula/tap already
#   public): do NOT re-run — release.py preflight will refuse the published
#   serial. Finish by hand: `brew update --force && brew reinstall
#   frdminc/sudo-secretspec/sudo-secretspec && brew test ...`. This is exactly
#   how the v0.19.1-sudo.15 release died (disk hit 100% mid-brew).

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
    packaging/stamp.py --version {{version}}
    packaging/release.py --version {{version}} --dry-run --allow-dirty --skip-tests

# Cut the release end to end. Extra flags reach release.py, e.g.
# `just release 0.19.1-sudo.N --build-from-source` to compile on this Mac
# instead of pouring the CI-built bottle.
release version *flags: preflight-disk
    #!/usr/bin/env bash
    set -euo pipefail
    packaging/stamp.py --version {{version}}
    git add Cargo.toml Cargo.lock secretspec-derive/Cargo.toml sudo-secretspec-cli/Cargo.toml
    if ! git diff --cached --quiet; then
        git commit -m "chore: stamp workspace {{version}}"
    fi
    git push origin sudo-main
    packaging/release.py --version {{version}} {{flags}}
    echo
    echo "Published. The INSTALLED boundary is still the previous version until:"
    echo "  sudo \"$(brew --prefix sudo-secretspec)/libexec/sudo-secretspec\" install"
    echo "Upgrading adopts the vault the installed config records, so no flag is"
    echo "needed. --adopt-existing is still required for a vault found only by"
    echo "path scan, which includes the retired wrapper's store."
