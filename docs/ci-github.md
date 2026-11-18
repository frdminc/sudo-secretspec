# GitHub Linux CI (ci/base)

CI runs on free GitHub-hosted runners via `ci/base` + `ci/run/**`: a Linux job
(the workspace minus macOS-only `sudo-secretspec-cli`) and a macOS job (that
crate, `tests/sudo_packaging`, the formula). Both are the release gate:
`packaging/release.py` pushes HEAD through the wrapper and watches the run
(2026-10-18); `--local-tests` runs the suites on the Mac instead.

1. Workflow: `.github/workflows/linux-ci.yml` on `ci/base`
2. Wrapper: `scripts/github-ci-run [REF]`
3. GitHub remote for this fork is `frdminc/sudo-secretspec` (also reachable as
   `djbclark/sudo-secretspec`). Push only `ci/**` branches.
4. Forgejo private duplicate remains until confirmed.
