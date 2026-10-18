# GitHub Linux CI (ci/base)

Linux cargo CI (excluding macOS-only `sudo-secretspec-cli`) runs on free
GitHub-hosted runners via `ci/base` + `ci/run/**`.

1. Workflow: `.github/workflows/linux-ci.yml` on `ci/base`
2. Wrapper: `scripts/github-ci-run [REF]`
3. GitHub remote for this fork is `frdminc/sudo-secretspec` (also reachable as
   `djbclark/sudo-secretspec`). Push only `ci/**` branches.
4. Forgejo private duplicate remains until confirmed.
