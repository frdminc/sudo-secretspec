# sudo-secretspec downstream packaging

Downstream releases are built from upstream SecretSpec `0.19.1` and stamp the
whole workspace — including the `secretspec` crate — with a downstream version
of the form `0.19.1-sudo.N`. `release.py` verifies both halves: that the
upstream tag it descends from carries `version = "0.19.1"`, and that this tree's
root `Cargo.toml` carries the downstream version being cut.

- Tag: `v0.19.1-sudo.N`
- Release title: `SecretSpec 0.19.1 — sudo-secretspec downstream N`
- Fork: `frdminc/sudo-secretspec` (parent `cachix/secretspec`)

The upstream base is a constant in `release.py`. Which downstream serial to cut
is a `--version` argument; rebasing onto a newer upstream tag is a separate,
larger decision and the script refuses to do it implicitly.

## Release

The maintainer entrypoint is `packaging/release.py`. It validates a clean
`sudo-main` tree, HTTPS remotes, the upstream `v0.19.1` ancestry/version, the
GitHub fork parent, that the workspace is stamped at the version being cut, and
that the tag is not already published — all before any write.

Bump `version` in the root `Cargo.toml` (and the two inter-crate `version =`
constraints beside it) first; preflight refuses to release a workspace stamped
at anything else.

```bash
# Safe preview; performs no writes.
python3 packaging/release.py --version 0.19.1-sudo.10 --dry-run

# Live release after packaging and companion changes are committed on sudo-main.
python3 packaging/release.py --version 0.19.1-sudo.10

# Alternate local tap clone.
python3 packaging/release.py --version 0.19.1-sudo.10 \
  --tap-path ~/src/homebrew-sudo-secretspec
```

The live flow gates on GitHub CI for HEAD (`scripts/github-ci-run`: the Linux
engine job plus a macOS job for the companion crate, this helper and the
formula; `--local-tests` runs those suites here instead), creates and pushes an
annotated tag, creates the titled GitHub Release with `gh`, downloads the tag
tarball over HTTPS, rewrites the formula SHA-256, commits/pushes that formula,
syncs the configured tap clone, force-refreshes Homebrew and the tap checkout,
reinstalls and tests the formula, then reads back repository parent, tag,
release title/state, and installed engine version. Interrupt cleanup removes
only a locally-created unpushed tag and an uncommitted formula rewrite; it
never deletes a pushed tag.

## macOS bottle

`brew reinstall` pours a bottle built on GitHub's macOS runner rather than
compiling the crate graph on the maintainer's Mac. Two jobs in
`.github/workflows/sudo-release.yml` do it, split so that the token that can
write to the repository never shares a runner with the crate graph's build
scripts:

1. `bottle` (read-only token, no `GH_TOKEN`) runs for a release tag push or a
   `workflow_dispatch`. It checks the tag against `^v0\.19\.1-sudo\.[1-9][0-9]*$`
   (and, on a tag push, against the commit the run was triggered for), stamps
   the release formula into a throwaway tap, runs `brew install --build-bottle`
   and `brew bottle --json --root-url=<the tag's release download URL>`, and
   signs a build-provenance attestation for the tarball
   (`actions/attest-build-provenance`; the job's only extra permissions are
   `id-token: write` and `attestations: write`, neither of which writes to the
   repository), and uploads the tarball, its JSON and the source archive's
   sha256 as the `sudo-secretspec-bottle` artifact. It publishes nothing.
2. `publish-bottle` (`contents: write`, no cargo, no brew) runs only for the
   push of a release tag, after `packaging` and `bottle` are green. It downloads
   that artifact and attaches the tarball and JSON to the tag's GitHub Release.
   An asset that already exists is a hard failure (no `--clobber`).

`workflow_dispatch` (optional `tag` input), even on a tag ref, only uploads the
artifact; the release is touched only by the push of a release tag.

After the tag push `release.py` finds the push run by head SHA (exactly one must
match), watches it, downloads the artifact and checks it: every tarball must hash
to the sha256 in its JSON and pass `gh attestation verify` (`--repo`,
`--signer-workflow` `sudo-release.yml`, `--source-ref refs/tags/<tag>`,
`--source-digest` the tag's commit, `--deny-self-hosted-runners`), the JSON must hold one entry named
`frdminc/sudo-secretspec/sudo-secretspec` at the release version with a bare
file name, and the CI source sha256 must equal the archive `release.py` hashes
for the formula. Before the tap is pushed it downloads each asset from the
GitHub Release and compares its sha256 too. Then it runs
`brew bottle --merge --write` into the tap formula, pushes the tap and reinstalls
with `--force-bottle`. A missing, red or mismatched bottle is an error, never a
quiet local compile: `--build-from-source`
(`just release VERSION --build-from-source`) is the explicit fallback and runs
`brew reinstall --build-from-source` through `bg`. Homebrew pours a bottle built
on an older macOS of the same architecture, so the runner's bottle installs on
newer macOS releases.

## Homebrew safety boundary

The formula runs `cargo install` twice — once for the upstream `secretspec`
engine, once for the `sudo-secretspec-cli` companion — and copies the AI
guidance and skill documents into `share/sudo-secretspec`.

Installation has no privileged side effects: it never invokes `sudo`, edits
sudoers, creates users, or mutates `/var/db`. The caveat tells the operator to
explicitly run `sudo-secretspec install` after reviewing the installed files.

Canonical formula: `packaging/homebrew/sudo-secretspec.rb`.
Tap clone default: `~/src/homebrew-sudo-secretspec`.
