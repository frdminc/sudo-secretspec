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
   (and, on a tag push, against the commit embedded in the source archive it
   downloads, `git get-tar-commit-id`), stamps
   the release formula into a throwaway tap, runs `brew install --build-bottle`
   and `brew bottle --json --root-url=<the tag's release download URL>`, and
   signs a build-provenance attestation for the tarball and the JSON
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
match), watches it, downloads the artifact and checks it: every JSON and every
tarball must pass `gh attestation verify` (`--repo`, `--cert-identity`
`https://github.com/frdminc/sudo-secretspec/.github/workflows/sudo-release.yml@refs/tags/<tag>`,
`--source-ref refs/tags/<tag>`, `--source-digest` the tag's commit,
`--deny-self-hosted-runners`) before the JSON is read; every tarball must hash
to the sha256 in its JSON; the JSON must hold one entry named
`frdminc/sudo-secretspec/sudo-secretspec` at the release version with the tap's
formula path, a known tag, cellar and rebuild, a 64-digit sha256 and a bare file
name; and the CI source sha256 must equal the archive `release.py` hashes
for the formula. The archive is downloaded and hashed **once** per run and the
digest memoised: hashing it again for the formula pinned a number from a later,
separate download that nothing had compared with CI, and GitHub's generated
archives are not contractually byte-stable. Before the formula is rewritten,
`require_archive_matches_tag` binds those bytes to the local tag commit by
reading the commit id GitHub embeds in the tar's global pax header -- the same
field CI's `git get-tar-commit-id` reads -- so the pinned digest is provably
the tag's tree without trusting CI. The artifact must hold exactly one bottle
JSON, and `source.sha256` is attested like the tarball and the JSON and
verified before it is read: it is derived from a step output recorded before
`brew install --build-bottle` runs, because the on-disk file is writable by
every `build.rs` and proc-macro in `Cargo.lock`. Before the tap is pushed it
downloads each asset from the GitHub Release into its own directory, requires
exactly that one file name to land (`--pattern` is a glob) and compares its
sha256 too. Then it runs
`brew bottle --merge --write` into the tap formula, refuses to commit unless
the `bottle do` block it wrote equals the one the validated fields make,
pushes the tap and reinstalls
with `--force-bottle`. A missing, red or mismatched bottle is an error, never a
quiet local compile: `--build-from-source`
(`just release VERSION --build-from-source`) is the explicit fallback and runs
`brew reinstall --build-from-source` through `bg`. Homebrew pours a bottle built
on an older macOS of the same architecture, so the runner's bottle installs on
newer macOS releases.

Before the reinstall it checks for a linked HEAD keg (`linked_head_keg`) and
refuses with its own hint if it finds one. `brew reinstall` reuses the spec of
the keg that is linked, so a linked HEAD keg makes `--force-bottle` report
"has no bottle" however good the published bottle is, and the
build-from-source fallback is the wrong advice for it: a HEAD build is exactly
what is already installed. The remedy the hint names is
`brew unlink ... && brew install --force-bottle ...`, revertible with
`brew link --overwrite <head keg>`. This is what kept 0.19.1-sudo.23 through
.28 from pouring on djbclark's Mac (found 2026-10-20, with HEAD-7c1f700
linked); unreadable `brew info` output counts as "not a HEAD keg", so the
check can only ever improve a message, never fail a release.

## Homebrew safety boundary

The formula runs `cargo install` twice — once for the upstream `secretspec`
engine, once for the `sudo-secretspec-cli` companion — and copies the AI
guidance and skill documents into `share/sudo-secretspec`.

Installation has no privileged side effects: it never invokes `sudo`, edits
sudoers, creates users, or mutates `/var/db`. The caveat tells the operator to
explicitly run `sudo-secretspec install` after reviewing the installed files.

Canonical formula: `packaging/homebrew/sudo-secretspec.rb`.
Tap clone default: `~/src/homebrew-sudo-secretspec`.
