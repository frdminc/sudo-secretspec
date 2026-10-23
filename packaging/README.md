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
`require_archive_matches_tag` checks those same bytes against the tag two
ways. First it reads the commit id GitHub embeds in the tar's global pax
header -- the same field CI's `git get-tar-commit-id` reads. That one is an
**accident** check, not an integrity one: the record lives inside the archive,
so whoever produces the bytes chooses it. It is kept because it gives a precise
diagnosis for the common cases (a stale tag, a regenerated archive of a
different tree, a fetch for the wrong ref).

Second, and this is the binding: the archive is extracted and its **tree** is
compared against `git archive` of the tag, built with the same
`<repo>-<version>/` prefix. Every path, executable bit, symlink target and
content digest on both sides, and nothing git does not track -- no mtimes, no
uid/gid, no directories. A forged archive can carry the genuine commit id and
cannot survive this: verified by building one that adds a hostile `build.rs`
to the real v0.19.1-sudo.28 archive, which passes the pax check and fails the
tree check naming `build.rs`. The two sides were also proved to agree on the
real thing -- GitHub's v0.19.1-sudo.28 archive and `git archive` of its tag
fingerprint to 601 identical entries, zero differences (adversary 1b,
2026-10-20).

Extraction uses `filter="data"`, explicitly, because this is the one place
release.py writes untrusted bytes to disk and the `extractall` default is one
that changes under you: 3.13 still writes an escaping member outside the
destination with only a DeprecationWarning, 3.14 refuses. (The release driver
runs under `#!/usr/bin/env python3`, whatever that resolves to; 3.13 is what
`sudo-release.yml`'s packaging job pins for the *tests*, which is a different
thing.) Note what the filter does and does not do: it **refuses** absolute
paths, `..`, special files and escaping symlinks and hardlinks, but it
silently **normalises** setuid, setgid, sticky and group/other write bits, and
directory modes altogether -- so the fingerprint compares post-filter modes.
That is harmless only because git cannot express those bits either. Both
checks read the memoised download, so the digest pinned into the formula is
the digest of the tree that was checked.

**What the tree comparison does not cover.** It checks *the operator's* copy
of the published archive against *the operator's* `git archive` of the tag. It
says nothing about which source bytes the runner compiled: the bottle job
fetches the archive itself, by URL, with its own curl
(`sudo-release.yml:177`), and `brew install --build-bottle` compiles exactly
those bytes. The bottle's attestation proves "`sudo-release.yml` at this tag
produced these bytes" and carries no statement about the source behind them.

So the artifact must hold exactly one bottle JSON, and `source.sha256` -- also
attested, and verified before it is read -- is compared against the digest of
the archive release.py downloaded. That comparison is **load-bearing**: it is
the only thing in the release tying the shipped, attested binary to the tree
that was checked against the tag. Serve codeload's two fetches different bytes
(cache poisoning, a hostile resolver on the runner's egress, or GitHub simply
regenerating the archive in between, which this repo already treats as
possible) and every other check still passes. Its bytes are written from a
step output recorded before `brew install --build-bottle` runs, so the on-disk
file a `build.rs` can reach is not what gets copied; the residual weakness is
that an attestation proves only "this workflow produced these bytes", never
"these bytes predate the third-party code", and the bottle job's filesystem
stays writable between the build step and the attest step (**F3.1**, accepted
as a residual by design). Only on `--build-from-source`, where there is no
bottle and this check never runs, is the tree comparison the whole binding.

F3.1's escalation -- compute the digest in a job that runs no cargo and no
brew, and verify *that job's* attestation -- is deliberately not implemented,
because a verifier cannot express it. The only identity `gh attestation
verify` can pin is the certificate identity, and that names the workflow
**file**, not the job. In the real v0.19.1-sudo.28 predicate, `builder.id`,
the workflow `externalParameters` and the certificate's SAN all read
`sudo-release.yml` and nothing finer, while `invocationId` names the run and
attempt, which every job of the run shares, so a second job would mint
attestations indistinguishable from the bottle job's. A **separate workflow
file** would have a distinct identity, so the escalation remains buildable as
a file and never as a job (2026-10-23).

Before the tap is pushed, release.py
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
