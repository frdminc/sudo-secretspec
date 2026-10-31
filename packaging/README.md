# sudo-secretspec downstream packaging

Downstream releases are built from upstream SecretSpec `0.21.1` and stamp the
whole workspace — including the `secretspec` crate — with a downstream version
of the form `0.21.1-sudo.N`. `release.py` verifies both halves: that the
upstream tag it descends from carries `version = "0.21.1"`, and that this tree's
root `Cargo.toml` carries the downstream version being cut.

- Tag: `v0.21.1-sudo.N`
- Release title: `SecretSpec 0.21.1 — sudo-secretspec downstream N`
- Fork: `frdminc/sudo-secretspec` (parent `cachix/secretspec`)

The upstream base is one constant, `UPSTREAM_VERSION` in `release.py`. The
release workflow reads the base from that same line when it validates a tag, and
its tag trigger (`v*-sudo.*`) names no base at all, so nothing else carries the
literal. Which downstream serial to cut is a `--version` argument; rebasing onto
a newer upstream tag is a separate, larger decision and the script refuses to
do it implicitly.

### Version history and the 0.21.1 base

Releases through `v0.19.1-djbclark.3` used the `-djbclark.N` spelling;
`v0.19.1-sudo.4` through `v0.19.1-sudo.30` used `0.19.1-sudo.N`. Those tags
remain published and are history: `release.py` accepts only the current base
for a new release, but still recognises the older spellings when it restamps a
formula that predates the change (`ANY_VERSION_RE`).

The base moved to `v0.21.1` by merging upstream `cachix/secretspec` `main`
(tag `v0.21.1` plus 47 commits, `a3e6cbeb`) into the fork, restamping the
workspace to `0.21.1-sudo.1` and changing `UPSTREAM_VERSION`; the serial
restarted at 1 because it counts releases per base. `release.py` checks the
`v0.21.1` tag is an ancestor of HEAD, which the merge satisfies. The next re-base goes the same way,
in one reviewed change set on a branch that is merged to `sudo-main` before any
release: fetch the new upstream tag, merge it (never rewrite published
history), change `UPSTREAM_VERSION`, run `packaging/stamp.py --version
<new base>-sudo.1`, update the test fixtures that name the base, then rehearse
with `python3 packaging/release.py --version <new base>-sudo.1 --dry-run`.

## Release

The maintainer entrypoint is `packaging/release.py`. It validates a clean
`sudo-main` tree, HTTPS remotes, the upstream `v0.21.1` ancestry/version, the
GitHub fork parent, that the workspace is stamped at the version being cut, and
that the tag is not already published — all before any write.

Bump `version` in the root `Cargo.toml` (and the two inter-crate `version =`
constraints beside it) first; preflight refuses to release a workspace stamped
at anything else.

```bash
# Safe preview; performs no writes.
python3 packaging/release.py --version 0.21.1-sudo.1 --dry-run

# Live release after packaging and companion changes are committed on sudo-main.
python3 packaging/release.py --version 0.21.1-sudo.1

# Alternate local tap clone.
python3 packaging/release.py --version 0.21.1-sudo.1 \
  --tap-path ~/src/homebrew-sudo-secretspec
```

The live flow gates on GitHub CI for HEAD (`scripts/github-ci-run`: the Linux
engine job, a Debian companion/installer job, the NixOS module job, and
a macOS job for the companion crate, this helper and the formula; `--local-tests` runs those suites here instead), creates and pushes an
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
   `workflow_dispatch`. It checks the tag against `v<UPSTREAM_VERSION>-sudo.N` (N a positive integer without leading zeros; the base is read from `release.py`)
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
(`sudo-release.yml:177`), hashes that download, and restamps the throwaway
tap's formula with the digest -- so `brew install --build-bottle` compiles
bytes *pinned to that digest* (brew re-fetches the URL into its own cache and
verifies it against the formula, which means two independent fetches must
agree). The bottle's attestation proves "`sudo-release.yml` at this tag
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

## Linux x86_64 installer media (0.21.1-sudo.1+)

Release tags also ship
`sudo-secretspec-<version>-x86_64-unknown-linux-gnu.tar.gz` and its `.sha256`
file. This is the companion, not the full upstream `secretspec` CLI. The tarball
contains one directory with `libexec/sudo-secretspec`,
`share/sudo-secretspec/AI-GUIDANCE.md`,
`share/sudo-secretspec/sudo-secretspec-retired.toml`,
`share/sudo-secretspec/skills/sudo-secretspec/SKILL.md`, `README.md`, `LICENSE`,
and `INSTALL.txt`. Extracting the archive only writes the media; privilege
changes require the explicit installer invocation below.

The `linux-artifact` job builds the locked companion crate for
`x86_64-unknown-linux-gnu` inside `debian:12` on a GitHub-hosted Ubuntu x86_64
runner. Debian 12 provides [glibc 2.36](https://packages.debian.org/bookworm/libc6);
this is the minimum supported glibc baseline, suitable for Debian 12/13 and
[Ubuntu 24.04 (glibc 2.39)](https://discourse.ubuntu.com/t/noble-numbat-release-notes/39890)
and newer. Ubuntu 22.04 has an older glibc and is unsupported.
The container stays on Debian 12 deliberately to avoid raising the binary's
runtime baseline when the Ubuntu runner image changes.

SQLite is dynamically linked to `libsqlite3.so.0`. The companion's explicit
`rusqlite` dependency does not inherit the workspace's `bundled` setting;
Cargo.lock resolves it through `libsqlite3-sys` with pkg-config. Using the
system library keeps the existing build configuration and distribution SQLite
security updates. The build installs `libsqlite3-dev` and asserts the ELF
binary actually names `libsqlite3.so.0`. Users need `libsqlite3-0` at runtime.
No Nix installation or passwordless sudo is required.

```bash
# As an operator with ordinary interactive sudo access:
sudo apt-get install sudo libsqlite3-0
# Download both release assets into the current directory, then verify:
sha256sum -c sudo-secretspec-<version>-x86_64-unknown-linux-gnu.tar.gz.sha256
gh attestation verify sudo-secretspec-<version>-x86_64-unknown-linux-gnu.tar.gz \
  --repo frdminc/sudo-secretspec
# Extract anywhere, inspect the files, and enter the extracted directory:
tar -xzf sudo-secretspec-<version>-x86_64-unknown-linux-gnu.tar.gz
cd sudo-secretspec-<version>-x86_64-unknown-linux-gnu
sudo ./libexec/sudo-secretspec install --declarations /path/secretspec.toml
sudo-secretspec doctor
```

On Linux the installer puts the public client at `/usr/bin/sudo-secretspec` and a
separate broker at `/usr/libexec/sudo-secretspec` (the macOS client stays at
`/usr/local/bin/sudo-secretspec`). Keep the extracted media for
upgrades; run installation from the new media, rather than the installed
client. NixOS continues to use `services.sudo-secretspec` declaratively and
refuses these imperative lifecycle commands.

`packaging/build-linux-artifact.sh` creates sorted GNU tar media with root
numeric ownership, fixed modes and the tag commit's timestamp; `gzip -n`
removes compressor timestamps. These controls make packaging the same payload
deterministic; they do not claim Rust builds are reproducible. The tarball and
checksum receive signed build provenance with the same pinned actions and
permission split as the bottle. `publish-linux` depends on `packaging` and
`linux-artifact`, holds `contents: write`, runs no Cargo code, and attaches
both assets only on a release tag push. Existing asset names fail rather than
being overwritten. Dispatches validate the same tag grammar as the bottle,
check out that tag's sources, and only upload workflow artifacts. Neither
platform's publish job depends on the other platform's build.

Known and accepted (adversary review 2, 2026-10-30): like the bottle job,
`linux-artifact` holds `id-token: write` and `attestations: write` while it
compiles the crate graph, so a hostile build script could request an
attestation for the artifact it builds. Neither permission writes to the
repository, and `release.py` verifies provenance against the exact tag and
commit, so a forged artifact must still come from this workflow at that ref.
Splitting attestation into a no-cargo job is possible but is not done.

After the push run reaches a terminal state, `release.py` judges only the jobs
the deliverable needs, not the whole run: `packaging`, `linux-artifact` and
`publish-linux` for Linux; `packaging`, `bottle` and `publish-bottle` for the
bottle. A red job of the other platform never blocks verifying this one, a job
the run does not report is an error, and the error names the job and the run
URL. This removes the red-versus-green coupling only: `release.py` still waits
for the whole run to reach a terminal state, so a macOS job stuck queued (a `runs-on`
label that matches no runner) delays Linux verification until the watch times out.
The CI gate still uses `gh run watch --exit-status`. `release.py` then
downloads the Linux workflow
artifact, verifies both attestations against this workflow at the exact tag
and commit, requires a single checksum record naming the expected bare
filename, compares its hash, and rejects unexpected members, traversal,
links, special files, duplicate paths, modes and owners before extraction
with the explicit tar data filter. It then requires the published Release to
list both names exactly once, downloads both assets, and compares their bytes
to CI's artifact. Linux verification also runs with `--skip-homebrew` and
`--build-from-source`; those options only change Homebrew handling.

The `debian` job in the `ci/base` overlay tests and lints the companion,
builds its release binary, and runs `scripts/debian-smoke.sh` as root in a
throwaway Debian 12 container. The smoke proves install metadata, sudoers
validation and limited broker grants, password-required lifecycle commands,
doctor, snapshot rollback, retained-state uninstall, explicit purge, and
runtime NixOS refusal followed by successful Debian reinstall. It never runs
against the maintainer's host.
