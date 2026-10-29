# Fork-only notes for AI agents (`frdminc/sudo-secretspec`)

This file is **downstream-only**. Do not port it upstream to `cachix/secretspec`.

## Layout that matters

| Path | Purpose |
|---|---|
| `sudo-secretspec-cli/` | Rust companion binary/library (the product) |
| `sudo-secretspec/` | Guidance, config example, companion README |
| `packaging/` | Release script + Homebrew formula |
| `skills/sudo-secretspec/` | Distributable AI skill |

All downstream work commits directly to `sudo-main`; there are no feature
branches and no PRs. "main" and "master" both mean `sudo-main`. `main` itself
is only the upstream mirror — do not develop on it, and do not merge it into
`sudo-main` unasked, since it carries post-0.19.1 upstream work held for a
future release. The downstream version scheme lives in `CLAUDE.md`, which is
loaded into agent context automatically.

## High-value lessons (save time)

1. **Do not write complex shell for the boundary.** Runtime policy is Rust.
2. **Avoid `rusqlite` `bundled` on this Mac.** It can hang in `libsqlite3-sys`
   build scripts. Prefer system SQLite:
   ```bash
   export PKG_CONFIG_PATH="/opt/homebrew/opt/sqlite/lib/pkgconfig:$PKG_CONFIG_PATH"
   export LIBRARY_PATH="/opt/homebrew/opt/sqlite/lib:$LIBRARY_PATH"
   export CPATH="/opt/homebrew/opt/sqlite/include:$CPATH"
   ```
   and `rusqlite = { version = "0.31" }` (no `bundled`).
3. **Cargo registry extract cache can be incomplete** after interrupted builds.
   Incomplete dirs under `~/.cargo/registry/src/index.crates.io-*` missing
   `Cargo.toml` can be deleted when the matching `.crate` archive exists.
4. **Toolchain is pinned** by `rust-toolchain.toml` (currently `1.92.0`). Ensure
   `PATH` includes `~/.cargo/bin`.
5. **macOS path aliases:** `/var` → `/private/var`, `/etc` → `/private/etc`.
   Validate resolved protected chains; accept public spellings.
6. **Dotenv provider must be pinned** to the vault file:
   `dotenv:///var/db/.../.env` — never bare `dotenv` (cwd-relative).
7. **Audit must fail closed.** Do not ignore `append_event` errors.
8. **Public client elevates with:**
   - lifecycle: `sudo -n /usr/local/libexec/sudo-secretspec __broker ...`
   - install/rollback: interactive `sudo` (Touch ID)
   - doctor: prefer `sudo -n` libexec elevation

   Always invoke `/usr/bin/sudo` by absolute path. A bare `sudo` resolves
   through the caller's `PATH`, and a planted one satisfies every broker call
   with forged values and no audit event — the whole boundary, defeated
   without root.

   The NOPASSWD grant is per-subcommand (`__broker *`, `doctor`), never
   `sudo-secretspec *`. The client and the broker are the same binary, so a
   blanket grant would expose `install` and `rollback` with no Touch ID.
   `main` enforces the same restriction internally, because sudoers argument
   matching is easy to get subtly wrong.
9. **Adopt-existing must not chown/chmod the vault.** Only verify metadata.
10. **Install UX goal:** short forms (`install`, `install --adopt-existing`) with
    auto-detection/prompts; long flags are overrides only.
11. **Adoption defaults on provenance, not on convenience.** A vault named by
    the installed root-owned config is adopted with no flag — the host vouching
    for the store it already serves from, so a reinstall over it is an upgrade.
    A vault found only by path scan still requires `--adopt-existing`, because
    one of the scan candidates is the retired wrapper's store. The rule is
    `install::adopts_without_flag`; keep it there rather than re-deciding it
    inline in `main.rs`.

## Useful commands

The companion targets macOS and Linux (ordinary Linux through the imperative
installer, NixOS through the module; the running system decides, see
`platform::host`). It is excluded from the workspace-wide test
invocations in `.github/workflows/test.yml` and `devenv.nix` (they also run on
Linux and Windows without its system tools: `dscl`, `useradd`, `/private/var`).
Its suite runs in `.github/workflows/sudo-release.yml` on macOS and in the
`debian` job of the `ci/base` overlay (`linux-ci.yml`, with
`scripts/debian-smoke.sh`). Test it locally with
`-p`, never by relying on `cargo test --all`.

```bash
# focused tests
cargo test -p sudo-secretspec-cli

# release binary
cargo build -p sudo-secretspec-cli --release
cp target/release/sudo-secretspec ~/bin/sudo-secretspec

# live smoke after install
sudo -n /usr/local/libexec/sudo-secretspec doctor
sudo-secretspec check --reason "smoke"
```

## Delivery conventions

- Commit directly to `sudo-main` on `frdminc/sudo-secretspec`. Do not create
  branches or open PRs for downstream work.
- Never open upstream issues/PRs without explicit permission.
- Keep `CHANGELOG.md` Unreleased entries user-facing.
- After privileged install, verify paths under `/usr/local` and vault ownership
  without reading secret values.

## Known residual findings on this host

After adopt-existing install of the stayturgid vault, doctor may report:

- `LEGACY_VAULT_CLUTTER` / previously `UNEXPECTED_RUNTIME_ENTRY` for `.local` /
  `.ansible` under the vault (non-secret tool state; safe to clean later).
  This is **advisory**: it prints under a passing `doctor: OK` and does not
  fail the check. Advisory codes must never clear `Report.ok` — agents treat a
  drift failure as a hard stop, so a permanent advisory would wedge every
  automated caller indefinitely.
- `CLIENT_DUPLICATE` if a byte-identical `sudo-secretspec` sits in a second
  root-owned search directory. Also **advisory**. The failing sibling is
  `CLIENT_SHADOWED`, which means a *different* binary would run instead of the
  installed client — that one is a hard stop, not residual noise. This host is
  expected to have exactly one copy, at `/usr/local/bin/sudo-secretspec`; the
  keg's `libexec` bootstrap is not on any search path and is not a shadow.
- `UPGRADE_AVAILABLE` when the keg's `libexec` bootstrap reports a different
  version than the installed boundary — a build staged by `brew` but never
  installed. Also **advisory**: an upgrade the operator has not run yet is not
  a reason to refuse credential operations. The version it compares against is
  the `version` key the installer stamps into
  `/usr/local/etc/sudo-secretspec.toml`; a boundary installed before that key
  existed reports nothing rather than guessing. Note the staged version is
  probed by the *unprivileged* client and passed in — the root broker must not
  execute anything out of an operator-writable Homebrew prefix.
- audit ledger ownership should be `_secretspec:staff` (fixed in current tree by
  chown-after-open when broker is root). The pre-open metadata check
  deliberately does not assert ownership; the post-open check does, so a
  ledger left root-owned by an older install is repaired rather than fatal.

## Reinstall required after the boundary hardening

The sudoers policy generated by `install` changed from a blanket
`sudo-secretspec *` grant to per-subcommand rules. Hosts installed before that
change still carry the old wildcard on disk — the narrowing only takes effect
after another `sudo-secretspec install` (since `0.19.1-sudo.17` an upgrade
adopts the installed config's vault with no flag). Until then the
in-binary guard in `main` is the only thing refusing `install`/`rollback`
through the libexec path.

## Related human/AI guidance

- `sudo-secretspec/AI-GUIDANCE.md`
- `skills/sudo-secretspec/SKILL.md`
- `packaging/README.md`
- Local reusable Rust agent notes: `~/src/agent-guidance/rust/AGENTS.md`

`SKILL.md` deliberately restates policy from `AI-GUIDANCE.md` rather than
linking to it: the skill is installed on machines that may not have this repo,
so it must stand alone. When the policy contract changes, update both.
