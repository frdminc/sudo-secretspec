# CLAUDE.md

When commiting changes related to Rust, make sure to update /CHANGELOG.md with one entry (can be multi-line). Don't create new release subsections; add the entry under the existing unreleased section. Keep entries user facing: leave out development and testing notes.

The documentation site is published from `main`, which may be ahead of the
latest SecretSpec release. Any unreleased provider, CLI command, configuration
field, or syntax must be labeled with its target version at each point of use.
Do not rely on an `Unreleased` changelog entry or a notice on one concept page:
users often land directly on provider and reference pages.

For an upcoming provider or feature:

- Add what version the provider was added in (to be released version)
- Mark entries in provider lists, tables, sidebars, selector examples, landing
  pages, README files, and generated documentation summaries with the minimum
  version, for example `(0.15+)`.

## Downstream fork notes (`frdminc/sudo-secretspec`)

This repository is a fork. In addition to upstream SecretSpec:

- Companion crate: `sudo-secretspec-cli` (binary `sudo-secretspec`)
- Downstream docs: `sudo-secretspec/README.md`, `README.downstream.md`
- AI automation contract: `sudo-secretspec/AI-GUIDANCE.md`
- Fork-only agent notes/tricks: `FORK-AI.md` (do not upstream)
- All downstream work goes on `sudo-main`. Commit and push directly to it — no
  feature branches, no PRs. If asked to work on "main" or "master", that means
  `sudo-main`.
- `main` exists only as the upstream mirror. Do not develop on it, and do not
  merge it into `sudo-main` without being asked: it carries post-0.19.1
  upstream work intended for a future release.
- Version scheme: `0.19.1-sudo.N`, where `N` is the downstream serial. Releases
  through `v0.19.1-djbclark.3` used the older `-djbclark.N` form; the tags
  remain, but new work uses `-sudo.N`. The `djbclark` in those tag names is the
  old *version* serial, unrelated to the org move below — do not rewrite them.
- The fork moved from the `djbclark` user to the `frdminc` org on 2026-08-15.
  GitHub redirects the old URLs, so stale references keep working and will not
  announce themselves; prefer `frdminc/...` everywhere. Note that `djbclark`
  also appears as the *operator's macOS username* (sudoers rules, audit test
  fixtures, install paths) — those are not org references and must stay.

When changing the companion, update `CHANGELOG.md` Unreleased with a user-facing
entry and keep privileged install explicit (Homebrew must not silently edit
sudoers/users/vaults).

Prefer system SQLite (not `rusqlite` bundled) on macOS; see `FORK-AI.md`.

## Build and Development Commands

```bash
# Enter development environment
devenv shell

# Run tests
cargo test --all

# Run a single test
cargo test test_name

# Run the CLI
cargo run -- <command>
cargo run -- init --from .env
cargo run -- check
cargo run -- set DATABASE_URL
cargo run -- run -- npm start

# Format code / Run linter
pre-commit run -a
```

## Architecture

The project is organized as a Rust workspace with two crates:

1. **secretspec** (src/): Main CLI and library
   - `bin/secretspec.rs`: CLI entry point that calls the main CLI module
   - `cli/mod.rs`: CLI command definitions (init, config, set/get, check, run, import)
   - `lib.rs`: Core library with `Secrets` struct, validation logic, and CRUD operations
   - `config.rs`: Core configuration types (Config, Secret), TOML parsing, and inheritance logic
   - `provider/`: Storage backend implementations with trait-based plugin architecture

2. **secretspec-derive**: Proc macro for type-safe code generation
   - Reads `secretspec.toml` at compile time
   - Generates strongly-typed structs from configuration
   - Supports both union types (safe for any profile) and profile-specific types
   - Validates secret names produce valid Rust identifiers

## Provider System

The provider system uses a trait-based architecture defined in `src/provider/mod.rs`. When implementing new providers:

1. Create module in `src/provider/your_provider.rs`
2. Implement the `Provider` trait with methods: `get()`, `set()`, `check_writable()`, `name()`, `description()`
3. Use the `#[provider]` macro for automatic registration
4. Handle profile-aware storage paths (e.g., `secretspec/{project}/{profile}/{key}`)

Providers support URI-based configuration (e.g., `keyring://`, `onepassword://vault`, `dotenv://.env.production`). The provider system handles URI parsing and provider instantiation directly within each provider module.

### Adding Provider Documentation

When adding a new provider, update **every** location below — provider names appear in several listings that drift out of sync if any are missed:

1. `docs/src/content/docs/providers/<provider>.md` - Create the provider's doc page and add a version compatibility notice if it is unreleased. Use `.mdx` instead when the provider accepts provider credentials, import the shared `ProviderCredentials` component, and add its catalog entry as described below.
2. `docs/astro.config.ts` - Add to sidebar navigation under "Providers" **and** to the providers sentence in the `starlightLlmsTxt` description block
3. `docs/src/content/docs/concepts/providers.mdx` - Add a row to the "Available Providers" table
4. `docs/src/content/docs/reference/providers.md` - Add a provider section **and** a row in the "Security Considerations" table
5. `docs/src/pages/index.astro` - Add to the `providerMetadata` array (top of file) **and** to the `secretspec config init` mini-terminal in the hero
6. `docs/src/content/docs/quick-start.mdx` - Update the `secretspec config init` example output to include the new provider
7. `README.md` (symlink to `secretspec/README.md`) - Add to the "Providers" bullet list **and** to the `secretspec config init` example output

Provider credential names, environment fallbacks, and minimum versions are
maintained in `docs/src/data/provider-credentials.json`. For a provider with a
non-empty Rust `credential_names` registration:

1. Add or update its catalog entry, including every Rust implementation file
   that contains its environment fallback definitions.
2. Add exactly one `## Provider credentials` section to its `.mdx` page and
   render `<ProviderCredentials provider="<provider>" />` there.
3. The same catalog renders the complete
   `docs/src/content/docs/reference/provider-credentials.mdx` reference. The
   provider-specific component links readers back to that page.
4. Run `npm --prefix docs run check:provider-credentials`. The check compares
   the catalog with Rust registrations, validates environment-source backlinks,
   and requires every credential-aware provider page to use the shared table.

If the provider is unreleased, add its target version (for example `(0.15+)`)
in every listing above. See
`docs/src/content/docs/development/adding-providers.md` for the full release
visibility checklist.

## Configuration System

### Profile Resolution
1. CLI flag (`--profile`)
2. Environment variable (`SECRETSPEC_PROFILE`)
3. User config default
4. Falls back to "default" profile

### Provider Resolution
1. **Per-secret providers** (with fallback chain): specified in `secretspec.toml` as `providers: [alias1, alias2, ...]`
   - Aliases resolved against the project `[providers]` table in `secretspec.toml` first, then the `[defaults.providers]` table in `~/.config/secretspec/config.toml`
   - Project-level aliases win on conflict
   - Tries each provider in order until secret is found
2. CLI flag (`--provider`)
3. Environment variable (`SECRETSPEC_PROVIDER`)
4. User config default provider
5. Falls back to keyring provider

### Per-Secret Provider Configuration
Secrets can specify their own providers using the `providers` field to override global defaults:

```toml
[profiles.production]
DATABASE_URL = { description = "Production DB", providers = ["prod_vault", "keyring"] }
API_KEY = { description = "API Key", providers = ["shared"] }
GITHUB_TOKEN = { description = "GitHub token from env", providers = ["env"] }
```

Provider aliases can be checked into the project in `secretspec.toml` so every team member and CI runner sees them automatically:
```toml
[providers]
prod_vault = "onepassword://Production"
shared = "onepassword://Shared"
keyring = "keyring://"
env = "env://"
```

They can also be defined per-user in `~/.config/secretspec/config.toml` (project entries win on conflict):
```toml
[defaults]
provider = "keyring"

[defaults.providers]
prod_vault = "onepassword://Production"
shared = "onepassword://Shared"
keyring = "keyring://"
env = "env://"
```

Manage the user-level map via CLI (project-level aliases are hand-edited in `secretspec.toml`):
```bash
# Add provider alias to user config
secretspec config provider add prod_vault "onepassword://Production"

# List user-level aliases
secretspec config provider list

# Remove a user-level alias
secretspec config provider remove prod_vault
```

### Secret Resolution
1. Check active profile for secret
2. Fall back to "default" profile
3. Apply defaults if configured
4. Validate required secrets are present

### Config Inheritance
Projects can extend other configurations via `extends = ["../shared/common"]`. The system loads configs recursively and merges them with proper precedence.

## Testing

- Unit tests are located alongside the code
- Integration tests in `secretspec-derive/tests/` and `tests/integration/`
- UI tests using `trybuild` for macro error testing
- Run specific test: `cargo test test_name`
- Test CI runs on Ubuntu and macOS using devenv

### Python packaging tests (`tests/sudo_packaging/`)

The downstream release driver (`packaging/release.py`) is Python, not Rust, and
its tests need an interpreter that the bare `python3` on `PATH` may not be:

```bash
~/ops/site-private/bin/bg uv run --python 3.13 --with pytest python \
  -m pytest tests/sudo_packaging/test_release.py -q
```

Name the **file**, not the directory. This repo is CI-first to `bg`, which
refuses a whole-directory run here with **exit 3** ("runs full suites and
builds on CI, never on this Mac") and admits only a targeted run -- a test
file, a `path::test` id, or `-k`. The whole directory is CI's job
(`sudo-release.yml`'s `packaging` job runs `pytest tests/sudo_packaging -q`),
or run it yourself with `scripts/github-ci-run --no-wait origin/sudo-main`.
If a second test file is added, name both or use `-k`.

Since 2026-10-23 a **push to `sudo-main` runs that `packaging` job by itself**:
`sudo-release.yml`'s `push` block now lists the branch as well as the release
tags. Only that job fires -- `bottle` is gated on `ref_type == 'tag' ||
workflow_dispatch` and `publish-bottle` on a tag push -- so a branch push costs
one short macOS job and never builds a bottle. Before that the branch triggered
**no workflow at all** and a commit could sit on it unverified unless someone
ran `scripts/github-ci-run` by hand, which is how `0c19acb` was checked
(overlay branch `ci/run/0c19acb-0c19acb4`, Linux CI, 2026-10-23) -- that is a
*push* of an overlay branch, not a `workflow_dispatch`. Note that block carries no `paths` filter on
purpose: GitHub ANDs `paths` with both `branches` and `tags`, so adding one
would gate the release-tag leg on a changed-file comparison.

No `--` after `bg`: it takes the command directly and refuses a lone `--` with
exit 2, which reads exactly like the tests failing.

**`gh` in this checkout answers about `cachix/secretspec` unless told
otherwise.** The repo has two remotes -- `origin` (the fork) and `upstream`
(`cachix/secretspec`) -- and with no `gh-resolved` set, `gh` picks **upstream**.
Run `gh repo set-default frdminc/sudo-secretspec` once (it writes
`remote.origin.gh-resolved`) and every unflagged command answers about the
fork. `--repo frdminc/sudo-secretspec` is still right to pass explicitly: it
works in any clone, and a plain clone of the fork has only `origin`, so the
trap appears once `upstream` has been added and `set-default` has not been run.

Which way it fails matters, because the dangerous direction is the quiet one:

- **Loud, and names the wrong repository**: `gh run view <id>` and
  `gh run watch <id>` print `HTTP 404` with a URL under
  `repos/cachix/secretspec`, and exit non-zero.
- **Loud, but names nothing**: `gh release view <tag>` exits 1 with
  `release not found` -- **also for a Release that exists on the fork**. It
  reads as a fact about the fork, and it is exactly the check the tag-only
  RESUME RULE in the justfile asks for. `gh api repos/{owner}/{repo}/...`
  prints `gh: Not Found (HTTP 404)` and no repository (a literal
  `repos/frdminc/...` path never reaches upstream at all). Check the `--repo`
  before believing any "not found".
- **Silent**, and this is the trap: queries that succeed with an upstream or
  empty answer. `gh run list --branch sudo-main` exits 0 with nothing (`[]`
  with `--json`), because upstream has no such branch; a bare `gh run list`
  shows upstream's pull-request runs; `gh pr list` shows upstream's PRs;
  `gh repo view` reports `cachix/secretspec`. Each reads as a fact about this
  fork.

A CI conclusion was stated from such a query on 2026-10-23 and had to be
retracted for want of evidence -- re-querying with the flag happened to support
it, but the original query had not.

Pin 3.13 because that is what the workflow's `packaging` job pins **for the
tests** -- a release itself runs under `#!/usr/bin/env python3`, whatever that
resolves to, and the `bottle` job executes `release.py` under its image's bare
`python3` with no `setup-python` at all. Pin it here because the suite is
interpreter-sensitive: `tarfile.extractall(filter=...)`
does not exist before 3.12, and its *default* changed to `data` in 3.14. On this
Mac (2026-10-20) `python3` resolves to 3.15 with no pytest installed, and
`/usr/bin/python3` is Xcode's 3.9.6, which has pytest and reports 9 spurious
failures in the archive-binding tests. Neither is a regression; both look like
one.

### Provider Integration Tests

Provider tests are located in `secretspec/src/provider/tests.rs` and test all provider implementations generically.

```bash
# Run provider tests
cargo test --package secretspec provider::tests

# Test specific providers using SECRETSPEC_TEST_PROVIDERS env var
SECRETSPEC_TEST_PROVIDERS=keyring,dotenv cargo test --package secretspec provider::tests::integration_tests

# Run with output visible
SECRETSPEC_TEST_PROVIDERS=dotenv cargo test --package secretspec provider::tests -- --nocapture
```

The integration tests cover:
- Basic get/set operations
- Multiple secrets handling
- Special characters and Unicode
- Profile-specific storage
- Error handling for edge cases

Note: Some providers (like `env`) are read-only and will skip write tests.

## Documentation Site (`docs/`)

The docs site is an Astro Starlight site deployed to https://secretspec.dev/.

### Structure

- `docs/astro.config.ts` - Sidebar navigation and site config
- `docs/src/pages/index.astro` - Home page (custom landing layout, not in the content collection)
- `docs/src/content/docs/` - All other content pages (markdown/mdx)
  - `quick-start.mdx` - Getting started guide
  - `concepts/` - Declarative config, profiles, providers overview
  - `providers/` - Individual provider docs (one `.md` or `.mdx` per registered provider; see [Adding Provider Documentation](#adding-provider-documentation) when adding a new one)
  - `sdk/` - Rust SDK docs
  - `reference/` - Configuration, CLI, providers reference, adding providers guide

### What to update

- **New doc page**: Create the `.md` file and add it to the sidebar in `docs/astro.config.ts`
- **New CLI command**: Update `docs/src/content/docs/reference/cli.md`
- **New config option**: Update `docs/src/content/docs/reference/configuration.md`
- **New provider**: See [Adding Provider Documentation](#adding-provider-documentation) above
- **New concept**: Create `docs/src/content/docs/concepts/<name>.md` and add to sidebar

For every unreleased item above, put the target-version notice on the specific
page or section where the item is documented. A notice elsewhere is not
sufficient.

## Key Files

- `secretspec.toml`: Project secrets configuration
- `secretspec/src/provider/mod.rs`: Provider trait definition and documentation
- `secretspec/src/cli/mod.rs`: CLI command definitions
- `secretspec/src/bin/secretspec.rs`: CLI entry point
- `secretspec/src/lib.rs`: Core SecretSpec implementation
- `secretspec-derive/src/lib.rs`: Code generation macro implementation
- `secretspec/src/provider/tests.rs`: Generic provider test suite

## CI (2026-10-18)

Linux CI runs on free GitHub runners, not Forgejo: `scripts/github-ci-run --no-wait origin/sudo-main` overlays the
`ci/base` branch (workflow + wrapper + `docs/ci-github.md`) onto the commit and pushes `ci/run/<slug>`.
Needs `origin/ci/base` fetched. `.forgejo/` is the retired Hyades flow; `load-watch ci` knows this repo.
The run has a macOS job too (the companion crate, `tests/sudo_packaging`, the formula), and
`packaging/release.py` gates a release on that run for HEAD (`--local-tests` to run it here).

macOS bottle (2026-10-18): `sudo-release.yml`'s `bottle` job (read-only token) builds the Homebrew bottle on a GitHub
macOS runner on every release tag and uploads an artifact; `publish-bottle` (write token, no cargo) attaches it to the
tag's release, only on a tag push (`gh workflow run sudo-release.yml --ref BRANCH` proves the build without publishing).
`packaging/release.py` waits for that push run, verifies the hashes, merges the `bottle do` block into the tap and pours
it; it never compiles here unless asked: `--build-from-source` (through `bg`, from `$HOME`; bg inside bg cannot wait on
its parent's slot, see `install_from_source`). See `packaging/README.md`.
