# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `set`, `get`, and `delete` on a name that is not declared in the active
  profile no longer print a garbled, doubly-quoted error such as
  `Secret 'Secret 'NAME' is not defined in profile 'default' ...' not found`.
  The message now reads once, still naming the available secrets. The
  non-zero exit status this already returned is unchanged.
- `install --adopt-existing` no longer refuses a vault that has already
  migrated to the sqlite-only secret store. It required a legacy `.env` file
  to exist even though `.env` has been vestigial since values moved into
  `secrets.db`, so adopting (and therefore upgrading) a fully migrated vault
  was refused with "adopted runtime file missing or symlinked: .../.env".
  `.env` is now optional on adoption, matching how the broker itself already
  treats it; a present `.env` still must be a real file, never a symlink.
- Deleting or destroying a secret now erases its plaintext from the database
  file instead of leaving it readable on a freed page. SQLite's
  `secure_delete` is a per-connection setting that is off by default in the
  library this build links, so removing a value only unlinked it from the
  index while its bytes stayed on disk until something happened to overwrite
  them — meaning `destroy`, whose purpose is to make a value unrecoverable,
  did not. Every connection the vault and the broker open now enables it.
  Note this applies to values removed from now on: plaintext already left
  behind by an earlier delete stays until the database is compacted with
  `VACUUM`.
- The installed sudoers policy no longer lets an unattended `restore --all`
  bypass authentication. Its NOPASSWD grant for `source-restore` used a `--*`
  wildcard that also matched `--all`, so a whole-vault restore ran with no
  prompt even though `--force` restores already required one. `--all` now
  goes through the same auth-gated verb `--force` does.
- `source-destroy` can now destroy the captured copies of a name that has no
  live value left. It previously refused, to avoid tombstoning those copies
  against an unrelated history entry — the copies were destroyed either way,
  but the ledger recorded the wrong event as having destroyed them. It now
  appends a history entry for the destroy itself, so the tombstones name the
  event that actually caused them.

### Changed

- A vault written by an older version is now refused with an explanation
  instead of being upgraded in place. In-place upgrades have been removed: the
  only vault that needed one has been rebuilt, and silently rewriting a secret
  store is a large risk to carry for a path nothing takes. A vault written by a
  *newer* version is refused too, rather than being written to by a build that
  does not understand it.
- A destroyed history snapshot can no longer become restorable again. Setting a
  secret back to a value it previously held recreated the exact stored copy
  `destroy` had removed, and because snapshots referred to their bytes by
  content, the destroyed snapshot matched that copy and could be restored.
  Snapshots now refer to a specific stored copy rather than to whatever
  currently matches, so a destroyed one refers to something that no longer
  exists and stays destroyed. The database upgrades itself in place on first
  open; no action is required, and `restore`, `destroy` and history
  verification are otherwise unchanged. An upgrade refuses, and reports which
  snapshot is at fault, if it finds a destroyed snapshot that still holds its
  plaintext or a live one whose bytes are missing, rather than guessing which
  of the two records is right.
- History rows can no longer be deleted, and a destroyed snapshot cannot be
  re-attributed to a different event once recorded.
- The vault stores each distinct captured value once instead of repeating its
  plaintext in every history snapshot. History captures every secret on every
  operation, so the stored copies previously grew with entries x secrets. The
  database upgrades itself in place on first open and is stamped with a schema
  version; no action is required, and `restore`, `destroy` and history
  verification are unaffected. Values are kept separately per secret name, so
  destroying one name never reaches another name's history even when the two
  hold the same value.
- `source-restore`, `source-restore-force` and `source-destroy` no longer create
  an empty `secrets.db` when the vault has none. They refuse as before, but on
  the way out they used to leave a schema-less database behind.
- `doctor` no longer fails because some unrelated file named `sudo-secretspec`
  sits on the caller's `PATH`. Only an executable regular file can shadow the
  installed client, which is what a shell would actually run; a non-executable
  file or a directory of that name is now ignored rather than treated as a hard
  stop.
- A mutating operation that fails on a freshly installed boundary now reports a
  clean rollback rather than an unknown outcome. Its pre-state — no vault
  database yet — is known, and rolling back removes what the failed operation
  created.
- A mutation that fails while taking its rollback copies no longer leaves the
  copy it had already made behind for the operator to find and judge.
- The `sqlite` provider now enforces foreign keys, so a captured value can no
  longer reference a history entry that does not exist.
- `undeclare` now takes the same rollback copy of the runtime manifest that
  every other mutating broker operation takes. It wrote the file directly, so an
  interrupted or failing write could leave the manifest truncated with no copy
  to restore it from — the one operation where that loss was unrecoverable.
- The privileged broker now enables the `sqlite://` provider's history
  retention (`?history=true`). Without it the vault database held no history
  tables at all, so `restore` could never return anything and `destroy` removed
  the live value *before* failing on the missing tables — turning the absent
  feature into a path to irrecoverable loss.
- `destroy` now tombstones the captured history it was meant to. It matched the
  bare secret name against `captured_values.item`, which holds the provider's
  full `{project}/{profile}/{key}` address, so it updated no rows and reported
  success while every captured copy of the value stayed readable.
- `restore` now finds the values it is asked for. `captured_values.item` holds
  the provider's full `{project}/{profile}/{key}` address while `--name` and the
  write-back both speak bare secret names, so `restore --name` matched nothing
  and `restore --all` fed full addresses back in as if they were names. The
  translation now happens in one place.
- The privileged broker links the `sqlite` provider feature. Its provider URI is
  a `sqlite://` one, so a build without the feature registered no backend and
  every operation failed with "Provider backend 'sqlite' not found".
- `restore` no longer replaces a captured value that is not valid UTF-8 with an
  empty string, which would have overwritten a live secret with `""` and
  reported success. It refuses instead. Two query paths that could panic or
  silently yield nothing now report the error.
- The per-invocation vault integrity gate now checks `secrets.db`, the store
  values actually live in, for symlinking, ownership, and mode `0600`. It
  checked only `secretspec.toml` and the now-retired `.env`, so the value store
  was unguarded. `secrets.db` and `.env` are checked when present rather than
  required, so a fresh vault without a database, or one whose retired `.env`
  has been removed, no longer refuses every operation.
- The engine's JSONL audit log is written inside the vault instead of under a
  home directory nothing may write. Every operation previously warned
  "Operation not permitted" and dropped its audit event.

- `template-check` now reports "no tracked declaration source configured" and
  succeeds when the root-owned config omits `declarations`, instead of failing
  with an error. This is the state the optional `declarations` field was
  introduced for: on a host whose tracked declarations file has been retired,
  the check previously could never pass, which left `doctor` permanently red.
- `undeclare` now proceeds when the root-owned config omits `declarations`,
  instead of refusing. A name cannot belong to a tracked template that does not
  exist, so nothing was being protected; refusing left the runtime manifest
  un-cleanable, since `add` could still add declarations that nothing could
  remove. A `declarations` path that *is* configured but cannot be read or
  parsed still fails closed, unchanged.

### Changed

- The privileged broker no longer requires `root` execution for mutation operations (`set`, `add`, `delete`, `undeclare`, etc.). These operations now execute securely as the dedicated `service_user` via `sudo -u`, dropping all incidental root privileges and strictly restricting the broker to the ownership bounds of its own vault directory.
- `sudo-secretspec` sudoers policy generation updated to bind operator mutations exactly to `({service_user})` instead of `(root)`.

### Added

- **SQLite provider** (`sqlite://`, 0.20+): stores each secret as one row in a
  local SQLite database, behind a new `sqlite` feature (enabled by default).
  Confidentiality comes entirely from filesystem permissions on the database
  file, so identical code serves an ordinary user-owned store and a
  privilege-boundary vault file with no code difference between them. Opt into
  `?history=true` and every `set` and `delete` is retained in a hash-chained
  history inside the same database, so a previous value can be recovered later.
  Each entry binds the *digest* of every value rather than its bytes, which is
  what lets a value be destroyed outright while the entry still proves what was
  destroyed and when.
- The privileged broker keeps an append-only, hash-chained history of the vault
  manifest (`secretspec.toml`) in `broker-history.sqlite3`, verifiable with
  `audit-verify`. Every mutating operation already copied the manifest aside
  before touching it and deleted that copy on success; the copy is now archived
  instead, so the declarations in force before any past change can be recovered.
  A failed archive does not fail the operation — the mutation has already
  committed — it leaves the copy on disk rather than losing it.
- The `secretspec` crate gains a `codegen-schema` feature, which exposes JSON
  Schema emission from a manifest without enabling the full `cli` feature. It
  exists for the same reason as `manifest-edit`: the privilege boundary needs
  the emitter and must not pull `clap` and `inquire` into a root-privileged
  process. Enabling `cli` turns it on, so nothing changes for existing users.
- **Azure App Configuration provider** (`aac://`, 0.20+): select direct
  values and Azure Key Vault references by label, prefix, and tags, with Entra
  ID or connection-string authentication and guarded writes, deletion, and
  declaration discovery. Azure Key Vault references can pin an exact secret
  version, cached-route validation compares canonical vault endpoints
  independently of authentication choice, and discovery rejects ambiguous or
  invalid convention keys. HTTP redirects are rejected so reads and
  secret-bearing writes remain confined to the configured store endpoint.
- The Rust SDK can describe secrets without TOML through the public `Spec`,
  `SpecBuilder`, `Profile`, and `Secret` API. TOML parsing and code generation
  use the same validated model, so Rust-first and file-backed projects share
  inheritance, generation, and provider behavior, including profile-level
  requiredness defaults and explicit opt-outs from inherited path, prompt, and
  generation settings. Existing specs can be copied or consumed back into a
  builder to add, replace, or remove declarations before rebuilding a validated
  spec. This validated declaration API replaces the previously exposed raw
  configuration and code-generation implementation types. Custom provider
  implementations should now return declarations such as
  `Secret::required(...)` from `Provider::reflect` instead of constructing raw
  configuration secrets.
- Structured caller context lets CLI and SDK integrations identify the invoking
  software, version, operation, and non-secret resource independently of the
  user-supplied access reason. Audit records and providers receive the context,
  but it never satisfies the `require_reason` policy.
- A secret's declared `description` now reaches the generated JSON Schema as
  a `description` key on its property. [quicktype](https://quicktype.io)
  turns that into a native docstring in every target language, so SDKs
  generated from a manifest carry the same descriptions the manifest already
  declares, instead of losing them at the schema boundary.
- The Fly.io `fly` provider publishes and deletes application secrets with
  `secretspec set` and `secretspec delete`, and discovers their names with
  `init --from`. Fly.io never exposes plaintext secret values, so the provider
  clearly rejects read operations and CLI guidance recommends only supported
  workflows. Writes keep values off process arguments by streaming them to
  `flyctl secrets set` over stdin, refuse boundary whitespace that `flyctl`
  would silently trim, and scrub ambient Fly token variables before injecting
  the token selected through the provider credential mechanism.
- `secretspec completions <shell>` generates completion scripts for Bash,
  Elvish, Fish, Nushell, PowerShell, and Zsh directly from the CLI definition,
  including descriptions and contextual suggestions for profiles, scopes,
  secret names, providers, aliases, paths, and commands. Completion reads
  configuration metadata only; it never queries providers or reads secret
  values.
- OnePassword: a batch resolution no longer degrades to per-secret `op read`
  calls when some referenced items don't exist. The provider now identifies
  missing items with one `op item list` per vault and retries the batch once
  without them (measured: 153-secret resolve with 3 missing items dropped
  from ~32s to ~6s). Authentication and unavailable-CLI errors during batch
  resolution now fail immediately instead of retrying every secret
  individually.
- OnePassword optional references whose item names resemble authentication
  diagnostics are omitted as missing instead of aborting batch resolution.

- `sudo-secretspec install` reports the version it moved the boundary through
  (`0.19.1-sudo.12 -> 0.19.1-sudo.13`, or `(reinstalled, unchanged)`) and the
  media it installed from. Previously the success line was identical whether
  the boundary had been upgraded or not, so confirming an upgrade meant
  separately running `--version`.
- `sudo-secretspec doctor` reports a build staged by the package manager but
  never installed as the new advisory `UPGRADE_AVAILABLE`, naming the path to
  run. Advisory, so it never fails `doctor`.
- The protected config records the installer's `version`. Configs written by
  earlier installers parse unchanged; until the first install that writes it,
  `doctor` reports no upgrade rather than guessing at one.
- A hash-chained history store (`broker-history.sqlite3`) behind the privilege
  boundary in the vault, recording pre-mutation snapshots of the manifest and
  secret values. Entries chain over metadata and per-value SHA-256 digests
  rather than raw secret bytes, allowing individual values to be destroyed
  later while keeping the history chain verifiable and tamper-evident. The
  store shares the audit ledger's hardening (0600 mode, ownership verification,
  and inode swap detection).
- The broker now archives pre-mutation copies of the manifest and dotenv into
  the vault history store on every mutation (`set`, `add`, `delete`,
  `undeclare`) instead of deleting them on commit. If archiving fails after a
  mutation commits, the operation succeeds and rollback copies are preserved
  in the vault for recovery and reported by `doctor`. History listings verify
  the hash chain on read and report entry metadata without exposing secret
  values or digests.

### Added

- `Spec` can perform format-preserving single-declaration edits on the document
  it was loaded from. `add_secret_to_text` and `remove_secret_from_text` return
  a new fully revalidated `Spec` whose text differs only by that declaration,
  leaving comments, key order, quoting, and unrepresented syntax byte for byte
  intact; `declares_secret_in_text` reports whether a name is declared in this
  document rather than inherited; `preserved_text` exposes the exact backing
  text, and `to_toml` renders freshly formatted TOML for any spec, including one
  built with `Spec::builder`, which has no backing text. Adding a declaration
  and then removing it restores the original bytes, so tools that compare
  manifests byte for byte can rely on the undo. A spec that inherits through
  `project.extends` keeps its own root document as the preserved text and is
  revalidated against its parents on every edit, so inherited declarations are
  never inlined into the child file.

### Changed

- `sudo-secretspec install` now adopts the vault named by the installed
  root-owned config without `--adopt-existing`, announcing on stderr which
  vault it adopted and where that was recorded. Upgrading an existing boundary
  therefore needs no flag; pass `--vault` to install somewhere else. A vault
  found only by scanning well-known paths — which includes the retired
  wrapper's store that migration deliberately leaves on disk — still requires
  `--adopt-existing`, so a new boundary is never silently bound to retired
  secrets. The refusal for a fresh install onto an existing boundary now prints
  the full command that adopts it instead of only naming the missing flag.

- Dotenv parsing and rendering now use dotenv-ng throughout the dotenv
  provider, age-encrypted dotenv blobs, and `secretspec export --format
  dotenv`. Values containing `$` remain literal, output uses only the quoting
  needed to round-trip, and bcrypt-style strings containing `$2a$10$...` are
  no longer corrupted while reading ([#73]). Dotenv keys may include hyphens,
  leading digits, leading dots, and Unicode. Whitespace, `=`, `#`, and control
  characters remain invalid in keys.

  [#73]: https://github.com/cachix/secretspec/issues/73

- Provider behavior, configuration, and supported URIs remain unchanged after
  reorganizing the shared provider infrastructure into focused modules.
- Applying an active profile preserves each provider's public URI and
  storage/cache identities, so profile-aware native references continue to
  match the same provider during planning and resolution.

- `sudo-secretspec install --dry-run` now resolves and validates the source
  media, which it previously skipped entirely — the checks ran only after the
  dry-run had already returned, so a dry run could not report the most likely
  problem with an install.
- An install that would copy the installed boundary onto itself, or that names
  incomplete source media, is now refused *before* elevating rather than after.
  Previously the operator paid an interactive authentication prompt to be told
  the install would do nothing. The privileged installer still repeats every
  check as root; that copy remains the authoritative one.

- `add` (both `secretspec add` and `sudo-secretspec add`) takes new
  `--optional` and `--required` flags, writing `required = false` or
  `required = true` on the new declaration. Omitting both writes no `required`
  key, exactly as before, leaving the secret to inherit `[defaults] required`
  from its profile. Previously there was no flag at all, so a secret only some
  hosts need had no CLI path to being optional short of hand-editing the
  manifest — and in a profile whose defaults set `required = false`, no path
  to being required either.
- `sudo-secretspec schema --reason <why>` emits a JSON Schema of the runtime
  manifest's typed shape (declared names and whether each is required) to
  stdout. It reads no secret values, and emits no descriptions — the schema
  carries one `type` key per property. The profile is the one recorded in the
  root-owned config, not a caller flag, so a caller cannot enumerate shapes of
  profiles the boundary is not configured for. Like every other brokered
  operation it requires a `--reason` and is recorded in the audit ledger.
  NOTE: unlike `template-check`, this needs a boundary reinstall — the older
  broker has no `source-schema` operation.


- Downstream `sudo-secretspec` privilege-boundary companion: a single Rust
  binary with mediated credential operations, fail-closed SQLite audit,
  metadata-only doctor/drift checks, explicit install/adopt/rollback, and
  Homebrew packaging that never performs privileged installation side effects.
- Short install UX: `sudo-secretspec install` / `install --adopt-existing`
  with declaration auto-detection and TTY prompts; long flags are overrides.
- Fork docs: `sudo-secretspec/README.md`, `README.downstream.md`, `FORK-AI.md`.


- The project moved from `djbclark/sudo-secretspec` to
  `frdminc/sudo-secretspec`, and its Homebrew tap from
  `djbclark/homebrew-sudo-secretspec` to `frdminc/homebrew-sudo-secretspec`.
  Install with `brew install frdminc/sudo-secretspec/sudo-secretspec`. Existing
  installations keep working — GitHub redirects the old URLs — but should be
  moved over with `brew tap frdminc/sudo-secretspec`,
  `brew reinstall frdminc/sudo-secretspec/sudo-secretspec`, then
  `brew untap djbclark/sudo-secretspec`. Release artifacts are unchanged: the
  `v0.19.1-sudo.5` tarball has the same SHA-256 under the new owner.

- `sudo-secretspec template-check --reason <why>` reports whether the runtime
  manifest in the vault still matches the tracked declaration template recorded
  in the protected config. It reads no secret values, and like every other
  brokered operation it requires a `--reason` and is recorded in the audit
  ledger. The privileged side already implemented this check; only the public
  subcommand was missing, so an existing boundary serves it without reinstalling.

- `sudo-secretspec uninstall` removes the privileged boundary this installer
  owns. Add `--dry-run` to see the plan first; like `install`, it requires
  interactive authentication. The sudo policy is removed before the binaries it
  grants, and only ever this project's own drop-in at
  `/etc/sudoers.d/sudo-secretspec` — never `/etc/sudoers`, and never another
  vendor's file in that directory. The policy is checked against the install
  manifest before it is unlinked and left in place with a warning if its bytes
  do not match, since the path is predictable and a file sitting there is not
  proof this installer wrote it. Rollback snapshots are removed too, because
  they restore artifacts that no longer exist.

  The vault and the service identity survive by default; each has its own
  opt-in flag with its own confirmation. `--purge-vault` deletes the vault
  directory and every secret in it. `--remove-service-user` deletes the service
  user and group, and refuses any identity that does not look like one this
  installer created — an adopted account may have other dependents, so it is
  reported rather than deleted. Both are settled before anything is removed, so
  a refusal cannot arrive part-way through.
- The generated sudoers policy now sets `timestamp_timeout=0` on the installed
  client path, so `install` and `rollback` require interactive authentication
  every time. Previously the gate was sudo's shared timestamp — five minutes by
  default, and satisfied by any other command, so `sudo true` followed by
  `sudo sudo-secretspec install` authenticated for nothing. Zero also stops
  boundary lifecycle from refreshing the timestamp for later commands. Mediated
  credential operations are unaffected: they run through the NOPASSWD broker
  path and never prompt. **Run `sudo-secretspec install --adopt-existing` to
  apply this to an existing policy.**
- `sudo-secretspec doctor` now checks which `sudo-secretspec` would actually
  run, not only whether the installed one is intact. A different binary found on
  the executable search path is reported as `CLIENT_SHADOWED` and fails the
  check; so is any copy reachable through a directory that is not root-owned or
  is group/world-writable, such as `/opt/homebrew/bin`, because anyone who can
  write there chooses what the operator runs. A byte-identical copy in a
  root-owned search directory is reported as the advisory `CLIENT_DUPLICATE`.
  The client passes its own search path to the privileged check, since `sudo`
  replaces `PATH` with the policy's `secure_path`; a fixed list of standard
  directories is always scanned, so this can only widen the check.
- `sudo-secretspec doctor` now reports neighbouring drop-ins in
  `/etc/sudoers.d` that are not doing what their owner expects. Three advisory
  codes, because sudo and `visudo -c` disagree about what is acceptable and the
  two failures have different consequences and different fixes:

  - `SUDOERS_NEIGHBOUR_IGNORED` — sudo will not read the file, so its rules
    never take effect. That means a file not owned by root, one that is
    world-writable, one that is group-writable with a group other than gid 0,
    a directory or special file, or a dangling symlink.
  - `SUDOERS_NEIGHBOUR_SKIPPED` — the name makes `#includedir` skip the file
    before it is ever read (any name containing `.` or ending in `~`). The fix
    is a rename, not a `chmod`.
  - `SUDOERS_NEIGHBOUR_VISUDO_REJECTED` — sudo reads and applies the file
    normally, but `visudo -c` rejects it, because visudo demands mode exactly
    `0440` and group gid 0 where sudo asks only that nobody outside root can
    write it. `visudo -c` validates the whole directory at once, so a single
    neighbour in this state fails the syntax check for every tool on the host.
    This is the state `/etc/sudoers.d/yabai` was in, and the reason `install`
    and `rollback` scope their own `visudo` check to a single file.

  All three are advisory and never fail the check: these files belong to other
  vendors, and this project neither edits nor removes them. Dotfiles such as
  `.DS_Store` are not reported. Note that a drop-in at mode `0640` is **not**
  ignored by sudo — its rules are live — even though `visudo -c` complains
  about it.

### Changed

- `sudo-secretspec add` and `undeclare` now edit the runtime manifest through
  the public `Spec` text API, so each edit is revalidated as a whole document:
  a declaration that would not load is refused before anything is written to
  the vault, rather than surfacing at the next `check`. A manifest that
  declares `project.extends` is refused rather than resolved, so the root
  process never reads parent files while editing. Comments, key order, and
  formatting are preserved exactly as before, and add-then-undeclare still
  restores the document byte for byte.

### Fixed

- `sudo-secretspec undeclare` now captures a rollback copy of the vault manifest
  before rewriting it, matching the protection `set`, `add`, and `delete`
  already have. Previously, `undeclare` was missing from the broker's mutating
  operations set, so an interrupted write could leave the vault manifest
  corrupt without a rollback copy to recover from.

- The refusal `sudo-secretspec install` prints when it is run from the
  installed boundary itself no longer tells the operator to re-run the command
  with `--adopt-existing`. Upgrading an installed boundary has needed no flag
  since the adoption rule started keying on provenance, so the suggested
  command asked for a trust decision the upgrade path no longer requires.

- `sudo-secretspec install` no longer destroys a populated vault. Run without
  `--adopt-existing` against a host that already had a boundary installed, it
  recreated the vault's runtime files from scratch and truncated `.env` to zero
  bytes, losing every stored secret value. The guard that refuses a fresh
  install onto an existing identity or vault ran only under `--dry-run`, so the
  rehearsal refused exactly what the real command went on to do. That guard now
  applies to the live path as well, and the runtime files are created only when
  missing — an existing `secretspec.toml` or `.env` (including a symlink, which
  is no longer written through) is refused rather than overwritten.

- `check` writes its report to stdout instead of stderr, so
  `secretspec check | grep ...` sees it. Previously the header, every ✓/○/✗
  line and the summary all went to stderr, leaving stdout empty — a pipeline
  observed nothing while the report still appeared on the terminal, which made
  the command look like it had found no secrets. This also corrects the
  colouring: `colored` decides whether to emit ANSI escapes by testing
  *stdout*, so a report written to stderr leaked raw escape bytes into
  redirected log files and dropped colour from terminals reading stdout. Exit
  codes are unchanged, and the error message for a missing required secret
  stays on stderr where it belongs.

  The report is written through a sink rather than `println!`, so a reader that
  closes the pipe early — `check | head` — reports a broken pipe as an ordinary
  error instead of panicking, the same way `export` already behaves. Note this
  hazard only exists at all because the report moved to stdout; the previous
  stderr-only behaviour could not encounter it.

- Google Cloud Secret Manager convention names now use the readable,
  versioned `secretspec2--{project}--{profile}--{key}` layout. Distinct logical
  addresses such as `my-app/prod/K` and `my/app-prod/K` can no longer collide
  on one stored secret. When the new id holds no value, reads fall back to the
  matching 0.19 `secretspec-{project}-{profile}-{key}` secret and warn once per
  run, so an upgraded project keeps working with no migration step and no new
  permissions: the fallback only reads, and credentials that cannot create
  secrets are unaffected. Writes always use the new id, so `secretspec set`
  moves a secret, after which reads stop consulting the legacy id. The 0.19
  secret is left in place for rollback and should only be deleted once its
  value has been written under the new id. Names that releases through 0.19
  accepted but the new layout cannot represent, such as a project containing
  `--`, keep reading their 0.19 secret with a warning; writing them requires
  renaming the component or addressing the secret with a `ref`.
  Secret-level IAM bindings on 0.19 ids also keep working when an unbound new
  id returns permission denied, while other access failures remain errors
  instead of being mistaken for missing values. Explicit `ref` addresses
  remain unchanged. ([#219])

  [#219]: https://github.com/cachix/secretspec/issues/219

- Bare `bws://<project-uuid>` provider URIs now target the Bitwarden US cloud
  vault instead of the public marketing site, restoring reads and writes while
  keeping the server pinned independently of ambient `bws` configuration.
  ([#359](https://github.com/cachix/secretspec/issues/359))

- Node SDK processes using `loadAsync()` or `reportAsync()` with AWS Secrets
  Manager or Parameter Store now exit normally after resolution. Provider
  runtime and TLS state is torn down on a short-lived resolver thread instead
  of remaining attached to a persistent libuv worker during macOS process
  shutdown. ([#343])

  [#343]: https://github.com/cachix/secretspec/issues/343

- The `awssm` and `scaleway` providers now treat a JSON `null` in a `ref` field
  as no value, the same as an absent key, so the provider chain continues.
  Previously it was rendered as the four-character string `null`, which
  satisfied a required secret and reached the program as a password or token
  spelled `n-u-l-l`. The `bw` and `dashlane` providers already behaved this way.
  An `extract` pointer is unchanged: it names one location and still reports a
  `null` there, and the two policies now sit next to each other in one place.
- The Python and Ruby SDKs' `Resolved.close()`/`Resolved#close` now remove every
  `as_path` temp file even when one of them cannot be removed, raising the first
  such error only after the rest are cleaned up. Previously the first failure
  aborted the loop and left the remaining secret files on disk, which is the
  outcome `close` exists to prevent. This matches the Go SDK's `firstErr` and the
  .NET SDK's `firstError`. The Ruby SDK also no longer skips a dangling symlink,
  which `File.exist?` reports as absent.
- The `awssm` provider now accepts a trailing slash in `?prefix=` without
  inserting a second slash into the AWS secret name. For example,
  `?prefix=myteam/` resolves to `myteam/secretspec/...`, matching
  `?prefix=myteam`, and both spellings share one provider identity so import
  diagnostics still recognize alias-specific references. This avoids silently
  treating the secret as missing or writing to a distinct double-slash name. Closes
  [#344](https://github.com/cachix/secretspec/issues/344).

- `import --delete-source` no longer fails partway through, after already
  writing the destination, for a provider that cannot delete. `check_deletable`
  previously answered whether an address's coordinates resolve, not whether
  the provider supports deletion at all, so a provider inheriting the default
  `delete` (which errors) still passed preflight. A new `Provider::supports_delete`
  capability lets `check_deletable` reject those providers up front, before the
  copy phase runs.

- Infisical secret references no longer require `?env=` in the provider URI: a
  `ref` names a folder and key but never an environment, so it now falls back to
  the profile the run resolves under. One alias can therefore serve every profile
  while naming secrets flat — `ref = { item = "/{key}" }` — instead of needing
  one alias per environment. An explicit `?env=` still pins the environment.
  When every requested secret gets Infisical's ambiguous 404, SecretSpec now
  checks the environment root once without requesting secret values and reports
  a missing environment or project, naming whether the profile or `?env=`
  selected it. A genuinely absent secret or folder in an existing environment
  remains unset so provider fallback still works. A credential declared with a
  `ref` still needs `?env=`, so it resolves the same way whichever profile is
  running. ([#338])

  [#338]: https://github.com/cachix/secretspec/issues/338

- `secretspec set` against an Infisical secret names the environment in its
  pre-write preview, which the previous description left out.

- Infisical import collision checks now recognize when aliases target the same
  secret through a profile-derived versus explicit environment, or through an
  absolute ref that overrides different configured path defaults, preventing
  aliased destinations from overwriting one another.

- `sudo-secretspec install` refuses to install from the installed boundary
  itself instead of silently upgrading nothing. `install` copies from the tree
  its own executable lives in, and `/usr/local` is shaped exactly like the
  distribution media — so running the *installed* client's `install` resolved
  every source path back to the already-installed files, copied each onto
  itself, wrote a rollback snapshot, and exited 0 reporting success while the
  version never moved. It now stops with an error naming the copy to run
  instead. Reaching the old client through `PATH` was only the most common way
  in; a symlink, an alias, or a hard link produced the same silent no-op, and
  all of them are now caught.

- The Homebrew formula now declares its SQLite dependencies. The companion
  builds `rusqlite` against the system SQLite rather than the bundled copy, so
  `pkg-config` is a build input and `sqlite` is a full runtime one — the
  installed companion links `/opt/homebrew/opt/sqlite/lib/libsqlite3.dylib`,
  not the copy in `/usr/lib`, so removing Homebrew's sqlite would leave a
  binary that cannot start. Previously neither was declared and a tap install
  failed at build time on a host that happened not to have them. The formula
  also declares `depends_on :macos`, since the privileged boundary it installs
  targets macOS paths and there is nothing for it to do on Linux.
- `Cargo.lock` now matches the workspace version. The `0.19.1-sudo.4` bump
  updated `Cargo.toml` but not the lockfile, and because the formula builds
  with `cargo install --locked`, an install from that tag aborted before
  compiling anything. `v0.19.1-sudo.4` is superseded and should not be
  installed; use `v0.19.1-sudo.5` or later. The release helper now refuses to
  cut a version whose lockfile disagrees with the manifest, and it understands
  the `-sudo.N` serial that `0.19.1-sudo.4` renamed to.

- Corrected the documented tamper-evidence of the audit ledger, in
  `AI-GUIDANCE.md` and in the library's own notes. Both said truncating the
  tail was detectable "because every event commits with the singleton `head`
  row". It is not: `head` lives in the same database as the events, so
  deleting the last N events and rewriting `head` to the new tip verifies
  cleanly. Truncation and whole-ledger deletion have the same mitigation —
  pinning the tip reported by `audit-verify` outside the vault. No code
  changed; the guarantee was always this one, and the note overstated it.
  `AI-GUIDANCE.md` also now records that secret values are not zeroized in
  the client, as accepted residual risk rather than an omission.
- The in-binary refusal of boundary lifecycle through the NOPASSWD path now
  fails closed. It treated "this process cannot identify itself" and "no broker
  is installed" as the same answer and allowed `install`/`rollback`/`uninstall`
  in both. Only the second is a reason to allow them — that is the case a
  first install runs in — so an unidentifiable process is now refused.
- `install` now requires `/usr/local/{bin,libexec,etc,share}` to be root-owned
  before writing into them, which it already documented but only enforced for
  the shared roots above them. A host carrying a legacy Intel-Homebrew
  `chown -R` of the prefix would otherwise let an unprivileged user replace
  the binary root executes through the NOPASSWD rule. The directories are also
  created at an explicit `0755` rather than inheriting the caller's umask.
- The broker now requires the vault's manifest and dotenv to be exactly mode
  `0600`. It previously accepted anything closed to group and world, so `0700`
  and `0400` passed the enforcing check while `doctor` reported them — leaving
  the enforcing side more permissive than the reporting one.
- `sudo-secretspec doctor` no longer writes to the audit ledger it is
  reporting on. Its drift check reached the ledger through the ordinary
  verification path, which opens read-write and normalises on the way in —
  resetting mode, reassigning ownership, and creating the schema if absent.
  Run as root, a health check could therefore quietly rewrite the ledger's
  metadata. Verification for checkers now opens read-only and reports what it
  finds; the repairing path stays with the broker, so a ledger left root-owned
  by an earlier install still recovers.
- `audit-verify` now asserts who the ledger belongs to. Both it and the drift
  check passed no expected owner, which skipped the ownership comparison on
  the directory *and* the ledger — on the one command whose purpose is to
  prove the ledger is intact. The full boundary check is deliberately still
  not required, so a drifted install can continue to verify its own ledger.
- A crashed credential mutation no longer wedges `doctor`. The broker's
  rollback backups are created by root with `fs::copy`, which carries the mode
  across but not the owner, so they landed root-owned inside a service-user
  vault — and the per-entry metadata check then turned the deliberately
  advisory `PENDING_ROLLBACK` into a hard `METADATA_MISMATCH`, failing
  `doctor` for anything that reads it as a stop condition. Backups are now
  assigned the vault's own owner, and `drift` reports a pending backup by its
  own code instead of also judging it against the steady-state rule, so hosts
  carrying a backup from an older build recover too. A symlink in that
  position is still refused.
- Every mediated operation now records a terminal audit event. A failure to
  create the rollback backups returned after the attempt event was already
  written, leaving an attempt with no outcome — indistinguishable in the
  ledger from a broker killed mid-operation.
- `sudo-secretspec doctor --json` now emits only the JSON report. `visudo`
  printed `<path>: parsed OK` to the same stream first, so anything parsing the
  output as JSON failed on the first character.
- `sudo-secretspec install` now prunes rollback snapshots instead of leaving one
  behind on every run. Snapshots that captured nothing — which is every first
  install, and which `rollback` refuses to restore from — are removed, and the
  three most recent restorable snapshots are retained. Install output gained a
  `pruned_snapshots=` line and reports `rollback_snapshot=none` when there was
  nothing to capture.
- The Homebrew formula now declares its version explicitly. Homebrew parsed the
  trailing `.1` of the `v0.19.1-djbclark.1` tag as the entire version, so kegs
  were recorded as version `1` and upgrade detection did not work.
- The Homebrew formula installs the companion to `libexec` instead of `bin`, so
  it is no longer linked onto `PATH`. The keg copy is only a bootstrap for the
  initial `install`; leaving it linked shadowed the client at
  `/usr/local/bin/sudo-secretspec` — the path the sudoers policy and installed
  manifest are pinned to — with a same-version, different-hash binary. Run the
  bootstrap from the path shown in `brew info sudo-secretspec` caveats.
- `sudo-secretspec` now invokes `/usr/bin/sudo` by absolute path. It previously
  resolved `sudo` through `PATH`, so a `sudo` planted earlier in `PATH` could
  satisfy any credential operation with forged values and no audit record.
- The generated sudoers policy grants NOPASSWD execution per subcommand
  (`__broker`, `doctor`) instead of for any arguments. The client and broker are
  the same binary, so the previous blanket grant exposed `install` and
  `rollback` — full boundary reconfiguration — without interactive
  authentication. The binary enforces the same restriction internally. **Run
  `sudo-secretspec install --adopt-existing` to replace an existing policy.**
- `install` and `rollback` validate a sudoers policy before it can take effect,
  instead of writing it live and checking afterwards. The policy is staged under
  a name sudo ignores, accepted by `visudo`, and only then renamed into place;
  the whole configuration is re-checked afterwards and the previous policy is
  restored if that fails. An unparseable `sudoers.d` file makes sudo refuse to
  run at all, which would have left no way to elevate and repair it.
- `rollback` verifies snapshots before restoring: destinations must be install
  artifacts, contents must match the snapshot manifest, and modes are taken from
  the installer rather than the snapshot. It no longer executes a `restore`
  program found in the snapshot directory.
- `install` now captures the outgoing artifacts into its rollback snapshot.
  Snapshots were previously created empty, so every `rollback` failed with
  "snapshot contains no restorable prior artifacts".
- `doctor` no longer fails on advisory findings. `LEGACY_VAULT_CLUTTER` and
  `PENDING_ROLLBACK` are reported under a passing check instead of permanently
  blocking automated callers, which are instructed to stop on drift.
- The broker validates vault and runtime-file ownership, mode, and the resolved
  vault path before every operation, and records the expected owner uid with each
  audit event.
- `run` passes `--` through to the target command, so `run -- cargo test --
  --nocapture` no longer tries to execute `--nocapture`.
- `run` no longer panics when the environment contains non-UTF-8 variables.
- A failed terminal audit append now exits 126 and reports the operation's real
  result code instead of masking it as a generic policy error.
- `sudo-secretspec audit-verify` verifies the audit ledger's hash chain and
  prints its event count and tip hash. The privileged side has always
  implemented this and `AI-GUIDANCE.md` already told deployments to pin the
  reported tip externally, but no public subcommand reached it — the same gap
  `template-check` had. Serves from an existing boundary without reinstalling.

- `sudo-secretspec add` now actually declares a secret. It was wired to the
  engine's `set`, which refuses a name that is not already declared, so `add`
  could never once perform the operation it is named for — every invocation
  failed with a `SecretNotFound` listing every existing secret. It now takes a
  required `--description` and edits the runtime manifest, and its output
  reminds you to mirror the declaration into the tracked declarations file.
  NOTE: unlike `template-check`, this needs a boundary reinstall — the older
  broker rejects the new `--description` argument.
- `sudo-secretspec check` no longer prompts. The broker ran the engine's check
  with prompting enabled, inside a root process with no usable terminal: a
  missing secret dropped it into interactive value entry, reading from whatever
  stdin the caller passed and writing the answers into the vault. An operation
  named `check` could therefore write, and with stdout redirected the prompt was
  invisible and it simply hung. It is now read-only and reports missing secrets.
- The downstream release workflow's tag trigger was pinned to the single
  literal `v0.19.1-djbclark.1`, so it fired exactly once in its entire history:
  `.2`, `.3`, `-sudo.4` and `-sudo.5` all published with the tag leg silently
  skipped. It now matches every downstream release tag, and its identity check
  asserts the tag names the version the workspace is actually stamped with —
  the same invariant `packaging/release.py` enforces in preflight, and the one
  that would have caught `v0.19.1-sudo.4` shipping uninstallable.
- `packaging/` and `tests/sudo_packaging/` are now formatted the way CI checks
  them. `ruff format --check` runs there on every pull request and had never
  passed.
- `sudo-secretspec undeclare NAME --reason <why>` removes a declaration this
  client added at runtime — the inverse `add` never had. `add` edits the runtime
  manifest immediately over the unprivileged NOPASSWD broker path, but `delete`
  only removes a *value*, so a declaration added at runtime could previously be
  undone only by an operator at an interactive authentication prompt. The cheap
  operation was one-way, and the drift it left fails `template-check`, which
  deployments call before publishing.

  Two guards keep it from becoming a way to edit policy. A name present in the
  tracked declaration template is refused, because removing one of those stays a
  review-and-release decision; and a name that still holds a value is refused,
  because undeclaring it would strand the value in the store with nothing
  declaring it. So teardown mirrors setup: `add` then `set`, `delete` then
  `undeclare`, and the runtime manifest can only ever move back toward the
  tracked template. The edit preserves surrounding formatting, so undoing an
  `add` restores the manifest byte for byte — which is what `template-check`
  compares.

- Documentation that gave wrong instructions is corrected. `packaging/README.md`
  described the downstream version scheme as `0.19.1-djbclark.N` and its three
  copy-pasteable `release.py` examples used it — every one of them fails now,
  because the helper accepts only `-sudo.N`. The `PROMPT-REVIEW.md` and
  `PROMPT-SECREV.md` review requests named a version four releases stale and
  advertised test counts of 58 and 102 against an actual 152. Historical
  records under `docs/handoffs/` and `docs/design/` are deliberately left
  alone: they describe what was true when written.

- Every crate manifest names the current workspace version again.
  `sudo-secretspec-cli` still required `secretspec 0.19.1-djbclark.2` and
  `secretspec-derive` still required `0.19.1-djbclark.1`. Both built, because a
  caret requirement on an older pre-release still admits the newer one, but the
  manifests advertised versions the workspace has not contained for four
  releases.

- `AI-GUIDANCE.md` now documents the companion's mediated surface. Six engine
  subcommands have no companion equivalent — `config`, `import`, `init`,
  `schema`, `cache`, `audit` — and nothing said so, or why, even though the same
  document forbids invoking `secretspec` directly. An agent that needed one had
  no guidance and every incentive to route around the boundary. `config` and
  `import` are documented as permanently excluded, with the reason: one
  repoints which provider and profile resolve, the other copies values to a
  store the boundary does not own. The other four are recorded as open operator
  questions rather than settled policy. The advisory-code list in the same file
  was two releases stale and now names all six.

- `import --delete-source` no longer promises a deletion the provider cannot
  perform. `Provider::delete` defaults to an unsupported-operation error, but
  `Provider::check_deletable` — the preflight that exists so an unsupported
  address cannot be discovered after earlier source entries are already gone —
  defaulted to merely resolving coordinates. Nineteen of the twenty-eight
  provider modules override neither, so preflight passed and the deletion phase
  then failed, after the copy phase had already written the destination. The
  preflight now refuses a provider that cannot delete at all, reporting the same
  reason `delete` would, and providers declare the capability explicitly through
  a new `Provider::supports_delete`, which defaults to `false` in lockstep with
  `delete`. Custom providers that implement `delete` must override it; the eight
  built-in ones that delete (dotenv, file, gopass, keeper, keyring, openbao,
  pass, vault) do. No secret was ever lost to this — copies precede deletions,
  so the first refusal aborted the run.

- `sudo-secretspec run` works again for a command named by an absolute path.
  The client forwarded the whole invocation as the audit ledger's command
  *basename*, and the privileged side validates that field as a basename — no
  path separators — so `run -- /bin/echo hi` was refused with `audit denied:
  invalid command basename`, which is most real invocations. Only a bare
  `run -- sh -c ...` got through. The client now takes the final component, and
  a target with no usable one is recorded as `unknown` rather than failing the
  run. Client-side only: no boundary reinstall needed.

- `v0.19.1-sudo.6` is superseded by `v0.19.1-sudo.7` and should not be used to
  install or adopt a boundary; its installer carries the vault-detection bug
  below. Nothing else in `.6` is affected, and an already-installed boundary is
  unharmed — the bug only fires while `install` is choosing what to adopt.

- `sudo-secretspec install --adopt-existing` now adopts the vault the installed
  boundary actually serves from, by reading the protected config, instead of
  guessing from a fixed list of directory names that put the retired
  `/var/db/stayturgid-secrets` first. On a host that had migrated to
  `/var/db/sudo-secretspec`, a routine reinstall silently repointed the boundary
  back at the wrapper's retired vault and its `_secretspec` service identity —
  migration leaves that directory in place on purpose, as the second copy of the
  secrets and the pre-migration audit ledger, so its presence never meant it was
  the live vault. `--vault` and `--service-user` still override, an installed
  config naming a vault that no longer exists falls back to detection rather
  than pinning the installer to it, and with no boundary installed the canonical
  vault is now preferred over the retired one.

- The workspace's own `secretspec` and `secretspec-derive` dependency
  requirements are stamped with the release version again. The `0.19.1-sudo.5`
  bump moved `workspace.package.version` but left both requirements naming
  `0.19.1-sudo.4`; every earlier downstream release had moved them together.
  The build was unaffected, since the stale requirement still admitted the
  newer version, but the manifest advertised a version the workspace no longer
  contained.

### Security

- The privileged broker no longer reads configuration the calling user can
  write. `sudo` on macOS hands the caller's `HOME` to the elevated process
  (the stock `/etc/sudoers` keeps `HOME` in `env_keep`, which overrides
  `env_reset`), and the SecretSpec engine resolves its user-global
  `config.toml` from that `HOME`. A root process was therefore reading
  `~/.config/secretspec/config.toml`, whose `[audit] path` aims a root writer
  at any absolute path — creating directories, appending the plaintext reason,
  and truncating the file once `max_size_bytes` is passed — and whose
  `[defaults] profile` selects which profile of the protected manifest
  resolves. The broker now pins `HOME` to `/var/root` and clears the whole
  `XDG_*` family before dispatching any operation, and the installed sudoers
  policy carries `env_keep-="HOME"` and `always_set_home` so the same
  guarantee holds before the process even starts. Re-run
  `sudo-secretspec install` to update the policy.
- The broker now clears **every** `SECRETSPEC_*` variable rather than four of
  them. The engine reads roughly twenty, and four (`SECRETSPEC_OPCLI_PATH`,
  `SECRETSPEC_BWS_CLI_PATH`, `SECRETSPEC_PASSBOLT_CLI_PATH`,
  `SECRETSPEC_PROTONPASS_CLI_PATH`) name an executable it launches — as root.
  The purge is now a prefix rule, so a knob added upstream is covered the day
  it lands, and it runs before dispatch rather than partway through.
- The reason for a credential operation is now hashed before it crosses the
  privilege boundary, which is what the design always claimed. It was passed
  to the broker as plaintext in `argv`, readable via `ps` and
  `KERN_PROCARGS2` by every process running as the same user, and left in
  shell history. `--reason` on the client is unchanged; only the internal
  broker protocol moved to a digest. A side effect worth having: the engine's
  own JSONL audit now records the same digest as the SQLite ledger, so the two
  can be joined on it. A client newer than the installed broker fails with a
  message pointing at `sudo-secretspec install` rather than falling back to
  plaintext.
- The manifest profile the broker resolves from is now recorded in the
  root-owned `/usr/local/etc/sudo-secretspec.toml` (new `profile` key,
  defaulting to `default`, settable with `sudo-secretspec install --profile`).
  It was previously allowed to fall through to the caller's user-global
  SecretSpec config. Existing configuration files without the key keep
  working.
- The bundled agent skill (`skills/sudo-secretspec/SKILL.md`) now documents the
  full mediated surface — `add`, `undeclare`, `export`, `template-check`, and
  `audit-verify` were missing — along with the six engine subcommands that are
  deliberately not exposed, the runtime declaration lifecycle and its `delete`
  then `undeclare` inverse, and the hazards worth knowing before the first
  command: `get`/`export` stream values to stdout, `check` reports to stderr,
  and every lifecycle command authenticates even under `--dry-run`. It also now
  tells readers to check each `doctor` finding's `advisory` field instead of
  matching a hardcoded list of codes, and flags `CLIENT_SHADOWED` as a hard
  stop.

## [0.19.1] - 2026-08-11

Republishes 0.19.0's command-line artifacts. The library and CLI behave exactly
as in 0.19.0.

### Added

- The age provider supports deleting secrets: `secretspec delete`,
  `secretspec import --delete-source`, and cache invalidation now work with
  it, so an age-encrypted file can serve as the local store of a cached
  provider alias — an encrypted-at-rest cache with no keyring daemon or OS
  keychain involved.
- Windows ARM64 CLI release artifacts (`aarch64-pc-windows-msvc`), attached to
  the GitHub Release as `secretspec-aarch64-pc-windows-msvc.zip` with a
  checksum. The static installer keeps selecting the x86_64 build on Windows
  ARM64, which runs under emulation, so download the archive directly for a
  native binary.

### Fixed

- The 0.19.0 GitHub Release shipped without its CLI archives, its installer,
  and the Swift XCFramework, so `curl https://install.secretspec.dev | sh` and
  `swift package` resolution of 0.19.0 both failed. Every language registry
  (crates.io, PyPI, npm, RubyGems, Hackage, NuGet) published 0.19.0 normally and
  is unaffected. Install 0.19.1 instead; SwiftPM version ranges resolve to it
  automatically.

## [0.19.0] - 2026-08-10

### Changed


- A provider URI may no longer carry a credential. A URI with a password
  (`scheme://user:PASSWORD@host`) is rejected, and `onepassword+token://` no
  longer accepts the service account token in its userinfo
  (`onepassword+token://token@vault`). A URI is committed to `secretspec.toml`,
  echoed into shell history, and printed by CI, so a credential written there is
  already disclosed and redacting it at the terminal cannot retract it. Keep the
  scheme and supply the credential through a provider credential
  (`secretspec config provider login <alias>`, or `credentials = { ... }` on the
  alias) or the provider's environment variable; the errors name both. An
  unparseable provider specification is now also redacted before it is reported.
- `secretspec get` resolves through the same path as the SDK's `resolve_named`,
  so a single-secret read makes exactly the decisions batch resolution makes. It
  continues to read the whole profile regardless of an active scope, and audits
  the coordinates it actually reached.
- 1Password field references now resolve in one batched CLI call, reducing
  repeated unlocks and process startup when loading multiple secrets. If a
  missing reference requires individual reads, those reads remain bounded and
  concurrent.
- The Rust SDK's `ProviderAlias` now provides `leaf`, `credentials`, and
  `credentials_mut` helpers so callers can construct and inspect leaf or
  inline-cached aliases without depending on their storage representation.

### Added

- The Rust SDK can resolve a single secret with `Secrets::resolve_named`, which
  reads only that secret and the inputs it composes from. An unrelated missing
  required secret no longer fails the call, and the result distinguishes an
  undeclared name (including one the active scope hides) from a declared secret
  with no value, reporting whether that value was required.
- `Secrets::with_default_reason` sets a session reason only when none is already
  in effect, so an embedding application can describe itself without discarding
  the reason its own caller supplied through `with_reason` or
  `SECRETSPEC_REASON`.
- Secrets can set `prompt = true` to request a hidden value from the controlling
  terminal when `secretspec run` finds no stored value. Writable providers save
  the answer for later runs; the `null` provider keeps it invocation-only.
- Profiles can opt out of inheriting `[profiles.default]` by setting
  `inherit = false` in their profile defaults (0.19+), allowing standalone
  secret sets alongside profiles that still share the default declarations.
- **Passbolt provider** (`passbolt://`): store and read secrets in a
  self-hosted Passbolt server through the community-maintained
  `go-passbolt-cli`, with convention-based names, references to existing
  resources, and credentials supplied by the CLI configuration or SecretSpec
  provider environment variables.
- Provider aliases can define native `ref` templates and secrets can override
  coordinates per leaf alias with `refs`, so fallback providers and import
  sources/destinations resolve independently. `import --delete-source` now
  preflights the whole migration, verifies all writes before cleanup, and can
  safely move between distinct entries in the same physical store.
- A `null` provider lets non-sensitive, version-controlled environment values
  use their manifest defaults and lets generated secrets stay ephemeral, with a
  fresh value returned for each resolution and nothing written to provider
  storage.
- `secretspec set` and interactive `secretspec check` now preview the resolved
  write destination before reading the value, including the exact file and
  selector for SOPS.
- A `file` provider stores each secret as one plaintext UTF-8 file beneath an
  explicitly configured relative or absolute directory, with project/profile
  isolation and support for existing file-mounted secrets through `ref.item`.
- Secrets can select values from stored JSON documents with RFC 6901 pointers
  using `extract`. Extraction composes with provider-native references and
  storage decoding; selected values are read-only so sibling document data is
  never overwritten or deleted.
- Secrets can store values as standard Base64, URL-safe Base64, or hexadecimal
  using `encoding`; writes encode logical text and reads decode stored values,
  while `as_path = true` materializes arbitrary decoded bytes.
- `secretspec-ffi` installs (via `cargo cinstall`) together with its C header
  and a `secretspec_ffi.pc`, so consumers can link it — statically or
  dynamically — without hand-written linker flags.
- The Haskell SDK's new `use-pkg-config` cabal flag
  (`cabal build -f use-pkg-config`) resolves an installed static or shared
  library through pkg-config.
- The Ruby SDK's native extension accepts a new `--enable-pkg-config` build
  flag (`gem install secretspec -- --enable-pkg-config`) that resolves an
  installed static or shared library through pkg-config.
- The Go SDK has a new `pkgconfig` build tag (`go build -tags pkgconfig`) that
  links an installed static or shared library, so it also works for a `go get`
  dependency.
- The Haskell SDK declares the archive's macOS system frameworks
  (`SystemConfiguration`, `Security`, `CoreFoundation`) in its cabal file, so
  GHC passes them to every link on macOS.
- A single provider can now attach its cache directly to the same alias with
  `uri` and `cache`, avoiding a second wrapper alias while retaining provider
  credentials. Cached `fallback` routes remain available for multiple
  authoritative providers.

### Fixed

- Ruby gems for Apple silicon now use the generic `arm64-darwin` platform
  instead of including the build runner's Darwin version.
- Windows shared `secretspec-ffi` installs now place the runtime DLL in the
  documented `PREFIX/lib` runtime library directory.
- `import` warns when a literal source uses convention naming but a provider
  alias for the same storage container addresses active secrets differently
  through a `ref` template or scoped `refs`. Import output also retains the
  selected source alias, making alias-specific addressing visible without
  changing literal-provider semantics.
  ([#312](https://github.com/cachix/secretspec/issues/312))
- The error for a coordinate a provider does not support now points at
  `refs.<alias>` and alias `ref` templates as well as at removing the
  coordinate, so a `field` written for one store no longer has to be dropped to
  reach another store that organizes the secret differently.
  ([#266](https://github.com/cachix/secretspec/issues/266))
- The Proton Pass provider works with `pass-cli` 2.2.4 and later, which removed
  the `pass-cli test` subcommand the provider ran to check the session before
  every read and write. The check now tries `pass-cli info` and falls back to
  `pass-cli test`, so a single build works across `pass-cli` releases that
  disagree about which check exists. A `pass-cli` with neither is reported as
  incompatible with the SecretSpec release, instead of passing the CLI's usage
  text through as the error.
  ([#279](https://github.com/cachix/secretspec/issues/279))
- SOPS write-target previews consistently use canonical physical paths on macOS
  and Windows, matching the files used for writes.
- Passbolt now updates UUID-addressed resources outside a configured folder,
  treats URI- and environment-selected forms of the same server as one import
  destination, rejects malformed provider query parameters, and avoids
  redundant resource listings during writes.
- Cache entries now store their absolute expiration time, allowing SecretSpec
  to remove an expired entry whenever it encounters one, including at an
  address previously used by another project or profile. Changing `max_age`
  invalidates entries written under the previous policy. Fresh v2 entries remain
  usable during migration, while foreign v2 entries remain untouched.
  ([#275](https://github.com/cachix/secretspec/issues/275))
- `run` preserves non-UTF-8 environment values byte-for-byte when launching
  child processes on Unix.
- Provider-scoped references now compare provider-defaulted coordinates before
  destructive imports, apply scoped address overrides before comparing stores,
  and recognize missing file destinations reached through symlinked parents.
  They also invalidate caches for every coordinate change without display-format
  collisions and retain the attempted native location in audit events when a
  provider read fails. Same-store import validation handles Windows provider
  paths without treating separators as TOML escapes.
- Profile overrides can switch between legacy `ref` and provider-scoped `refs`
  without retaining both inherited address models and failing validation.
- JSON extraction from file-backed documents now handles Windows store paths
  without treating path separators as TOML escapes.
- SDK pkg-config setup now pins cargo-c's library and metadata install
  directories, so Go, Ruby, and Haskell reliably discover
  `secretspec_ffi.pc` across environments.
- The keyring provider no longer intermittently fails with a "No default store
  has been set" error when resolving multiple secrets concurrently.
- The SOPS provider no longer substitutes a second time into a rendered path
  segment, so a project or profile literally named `{profile}` or `{project}`
  resolves to the file you configured instead of a different one.
- Invalid SOPS path templates are now rejected when loading serialized
  provider configurations instead of being accepted without validation.
- The LastPass provider now reports its full item template rather than only the
  first segment. A multi-segment template such as
  `lastpass://Shared/{project}/{profile}/{key}` used to be reported as plain
  `lastpass`, which reads back as the default `secretspec/{project}/{profile}/{key}`
  template — a different folder — and `lastpass://Work/TeamA/{key}` read back as
  the literal item `Work`, one item for every secret. Templates that differ
  below their first segment are now distinguished, so repointing a cached route
  at a new template invalidates its cached values instead of serving the old
  ones until they expire. Single-segment templates are unaffected; cached
  entries for a multi-segment template refetch once, silently, on first run.
- Provider fallback chains now reuse each provider and resolve independent
  primary misses concurrently. Azure Key Vault providers also reuse their
  client and serialize its initial challenge-based authentication, so chains
  such as `providers = ["keyring", "akv"]` no longer fetch every fallback in
  series or launch separate Azure CLI processes for the same resolution.
- Reusing a `Secrets` instance now refreshes fallback providers for each
  resolution, so provider-side caches observe rotated values and providers use
  the latest reason supplied with `with_reason`.

## [0.18.0] - 2026-08-03

### Changed

- The keyring provider now uses keyring 4's Rust-native Secret Service
  transport on Linux, so source builds and binaries no longer require system
  libdbus.
- `secretspec init --from` now accepts every provider with declaration
  reflection, including age, AWS Parameter Store, and Bitwarden Password
  Manager, and accepts `--project` and `--profile` as explicit discovery
  context for hierarchical stores.
- Custom Rust providers now pass discovery context to the
  `Provider::reflect` hook so hierarchical stores can select the project and
  profile namespace.

### Fixed

- The Bitwarden provider now treats a locked vault or a missing session as a
  clear authentication failure on `get`/`set`, with the same "run `bw login`
  and `bw unlock`, then set `BW_SESSION`" guidance in both cases, instead of
  surfacing the underlying CLI error text.
- The Bitwarden provider now reports a missing `bw` CLI with install
  instructions instead of an authentication error: a machine without the CLI
  is not an authentication state, and the install guidance ("…run 'bw login'
  and 'bw unlock' to authenticate") used to match the not-authenticated
  classifier and mask the real problem.
- Vault and OpenBao JWT authentication now allows the role to be omitted when
  the auth mount has a server-configured `default_role`, while explicit URI or
  environment roles continue to take precedence.
- Vault and OpenBao AppRole authentication now supports roles configured with
  `bind_secret_id=false` by omitting `secret_id` from the login request when no
  SecretID credential is configured.
- `secretspec import --delete-source` now compares resolved storage entries
  without conflating distinct cache address spaces, preventing equivalent
  provider configurations (including dotenv path aliases) from deleting the
  destination value. Sources without deletion support are also rejected before
  any destination is written.
- The AWS Secrets Manager provider now authenticates with shared credentials
  file profiles backed by an active AWS login session, which previously failed
  because the required AWS SDK feature was not enabled. `BatchGetSecretValue`
  failures also report the full service error instead of a shortened message.

### Added

- The dotenv provider accepts a leading `~` in custom paths, such as
  `dotenv:~/.config/my-project/.env`, and resolves it to the user's home
  directory.
- Vault and OpenBao AppRole and JWT authentication can target non-default auth
  method mounts, including printable Unicode mount names, with the `auth_mount`
  provider URI option.
- `secretspec add NAME --description "..."` (available in 0.18) adds a secret
  declaration to the active profile while preserving the manifest's
  existing comments, formatting, and unrelated configuration.
- AWS Parameter Store convention templates and bounded `GetParametersByPath`
  discovery can create declarations from the direct children of an existing
  hierarchy without decrypting their values.
- Swift SDK (available in 0.18) for resolving SecretSpec manifests from macOS
  12+ on Intel and Apple silicon. The SwiftPM package provides fluent and
  one-shot resolution, typed failures, scopes, value-free reports, provenance,
  environment export, codegen input, and deterministic `as_path` cleanup. Its
  checksummed XCFramework includes the shared Rust resolver, so applications do
  not need a Rust toolchain or separately installed native library.
- `secretspec delete` removes one or more stored secret values without changing
  their manifest declarations, while `--all` requires explicit confirmation.
  `secretspec import --delete-source` verifies each destination value before
  deleting its source, and retains the source when an existing target differs.
- Bitwarden Password Manager provider (`bw://`, `bw` build feature) for reading
  and writing secrets in a personal or organization vault through the `bw` CLI.
  Collections and organizations are addressed by name or by id
  (`bw://myorg@dev-secrets`), `?type=` and `?field=` select an item type and
  field, and `?server=` asserts which self-hosted server the configuration
  expects. Every item type is supported (login, secure note, card, identity, SSH
  key), each with a default field shared by reads and writes. Item names are
  matched in full and case-insensitively, and an ambiguous name is refused with
  the colliding ids rather than resolved to an arbitrary item.
- Dashlane provider (`dashlane://`) for reading secrets from a Dashlane vault
  through the `dcli` CLI. Convention secrets read the item titled
  `secretspec/{project}/{profile}/{key}`, and a `ref` names an existing item by
  title or identifier with an optional `field`. `dashlane://note`,
  `dashlane://secret`, or `dashlane://password` restrict the search to one
  content type. The provider is read-only, because `dcli` has no command that
  creates or edits a vault item; `secretspec set` fails with that reason.
  Non-interactive use is supported through `DASHLANE_SERVICE_DEVICE_KEYS`,
  which can also be injected as the `service_device_keys` provider credential.
  Injected credentials read through a private, owner-only `dcli` state
  directory of their own, because `dcli` otherwise prefers a device already
  registered on the machine and reads that identity's vault instead.
- Keeper Secrets Manager provider (`keeper://FOLDER_UID`, `keeper` build feature) using
  Keeper's official Rust SDK, with convention-based records, references to
  existing records and fields, provider credentials, batch reads, writes, and
  cache-compatible deletion. SDK calls are safe from async Rust applications,
  and updates preserve the JSON types of Keeper fields such as dates,
  checkboxes, hosts, and names.
- AWS Systems Manager Parameter Store provider (`awsps://`, `awsps` build
  feature) for reading and writing KMS-encrypted
  `SecureString` parameters. It supports AWS profiles and regions, an optional
  hierarchy prefix, customer-managed KMS keys, parameter tiers, batched reads,
  and references by parameter name, version, label, or ARN. Unversioned
  parameter-name references can be written in place; version-, label-, and
  ARN-pinned references are read-only. Writes reject unsupported reference
  coordinates before requesting a value, and versioned ARN errors point to
  writable parameter-name references. AWS service errors include their error
  codes and messages instead of only `unhandled error`.
  ([#209](https://github.com/cachix/secretspec/issues/209))

## [0.17.1] - 2026-08-01

### Fixed

- Vault and OpenBao AppRole and JWT authentication methods now reuse login
  tokens within each provider operation up to each token's reported use and
  lease limits, including time spent completing authentication, avoiding
  repeated logins without exhausting or outliving tokens during batches,
  writes, or deletes. Invalid batch addresses are rejected before login, and
  concurrent requests remain safe across Tokio runtime flavors while keeping
  pooled HTTP connections alive for the full operation.
- Cached provider routes now recognize Vault and OpenBao configurations that
  address the same endpoint, namespace, and mount as one store, even when they
  use different provider names or authentication methods, so a cache cannot
  target its own authoritative source.
- Provider and SDK errors now retain underlying causes such as authentication,
  timeout, DNS, TLS, connection, and response-parsing failures. AWS Secrets
  Manager errors also report AWS error codes and messages instead of only
  `unhandled error`.
- Prebuilt Linux Go SDK and `secretspec-ffi` libraries now include libdbus
  instead of requiring the build host's `libdbus-1.so.3`, so they load on
  NixOS and other systems without a matching system library.
  ([#214](https://github.com/cachix/secretspec/issues/214))
- The dotenv provider's "cannot store" error now tells you to rename the secret
  in `secretspec.toml` when the name came from a manifest declaration, instead
  of always pointing at a `ref` item the config may not contain.
- Typed loaders generated by `secretspec-derive` now keep temporary files for
  `as_path` secrets alive until the returned resolved secrets are dropped.

## [0.17.0] - 2026-07-26

### Fixed

- Cache reads, refreshes, and clears now share one ownership and freshness
  policy, consistently handling expiration boundaries, clock rollback,
  corrupted SecretSpec entries, and values owned by another project or profile.
- Vault and OpenBao providers reuse one `reqwest::Client` per provider
  instance (same `OnceLock` pattern as Infisical) instead of building a fresh
  client on every get/set/login. Concurrent `get_many` of many secrets no
  longer opens one TCP(+TLS) handshake per secret against reverse-proxied
  deployments, which was observed to drop part of the burst with
  `Failed to connect to Vault`.
- `get_each` (default `Provider::get_many`) caps concurrent unique-address
  fetches at 8 by default, overridable with `SECRETSPEC_PROVIDER_CONCURRENCY`.
  Waves replace a single unbounded `thread::scope` fan-out.
- Vault/OpenBao HTTP sends retry up to 3 times on connect/timeout errors only
  (not on HTTP 4xx/5xx), with a short backoff between attempts.

### Added

- SOPS provider (`sops://`, `sops` build feature) for reading and writing
  YAML, JSON, dotenv, and INI files through the SOPS CLI, including templated
  per-project/profile paths and provider-credential injection for encryption
  keys and cloud authentication. Writes are serialized and atomically replace
  encrypted files, with secret values passed to SOPS over standard input.
- Scaleway Secret Manager provider (`scaleway://`, `scaleway` build feature) for
  storing secrets in Scaleway's Secret Manager over its v1beta1 REST API.
  Authenticates with an API secret key (`secret_key` credential or
  `SCW_SECRET_KEY`), targets a region (URI host or `SCW_DEFAULT_REGION`, default
  `fr-par`) and project (`?project_id=` or `SCW_DEFAULT_PROJECT_ID`), and stores
  convention secrets under the folder path `secretspec/{project}/{profile}` with
  the key as the secret name. Native `ref` references may select a JSON key with
  `field` and a revision with `version`, and are read-only.
- Cached provider aliases with ordered authoritative `fallback` routes,
  configurable local cache freshness, cache-first reads, automatic refresh
  after reads and writes, and `secretspec cache clear` invalidation.

  A cache must be a distinct store from the route's own authoritative providers
  (compared by canonical provider URI, so equivalent spellings of one store
  cannot disguise a cache as its own source), must be a store SecretSpec can
  delete from (keyring, pass, gopass, dotenv, or a Vault/OpenBao KV v2 mount) so
  its entries can be invalidated, and must be the only entry in a `providers`
  list. All three are reported when the route is planned, and an unusable
  `max_age` when the configuration loads.

  Every entry records the project and profile that own it, and SecretSpec only
  changes an entry it can show is its own: a value it did not write, or one
  belonging to another project or profile, is left alone by reads and refreshes
  and reported by `cache clear` rather than deleted, since an address alone is not
  proof of ownership when a store is shared. An entry marked as SecretSpec's own
  but unreadable is replaced.

  A cached value never outlives the write that superseded it: a failed refresh, a
  cache that could not be constructed, and a write that bypassed the cache with
  `--provider` all invalidate the entry. An entry no read can serve — expired, or
  written for a different route — is deleted when found rather than skipped, so an
  expired value does not keep its plaintext in a store that cannot expire
  anything. Where the store can expire a value itself, `max_age` is applied
  server-side — Vault and OpenBao set the KV v2 path's `delete_version_after` — so
  a cached copy stops existing at that age even if SecretSpec is never run again,
  and clearing a KV v2 entry destroys its recoverable version history.

  `cache clear` reports how many entries it actually removed, ignores provider
  overrides, and clears what it can before reporting a cache store it could not.
  Cache writes are audited as `cache_refresh` rather than `set`.
  ([#199](https://github.com/cachix/secretspec/issues/199))
- `secretspec config global init --provider <PROVIDER> --profile <PROFILE>`
  can save explicitly user-global defaults without interactive prompts,
  including `--profile none` to clear the default profile. The `global`
  namespace also supports config inspection and provider-alias commands;
  existing invocations without the namespace remain compatible.
  ([#171](https://github.com/cachix/secretspec/issues/171))
- Secret **scopes**: a `[scopes]` table names membership-only subsets of a
  profile's secrets, so a single service or task resolves only what it declares
  instead of the whole profile. `check`, `run`, and `export` take `--scope`
  (`SECRETSPEC_SCOPE`); the consumer-visible set is the intersection of the
  selected profile and the scope's secret list. Scopes are orthogonal to
  profiles and never change a secret's `required`/`default`/providers or its
  storage address. A composed secret in a scope still resolves its dependencies
  — even ones the scope leaves out — to build its value, but those dependencies
  are never exposed to the scope, and a provider warning about one calls it "a
  hidden composition input" rather than naming it; a secret that is neither in the scope nor a
  dependency of one is never fetched, and a scope whose intersection with the
  selected profile is empty contacts no provider at all (resolve and report
  results then carry an empty `provider`). A scope's own list must name at least
  one secret, with no blank or repeated entries.
  `run --scope` removes every manifest-declared secret the scope does not
  admit from the child environment — across all profiles, even one the parent
  already exported — so no value can leak into the launched process; a secret
  the scope lists is kept even when the selected profile does not declare it.
  `export --scope` emits the scoped subset but unsets nothing, since no output
  format can express an unset. `set`, like `import`, ignores an ambient
  `SECRETSPEC_SCOPE` entirely, and a blank `--scope` (or a blank
  `SECRETSPEC_SCOPE`) clears an inherited scope instead of deferring to it. Under
  project `extends`, a child scope replaces the parent scope of the same name
  outright rather than unioning their secret lists. Typed SDK loaders ignore an
  ambient `SECRETSPEC_SCOPE`, since a generated struct always expects the full
  profile; `import` likewise ignores scope and always copies the whole profile.
  Untyped SDK/FFI builders expose explicit scope selection and return the active
  scope in resolve/report results. Audit events for scoped `check`, `run`, and
  `export` operations record the scope name as well as the keys accessed or
  exposed.
- age provider (`age://`) for storing dotenv-style secret sets in an
  age-encrypted file, with ASCII armor by default, team recipient rosters,
  direct X25519 and SSH key support, native tagged recipients, and
  non-interactive age plugins. Hybrid ML-KEM-768 + X25519 keys are recommended
  for new setups to protect stored ciphertext against future quantum attacks.
- Read-only systemd credential provider (`systemd-credential://`) for resolving
  secrets and provider authentication credentials from the current service's
  `$CREDENTIALS_DIRECTORY`, including exact-name references and strict
  filename, file-type, and text validation.
- KeePass KDBX provider (`kdbx:`, `kdbx` build feature) for local encrypted
  databases. It reads KDBX 3 and KDBX 4, writes KDBX 4 with atomic file
  replacement, supports master passwords and key files, and can address
  standard or custom entry fields through secret references.
- The `required` field accepts `at_least_one` and `exactly_one` group tables,
  supporting overlapping alternative and mutually exclusive credentials
  across `check`, `run`, and SDK resolution.
- OpenBao provider (`openbao://`, `openbao` build feature) with its
  own provider identity, documentation, and OpenBao CLI configuration through
  `BAO_ADDR`, `BAO_NAMESPACE`, `BAO_TOKEN`, and `BAO_TOKEN_PATH`. The
  provider also has OpenBao-prefixed AppRole and JWT inputs; corresponding
  `VAULT_*` names remain compatibility fallbacks. Compatible KV and standard
  authentication mechanics are shared internally with the Vault provider.
  Vault-compatible addresses accept trailing slashes, and AppRole/JWT login
  exchanges now honor the configured namespace. Reported provider URIs strip
  endpoint credentials while retaining non-secret store and authentication
  attribution.
- Vault / OpenBao JWT/OIDC authentication (`?auth=jwt`) logs in through a
  configured Vault role using `VAULT_JWT`, or requests a short-lived OIDC token
  automatically in GitHub Actions and Forgejo Actions jobs with `id-token:
  write`. The role and optional audience can be set in the provider URI or with
  `VAULT_JWT_ROLE` and `VAULT_JWT_AUDIENCE`.
- The Python SDK now publishes a Windows x64 wheel to PyPI, so
  `pip install secretspec` and `uv add secretspec` work on Windows.
  ([#177](https://github.com/cachix/secretspec/issues/177))
- The Ruby SDK now publishes a Windows gem (`x64-mingw-ucrt`) to RubyGems, so
  `gem install secretspec` works with RubyInstaller on Windows.
- The PHP SDK now publishes prebuilt Windows x64 extension binaries
  (`secretspec-php-native-<php>-nts-x86_64-pc-windows-msvc.dll`) alongside the
  Linux and macOS builds on each release.

### Changed

- The Bitwarden Secrets Manager provider now invokes the separately installed
  official `bws` CLI instead of linking the Bitwarden SDK. This removes the
  SDK's restricted-license dependency from SecretSpec distributions while
  preserving project-scoped reads, writes, access-token credentials, and
  EU/self-hosted server selection.
- Secret status output now emphasizes secret names, de-emphasizes descriptions,
  and omits placeholder text when a description is unavailable, making long
  `check` and `import` results easier to scan.
  ([#139](https://github.com/cachix/secretspec/issues/139))

### Fixed

- BWS CLI writes preserve secret keys and values that begin with `-`, and
  hostless BWS provider URIs stay pinned to Bitwarden's default server even
  when ambient BWS profiles or server settings are configured.
- The dotenv provider rejects variable names its parser cannot read back
  (anything outside `[A-Za-z_][A-Za-z0-9_.]*`, for example a `ref` item
  containing a dash) instead of writing a line that made every later read and
  write of the whole file fail to parse. The rejection happens before the CLI
  prompts for a value and names the offending item.

## [0.16.0] - 2026-07-17

### Added

- Composed secrets derive read-only values such as connection strings from
  other declared secrets using strict `${UPPERCASE_NAME}` templates; names must
  match `[A-Z][A-Z0-9_]*`, `$$` produces a literal dollar sign, and ordinary
  braces remain literal. Dependencies are order-independent, may include other
  compositions, and are validated for unknown references and cycles before
  provider access; unlike dotenv expansion, values are substituted once
  without ambient environment lookup, fallback operators, recursive expansion,
  or silent empty replacements.
- C# SDK (`Cachix.SecretSpec`, available in 0.16): resolve secrets from .NET
  through the shared native resolver, with fluent builder and one-shot APIs,
  typed failure exceptions, value-free preflight reports, provenance,
  environment export, typed-codegen input, and deterministic cleanup of
  `as_path` files. The trimming-safe, NativeAOT-compatible NuGet package
  includes native resolver builds for glibc and musl Linux x64/Arm64, macOS
  x64/Arm64, and Windows x64/Arm64; Windows applications do not need a separate
  Visual C++ Redistributable.
- Infisical provider (`infisical://`), for Infisical Cloud and self-hosted
  instances. Authenticates as a machine identity via Universal Auth, whose
  `client_id` and `client_secret` can be sourced as provider credentials (with
  `INFISICAL_CLIENT_ID`/`INFISICAL_CLIENT_SECRET` fallbacks), or with a
  ready-made `token`/`INFISICAL_TOKEN`. A profile names the Infisical
  environment, so a `production` profile reads the `production` environment;
  projects whose environments do not correspond to profiles pin one with
  `?env=`, and profiles stay separate either way. Secrets live at
  `/secretspec/{project}/{profile}` (`?path=` overrides the prefix), with keys
  stored verbatim, and secrets sharing a folder are fetched in one request. A
  folder's imported secrets resolve too, with Infisical's own precedence. A
  secret's `ref` can name an Infisical secret by folder, key and `version`.
  Self-hosted and EU instances are named by the URI host, `INFISICAL_DOMAIN`, or
  Infisical's legacy `INFISICAL_API_URL`. Provider selection and Rust API
  documentation identify Infisical as available from SecretSpec 0.16.

## [0.15.0] - 2026-07-16

### Added

- Gopass provider (`gopass://`) for GPG-based password manager with git-synced password store.
- `secretspec export` command that resolves every secret for the active profile
  and writes them to stdout without running a command, in a chosen `--format`:
  `shell` (`export KEY='value'`, for `eval "$(secretspec export)"`), `dotenv`,
  `json`, or `gha` (appends to `$GITHUB_ENV` and emits `::add-mask::` for each
  value). Unlike `run` it never prompts and exits non-zero on a missing required
  secret, so CI can gate on it.
- Azure Key Vault provider (`akv://`). Authenticates via a service principal
  whose `tenant_id`, `client_id`, and `client_secret` can be sourced as provider
  credentials (with `AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET`
  fallbacks), falling back to a signed-in Azure CLI / Azure Developer CLI
  session when none are available; managed identity and
  AKS workload identity are also available via `?auth=managed_identity` and
  `?auth=workload_identity`. Sovereign clouds can be addressed with a full
  DNS hostname or an explicit `?suffix=` override. Project/profile/key
  components use lowercase, unpadded Base32 so case and punctuation remain
  distinct within Azure's restricted, case-insensitive secret-name namespace.
- The `awssm` provider accepts `kms_key_id` and `tag.NAME=VALUE` query
  parameters (e.g. `awssm://prod@us-east-1?kms_key_id=alias/my-key&tag.team=platform`).
  Both are applied only when secretspec creates a secret, so accounts that enforce
  a customer-managed KMS key or "tag-on-create" guardrails (an SCP requiring
  `aws:RequestTag/*` on `CreateSecret`) can now store secrets. A pre-existing
  secret keeps the key and tags it was created with.
- PHP SDK (`cachix/secretspec`): resolve secrets from PHP, Laravel, and Symfony
  over the same shared resolver as the other language SDKs. It ships as a native
  PHP extension that embeds the resolver (works under PHP-FPM with no
  `ffi.enable`, like `ext-redis`), with an `ext-ffi` fallback that dlopens the
  library at runtime for CLI and local development.
- Provider aliases can now source their own credentials from another provider.
  An alias in `[providers]` may declare a `credentials` map binding a semantic,
  provider-specific name (such as `access_token`, `token`, `role_id`, or
  `client_secret`) to a source: a bare provider spec, which reads the value at
  the convention path, or a table with a `ref` giving the exact coordinates.
  The credential is fetched from that provider and handed to the store, so a
  machine token can live in the OS keyring instead of a plaintext environment
  variable, and is never written
  into the environment of processes started by `secretspec run`. A configured
  credential is authoritative; providers retain their conventional environment
  fallback when no explicit credential is supplied. Chains are limited to one
  hop, and that limit is enforced wherever the alias appears, as a chain
  fallback or the default provider included. Provider credentials also apply
  when the alias is selected with an explicit `--provider <alias>` or
  `SECRETSPEC_PROVIDER`, and
  they are fetched from their source once per invocation and profile, then
  reused across all secrets routed at the alias (convention-path credentials
  live under a profile, so switching profiles re-reads them). Each source read,
  and each credential stored through `login`, is audited with a `credential`
  marker naming the semantic credential and the source store; a credential
  stored through `login` takes effect immediately. Unsupported credential names
  fail validation before a source is accessed.

  ```toml
  [providers]
  bws = { uri = "bws://project-uuid", credentials = { access_token = "keyring" } }
  akv = { uri = "akv://myvault", credentials = { tenant_id = "keyring", client_id = "keyring", client_secret = "keyring" } }
  vault = { uri = "vault://kv/app?auth=approle", credentials = {
    role_id   = { provider = "onepassword", ref = { vault = "Infra", item = "approle", field = "role_id" } },
    secret_id = { provider = "onepassword", ref = { vault = "Infra", item = "approle", field = "secret_id" } },
  } }
  ```

- `secretspec config provider login <alias>` prompts for each provider
  credential a provider alias declares and stores it in its source provider, so
  it can be read back on the next resolution. `secretspec config provider add`
  gains a repeatable `--credential NAME=PROVIDER` flag for declaring credential
  sources from the command line.

### Changed

- Rust SDK validation errors now store their detailed report out of line,
  reducing the size of `SecretSpecError` values while preserving diagnostics.
- Generated types now describe the values resolution can actually return:
  omitted `required` still means required, secrets supplied by a manifest
  default or generator are non-nullable, and profile-specific types include
  secrets inherited from the `default` profile. Profile JSON Schemas are now
  exhaustive (`additionalProperties: false`) for the same reason.
- A `ref` routed at a single store (an explicit `--provider`, a single-provider
  chain, or the default provider) is now checked up front, before any store is
  contacted, for coordinates that store cannot honor (e.g. a `field` ref pointed
  at a `.env` file), failing fast with a clear message instead of at fetch time.
  A `ref` on a multi-store fallback chain is still validated per store as the
  chain is walked, so a coordinate a later store cannot express never blocks a
  provider earlier in the chain that can.
- Provider chains accept bare provider names and `scheme:path` shorthand
  (e.g. `providers = ["keyring"]`), the same specs `--provider` accepts.
  Previously a chain entry had to be a declared alias or a full `scheme://` URI.
- An explicitly empty `providers = []` list now uses the default provider for
  `get` as well, matching how `check` and `run` already treated it.
- A `providers` chain whose *first* entry misspells `onepassword` as
  `1password` now fails up front with the corrective "use `onepassword`
  instead" message — the same hard error any other invalid primary gets —
  instead of warning and falling through to the rest of the chain. As a
  fallback entry it is still skipped with a warning, like any broken link.
- Rust SDK: `ProviderAlias::credentials` is a plain map whose empty state means
  "no provider credentials", rather than an `Option`, so the two ways of spelling
  an alias without credentials cannot diverge.

### Removed

- The unused public `Config::merge_with` and `Profile::merge_with` methods.
  Configuration inheritance (`extends`) is now applied entirely through the
  internal overlay used by the loader, so these self-wins merge helpers no
  longer had any callers.

### Fixed

- Configuration inheritance now loads an `extends` hierarchy as a DAG. Shared
  ancestors in diamond-shaped graphs are applied once instead of being reported
  as cycles, later entries in `extends` correctly override earlier entries, and
  profile `[defaults]` are inherited across source files.
- Runtime planning, semantic validation, Rust derive output, and JSON Schema
  generation now share one compiled effective-manifest model and one
  missing-value policy, preventing raw `required`/`default` interpretation from
  drifting between surfaces.
- Profile overrides no longer need to repeat the secret's `description`:
  validation now checks each secret's effective, merged configuration, so a
  partial override like `[profiles.development] DATABASE_URL = { default =
  "sqlite:///dev.db" }` inherits the description (and `type`, for `generate`)
  from the default profile instead of failing with "missing description".
  The merged view is also validated for real conflicts, so a `generate`
  secret in the default profile combined with a `default` value from an
  override or a profile `[defaults]` table is now rejected at load instead of
  silently generating a random value and ignoring the default. Validation
  errors are reported deterministically, attributed to the profile that
  declares the offending field, and `check` and `run` list secrets in stable
  name-sorted order.
- Provider fallback chains (`providers = [...]`) are now tried strictly in
  order: each link is resolved only when a read actually reaches it, and a
  broken link (an undefined alias, an unreachable store) is skipped with a
  warning so a working provider later in the chain still answers. `check`,
  `run`, and `get` all walk the chain the same way.
- `get` and `set` now record an audit event when a secret's provider routing
  fails to resolve (for example an undefined alias), matching how `check` and
  `run` audit every attempted read.
- A provider chain entry that misspells `onepassword` as `1password` now gets
  the same "use `onepassword` instead" correction that `--provider 1password`
  gives, instead of a generic undefined-alias error.
- Blank or whitespace-only profile and provider overrides (`--profile`,
  `SECRETSPEC_PROFILE`, `--provider`, `SECRETSPEC_PROVIDER`, and the Rust SDK
  builder) are now trimmed and treated as unset, so a padded value such as a
  trailing newline from `$(cat file)` can no longer select a nonexistent
  profile or provider.
- `import` prints its per-secret summary in a stable, name-sorted order.
- `run` no longer aborts when the environment contains a non-UTF-8 variable.
  Such variables are now passed through to the child process untouched, with
  resolved secrets overlaid on top.
- The prebuilt Linux addons of the Node SDK are now built against glibc 2.28
  (manylinux_2_28) with libdbus compiled in statically, so `npm install
  secretspec` works on Amazon Linux 2023, RHEL 8/9, and other distros with an
  older glibc, instead of the addon failing to load with "version `GLIBC_2.38'
  not found". ([#136](https://github.com/cachix/secretspec/issues/136))

## [0.14.0] - 2026-07-09

### Added

- **`ref`: native secret references on secrets**: a secret can name one
  externally managed secret by its store's own coordinates, instead of
  SecretSpec's `{project}/{profile}/{key}` naming:

  ```toml
  [profiles.production]
  DATABASE_URL = { description = "...", ref = { item = "db", field = "password" }, providers = ["prod_op"] }
  ```

  `item` is the store's own name for the secret (1Password item title, Vault
  KV path, AWS secret name or ARN, `.env` key, environment variable, ...);
  optional keys refine it where the store supports them: `field` (1Password
  field label, Vault KV field, AWS JSON key, keyring account), `vault` and
  `section` (1Password), and `version` (Google Secret Manager). Every provider
  resolves refs; coordinates a store has no equivalent for are rejected with a
  clear error rather than guessed at.

  The coordinates supply naming only — *which* store resolves them follows the
  same routing as every other secret (the secret's `providers` chain, the
  `--provider`/`SECRETSPEC_PROVIDER` override, or the default provider). That
  means refs compose with `providers` fallback chains, and an explicit
  override redirects them like any secret, e.g. at a `.env` fixtures file
  during tests. Writes are symmetric where the backend allows it:
  `secretspec set` and `check` prompting write through the coordinates in
  place (1Password `op item edit`, keyring, pass, dotenv, Bitwarden, Proton
  Pass, LastPass); Vault, AWS, and GCSM refs are read-only. Secrets sharing
  identical coordinates fetch once, and audit events record the coordinates in
  a new `ref` field. A `ref` also composes with `generate`: a missing
  referenced secret is minted and written straight to its coordinates.
- **Inline provider URIs in `providers` chains**: chain entries that are
  already URIs (`providers = ["onepassword://Production", "keyring"]`) now
  pass through without declaring a `[providers]` alias first.

### Changed

- **Faster multi-provider resolution**: `check`, `run`, and SDK resolution now
  group secrets by store and fetch the groups concurrently instead of one
  after another; within a group, `ref` secrets batch through the store's bulk
  surface where it has one (AWS `BatchGetSecretValue`, the single Bitwarden,
  Proton Pass, and 1Password listings) and otherwise resolve concurrently,
  each unique coordinate fetched once. CLI authentication (1Password,
  LastPass, Proton Pass) is probed once per account/session instead of once
  per provider instance.
- **Provider trait speaks one address vocabulary** (affects custom providers
  built on the Rust library): each provider now compiles SecretSpec's
  `{project}/{profile}/{key}` convention into its native coordinates via a
  new required `convention_address` method, and reads resolve every address
  through the same coordinate path a `ref` uses. The convention-only
  `get_batch` method is replaced by `get_many`, which takes addresses and so
  batches `ref` secrets too. A provider declares the `ref` coordinates it
  honors with `supported_coords` and the rest are rejected for it, and
  `allows_set` is replaced by `check_writable`, which returns the reason a
  write is refused rather than a bare `false`.
- **Manifest validation runs on load**: the semantic rules `secretspec.toml`
  documents (a required secret cannot carry a `default`, `generate` needs a
  `type`, `ref` coordinates must be non-empty and non-whitespace) are now
  enforced whenever the config is loaded. Configs that silently violated them
  previously will now fail with a pointed error.

### Fixed

- **onepassword**: URIs carrying an item path (e.g. the
  `onepassword://vault/Production` form some older docs showed) previously
  discarded the path silently and targeted a vault literally named `vault`.
  Item paths — including pasted `op://vault/item/field` references — now fail
  with an error spelling out the exact `ref` coordinates to write instead.
- **`set` on a read-only `ref`** reported "Provider '<name>' is read-only and
  does not support setting values", which is untrue of Vault, AWS, and GCSM —
  they write the conventional layout fine and refuse only refs. The store's own
  reason is now shown (e.g. writing one Vault field would clobber the sibling
  fields at the same KV path).

## [0.13.0] - 2026-07-03

### Added

- **Language SDKs for Python, Go, Ruby, Node.js / TypeScript, and Haskell**
  (`secretspec-py`, `secretspec-go`, `secretspec-rb`, `secretspec-node`,
  `secretspec-hs`). Resolve the secrets declared in your `secretspec.toml` from
  each language using the same providers, profiles, fallback chains, and
  generators as the CLI and the Rust SDK — no per-language configuration. Each
  mirrors the Rust derive crate's vocabulary: a builder taking a provider,
  profile, and access reason; `load()` returns the resolved secrets and can export
  them into the process environment, while a value-free `report()` previews how
  each secret would resolve without reading any value. A missing required secret
  raises a typed error; `as_path` secrets are returned as a readable file path,
  with an explicit (or scope-based) cleanup that removes the backing temp file.
- **`secretspec-ffi` crate**: a small, versioned C ABI for resolving secrets from
  any language, plus the public Rust building blocks the SDKs are built on
  (`Secrets::resolve()` and `Secrets::report()`). Use it to write a binding for a
  language we do not ship yet.
- **`secretspec schema`**: emits a JSON Schema for your manifest's typed shape
  (the union of all profiles, or one profile via `--profile`). Feed it to
  [quicktype](https://quicktype.io) to generate idiomatic typed classes in any
  language, populated from each SDK's `fields()` map — type-safe secret access
  without hand-writing a generator per language.
- **`secretspec check --json` / `--explain`**: a value-free report of how every
  declared secret resolves for the active profile — its status (`resolved`,
  `missing_required`, `missing_optional`), where the value would come from
  (a provider, with a credential-free URI; a generator; or a committed default),
  and whether it is exposed `as_path`. Values are never included, and both flags
  skip the interactive prompt and exit non-zero when a required secret is missing,
  so CI can gate on them. The same report is available to the Rust SDK via
  `ValidatedSecrets::report()` / `ValidationErrors::report()`.

### Fixed

- A per-secret provider chain whose primary provider errors (e.g. an unreachable
  vault) and whose fallback chain yields no value now surfaces that provider error
  instead of silently reporting the secret as `missing_required`, so a provider
  outage is distinguishable from an unprovisioned secret.

## [0.12.2] - 2026-06-22

### Added

- The `pass` provider accepts a `store_dir` query parameter (e.g.
  `pass://?store_dir=/path/to/store`) to use a password store directory other
  than the default `~/.password-store`. It is applied as `PASSWORD_STORE_DIR`
  scoped to each `pass` invocation.

### Fixed

- Provider URIs now correctly round-trip query parameters whose values contain
  characters that are significant in a query string (`&`, `+`, `#`, `%`, and
  spaces). Previously such characters in the `awssm` `prefix` (and the new `pass`
  `store_dir`) were emitted unescaped, so the value could be silently truncated
  or altered when the URI was parsed back.
- `secretspec import <FROM>` now accepts a provider alias (from `[providers]` or
  the global `[defaults.providers]`) as its source, not just a literal provider
  URI. Passing an unknown provider or alias now reports the available aliases.

## [0.12.1] - 2026-06-15

### Fixed

- Windows: a `dotenv://` provider URI built from an absolute path (e.g.
  `dotenv://C:\path\.env`) no longer fails to parse with "invalid port number".
  The drive-letter colon was being read as a `host:port` separator; such paths
  are now carried through the URL intact.
- Windows: the audit log no longer fails to reset at its size cap. Truncation on
  the append-only handle was denied by the OS; it now truncates through a
  separate write handle.
- Relative `dotenv` paths (e.g. `dotenv:.config/.env`) now resolve against the
  directory containing `secretspec.toml` instead of the current working
  directory. Running `secretspec run --file ../secretspec.toml` from a
  subdirectory previously failed to find the referenced `.env` file because it
  was looked up relative to the working directory rather than the project root
  (#59). Absolute `dotenv` paths are unaffected.
- The `protonpass` provider now works with Proton Pass CLI `pass-cli >= 2.0.3`.
  The `item list --output json` payload changed shape in 2.0.3 (the item title
  moved from a nested `content.title` to a top-level `title`, and `content` was
  dropped from list output), which made `secretspec` report active secrets as
  missing. Both the old (`<= 2.0.2`) and new (`>= 2.0.3`) list shapes are now
  accepted. ([#104](https://github.com/cachix/secretspec/issues/104))

## [0.12.0] - 2026-06-08

### Added

- Audit logging for secret access, on by default. Every secret read and write,
  from both the CLI and the Rust SDK, is appended to a local per-user log as JSON
  Lines. Only metadata is recorded (secret names, the serving provider with any
  embedded credentials redacted, outcome, reason, and actor including a detected
  coding agent); secret values are never written. Each operation is recorded once:
  `get` and `set` per secret, `check` as a single event, `run` when the child
  process starts, and `import` per copied secret. Auditing never blocks secret
  access; if it cannot write the log it warns on stderr and continues. The log is
  a single file capped at 1 MiB. It is configured per machine via the `[audit]`
  table in `~/.config/secretspec/config.toml` (not the project's
  `secretspec.toml`), so a cloned repository cannot redirect or silence it. The
  new `secretspec audit` command reads the log, with `--project`, `--action`,
  `--tail`/`-n`, and `--json` filters. See
  [Audit Logging](https://secretspec.dev/concepts/audit/) for details.
- `--reason` CLI flag (and `SECRETSPEC_REASON` env var) records a human-readable
  reason for a session's secret access, forwarded to providers that support audit
  logging. `SECRETSPEC_REASON` is honored across the SDK/library too: it is resolved
  by `Secrets::load`/`load_from` (so `secretspec-derive`-generated code and other
  library callers can satisfy the `require_reason` policy and supply an audit reason
  without code changes), and `Secrets::with_reason(...)` sets it explicitly, taking
  precedence. The `secretspec-derive`-generated typed builder also gains a
  `with_reason(...)` method, so SDK callers can satisfy `require_reason` in code
  (not only via the env var). Blank or whitespace-only reasons are ignored so they
  cannot satisfy the policy. Backed by a new `Provider::set_reason` trait method
  (default no-op).
- `[project] require_reason` policy in `secretspec.toml`, controlling when secret
  access must supply an explicit reason. Accepts `"agents"` (the default — require
  a reason only when an AI agent is detected), `true` (require it from every
  caller), or `false` (never). Agent detection is delegated to the
  `detect-coding-agent` crate (Claude Code, Cursor, Codex, Gemini CLI, Copilot,
  ...), plus a `SECRETSPEC_AGENT` opt-in for harnesses it does not recognize.
  Because the tool enforces it and it is checked into the repo, the policy applies
  uniformly and cannot be bypassed by an individual tool's configuration. An invalid
  `require_reason` value is rejected at config-parse time rather than silently
  falling back to the default. The policy is inherited through `extends`: a shared
  base config's `require_reason` applies to every config that extends it, unless the
  child sets its own.
  **Note:** the default `"agents"` means AI agents must now pass a reason out of
  the box.
- `bws` provider now accepts an optional server base in the URI
  (`bws://[server-base@]project-uuid`) to target EU cloud or self hosted
  Bitwarden instances. When set, the identity and API endpoints are derived as
  `https://<server-base>/identity` and `https://<server-base>/api`; omitting it
  keeps the `bitwarden.com` US cloud default.

### Changed

- Minimum supported Rust version raised to 1.92 (required by the
  `detect-coding-agent` dependency). The devenv toolchain is pinned accordingly.

### Fixed

- Proton Pass provider now works with `pass-cli` >= 2.1.0 agent sessions. Since
  2.1.0, audited item operations (`item view`, `item create`, `item delete`)
  fail unless `PROTON_PASS_AGENT_REASON` is set, which made existing secrets
  appear missing under an agent session. The provider now sets this variable on
  every `pass-cli` invocation. The reason is resolved as `--reason`/`with_reason`,
  then `PROTON_PASS_AGENT_REASON`, then a secretspec-versioned default
  (`secretspec/<version> (https://secretspec.dev)`); each source is normalized first,
  so a blank reason falls through to the next rather than masking it. It is ignored by
  older releases and non-agent sessions.
- `secretspec init` now serializes the generated `secretspec.toml` with
  `toml_edit` instead of hand-interpolating strings. This fixes several cases
  that previously produced TOML that could not be parsed back: a project name,
  secret description, or default value containing a double-quote, backslash,
  control character (including U+007F), or newline; a secret name containing a
  dot (e.g. `FOO.BAR`, which dotenvy accepts and which silently collapsed to a
  nested key); and a configured `project.extends`, which was dropped entirely.
  Output is now also deterministically ordered.
- `secretspec init` no longer defines a conflicting `-f` short flag for
  `--from`; `-f` is reserved for the global `--file` option. The duplicate
  short flag made `secretspec init` panic in debug builds and was ambiguous in
  release builds.

## [0.11.0] - 2026-05-22

### Added

- AWS Secrets Manager (`awssm`) provider: support for a `?prefix=` query
  parameter in the provider URI (e.g., `awssm://us-east-1?prefix=myteam`).
  The prefix is prepended to all secret names
  (`myteam/secretspec/{project}/{profile}/{key}`). Closes
  [#92](https://github.com/cachix/secretspec/issues/92).
- Provider aliases can now be declared at the project level in a top-level
  `[providers]` table of `secretspec.toml`. Aliases declared there are visible
  to per-secret `providers = [...]` lists and to `--provider`/`SECRETSPEC_PROVIDER`,
  and are merged with the existing user-level `[defaults.providers]` map in
  `~/.config/secretspec/config.toml`. On name conflicts the project entry wins,
  so a team's checked-in mapping cannot be silently shadowed by a stale local
  config. Closes [#79](https://github.com/cachix/secretspec/issues/79) and
  addresses the "share aliases via VCS" half of
  [#90](https://github.com/cachix/secretspec/issues/90).

### Fixed

- Profile-not-found errors no longer surface as the confusing
  `Secret 'Profile 'X' not found' not found`. They now use the dedicated
  `InvalidProfile` variant and include the list of profiles defined in
  `secretspec.toml`, e.g.
  `Invalid profile: 'production' is not defined in secretspec.toml. Available profiles: default, dev`.
  Affects `check`, `run`, `get`, `set`, and `import`. Surfaced via
  [#79](https://github.com/cachix/secretspec/issues/79).

## [0.10.1] - 2026-05-11

### Fixed

- `secretspec check`: optional secrets that aren't set no longer render with a
  green `✓` and aren't counted as "found" in the trailing summary. They now
  display with the same blue `○ (optional)` styling already used in the
  missing-required path, and the summary appends `, N optional` whenever
  optional secrets are absent (e.g. `Summary: 4 found, 0 missing, 1 optional`).
  If every optional secret is set, the summary line stays in its previous
  `X found, Y missing` form. Fixes
  [#72](https://github.com/cachix/secretspec/issues/72).

## [0.10.0] - 2026-05-11

### Added

- Proton Pass provider that stores secrets in a Proton Pass vault via the
  `proton-pass` CLI. Configured as `protonpass://<vault>`; items are
  organized per project / profile and read / write both go through the
  CLI.

### Fixed

- OnePassword provider: the auth preflight now probes `op vault list` instead
  of `op whoami`. Under the 1Password desktop app's delegated-session
  integration, `op whoami` reports `account is not signed in` even when
  `op item get` / `op vault list` work fine — so every secret read or write
  failed at preflight with a misleading "not signed in" error. `op vault
  list` exercises the actual access path and succeeds when the desktop app
  can serve secrets. Additionally, `OP_SESSION_*` environment variables
  (left over from `eval $(op signin)`) are now stripped before spawning
  `op` so a stale shell session can't shadow the desktop integration. Auth
  failure and install hints now point users at desktop integration as the
  primary local-dev path. Fixes
  [#80](https://github.com/cachix/secretspec/issues/80).
- Vault / OpenBao provider: HTTPS requests now trust certificates from the
  operating system trust store (and honor `SSL_CERT_FILE` / `SSL_CERT_DIR`),
  so servers fronted by a private / internal CA work without modification.
  Previously the bundled `webpki-roots` set was the only trust anchor and any
  non-public CA produced `Failed to connect to Vault ... error sending
  request`. Switches the `reqwest` workspace dependency from `rustls-tls` to
  `rustls-tls-native-roots`. Fixes
  [#85](https://github.com/cachix/secretspec/issues/85).

## [0.9.1] - 2026-05-07

### Changed

- Dropped the `serde-envfile` dependency in favor of a small in-tree
  `.env` serializer. The previous git-pinned fork blocked publishing to
  crates.io; the new serializer applies the same escapes (backslash,
  double quote, dollar, newline) that the fork added and emits keys in
  sorted order for stable diffs.

## [0.9.0] - 2026-05-07

### Fixed

- The `--provider` CLI flag now correctly takes precedence over the
  `SECRETSPEC_PROVIDER` environment variable. Previously the env var was
  consulted before the value forwarded from `--provider` (via `set_provider`),
  so users could not temporarily override the provider on the command line
  while the env var was set. Fixes
  [#77](https://github.com/cachix/secretspec/issues/77).
- Per-secret `providers = [...]` chains now behave as a true fallback chain
  when an upstream provider errors (e.g. a 403 from a vault the current user
  cannot access). Previously the first provider's error short-circuited the
  whole operation; now the error is logged as a warning and the next provider
  in the chain is tried. The original error is only surfaced if every
  provider in the chain failed (so genuine outages still bubble up), or if
  the secret has no alternative to fall back to. Fixes
  [#83](https://github.com/cachix/secretspec/issues/83).
- `secretspec run` now removes the temporary files it creates for
  `as_path = true` secrets after the child process exits. Previously the
  files were leaked under `/tmp` because `std::process::exit` skipped the
  destructors that own them. Fixes
  [#71](https://github.com/cachix/secretspec/issues/71).
- Provider URIs now support spaces and special characters in names
  (e.g., `onepassword://Home Lab`). All providers receive automatically
  percent-decoded values via a new `ProviderUrl` wrapper type.
- dotenv provider: setting a secret no longer corrupts neighboring values
  that contain double quotes, backslashes, dollar signs, or newlines
  (e.g. JSON values). The underlying `serde-envfile` serializer did not
  escape these characters; fix is pinned via a fork until
  [lucagoslar/serde-envfile#6](https://github.com/lucagoslar/serde-envfile/pull/6)
  lands upstream. Fixes [#74](https://github.com/cachix/secretspec/issues/74).
- `--provider` (and `SECRETSPEC_PROVIDER`) is now honored on every command
  even when a `providers = [...]` chain is configured for the secret or
  profile. Previously `set`, `get`, `check`, `import`, and `run` silently
  used the first provider in the chain and ignored the explicit override,
  making `secretspec set --provider <alias>` a no-op against the requested
  target. The flag now consistently takes precedence: `set`/`import`/
  generation write only to the chosen provider, and `get`/`validate` read
  only from it (no chain fallback). Provider aliases declared in
  `~/.config/secretspec/config.toml` can now be passed directly to
  `--provider`. Fixes [#81](https://github.com/cachix/secretspec/issues/81).

### Added

- BWS (Bitwarden Secrets Manager) provider with async SDK integration, secret caching, and full read-write support (requires `--features bws`)

### Changed

- `secretspec-derive` now depends on `secretspec` with `default-features = false`, avoiding pulling in CLI and provider features when only the derive macro is used.

## [0.8.2] - 2026-03-19

### Changed

- All provider features (`gcsm`, `awssm`, `vault`) are now enabled by default
- AWS Secrets Manager (`awssm`) provider: batch fetching via `BatchGetSecretValue` API,
  reducing N sequential API calls to ceil(N/20) batched calls. For 30 secrets this means
  2 API calls instead of 30. **Note:** requires the `secretsmanager:BatchGetSecretValue`
  IAM permission in addition to existing permissions.

## [0.8.1] - 2026-03-15

### Added

- `rsa_private_key` secret generation type: generates RSA private keys in PKCS1 PEM format,
  defaults to 2048 bits, configurable via `generate = { bits = 4096 }`

### Fixed

- Check provider authentication (e.g. OnePassword, LastPass) before prompting
  user for secrets, via a `PreflightGuard` that runs the check exactly once
  per provider instance

## [0.8.0] - 2026-03-11

### Added

- HashiCorp Vault / OpenBao (`vault`) provider for Vault KV v1/v2 secret storage, with support
  for namespaces, TLS configuration, and OpenBao compatibility (requires `--features vault`)
- AWS Secrets Manager (`awssm`) provider for AWS secret storage integration (requires `--features awssm`)
- Support running secretspec from subdirectories: the CLI now walks up the directory tree to find the nearest `secretspec.toml`, similar to `cargo` and `git`. Also adds a `-f`/`--file` flag (and `SECRETSPEC_FILE` env var) to explicitly specify the config file path (#59)

### Changed

- Extract shared `block_on` async helper from AWSSM and GCSM providers into `provider::block_on`

### Fixed

- GCSM provider no longer panics when called from within an existing tokio runtime

## [0.7.2] - 2026-02-24

### Added

- Keyring and pass providers now support `folder_prefix` via URI (e.g., `keyring://secretspec/shared/{profile}/{key}`)
  to share secrets across projects, matching the existing OnePassword and LastPass behavior

### Changed

- Support `XDG_CONFIG_HOME` on macOS by switching from `directories` to `etcetera` crate.
  Existing macOS configs at `~/Library/Application Support/secretspec/` are automatically
  migrated to `~/.config/secretspec/` (#28)

### Fixed

- Reject empty values when setting a secret

## [0.7.1] - 2026-02-08

### Changed

- Improved interactive prompt for missing secrets: lists all missing secrets upfront with descriptions, adds step counter (`[1/3]`), and uses `inquire::Password` for consistent masked input. Removed `rpassword` dependency.

### Fixed

- Use a fork of inquire to support setting multi-line secrets (#32)

## [0.7.0] - 2026-02-08

### Added

- Declarative secret generation: secrets can now be auto-generated when missing by adding
  `type` and `generate` fields to secret config. Supported types: `password`, `hex`, `base64`,
  `uuid`, and `command` (for arbitrary shell commands). Generation triggers during `check`/`run`
  when a secret is missing, and the generated value is stored via the configured provider.

### Changed

- OnePassword provider: Significant performance improvement by caching authentication status
  and using batch fetching with parallel threads. Reduces CLI calls from 2N sequential to
  ~2 sequential + N parallel for N secrets.

## [0.6.2] - 2026-01-27

### Added

- CLI: Add `--no-prompt` (`-n`) flag to `secretspec check` command for non-interactive mode.
  When used, the command exits with non-zero status if secrets are missing instead of prompting for values.
  Useful for CI/CD pipelines, scripts, and automation. (#55)

## [0.6.1] - 2026-01-15

### Fixed

- OnePassword provider: Fix duplicate item creation when existing item has no extractable value.
  Now uses `op item list` for existence checks and updates by item ID to avoid ambiguity.
- OnePassword provider: Handle "More than one item matches" error gracefully by falling back to ID-based lookup.

## [0.6.0] - 2026-01-12

### Added

- Google Cloud Secret Manager (GCSM) provider for GCP secret storage integration (#53)

### Fixed

- LastPass provider: Fix creating new secrets by using correct `lpass add` command instead of non-existent `lpass set` (#54)

## [0.5.1] - 2026-01-02

### Changed

- CI: Updated macOS runners from deprecated macos-13 to macos-15 (Intel) and macos-latest (ARM)

## [0.5.0] - 2026-01-02

### Added

- Pass (password-store) provider for Unix password manager integration
- `ensure_secrets()` method is now public in the Rust SDK
- Support specifying full file paths (ending in `.toml`) in `extends` field, in addition to directory paths

### Changed

- Performance: avoid double validation in `check()` for happy path

### Fixed

- Display correct error message when extended config file is not found, instead of the misleading "No secretspec.toml found in current directory" error

## [0.4.1] - 2025-11-27

### Added

- OnePassword provider: Support for `SECRETSPEC_OPCLI_PATH` environment variable to specify custom path to the OnePassword CLI
- OnePassword provider: Automatic detection of Windows Subsystem for Linux 2 (WSL2) and use of `op.exe` on that platform
- Documentation for `as_path` option in configuration reference, Rust SDK docs, and landing page
- Documentation for per-secret providers with fallback chains on landing page

### Changed

- OnePassword provider: Use stdin instead of temporary files when creating items for WSL2 compatibility (WSL paths are invalid when passed to Windows executables)

### Fixed

- Output status/progress messages to stderr instead of stdout, fixing direnv integration where stdout was evaluated as shell code

## [0.4.0] - 2025-11-24

### Added

- Profile-level default configuration: `profiles.<name>.defaults` section for shared settings across secrets in a profile
- Default providers for profiles: define common providers once and have all secrets use them unless overridden
- Default values and required settings can now be specified at profile level to reduce repetition
- `as_path` option for secrets: write secret values to temporary files and return the file path instead of the value. Temporary files are automatically cleaned up when the resolved secrets are dropped in Rust SDK usage. For CLI commands (`get` and `check`), temporary files are persisted and NOT deleted after the command exits. In the Rust SDK, fields with `as_path = true` are generated as `PathBuf` or `Option<PathBuf>` instead of `String`

### Changed

- Secret `required` field is now `Option<bool>` to allow profile-level defaults to apply when not explicitly set
- Secret `default` field can now inherit from profile-level defaults if not specified per-secret
- Secret `providers` field can now inherit from profile-level defaults if not specified per-secret
- Profile defaults only apply to secrets that don't explicitly set these fields

## [0.3.4] - 2025-11-09

### Changed

- `Secrets::check()` now returns `Result<ValidatedSecrets>` instead of `Result<()>`, allowing callers to access the validated secrets

## [0.3.3] - 2025-09-10

### Fixed

- CLI: Count optional secrets as "found" in the summary

## [0.3.2] - 2025-09-10

### Added

- Support for piping multi-line secrets via stdin

### Fixed

- Import command now resolves secrets from all profiles, not just the active profile (fixes issue #36)
- Fix incorrect stats in the summary for certain configurations

## [0.3.1] - 2025-07-28

### Fixed

- Installers for arm/linux

## [0.3.0] - 2025-07-25

### Added

- Integrate `secrecy` crate for secure secret handling with automatic memory zeroing
- Add `reflect()` method to Provider trait for provider introspection
- Export `Provider` trait from secretspec crate for use in derived code

### Changed

- Made keyring provider optional via `keyring` feature flag (enabled by default)
- Unified provider parsing logic in init command to support all provider formats consistently
- Downgraded keyring dependency to 3.6.2
- Updated `with_provider` in derive macro to accept `TryInto<Box<dyn Provider>>` for consistent provider handling

### Fixed

- Fixed secret optionality logic: having a default value no longer makes a secret optional in generated types

## [0.2.0] - 2025-07-17

### Changed

- SDK: Added `set_provider()` and `set_profile()` methods for configuration
- SDK: Removed provider/profile parameters from `set()`, `get()`, `check()`, `validate()`, and `run()` methods
- SDK: Embedded Resolved inside ValidatedSecrets

### Fixed

- Fix stdin handling for piped input in set/check commands
- Fix SECRETSPEC_PROFILE and SECRETSPEC_PROVIDER environment variable resolution
- Ensure CLI arguments take precedence over environment variables
- add CLI integration tests
- Update test script to handle non-TTY environments correctly

## [0.1.2] - 2025-01-17

### Fixed

- SDK: Hide internal functions

## [0.1.1] - 2025-07-16

### Added

- `secretspec --version`

### Fixed

- Profile inheritance: fields are merged with current profile taking precedence

## [0.1.0] - 2025-07-16

Initial release of SecretSpec - a declarative secrets manager for development workflows.
