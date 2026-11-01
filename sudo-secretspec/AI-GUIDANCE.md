# AI and automation contract for sudo-secretspec

Use this policy in `AGENTS.md`, skills, runbooks, and autonomous-agent prompts for deployments of sudo-secretspec.

## Required behavior

- Use only the installed `/usr/local/bin/sudo-secretspec` client for credential CRUD and use.
- Supply a short operational `--reason` for every `add`, `undeclare`, `set`, `delete`, `get`, `check`, `export`, `template-check`, `schema`, or `run` operation. `add` additionally requires `--description`: it declares a secret, it does not set a value. The protected audit ledger stores only its SHA-256 digest.
- Run a consumer as `sudo-secretspec run --reason "purpose" -- <command>` instead of extracting values into shell history or command arguments.
- Treat an unavailable broker, failed audit append/verification, declaration mismatch, authorization failure, or non-advisory drift finding as a hard stop. `doctor` marks advisory findings — currently `LEGACY_VAULT_CLUTTER`, `PENDING_ROLLBACK`, `CLIENT_DUPLICATE`, `UPGRADE_AVAILABLE`, and the three `SUDOERS_NEIGHBOUR_*` codes — and still exits zero; report them to the operator and continue. Read the `advisory` field rather than matching code names: that list has already grown three times, and this sentence is the wrong place to learn it has grown again.
- Treat `CLIENT_SHADOWED` as a hard stop and do not work around it: it means a different `sudo-secretspec` would run instead of the installed client, so no operation you perform can be trusted to have reached the boundary. Report the reported path to the operator.
- Report only the non-secret error and request operator action for boundary installation or repair.
- Normal broker-mediated credential operations are autonomous when the installed sudoers policy allows them.

## Forbidden behavior

Never:

- invoke `secretspec` directly for a managed deployment;
- select or create another manifest, provider, profile, binary, dotenv file, or credential store;
- set `SECRETSPEC_FILE`, `SECRETSPEC_PROVIDER`, `SECRETSPEC_PROFILE`, or a direct-mode bypass;
- read, write, copy, symlink, regenerate, relocate, chmod, chown, rename, unlink, or repair protected backing files;
- weaken permissions or ACLs to inspect the store;
- place secret values in reasons, logs, audit metadata, command arguments, issue text, commits, tests, or documentation;
- treat inability to stat a `0700` store as evidence that files are absent;
- use a watchdog or drift check to mutate or repair state.

## Mediated surface

The companion is not a wrapper around the whole engine. It exposes `add`, `undeclare`, `set`,
`delete`, `get`, `check`, `export`, `run`, `template-check`, `schema`, `audit-verify`, and
`doctor`, plus the operator-only lifecycle commands `install`, `uninstall`, and
`rollback`. Five engine subcommands have **no** companion equivalent: `config`,
`import`, `init`, `cache`, and `audit`.

Their absence is deliberate, not an oversight, and it is not a gap to route
around. Combined with the rule above against invoking `secretspec` directly, the
correct response to needing one of these is to ask the operator — never to reach
past the boundary.

Two must stay excluded, because exposing them would defeat the boundary rather
than extend it:

- **`config`** rewrites which provider and profile resolve. A caller who can
  repoint those chooses which store answers, which is the single decision the
  protected installed config exists to take away from the caller.
- **`import`** copies values between providers. A caller who can name the
  destination can move every managed secret into a store the boundary does not
  own, which is exfiltration wearing the clothes of a migration.

The remaining three are open questions for the operator rather than settled
policy. `init`, `cache`, and `audit` are judgement calls: each touches state the
boundary owns, but none hands the caller the provider/profile choice the way
`config` and `import` do. Do not assume their absence is permanent, and do not
assume it is arbitrary.

## Declaration lifecycle

Tracked Git content contains declarations only. A new name must first be reviewed and released in the declaration file. `sudo-secretspec add NAME --description "what it is" --reason "purpose"` declares the name in the runtime manifest and creates **no** value; `sudo-secretspec set NAME --reason "purpose"` then supplies one. `add` writes no `required` key by default, so the declaration inherits the profile's `[defaults] required` (usually required, but not always — which is why there are two flags). In `0.19.1-sudo.12+`, pass `--optional` for a secret only some hosts need, so `check` stays green everywhere else, or `--required` to force it required where the profile's defaults set `required = false`; the two cannot be combined, and omitting both writes exactly what `add` wrote before. Requiredness decides whether `check` passes, so it is not cosmetic. Neither flag can *change* an existing declaration — `add` refuses an already-declared name; flip it with `delete`, `undeclare`, then `add` again. Adding at runtime puts the manifest ahead of the tracked declarations, so mirror the declaration through review/release — `template-check` reports the drift until you do. Removing a declaration that is in the tracked file stays a review/release decision. A declaration **you** added at runtime has a runtime inverse: `sudo-secretspec delete NAME --reason "purpose"` drops the value, then `sudo-secretspec undeclare NAME --reason "purpose"` drops the declaration, restoring the manifest and clearing the `template-check` drift your `add` created. `undeclare` refuses a name present in the tracked declarations file, and refuses a name that still holds a value, so it can only ever move the runtime manifest back toward the template. The broker rolls manifest/value mutations back on failure and records an explicit `unknown` terminal state if restoration cannot be proven.

`template-check` compares raw bytes, not parsed structure. That is deliberate: it is what makes a green result mean the running manifest is the exact bytes that were reviewed, and what makes `add` → `undeclare` a provable byte-for-byte undo. Do not propose relaxing it to a semantic comparison; the reasoning, and the cheaper fix for the resync friction it causes, are recorded in `docs/design/template-check-resync.md`.

## Security scope

Ownership: the public client and the sudoers policy belong to root; the broker
binary, the config and the shared assets belong to the service user. A
compromised service-user process could therefore modify the broker and config,
which is why this boundary is friction plus audit, not isolation.

The public client may export the full declared environment to a requested child process; this is intentional for a deployment where every authorized local AI/user may use every managed credential. The boundary provides integrity, singular control-plane enforcement, least-privilege backing-file access, and value-free audit—not per-secret confidentiality among callers sharing the authorized operator identity.

Client-family labels are correlation metadata, not authenticated principals. Deployments requiring per-agent or per-secret authorization need a stronger principal model and policy layer rather than trusting environment markers.

The audit ledger is hash-chained, so altering or removing any event other than the last one is detectable. Truncating the tail is **not**, and neither is deleting the ledger outright: the `head` row that names the tip lives in the same database as the events, so whoever can delete the last N events can rewrite `head` to match, and verification then passes. Deleting everything is the same move taken to its limit — an empty ledger is indistinguishable from a fresh install. Reaching either state requires write access to the vault as root or the service user, which the mediated sudoers policy does not grant. Tamper-evidence against a principal who can write the ledger cannot come from inside the ledger; a deployment that wants it must record the tip hash reported by `audit-verify` outside the vault and compare on each run.

Secret values are not zeroized in the client. `run` holds the exported environment as a byte buffer, then as parsed JSON, then copies each value into the child process — three plaintext copies in the client's heap, none scrubbed. This is accepted rather than fixed: Rust's `Vec`/`String` reallocation makes zeroization best-effort even with a dedicated crate, and the values are bound for the child's environment regardless, where they are readable for the whole life of that process. A deployment with a specific threat here — core dumps, or another process scraping memory — needs process hardening, not a scrubbing pass in this client.

## Verification

Use:

```bash
sudo-secretspec doctor
sudo-secretspec install --dry-run <install options>
```

The dry-run still uses `sudo` because protected metadata cannot be validated honestly from the operator UID. It never reads secret contents. Since 0.19.1-sudo.13 it also resolves and validates the source media, so it catches a bad upgrade invocation rather than reporting on everything except the thing most likely to be wrong.

Upgrading is not `brew upgrade` alone: Homebrew only replaces files, and never touches the privilege boundary, so the installed boundary goes on running the old version until `install` replaces it. The rule for which binary to run is that **`install` copies from the tree its own executable lives in**. Run the copy the package manager just staged — kept off `PATH` so it cannot shadow the installed client:

```bash
"$(brew --prefix)"/opt/sudo-secretspec/libexec/sudo-secretspec install --adopt-existing
```

Plain `sudo-secretspec install` reaches the *installed* client instead, whose tree is the install destination, so it would copy every artifact onto itself. Since 0.19.1-sudo.13 that is refused with an error naming the correct command; on earlier versions it succeeded, wrote a rollback snapshot, and upgraded nothing. Since 0.19.1-sudo.14 the refusal happens before elevating, so a wrong invocation exits 2 immediately and costs no authentication prompt — which also means the behaviour is reachable unattended rather than only by an operator at the machine. The install reports the version transition it performed (`0.19.1-sudo.13 -> 0.19.1-sudo.14`, or `(reinstalled, unchanged)`), so its own output is the evidence — a bare success line no longer has to be taken on trust.

Since 0.19.1-sudo.17, `install` adopts the vault the installed config names, without `--adopt-existing`, and says so on stderr. That covers every upgrade, because the boundary is the thing recording which vault it serves from. The flag is still required for a vault found only by scanning well-known paths — there the vault is a guess, and one candidate is the retired wrapper's store that migration deliberately leaves on disk, so adopting it would silently bind a new boundary to retired secrets. Pass `--vault` to install somewhere other than the recorded one.

On 0.19.1-sudo.16 and earlier, `--adopt-existing` is not optional on a host that already carries a boundary, and an automation that omits it is handing the operator a command that fails at best. Before .16 it was worse than a failure: the fresh-install path recreated the vault's runtime files, truncating `.env` to zero bytes and destroying every stored secret value; the guard that refused a fresh install onto an existing identity or vault ran only inside the `--dry-run` branch, so the pre-flight refused precisely what the live run went on to do. Treat a green `--dry-run` on a pre-.16 boundary as saying nothing about the live path. Since .16 the guard applies to both, and the runtime files are created only when missing, with an existing or symlinked `secretspec.toml`/`.env` refused rather than overwritten. Recovery from a truncated vault is from backup: rollback snapshots preserve the vault rather than restoring it, so there is nothing in the snapshot to recover the values from.

`doctor` reports a staged-but-uninstalled build as the advisory `UPGRADE_AVAILABLE`, naming the path to run. Advisory findings do not clear `ok`, so this must not be treated as a stop condition.

Rollback snapshots cover installed artifacts only and deliberately preserve the runtime vault:

```bash
sudo-secretspec rollback /usr/local/libexec/sudo-secretspec-rollback-<timestamp>
```

Removing the boundary is `sudo-secretspec uninstall`, and it is an operator
action, not an automation one. Never run it to work around a failed check. It
too requires interactive authentication, and `--dry-run` prints the plan without
changing anything. It preserves the vault and the service identity unless
`--purge-vault` or `--remove-service-user` is passed; do not pass either.
