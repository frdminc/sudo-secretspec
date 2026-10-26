---
name: sudo-secretspec
description: Use managed credentials through the privilege-separated sudo-secretspec client instead of touching a secret store directly. Use when a task needs an API key, token, or password; when a credential must be declared, set, rotated, read, deleted, or injected into a child process; or when the boundary, drift checker, or audit ledger reports an error. Also covers what is deliberately NOT exposed and must be asked of the operator.
version: 0.8.1
author: Dan Clark (djbclark), Hermes Agent
license: Apache-2.0
platforms: macos
tags: secrets, privilege-separation, audit, macos
---

# sudo-secretspec Skill

Use the installed privilege-separated client for autonomous credential CRUD and
consumer execution. Do not access SecretSpec's provider, manifest, or protected
backing files directly, and never invoke `secretspec` itself for a managed
deployment.

Verified against client **0.19.1-sudo.15**. `sudo-secretspec --version` is the
authority; if it reports something newer, re-read
`sudo-secretspec/AI-GUIDANCE.md` rather than trusting this file's specifics.
If it reports something *older*, the flags marked with a minimum version below
will be rejected by your client — check `--help` before assuming a flag exists.

## When to Use

- A task needs an API key, token, password, or other declared credential.
- A credential must be declared, initialized, rotated, read, deleted, checked,
  exported, or injected into a child process.
- The managed boundary or drift checker reports an error.

Do not use for boundary installation, adoption, uninstall, rollback, or repair
without explicit operator authorization.

## Prerequisites

- `/usr/local/bin/sudo-secretspec` is installed and is the binary that actually
  runs (see `CLIENT_SHADOWED` under Verification).
- The consumer can read its credentials from environment variables when using
  `run`.

## Mediated surface

The companion is not a wrapper around the whole engine. It exposes exactly:

| Command | Purpose |
| --- | --- |
| `add NAME --description D --reason R [--optional\|--required]` | Declare a name in the runtime manifest. Sets **no** value. The requiredness flags are `0.19.1-sudo.12+`. |
| `undeclare NAME --reason R` | Inverse of `add`. Guarded — see Declaration lifecycle. |
| `set NAME --reason R` | Supply or rotate a value. |
| `delete NAME --reason R` | Drop a value, keeping the declaration. |
| `get NAME --reason R` | Print one value **to stdout**. |
| `check --reason R` | Validate that required credentials are present. |
| `export --reason R` | Print **all** name→value pairs as JSON to stdout. |
| `run --reason R -- cmd args...` | Run a child with the declared environment. |
| `template-check --reason R` | Compare runtime manifest against the tracked declaration template. |
| `schema --reason R` | Emit a JSON Schema of the runtime manifest's typed shape. |
| `audit-verify` | Verify the ledger's hash chain and report its tip. |
| `doctor` | Drift and health check. |

Plus the operator-only lifecycle commands `install`, `uninstall`, and
`rollback`.

Five engine subcommands have **no** companion equivalent: `config`, `import`,
`init`, `cache`, and `audit`. Their absence is deliberate and is not a
gap to route around — the correct response to needing one is to ask the
operator. `config` and `import` are permanently excluded (they would let a
caller repoint which store answers, or move every secret into a store the
boundary does not own). The other three are open operator questions; do not
assume their absence is either permanent or arbitrary.

## How to Run

Every operation except `audit-verify`, `doctor`, and the lifecycle commands
takes a short, non-secret `--reason`.

```bash
sudo-secretspec run --reason "query provider API" -- command args...
sudo-secretspec get NAME --reason "inspect managed credential"
sudo-secretspec set NAME --reason "rotate managed credential"
sudo-secretspec check --reason "validate required credentials"
sudo-secretspec template-check --reason "confirm manifest matches declarations"
sudo-secretspec schema --reason "generate typed accessors"
sudo-secretspec audit-verify
```

### Supplying a value without a terminal (verified 2026-10-24, client `0.19.1-sudo.30`)

`set` reads the value from **stdin when stdin is not a terminal**, so an agent
that must store a secret the operator has put on the clipboard (or in a pipe)
never needs a TTY and the value never enters argv, a transcript or shell
history:

```bash
export LC_CTYPE=en_US.UTF-8     # pbpaste mangles non-ASCII without it
pbpaste | sudo-secretspec set NAME --reason "purpose"     # prints: Secret 'NAME' saved to sqlite
printf 'cleared' | ~/ops/site-private/bin/clip             # then overwrite the clipboard
```

Check it landed with `sudo-secretspec run --reason R -- sh -c 'echo ${#NAME}'`
(a length, never the value). Do not ask the operator to type `set` themselves
and do not `get` the value back to compare.

A length alone can pass on garbage. When the value came from a clipboard, also
assert its **shape** under `run` before building on it: character-class counts
and the longest alphanumeric run, compared against the provider's documented
key format (UUID, `sk-…`, 64-hex, …). Real case (2026-10-24, vapi.ai private
key): `set` succeeded, the length check passed at 224, and the value was a
masked UI rendering — 92 box-drawing characters around column text, longest
alphanumeric run 10, no key anywhere in it. A shape check fails that loudly; a
real key passes without being printed. If the shape is wrong, do not try to
parse the key out of the rendering: `delete` the value and have the operator
copy again. Ask them for the first/last couple of characters of what they
copied so a re-copy can be corroborated (startswith/endswith under `run`)
without printing the value.

Race hazard: classifying in one command and piping `pbpaste | set` in a later
one leaves a window where the operator's *next* copy is what gets stored. Same
day, same key: between the two commands the operator copied the section title
"Private API keys / Server-side API access" (to tell the agent where they
were), and `set` stored that text. Do the classify and the forward in **one**
process: pipe `pbpaste` into a short script that buffers stdin, validates the
expected shape, and only on success invokes `sudo-secretspec set` itself with
the buffered value on stdin. A mismatch then refuses the store instead of
storing whatever arrived.

### The operator types them: `scripts/secrets-collect.py` (built 2026-10-25)

**Use this whenever a human has to hand over one or more values.** Do not ask
them to paste a key into the chat — that puts it in a transcript, which is the
one thing this whole boundary exists to prevent. This is the general form of the
one-process rule above, and it needs nothing from the agent's side:

```bash
S=~/src/sudo-secretspec/skills/sudo-secretspec/scripts/secrets-collect.py

# three values, with expected lengths (a mismatch warns, never blocks)
python3 $S \
  --secret 'OVH_APPLICATION_KEY=Application Key (AK):16' \
  --secret 'OVH_APPLICATION_SECRET=Application Secret (AS):32' \
  --secret 'OVH_CONSUMER_KEY=Consumer Key (CK):32' \
  --notify-to dann

python3 $S --secret 'FOO_API_KEY=the API key'      # one value
python3 $S --secret 'OVH_ENDPOINT=API endpoint' --literal   # not a key: skip the alnum check
python3 $S --secret 'NAME=desc:8' --dry-run        # validate only, store nothing
python3 $S --secret 'NAME=desc' --clipboard        # read from pbpaste instead of typing
```

1. **It prompts for each value with the input hidden** (`getpass`), so nothing is
   echoed — not into the scrollback, not into shell history, not into the
   process table (values reach `set` on stdin, never in argv).
2. **All-or-nothing:** nothing is stored until every value is collected and the
   operator confirms the summary, so Ctrl-C or a closed stdin leaves the store
   exactly as it was. Verified 2026-10-25.
3. **It refuses a value that cannot be a key.** Alphanumeric-plus-`_`/`-` by
   default, with the offending characters named — which is what catches the
   masked-UI-rendering case above *before* it is stored. `--literal` for
   endpoints and URLs.
4. **It prints names and lengths only**, and the `--notify-to ROLE` message
   carries names and lengths only.
5. **EOF is "no", never a crash** — safe under a pipe or a closed stdin.

The declaring agent still declares the names first (`add --optional`), and still
proves the result with `run` (a length), never `get`. This script replaces the
"ask the human, then pipe" dance; it does not replace the declaration or the
verification.

**An agent with no terminal** cannot answer the final prompt or press Enter, so
use `--clipboard --yes` — **ONE secret per run** (the clipboard cannot change
between secrets; more than one `--secret` with `--clipboard` and a non-tty stdin
exits 2). `--yes` skips only the "Store these?" prompt; every check, the
all-or-nothing rule, and stdin-only delivery are unchanged. With a non-tty stdin
it also reads `pbpaste` once, immediately, and aborts (exit 1, nothing stored) on
an empty or bad-shape value rather than retrying. Without `--yes`, EOF at the
prompt is still "no". Then overwrite the clipboard and prove the result with a
length, never `get`:

```bash
python3 $S --secret 'NAME=desc' --literal --clipboard --yes
printf 'cleared' | ~/ops/site-private/bin/clip
sudo-secretspec run -- sh -c 'echo ${#NAME}'
```

Verified 2026-10-26 (stub `sudo-secretspec`/`pbpaste`; no live vault).


### Giving a consumer a secret it reads itself

A daemon that needs a value in-process (a router, a proxy) does not need the
value in its LaunchAgent plist or environment. Give it the **name** (for
example `FIRECRAWL_ROUTER_GITHUB_SECRET: FIRECRAWL_GITHUB_PUBLIC_TOKEN` in the
Ansible role's env block, a non-secret string) and let it run
`sudo-secretspec get NAME --reason ...` once, holding the result in memory
(`bin/firecrawl-router` `read_secret` is the model: argv list, stdin
`DEVNULL`, stdout captured, nothing logged). The client works from a launchd
job with no `sudo` and no Touch ID (probed 2026-10-24 with `launchctl submit`
running `sudo-secretspec run`). A name selected this way must be declared
first (`add`), or `get` fails as "not defined in profile".

## Declaration lifecycle

Tracked Git content contains declarations only. Two routes exist, and the right
one depends on whether the name is meant to persist:

- **Persistent name:** mirror the declaration into the tracked declarations file
  through review and release. This is the durable path.
- **Runtime declaration:** `add` writes the runtime manifest immediately, so the
  manifest goes ahead of the tracked declarations and `template-check` reports
  drift until you either mirror it through release or undo it. **On a host with
  no tracked declarations source, `template-check` prints `no tracked declaration
  source configured` and there is nothing to mirror: the `add` output's drift
  warning does not apply there. Run `template-check` before promising a mirror
  step.**

```bash
sudo-secretspec add NAME --description "what it is" --reason "purpose"
sudo-secretspec set NAME --reason "purpose"
# undo, in this order:
sudo-secretspec delete NAME --reason "purpose"
sudo-secretspec undeclare NAME --reason "purpose"
```

`--description` is required by `add` and may not be empty.

**Names must match `^[A-Z][A-Z0-9_]*$`** — an environment-variable name in
upper case, starting with a letter (`CLINE_PASS_KEY_2`, not `cline_pass_key_2`).
The audit ledger enforces this for every subcommand that takes a name, and it
checks before the command runs, so a bad name fails as
`broker: audit attempt failed: audit denied: invalid secret name` and the
client then prints a hint about `--reason-sha256` and re-running `install`.
**Ignore that hint**: it is a generic fallback for any audit denial, not the
cause here. Upper-case the name and retry.

### Requiredness (`0.19.1-sudo.12+`)

`add` writes no `required` key by default, so the declaration inherits the
profile's `[defaults] required`. That inherited value is **usually** required,
but not always — which is why there are two flags rather than one:

```bash
# only some hosts need it -- `check` stays green on the hosts that don't set it
sudo-secretspec add NAME --description "what it is" --optional --reason "purpose"

# force required where the profile's [defaults] set required = false
sudo-secretspec add NAME --description "what it is" --required --reason "purpose"
```

The two cannot be combined; passing both is refused. Omitting both writes
exactly what `add` wrote before `0.19.1-sudo.12`.

This matters because it decides whether `check` passes: a required-but-unset
secret fails `check` (and anything gating on it), while an optional-but-unset
one does not. Neither flag can *change* an existing declaration — `add` refuses
a name that is already declared. To flip requiredness on a runtime declaration,
`delete` then `undeclare` then `add` again; for a tracked one it is a
review-and-release decision.

### Undo guards

`undeclare` refuses a name present in the tracked declarations file (removing
one of those is a review-and-release decision) and refuses a name that still
holds a value, so `delete` must come first. Those two guards mean `undeclare`
can only ever move the runtime manifest back toward the template. Removing a
*tracked* declaration is never a runtime action.

The broker rolls manifest and value mutations back on failure, and records an
explicit `unknown` terminal state if restoration cannot be proven.

## Procedure

1. Prefer `run` for consumers so values never enter command arguments, source
   files, or shell history. Completion: the child receives its environment with
   no value in the agent transcript.
2. If the name is not yet declared, decide between the release path and a
   runtime `add` per Declaration lifecycle above. A runtime `add` obliges you to
   either mirror it or `undeclare` it — do not leave unexplained drift behind.
3. Use `add`, `undeclare`, `set`, `delete`, or `get` only through
   `sudo-secretspec`, always with a non-secret reason. Completion: the command
   returns success and the audit ledger records a terminal outcome.
4. On any broker, audit, authorization, or drift failure, stop and report only
   the non-secret error. Completion: no fallback store, manifest, provider,
   symlink, copy, permission change, or repair was attempted.

## Pitfalls

- **`run` puts EVERY declared secret in the child's environment, so never list that environment.** `run -- env`, `printenv`,
  `env | cut -d= -f1`, `set` and `/proc/*/environ` all print values or pieces of them: a multi-line value (an age identity,
  a PEM) has lines with no `=`, and `cut` passes those through whole. To find what `run` adds, test for ONE name you
  already know (`sh -c 'test -n "$NAME"'`) or compare `len(os.environ)` before and after in a script that prints a count.
  Conversely, a long-lived consumer you start under `run` (a watcher, a daemon) hands that whole environment to every
  child it spawns (`ssh`, notifiers, helper CLIs): read the one value it needs, then delete the rest from `os.environ`
  (keep `PATH`, `HOME`, `SSH_AUTH_SOCK` and your own config names) before starting any subprocess.
- **`get` and `export` stream values straight to your stdout.** `export` writes
  a JSON object of every declared name→value pair. Never print either into a
  transcript, log, or tool output — parse and assert on keys. The client
  deliberately does not capture this stream, so redaction is entirely on the
  caller.
- **`check` reports to stdout (0.19.1-sudo.15+; it was stderr before).** Read
  the exit status, not the presence of output: `0` all required secrets
  present, `1` at least one missing. Against an older boundary the report is on
  stderr instead, so read *both* streams if you must support both, and never
  treat an empty stdout as a pass on its own. The report names secrets but
  never prints values, so it is safe to log. Because it is now on a stream you
  can close early, `check | head` ends with `IO error: Broken pipe` and a
  non-zero exit rather than a panic — that exit status means your reader closed
  the pipe, not that a secret is missing, so do not read it as a check failure.
- **Lifecycle commands authenticate even under `--dry-run`.** `install`,
  `uninstall`, and `rollback` re-exec through interactive `sudo` before the
  dry-run flag is ever considered, under `timestamp_timeout=0`. Every
  invocation costs a fresh Touch ID prompt. Never put one in a loop or an
  unattended script.
- **`template-check` is a raw byte comparison**, not a semantic one. Formatting
  changes register as drift. This is deliberate — it is what makes green mean
  "the running file is the exact bytes that were reviewed", and what makes
  `add` → `undeclare` a provable undo. Do not propose loosening it; see
  `docs/design/template-check-resync.md`.
- **A consumer's output variable name is not the declared name.** Every
  subcommand operates on names declared in the profile. A consumer frequently
  re-exports a secret downstream under a *different* name, and probing that
  downstream name returns `broker: <NAME> is not resolved`, which reads exactly
  like a missing secret. It is not — it is the wrong question. Find the mapping
  in the consumer before concluding anything is absent. Real example: the
  `litellm` Ansible role reads `CLINE_API_KEY` and `OPENCODE_ZEN_API_KEY` from
  the vault (`roles/litellm/defaults/main.yml`) and emits them into a launchd
  plist as `CLINEPASS_API_KEY` and `OPENCODE_GO_API_KEY`. Probing the plist
  names reported two secrets "missing" that were present and correct, and the
  conclusion drawn from it — that applying the role would strip keys from a live
  gateway — was wrong in both directions. `get`/`check` tell you about
  *declared* names only; grep the consumer for `lookup('env'` or its equivalent
  to learn which those are.
- **`set`'s exit status on an undeclared name was already correct; this entry
  used to claim otherwise.** Direct testing against the installed
  0.19.1-sudo.22 boundary (2026-10-03) found it already returns a non-zero
  exit and writes nothing — the opposite of what this note previously said.
  What *was* real: the error message wrapped itself a second time, reading
  `broker: Secret 'Secret '<NAME>' is not defined in profile '<P>' ...' not
  found` — a fully-formed sentence re-wrapped by its own error type's
  `Display` template. Fixed in 0.19.1-sudo.23: the message now reads once,
  still naming the available secrets, and the exit status is unchanged. `get`
  and `delete` on an undeclared name were audited at the same time and hit
  the same double-wrap on their `SecretNotFound` path; `check` and
  `undeclare` use a different error type and were already single-wrapped.
  Still follow a `set` an unattended script depends on with a presence
  check — a non-zero exit is the real signal, but confirming the value
  actually changed catches a different class of failure, such as a provider
  that silently no-ops.
- **`run` needs no `sudo` and costs no Touch ID prompt.** The client is
  privilege-separated: the unprivileged side asks the boundary daemon for the
  declared environment. Only the lifecycle commands (`install`, `uninstall`,
  `rollback`) re-exec through `sudo`. Do not conclude that a `run`-wrapped
  command is un-runnable because `sudo -n true` fails — that belief propagated
  between two agent sessions in one day and nearly left a live service running
  an unpatched config indefinitely. Test `run` itself before reporting it
  blocked.
- **`install --declarations` does not prune.** It is not a cleanup route for a
  runtime declaration; `undeclare` is.
- **Upgrade by running the newly installed copy, not the installed one.**
  `brew upgrade` only replaces files; it never touches the privilege boundary,
  so the installed boundary goes on running the old version until `install`
  replaces it. The rule for *which* binary to run is: **`install` copies from
  the tree its own executable lives in.** Run the copy your package manager
  just staged, which is kept off `PATH` so it cannot shadow the installed
  client:

  ```bash
  "$(brew --prefix)"/opt/sudo-secretspec/libexec/sudo-secretspec install --adopt-existing
  ```

  Running plain `sudo-secretspec install` instead reaches the *installed*
  client, whose tree is the destination — so it would copy every artifact onto
  itself. Since 0.19.1-sudo.13 that is refused outright, with the correct
  command in the error; before .13 it silently succeeded and upgraded nothing.
  Since 0.19.1-sudo.14 the refusal happens *before* elevating, so a wrong
  invocation costs no authentication prompt at all and exits 2 immediately.
  The install also prints the version transition
  (`0.19.1-sudo.13 -> 0.19.1-sudo.14`), so the output itself is the evidence
  the upgrade happened. A *correct* install is still an operator action — it
  authenticates interactively.
- **`--adopt-existing` is mandatory on any host running 0.19.1-sudo.16 or
  earlier that already has a boundary.** Never hand such an operator a plain
  `install` on a machine with a populated vault. Before .16 the fresh-install
  path recreated the vault's runtime files and truncated `.env` to zero bytes,
  destroying every stored secret value — and the guard that refused it ran only
  under `--dry-run`, so the rehearsal refused exactly what the live command
  then performed. A green `--dry-run` was therefore *not* evidence the real run
  was safe. Since .16 both paths refuse, and the runtime files are created only
  when missing. On a host still running an older boundary, treat plain
  `install` as destructive.
  Since 0.19.1-sudo.17 the flag is no longer needed for an upgrade: `install`
  adopts the vault the installed root-owned config names, and announces it on
  stderr. It is still required for a vault found only by path scan — including
  the retired wrapper's store, which migration leaves on disk on purpose.
  A vault that has been truncated shows as `.env` at 0 bytes with `check`
  reporting most secrets missing; recovery is from backup, not from the
  rollback snapshot, which deliberately excludes the vault.
- **Before 0.19.1-sudo.24, `install --adopt-existing` refused any vault
  already migrated off `.env`.** The adoption check hard-required `.env` to
  exist, but `.env` is vestigial once values move into `secrets.db` — the
  same reasoning that already makes it optional in the broker's own
  boundary check. The refusal read `adopted runtime file missing or
  symlinked: .../.env`, which looks like a corrupted vault but is not: a
  fully migrated vault legitimately has no `.env`. Fixed in .24; `.env` is
  now optional on adoption and only validated (never symlinked, must be a
  real file) if present at all.
- **`doctor` reports a staged upgrade** as the `UPGRADE_AVAILABLE` advisory
  (0.19.1-sudo.13+), naming the path to run. Advisory means `doctor` still
  exits 0; it is not a stop condition.
- Permission denied while inspecting a `0700` store is expected and does not
  mean files are missing.
- Reasons are hashed in the protected broker ledger but may reach SecretSpec's
  native reason interface; never put values in them.
- Client labels are correlation hints, not authenticated AI identities. Every
  authorized local caller may use every managed credential — the boundary gives
  integrity, single-control-plane enforcement, least-privilege file access, and
  value-free audit, not per-secret confidentiality between callers.
- An alert-only watchdog must never repair state.
- `install`, `uninstall`, and `rollback` are not available through the NOPASSWD
  broker path. Never run `uninstall` to work around a failed check, and never
  pass `--purge-vault` or `--remove-service-user`.

## Recipe: a new scoped credential, end to end

Worked example, GitHub (2026-10-24, `FIRECRAWL_GITHUB_PUBLIC_TOKEN`): a fine-grained
token limited to public repositories, so a daemon with an unauthenticated
listener cannot reach private data through it.

1. **Mint (operator only; open the page for them in the default browser with `open <url>`).**
   GitHub fine-grained token: `https://github.com/settings/personal-access-tokens/new`;
   Resource owner = the account, Repository access = **Public repositories (read-only)**, no permissions,
   an expiry you write down. A fine-grained token is `github_pat_` plus 82 characters (93 in all).
2. **Declare:** `sudo-secretspec add NAME --description "..." --optional --reason "..."`
   (`--optional` so `check` stays green on hosts that never set it).
3. **Store:** the clipboard route above; then overwrite the clipboard.
4. **Prove its reach without printing it.** Run a throwaway script under `run` that prints only
   the length, the prefix and HTTP statuses, then delete the script:
   ```bash
   sudo-secretspec run --reason "verify the token's scope" -- python3 -I /tmp/probe.py
   ```
   For a public-only GitHub token the expected answers were: `/user` 200, a private repo 404,
   `search/code` on that private repo `total_count` 0, `search/issues` on it 422 ("cannot be
   searched ... do not exist or you do not have permission"), and public searches 200. A classic
   `repo`-scope PAT answers the private queries with real results: that is the difference you
   are testing for. `x-oauth-scopes` is a classic-token header and is absent on fine-grained ones.
5. **Wire the consumer by name** (previous section), apply the role, restart through its
   launchd job, and repeat the end-to-end call.

Where each consumer runs matters before you wire anything: grep the deploy repo
(`rg -l <consumer> ~/ops/site-djbclark`) and the role's host list (`shared_mcp_hosts`
defaults to `mac`). The Hyades microVMs run Firecrawl itself, not `firecrawl-router`,
so a router-side secret is not needed (or stored) there.

## Verification

**Checking presence without leaking values.** `get` and `export` stream values
to stdout, so neither belongs in a transcript. To assert that a set of secrets
resolves, run a child under `run` and report only derived facts — a length, or a
short hash prefix — never the value:

```bash
sudo-secretspec run --reason "verify provider keys resolve" -- \
  bash -c 'for v in CLINE_API_KEY GEMINI_API_KEY; do
    val="${!v}"
    [ -n "$val" ] && printf "%-24s PRESENT (len=%s)\n" "$v" "${#val}" \
                  || printf "%-24s EMPTY\n" "$v"
  done'
```

A length is usually enough to corroborate an identity claim too: a vault entry
and a deployed copy of the same credential should agree on length, which
distinguishes "the same secret under two names" from "two different secrets"
without revealing either.

```bash
sudo-secretspec doctor
```

Success requires a zero exit status. Some findings are advisory and still exit
zero — report them to the operator and continue.

**Read the `advisory` field on each finding rather than matching code names.**
That list has grown three times already; at 0.19.1-sudo.13 it is
`LEGACY_VAULT_CLUTTER`, `PENDING_ROLLBACK`, `CLIENT_DUPLICATE`,
`UPGRADE_AVAILABLE`, and the three `SUDOERS_NEIGHBOUR_*` codes, but treating
those names as the definition is how this instruction goes stale. Any
non-advisory finding is a hard stop.

`CLIENT_SHADOWED` is always a hard stop and must not be worked around: it means
a different `sudo-secretspec` would run instead of the installed client, so no
operation you performed can be trusted to have reached the boundary. Report the
reported path to the operator.

Do not run `install` or `rollback` merely to verify a normal credential
operation.

See `sudo-secretspec/AI-GUIDANCE.md` in the distribution for the complete policy
contract, including the audit ledger's tamper-evidence limits and the client's
non-zeroization of values in memory.
