# Design note: the dann deployment threat model (H6 / M1)

**Status:** decision recorded; the deployment wiring itself is the Wave 2
workstream (site-dann NixOS module + sops).
**Date:** 2026-10-29
**Scope:** `dann.dclark.us` (the site-dann NixOS host). Not upstream material.
**Prompted by:** adversary review findings H6 and M1 on the Linux port.

This note records, honestly, what sudo-secretspec *is* and *is not* on dann, and
which secrets belong in its vault. It is the counterpart to
`privilege-boundary-and-packaging.md`, which assumes a macOS host where the
operator is a *non-root* user and the boundary is real. On dann that assumption
does not hold, and the design must say so rather than pretend otherwise.

## What the boundary is not, on dann

On the Mac the boundary is genuine: the operator is an unprivileged account, the
broker's NOPASSWD verbs are the only route to the vault, and every other
operation (install, uninstall, rollback, `source-restore-force`,
`source-destroy`) falls through to interactive Touch ID.

On dann the same module cannot deliver that. The host is disposable and
operator-managed end to end:

- `configuration.nix` grants `%wheel ALL=(ALL:ALL) NOPASSWD:SETENV: ALL`, and
  places the operator in `wheel` with `wheelNeedsPassword = false`. The operator
  is therefore **root-equivalent**: `sudo cat /var/lib/sudo-secretspec/…` reads
  the vault directly, so **confidentiality against the operator is nil.**
- The audit ledger is service-owned, and root can re-chain it from genesis (the
  chain has no external anchor), so **audit is not tamper-evident against the
  operator.**
- sudoers applies tags last-match-wins, so the `SETENV` tag on the wheel rule
  (`%wheel ALL=(ALL:ALL) NOPASSWD:SETENV: ALL`) wins for the operator regardless
  of the module's own NOPASSWD grant lines (which carry no `SETENV` tag). The
  real route is `sudo -u <svc> env VAR=… $BROKER …`, which reaches the broker
  with caller-chosen variables that `purge_ambient_env` does not cover. This is
  moot while the operator is root — which is the point — and it is a reason
  never to deploy this pattern on a host where the operator is *not* already
  root-equivalent.

So on dann, sudo-secretspec provides exactly two things, and it is worth naming
them because they are the whole reason to run it there:

1. **Reason-forcing friction.** A credential operation goes through a named
   verb with a required `--reason`, recorded in the ledger, rather than a bare
   `sudo cat`. It does not stop the operator from reading a secret; it makes the
   act deliberate and legible.
2. **A convenience audit trail.** The ledger is a searchable record of *what was
   read or written, when, and why*, which is a workflow convenience rather than
   a security control on this host.

This matches `configuration.nix`'s own honesty rule and the host's disposability
invariant: nothing on the box survives a rebuild, so nothing on it should be
treated as a tamper-proof record.

## What goes in the vault (M1)

The five AI-pool keys are **declarative**: sops → `environmentFiles` → Hermes's
`.env` at activation. Putting any of them in the vault would create a second,
mutable source of truth that a rebuild does not restore, and the two copies
would drift — a `sudo-secretspec set` "rotation" would never reach Hermes, which
keeps reading the sops value, while the operator believes the key rotated.
Bridging the vault into `/run/secrets` (or Hermes's env) would make the
NOPASSWD `source-set` writer a confused deputy for another service's
credential.

**Decision:** the pool keys stay sops-only. Nothing is bridged between the vault
and `/run/secrets`.

The minimum vault set is the secrets **the entity itself mutates at runtime or
uses interactively, which no NixOS service consumes**:

| Secret | Where it lives | Why |
| --- | --- | --- |
| `GITHUB_TOKEN` | sops, `owner = "dann"; mode = "0400"` | Static; no runtime mutation. Reproducible from sops. |
| Gmail OAuth **refresh token** | vault | Rotates, so it needs a mutable store. |
| Gmail OAuth client id/secret | sops | Configuration, not high-value. |
| Google account **password** | **the Mac only** | Enables account recovery and 2FA changes; the refresh token already covers Gmail. |

A static secret with no runtime mutation gets the same protection from sops, so
the vault exists for the refresh token — or, more precisely, it exists for the
reason/audit UX described above, and the refresh token is the one secret that
genuinely needs its mutable store.

Two consequences, recorded so they are not re-litigated:

- **Back up the vault, or accept re-auth after a reinstall.** The refresh token
  is the one piece of vault state a rebuild does not restore.
- **No Google password on the VPS, ever.** It is the account-recovery and 2FA
  key, and its presence would convert a disposable box into a credential the
  operator must treat as if it were the Mac.

## Tamper-evidence, if it is ever wanted

None of this is a boundary, and the ledger is not tamper-evident against a
root-equivalent operator. If tamper-evidence *does* matter at some point, the
cheap next step is to ship `audit-verify`'s tip hash off-host on a schedule
(e.g. via `fleet-watch`), which gives the chain an external anchor and makes
retrospective tampering detectable. That is deliberately **not** in scope for
the port; it is recorded here as the known upgrade path rather than discovered
again later.
