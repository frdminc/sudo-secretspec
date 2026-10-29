# sudo-secretspec (downstream companion)

Privilege-separated SecretSpec companion for this fork
(`frdminc/sudo-secretspec`).

Upstream SecretSpec remains the declaration/provider engine. This companion adds
a single mediated control plane for autonomous local AI/operator use on macOS
and on Linux (Debian and other non-NixOS systems through the imperative
installer; NixOS through `services.sudo-secretspec`).

## Quick start (short forms)

After the binary is available (`brew install` or local build):

```bash
# Preferred short install forms
sudo-secretspec install
sudo-secretspec install --adopt-existing

# Day-to-day use
sudo-secretspec check --reason "smoke"
sudo-secretspec run --reason "start gateway" -- your-command
sudo-secretspec doctor
```

`install` auto-detects common declaration paths and existing vaults, and
prompts on a TTY when needed. Since `0.19.1-sudo.17` it adopts the vault the
installed root-owned config names without `--adopt-existing`, announcing it on
stderr, so the plain form above is also the upgrade form. `--adopt-existing`
is still required for a vault found only by scanning well-known paths, which
includes the retired wrapper's store that migration leaves in place. Use flags
only to override defaults:

> **Which binary runs `install` matters.** `install` copies from the tree its
> own executable lives in, so it must be run from the copy your package manager
> ships — `"$(brew --prefix)"/opt/sudo-secretspec/libexec/sudo-secretspec`,
> which is kept off `PATH` so it cannot shadow the installed client. The short
> forms above are what you type for a *first* install, when nothing is installed
> yet and that keg copy is the only one present. Once a boundary is installed,
> `sudo-secretspec install` would reach the installed client, whose tree is the
> destination; since `0.19.1-sudo.13` that is refused with the correct command
> in the error, and on earlier versions it silently upgraded nothing.

```bash
sudo-secretspec install \
  --declarations /path/to/secretspec.toml.example \
  --vault /var/db/stayturgid-secrets \
  --service-user _secretspec \
  --service-group staff \
  --operator "$USER" \
  --adopt-existing
```

## What gets installed

| Path | Role |
|---|---|
| `/usr/local/bin/sudo-secretspec` | public client |
| `/usr/local/libexec/sudo-secretspec` | privileged broker (same binary) |
| `/usr/local/etc/sudo-secretspec.toml` | protected config |
| `/etc/sudoers.d/sudo-secretspec` | NOPASSWD broker policy for operator |
| `/usr/local/share/sudo-secretspec/` | declarations pin, guidance, manifest |
| vault (e.g. `/var/db/stayturgid-secrets`) | `_secretspec`-owned runtime store |

Privileged boundary creation always requires an explicit `sudo-secretspec
install` (Touch ID/sudo); see [`../packaging/README.md`](../packaging/README.md)
for the Homebrew safety boundary.

## Linux

Which Linux you are on decides how the boundary is managed, and it is decided
from the running system (`/run/current-system`), not from how the binary was
built:

| System | How the boundary is managed |
|---|---|
| NixOS | Declaratively by `services.sudo-secretspec` (`nixosModules.default`). `install`, `uninstall`, `rollback` and `doctor` refuse and point there; a rebuild is the only way the boundary changes. |
| Debian and other Linux | `sudo-secretspec install`, as on macOS, with the paths below. |

On Debian, install from the extracted Linux x86_64 release artifact (see
[`../packaging/README.md`](../packaging/README.md)); the media is the directory
tree you extracted, not an installed copy:

```bash
sudo ./libexec/sudo-secretspec install --declarations /path/to/secretspec.toml
sudo-secretspec doctor
```

| Path | Role |
|---|---|
| `/usr/local/bin/sudo-secretspec` | public client (on `PATH`) |
| `/usr/libexec/sudo-secretspec` | privileged broker (a separate copy of the binary) |
| `/etc/sudo-secretspec.toml` | protected config |
| `/etc/sudoers.d/sudo-secretspec` | NOPASSWD broker policy for the operator |
| `/usr/share/sudo-secretspec/` | declarations pin, guidance, manifest |
| `/var/lib/sudo-secretspec` | 0700 vault owned by the `sudo-secretspec` system user |

The sudoers file is validated with `visudo` before it can take effect.
NOPASSWD covers only the broker path and the mediated broker verbs: never
`install`, `uninstall`, `rollback` or `doctor` (they ask for the operator's
password every time, because the client carries `timestamp_timeout=0`), and
never `ALL`. `uninstall` removes the service user and group only when they are
the dedicated service identity.

## Removing it

```bash
sudo-secretspec uninstall --dry-run   # print the plan, change nothing
sudo-secretspec uninstall
```

Removes exactly the paths in the table above, sudo policy first. The vault and
the service identity are left alone: `--purge-vault` deletes the vault and every
secret in it, and `--remove-service-user` deletes the service user and group.
Each prompts for its own confirmation, and `--remove-service-user` refuses an
identity this installer did not create — an adopted account such as
`_secretspec` has other consumers.

The sudo policy is checked against the install manifest before it is unlinked.
If its bytes do not match, it is left in place with a warning: the path is
predictable and other vendors keep drop-ins in the same directory, so a file
sitting there is not proof this installer wrote it.

## Security model

- Singular mediated path for credential CRUD/use
- Fail-closed value-free SQLite audit (`broker-audit.sqlite3`)
- No caller-selected manifests/providers/profiles
- Ownership, mode, and the resolved vault path are enforced before every
  operation, not only by `doctor`
- Doctor/drift is metadata-only and never repairs; advisory findings are
  reported without failing the check
- The NOPASSWD policy covers only mediated broker operations and `doctor`;
  `install`, `rollback`, and `uninstall` always require interactive
  authentication
- Rollback snapshots restore installed artifacts, not vault secret values, and
  are verified against the snapshot manifest before anything is written

See `AI-GUIDANCE.md` for AI/automation rules.

## Develop

Workspace member: `sudo-secretspec-cli`. Build/test commands and macOS build
caveats are in [`../FORK-AI.md`](../FORK-AI.md); the downstream version scheme
is in [`../CLAUDE.md`](../CLAUDE.md). All downstream work commits directly to
`sudo-main`; `main` is the upstream mirror only.
