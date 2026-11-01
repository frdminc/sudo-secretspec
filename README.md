# sudo-secretspec

[![sudo-release](https://github.com/frdminc/sudo-secretspec/actions/workflows/sudo-release.yml/badge.svg?branch=sudo-main)](https://github.com/frdminc/sudo-secretspec/actions/workflows/sudo-release.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`sudo-secretspec` is a privilege-separated companion to
[SecretSpec](https://secretspec.dev) for autonomous local AI and operator use on
macOS and Linux. One root-owned broker mediates every credential read, write and
use, so an agent running as your user can use secrets without being able to read
the store, pick another provider, or skip the audit log.

This repository (`frdminc/sudo-secretspec`) is a downstream fork of
[`cachix/secretspec`](https://github.com/cachix/secretspec). Upstream remains the
declaration and provider engine; the fork adds the companion and its packaging.

## Upstream base

| | |
|---|---|
| Upstream | [`cachix/secretspec`](https://github.com/cachix/secretspec) |
| Based on | `v0.21.1` plus 49 upstream commits, up to [`d3a1d081`](https://github.com/cachix/secretspec/commit/d3a1d081e233e6f75c0238bac87e3a331f251bb3) (2026-10-31) |
| Release stamp | `0.21.1-sudo.N` (current: `0.21.1-sudo.3`) |
| Upstream README at that version | [`cachix/secretspec@d3a1d081` `README.md`](https://github.com/cachix/secretspec/blob/d3a1d081e233e6f75c0238bac87e3a331f251bb3/README.md) |
| Upstream README, current | [`cachix/secretspec@main` `README.md`](https://github.com/cachix/secretspec/blob/main/README.md) |

The commits past `v0.21.1` are unreleased upstream work, so some features in the
upstream documentation carry a `0.22+` label even though this fork is stamped
`0.21.1-sudo.N`. Upstream's product README, with its providers, SDKs and
`secretspec` CLI reference, is kept unchanged in this tree at
[`secretspec/README.md`](secretspec/README.md).

## Install

macOS, through the Homebrew tap (the bottle is built on a GitHub macOS runner):

```bash
brew install frdminc/sudo-secretspec/sudo-secretspec
```

Linux x86_64 (Debian 12/13, Ubuntu 24.04 or newer): extract
`sudo-secretspec-<version>-x86_64-unknown-linux-gnu.tar.gz` from the
[latest release](https://github.com/frdminc/sudo-secretspec/releases/latest),
review it, and run the installer from the extracted tree. NixOS uses the
`services.sudo-secretspec` module from this flake instead. Details:
[`packaging/README.md`](packaging/README.md) and
[`sudo-secretspec/README.md`](sudo-secretspec/README.md).

Installing the package does **not** create the privilege boundary. That needs an
explicit, interactive install (Touch ID or `sudo` password):

```bash
sudo-secretspec install                    # first install; prompts and auto-detects
sudo-secretspec install --adopt-existing   # adopt a vault found only by path scan
```

Upgrades are not `brew upgrade` alone: Homebrew replaces files but never the
installed boundary, which keeps running the old version until `install` is run
again from the newly staged copy. See
[`sudo-secretspec/README.md`](sudo-secretspec/README.md#quick-start-short-forms).

## Use

```bash
sudo-secretspec check --reason "smoke"
sudo-secretspec run --reason "start gateway" -- your-command
sudo-secretspec doctor
```

Every mediated operation takes a short `--reason`; the audit ledger stores only
its SHA-256 digest. Run consumers with `run`, never by extracting values into
shell history or arguments.

The companion exposes `add`, `undeclare`, `set`, `delete`, `get`, `check`,
`export`, `run`, `template-check`, `schema`, `audit-verify` and `doctor`, plus
the operator-only `install`, `uninstall` and `rollback`. It deliberately has no
`config`, `import`, `init`, `cache` or `audit`: `config` and `import` would let a
caller choose which store answers or copy secrets out of the boundary.

## Security model

- A single mediated path for credential create, read, update, delete and use.
- Fail-closed, value-free SQLite audit (`broker-audit.sqlite3`); an audit failure
  stops the operation.
- No caller-selected manifest, provider or profile; those come from the
  root-owned config.
- Ownership, mode and the resolved vault path are enforced before every
  operation, not only by `doctor`.
- `doctor` is metadata-only and never repairs.
- NOPASSWD sudo covers only the mediated broker verbs and `doctor`. `install`,
  `uninstall` and `rollback` always require interactive authentication.
- Rollback snapshots restore installed artifacts, not secret values.

Policy for agents and automation: [`sudo-secretspec/AI-GUIDANCE.md`](sudo-secretspec/AI-GUIDANCE.md)
and the distributable skill
[`skills/sudo-secretspec/SKILL.md`](skills/sudo-secretspec/SKILL.md).

## Documentation

| Topic | File |
|---|---|
| Companion install, usage, installed paths, Linux/NixOS | [`sudo-secretspec/README.md`](sudo-secretspec/README.md) |
| AI and automation contract | [`sudo-secretspec/AI-GUIDANCE.md`](sudo-secretspec/AI-GUIDANCE.md) |
| Release process, Homebrew and Linux packaging | [`packaging/README.md`](packaging/README.md) |
| Fork development notes and build lessons | [`FORK-AI.md`](FORK-AI.md) |
| Version scheme and branch policy | [`CLAUDE.md`](./CLAUDE.md) |
| Changelog | [`CHANGELOG.md`](CHANGELOG.md) |
| Upstream product (providers, SDKs, `secretspec` CLI) | [`secretspec/README.md`](secretspec/README.md), <https://secretspec.dev> |

## Development

Workspace member: `sudo-secretspec-cli` (binary `sudo-secretspec`). All
downstream work commits directly to `sudo-main`; `main` is the upstream mirror
only. Versions are `0.21.1-sudo.N`, where `N` counts downstream releases on the
current upstream base.

## License

Apache License 2.0, as upstream. See [`LICENSE`](LICENSE).
