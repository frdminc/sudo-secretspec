# frdminc/sudo-secretspec

Downstream fork of [cachix/secretspec](https://github.com/cachix/secretspec)
with an optional privilege-separated companion for autonomous local AI/operator
use on macOS and Linux (Debian and other non-NixOS systems through the
imperative installer, NixOS through the `services.sudo-secretspec` module).

## Upstream SecretSpec

See [`secretspec/README.md`](secretspec/README.md) for the upstream product,
providers, and quick start.

## Downstream companion: `sudo-secretspec`

This fork adds **`sudo-secretspec`**: a single Rust binary that mediates all
credential CRUD/use through a root-owned broker, fail-closed value-free audit,
and metadata-only doctor checks.

```bash
sudo-secretspec install                 # prompts / auto-detects when possible
sudo-secretspec run --reason "start app" -- your-command
```

## Where things are documented

| Topic | File |
|---|---|
| Companion install, usage, installed paths, security model | [`sudo-secretspec/README.md`](sudo-secretspec/README.md) |
| AI/automation policy contract | [`sudo-secretspec/AI-GUIDANCE.md`](sudo-secretspec/AI-GUIDANCE.md) |
| Distributable AI skill | [`skills/sudo-secretspec/SKILL.md`](skills/sudo-secretspec/SKILL.md) |
| Fork development notes, build lessons | [`FORK-AI.md`](FORK-AI.md) |
| Release process and Homebrew packaging | [`packaging/README.md`](packaging/README.md) |
| Downstream version scheme | [`CLAUDE.md`](CLAUDE.md) |

All downstream work lives on `sudo-main`. `main` is the upstream mirror only.
