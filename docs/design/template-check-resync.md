# Design note: `template-check` byte-exactness and a lighter resync

**Status:** implemented as `export-declarations` in 0.21.1-sudo.7. The
byte-exact comparison is unchanged; the command adds the cheap value-free
resync this note proposed.
**Date:** 2026-08-15 (analysis); 2026-11-20 (implemented)
**Scope:** fork-only (`frdminc/sudo-secretspec`). Not upstream material.
**Prompted by:** an operator report, after they hit the resync cost and
resolved it by abandoning the tracked-declarations workflow entirely.

This records the reasoning so it survives the decision not to build it. The
useful content here is the *rejection* of the obvious fix, which is a trap.

## The friction

`template-check` compares the runtime manifest (`/var/db/sudo-secretspec/
secretspec.toml`, root-owned) against a git-tracked declaration template. It
compares **raw bytes**, not parsed structure.

`add` edits the runtime manifest immediately, over the cheap NOPASSWD broker
path. So one `add` puts the two files out of sync and `template-check` goes
red — correctly; that is the drift it exists to report. The problem was
getting back to green. The only route was `install --declarations <file>`, a
full boundary **lifecycle** command behind interactive `sudo`/Touch ID.

That left exactly two granularities available: "declare one secret" and
"reinstall the entire boundary." Nothing in between, for what is conceptually
a one-line change to a text file.

## The obvious fix is wrong

The tempting fix is to make the comparison **semantic** — parse both files,
compare the declarations, ignore formatting. Do not do this.

Byte-exactness is load-bearing, not incidental strictness:

- It is what makes `template-check` green mean *the running file is the exact
  bytes a human reviewed*. A semantic comparison downgrades that to "the
  running file means something equivalent to what a human reviewed," which is
  a materially weaker claim about a file that decides which secrets exist.
- It is what makes `add` → `undeclare` a **provable** undo. `toml_edit`
  preserves untouched formatting, so removing a declaration `add` inserted
  restores the file byte for byte. Two tests assert exactly this
  (`removing_an_added_declaration_restores_the_original_bytes`, and
  `..._explicit_requiredness_...` for the `--optional`/`--required` path). A
  semantic comparison would let a reserialising undo pass while silently
  leaving the file permanently different from the template.

Weakening the check to buy ergonomics trades a security property for
convenience. The friction is real, but it is not the comparison's fault.

## The fix worth building, when someone needs it

Add a value-free read — call it `export-declarations` — that streams the
runtime manifest's bytes to stdout over the same NOPASSWD broker path
`schema` and `export` already use. Resync then costs no privilege escalation
at all:

```bash
sudo-secretspec export-declarations --reason "resync after add" \
  > secretspec.toml.example
git commit -am "declare FOO"
```

Why this is small and safe:

1. **The privileged step is only the read.** The tracked template is an
   ordinary git-owned file in the operator's repo, so the *write* needs no
   root. Only reading the root-owned manifest crosses the boundary.
2. **No new privilege class.** Manifest reads are already exposed: `schema`
   does precisely this and is audited like everything else. The manifest holds
   declarations, never values — values live in the `.env` beside it.
3. **It preserves byte-exactness instead of weakening it.** Copying the exact
   bytes is what makes the next `template-check` green. The guarantee is kept;
   only the cost of restoring it changes.

It would need the same treatment as every other mediated operation: a
`--reason`, an audit event, and refusal on the privileged-broker path.

## Why it was not built

The operator's own resolution was to delete the tracked-declarations file and
its repo symlinks outright, treating the runtime vault as the single source of
truth. `add`/`set`/`check`/`schema` are now the whole interface, so the
tracked-file workflow has **zero users**.

Shipping an unused code path into a root-privileged broker is a liability, not
an asset: it is surface that must be maintained and audited while nothing
exercises it. This is roughly an hour of work whenever a real user appears —
cheaper to build then than to carry untested now.

If the tracked-file pattern is ever revived, build `export-declarations`; do
not touch the comparison.

## Decision, 2026-08-17: report the retired source instead of failing

The tracked-declarations file and its repo symlinks were deleted in
`djbclark/site-private#87` (merged 2026-08-16), which is the resolution this
note anticipated. The consequence was not anticipated: `template-check` still
runs, and can now never pass.

What is actually on this host: `cfg.declarations` points at
`/usr/local/share/sudo-secretspec/secretspec.toml` — 9663 bytes, `root:wheel`,
`0444`, frozen at the moment the tracked file was deleted, and regenerated by
nothing. The runtime manifest is 9735 bytes and moves with every `add`. The
byte comparison at `broker.rs:915` therefore reports drift permanently, and
`doctor` stays red — which erodes the "treat `doctor` as a stop" convention
every agent in this fork is instructed to follow. A check that cannot pass
teaches operators to ignore it.

**Decision: `template-check` detects that no tracked declaration source is
configured and reports that as a distinct, non-failing state.** It is not
retired along with the file, so that reviving the tracked-file pattern needs
no new code — only a configured path.

### Detection is explicit, not inferred from a missing file

`declarations` becomes `Option<PathBuf>` in the root-owned config. `None` —
the key simply absent — means *there is no tracked declaration source*.

The rejected alternative is treating a **missing file** as retirement. That
repeats a mistake this codebase already refuses elsewhere: the `undeclare`
guard at `broker.rs:809` documents that "an unparseable template is not
evidence that the name is absent from it." By the same reasoning, a file that
will not open is not evidence that the source was retired — it is equally
consistent with a broken install, which is exactly the case a check exists to
catch. Retirement is a statement the installer makes, not a condition inferred
from a failed `read`.

The migration is safe in the only direction that matters. Every config written
so far carries a `declarations` path, so `Option` parses them unchanged and
the check keeps comparing. The state flips only when an installer that was
given no tracked source writes a config omitting the key — the correct
trigger, and an explicit one.

### Resulting states

| Config | File | Result |
|---|---|---|
| `declarations` absent | — | `no tracked declaration source configured` — success |
| path configured | matches manifest | unchanged: success |
| path configured | differs | unchanged: drift, rc 1 |
| path configured | missing or symlinked | unchanged: rc 2. Still an error, *not* retirement |

### The `undeclare` guard moves with it, carefully

`broker.rs:802` reads `cfg.declarations` to refuse undeclaring a name that the
tracked template protects. With `None` that question has the answer "there is
no tracked template" — genuinely different from "I could not read the
template" — so `undeclare` proceeds.

This is the one place the change relaxes a deliberately fail-closed guard, and
it is only sound because the two cases are distinguished at the type level. An
explicit `None` permits; a configured path that fails to read must keep
refusing exactly as it does today. Implemented as a `match` on the `Option`
with the read error arm untouched, never as a truthiness check that would
collapse the two.

## Implemented, 2026-11-20 (0.21.1-sudo.7)

The operator re-adopted the tracked-declarations workflow, so the cheap resync
this note proposed is now built. `sudo-secretspec export-declarations` is a new
mediated, value-free read that streams the runtime manifest's exact bytes to
stdout over the same NOPASSWD broker path as `schema` and `export`:

```bash
sudo-secretspec export-declarations --reason "resync after add" \
  > secretspec.toml.example
git commit -am "declare FOO"
```

It takes a `--reason` and records an audit event like every other mediated
operation, is read-only (no rollback copy, no history entry), and never opens
the value store — the broker arm reads `secretspec.toml` directly and never
touches the loaded `Secrets`, so no provider value is resolved. The raw-byte
comparison in `template-check` is unchanged; the command exists only to make
returning to green cost no privilege escalation, exactly as this note argued.
