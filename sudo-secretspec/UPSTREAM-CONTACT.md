# Upstream contact ledger — `cachix/secretspec`

Every thread this fork has opened or spoken in upstream, and what state it was
in when last checked. **Re-check this whole file at the start of every session**
(`/baton` / `/resume`); upstream moves fast and closes stale work.

Last verified: **2026-08-16** (upstream `main` still at `dfa4b10`, merged into
`sudo-main` at `92eee84`).

## How to re-check

```bash
git -C ~/src/sudo-secretspec fetch upstream main
git -C ~/src/sudo-secretspec log --oneline HEAD..upstream/main | wc -l   # commits we're behind

# Union of everything we authored or commented on:
gh search issues --repo cachix/secretspec --author    djbclark --include-prs --limit 40 \
  --json number,title,state,isPullRequest \
  --jq '.[] | "\(.number) [\(if .isPullRequest then "PR" else "issue" end)/\(.state)] \(.title)"'
gh search issues --repo cachix/secretspec --commenter djbclark --include-prs --limit 40 \
  --json number,title,state,isPullRequest \
  --jq '.[] | "\(.number) [\(if .isPullRequest then "PR" else "issue" end)/\(.state)] \(.title)"'
```

`--commenter` catches threads we don't own (e.g. #334, #64); `--author` catches
ours. Neither is a superset of the other — run both.

Then diff the result against the table below and update this file. A thread that
changed state since "last verified" is the session's first order of business.

## Open — needs attention

| # | Kind | Title | Why it's live |
|---|------|-------|----------------|
| [370](https://github.com/cachix/secretspec/issues/370) | issue | Format-preserving single-declaration edits on `Spec` | Filed 2026-08-16 at the maintainer's explicit invitation on #356 and #357. Lands the capability **on `Spec`** (`to_toml()` + `preserved_text()` + text-edit methods), not as a parallel free-function API — he declined that shape twice in one minute. Awaiting a maintainer response; we offered the PR. Reference implementation to build: [item 9 below]. |
| [371](https://github.com/cachix/secretspec/issues/371) | issue | No supported path from `Spec` to a JSON Schema | Filed 2026-08-16, **deliberately separate from #370** so a focused ask is not diluted. Asks for `Spec::schema_json(profile)`. This is the thread that retires the `source-schema` shape debt below. |
| [64](https://github.com/cachix/secretspec/issues/64) | issue | Support out-of-tree providers via gRPC interface | We closed our own #345 as a duplicate of this one, so it now carries the fork's entire `exec://` / provider-plugin interest. Not ours; we're a commenter. **Answered by #362** — see below; the maintainer's 2026-08-16 comment here is just a pointer to it. |
| [372](https://github.com/cachix/secretspec/issues/372) | issue | `check` writes its entire report to stderr | Filed 2026-08-16 from `drafts/upstream-check-stdout-issue.md`. PR #373 opened against it the same session. |
| [373](https://github.com/cachix/secretspec/pull/373) | PR | fix(check): write the report to stdout so it can be piped | Opened 2026-08-16 from branch `fix/check-report-to-stdout` (built on `upstream/main`, **not** on `sudo-main`). Carries only the `secrets.rs` + `check_report_stream.rs` hunks plus a hand-written `Changed` CHANGELOG entry. All 3 regression tests verified passing against a pure `dfa4b10` base, not merely against our merged tree. |
| [362](https://github.com/cachix/secretspec/pull/362) | PR | feat: add versioned client and provider IPC | **Not ours — the most consequential upstream thread for this fork, and it went untracked for a session.** The maintainer's own PR introducing SecretSpec IPC v1 for 0.20+: `secretspec.client/1` and `secretspec.provider/1` over framed JSON-RPC, `secretspec broker --stdio`, broker-owned file leases, trusted external-provider discovery, a C11 client, and `secretspec-ffi` → `libsecretspec`. Analysis: `docs/design/upstream-ipc-v1-and-the-fork.md`. Short version: it is the `exec://` mechanism #345 asked for, and upstream's "broker" is an IPC endpoint **inside the caller's trust domain**, not a privilege boundary — so it complements this fork rather than subsuming it. |

## Closed / merged — history

| # | Kind | State | Title | Outcome |
|---|------|-------|-------|---------|
| [357](https://github.com/cachix/secretspec/pull/357) | PR | closed | feat(sdk): expose `Secrets::config()` publicly | Closed 2026-08-16T19:35:50Z "in favor of #334". Maintainer: *"the public api will be `Spec` and `Spec::from(path)` instead of the internal Config."* **Do not delete branch `explore/pr-334-rust-first-spec`** — commit `bf0b25c` is linked by SHA from our public comment here. |
| [356](https://github.com/cachix/secretspec/pull/356) | PR | closed | feat(cli): declare secret requiredness at add time, extracting manifest_edit | Closed 2026-08-16T19:36:30Z, 60s after #357, same sentence: "in favor of #334, please open an issue with your use case if that doesn't fit". The tri-state requiredness half **did** land in #334 (`Secret::optional`/`required`, `required_setting() -> Option<bool>`). The manifest-editing half did not. Invitation to open an issue is **outstanding and unactioned**. |
| [355](https://github.com/cachix/secretspec/pull/355) | PR | merged | feat(codegen): emit description in JSON Schema properties | Merged 2026-08-16. Its merge semantically broke #334 (textually clean, compile failure); we reported it and supplied the one-line fix. |
| [354](https://github.com/cachix/secretspec/pull/354) | PR | merged | fix(provider): add `Provider::supports_delete` capability | Merged 2026-08-16. |
| [345](https://github.com/cachix/secretspec/issues/345) | issue | closed | Proposal: Generic `exec://` Provider Plugin Protocol (and an AI privilege boundary showcase) | Closed **by us** 2026-08-14 as a duplicate of #64. Maintainer: *"something we still need to explore as there are many ways."* |
| [334](https://github.com/cachix/secretspec/pull/334) | PR | merged | Add Rust-first Spec API | **Not ours** — we commented. Merged `cdda3e7` 2026-08-16T22:06Z. We reported that #355 broke its compile and supplied the fix (`build_ir` → `build_ir_from_config` at `codegen.rs:573`); maintainer replied "Rebased and fixed" and the merged tree carries our fix. This PR is now the centre of gravity for the public API. |

## Owed / planned

Not yet filed. Track here so they don't get lost.

- **Comment on #362** announcing intent to ship `sudo-secretspec` as the first
  out-of-tree *privileged* `secretspec.provider/1` endpoint, closing the loop on
  #345. One technical point is worth making from shipped experience: #362's
  registration trust check validates only the **immediate parent** directory
  (`external.rs:335-361`, via symlink-following `fs::metadata`), but on macOS
  the system path's ancestor `/Library/Application Support` is admin-group
  writable. This fork already walks the full ancestor chain with
  `symlink_metadata` (`drift.rs` `check_ancestor_chain`) for exactly that
  reason. Offer it as review feedback plus conformance cases, not a demand.

Filed 2026-08-16 and moved to the open table above: the `Spec::to_toml()` ask
(#370), the `Spec::schema_json()` ask (#371), and the `check` stdout bug (#372)
with its PR (#373). Drafts retained at
`sudo-secretspec/drafts/upstream-spec-to-toml-issue.md`,
`sudo-secretspec/drafts/upstream-spec-schema-json-issue.md` and
`sudo-secretspec/drafts/upstream-check-stdout-issue.md`.

## Deliberate stopgaps to revisit — not functionality debt, *shape* debt

These work. They are recorded because they are uglier than they should be, and
the right shape depends on an upstream answer we have not received yet. Revisit
each one when the corresponding thread moves, **even if there is no functional
gain** — the point is to stop depending on surfaces upstream has disclaimed.

### `source-schema` went through `__private` + a local feature (retired in 0.21.1-sudo.1)

Until the 0.21.1 merge, `sudo-secretspec-cli/src/broker.rs` `emit_schema`
reached codegen through `secretspec::__private::codegen::{build_ir, schema}`
plus a fork-local `codegen-schema` feature that widened `codegen::schema` to
`pub`. Upstream since shipped `Spec::schema_json(profile)` (0.20), the shape
issue #371 asked for, and `emit_schema` now calls it. The `codegen-schema`
feature and the fork's `manifest-edit` feature are gone; the broker's manifest
edits go through upstream's `SpecBuilder::add_secret`/`remove_secret`, which
preserve the retained TOML text.

Note the broker no longer uses `Secrets::config()`: it loads a `Spec` from the
protected manifest path instead, which let `secretspec/src/secrets.rs` return to
exact upstream parity and retired a conflict site on a file upstream edits
often. Keep it that way.

## Standing rules

- Upstream `main` moved twice during one session (`cdda3e7` → `dfa4b10`).
  Never trust a previous session's upstream analysis without re-fetching.
- Where upstream has stated a direction, **follow it rather than arguing** —
  reshape our code to match and offer it as a reference implementation.
- GitHub redirects `djbclark/*` → `frdminc/*`, so stale references keep working
  silently. Prefer `frdminc/...` in anything we post upstream.
