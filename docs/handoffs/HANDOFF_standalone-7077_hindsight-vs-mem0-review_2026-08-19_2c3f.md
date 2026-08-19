---
schema_version: 1
handoff_id: 2c3f
parent_handoff_ids: []
lineage: none
chain: [standalone-7077]
repo: frdminc/sudo-secretspec
workspace: sudo-secretspec
branch: sudo-main
head_sha: d513bdf32fafc06e8d6a7a09f910aff5d6705c88
created_at: 2026-08-19T15:08:34+00:00
writer: claude-code
---

# Handoff — Hindsight vs Mem0 research + Hindsight implementation health check

## The Goal

Operator asked: research Hindsight vs Mem0 (the AI-agent-memory products), and
separately look into whether *our* Hindsight coding-agent memory setup (the
`hermes-shared` bank backing this machine's Claude Code / Codex / Hermes
sessions) actually works well, with improvement suggestions. This is a
tooling/infrastructure investigation, not sudo-secretspec code work — no repo
files were touched, no tests run, `git diff --stat` is empty. It happens to
be filed from this repo because that's where the session was running.

## Where We Are

Investigation complete, findings delivered to the operator in chat, and one
project memory saved to
`~/.claude/projects/-Users-djbclark-src-sudo-secretspec/memory/hindsight-bank-globally-shared.md`
(indexed in that dir's `MEMORY.md`). No config changes made — the Hindsight
config is machine-wide shared infrastructure other sessions depend on, so
per the existing "never break the live boundary unannounced" pattern in this
repo's memory, nothing was changed without explicit operator sign-off.

**Awaiting operator decision** on the two proposed next steps below before
any action is taken.

## What We Tried

- `find . -iname "*hindsight*"` in the repo — nothing (config lives outside
  the repo, at `~/.hindsight/coding-agent.json`).
- `mcp__hindsight__hindsight_diagnose` / `hindsight_sync_status` — bank
  resolves to `hermes-shared`, `synced: true`, but `gitDiffDocs: 0` of a
  `gitDiffTarget: 300` (only commit messages ingested, no diffs).
- Read `~/.hindsight/coding-agent.json` directly — confirmed a **static
  top-level `"bankId": "hermes-shared"`** with no `mapPathToBank`/per-repo
  override, meaning every repo on the machine shares one bank instead of the
  plugin's documented per-repo `coding-agent::<repo>` default (per the
  `hindsight-coding-agent` skill).
- Read all 5 "core" knowledge pages for this project via
  `hindsight_read_knowledge_page` instead of trusting they existed:
  - "Component map", "Conventions and patterns", "Core concepts" all came
    back `"I don't have information..."` — empty, despite hundreds of
    clearly relevant sudo-secretspec memories in the bank.
  - "Key decisions and rationale" came back almost entirely about **tendcf**
    (a different, unrelated repo on the same machine) — goal-file schema,
    CFEngine projector, Shizuku tag verification. Only one bullet was
    actually about sudo-secretspec.
  - "Initiatives and enhancements" was the one page that came back correct
    and on-topic.
- `hindsight_search_knowledge_pages("pkg-config linking onepassword
  concurrency")` — a query that should trivially match known memories —
  returned near-zero relevance scores (~0.016) and nothing on-topic.
- `hindsight_reflect("What testing conventions and provider architecture
  patterns does the sudo-secretspec project follow?")` — gave a mostly
  accurate, on-topic answer (one minor tendcf leak: "Identity-keyed maps for
  entry storage"), pulling from the *same* contaminated bank. So raw
  retrieval/reasoning works; the pre-generated static pages are the broken
  layer.
- `mcp__hindsight-shared__list_memories` sampling + `list_tags` — confirmed
  cross-repo contamination directly (tendcf and stayturgid facts present
  alongside sudo-secretspec facts in the same bank), and found a consistent
  duplication pattern: nearly every ingested fact (git-log, chat, uploaded
  docs) is stored twice — a terse `observation` copy
  (`consolidated_at: null`) and a fuller `experience`/`world` restatement
  (`consolidated_at` set, "Involving: X | This ..." suffix appended).
  Tag counts: `source:chat` 1454, `source:git`/`source:git-log` 487 each,
  `source:upload` 165, out of 2114 total memories — roughly double what a
  deduped count would likely show.
- Web research: fetched vectorize.io's and mem0.ai's own head-to-head
  comparison pages. Both are vendor content (Vectorize ships Hindsight —
  same `@vectorize-io/hindsight-coding-agents` package installed here — so
  its numbers favor Hindsight; Mem0's page equally favors Mem0). Findings
  cited to the operator with that caveat attached, not presented as neutral.

## Key Decisions

- **Did not edit `~/.hindsight/coding-agent.json`** even though the fix for
  finding #1 is a one-line config change — it's shared infrastructure other
  sessions (Hermes, Codex, other repos' Claude Code sessions) depend on.
  Surfaced the tradeoff to the operator instead: keep the global
  `hermes-shared` bank (accept degraded/wrong per-repo knowledge pages) vs.
  split to per-repo banks (lose whatever cross-project awareness the shared
  bank was set up for).
- **Did not call `hindsight_ingest_document("Correction: ...")`** for the
  tendcf-contaminated "Key decisions and rationale" page. A correction
  document fixes a *fact*; this is a page-scoping/config bug that would just
  recur on next regeneration. Recommended a config fix + page regen instead
  of a point correction.
- Chose a **fresh standalone chain** (`standalone-7077`) rather than
  continuing this repo's long-running `standalone-b2db` chain (used across
  ~38 prior handoffs for actual sudo-secretspec development work) — this
  session did no code work and has no continuation from any prior handoff's
  "Where We're Going", so `parent_handoff_ids: []` / `lineage: none`.

## Evidence & Data

- Bank: `hermes-shared`, 2114 total memories, `synced: true`,
  `gitDiffDocs: 0/300`, `chatDocs: 41`, `pagesCount: 12`.
- `list_memories(type=observation)` → total 1019; `list_memories(type=experience)`
  → total 702. Tag totals: `source:chat` 1454, `source:git` 487,
  `source:git-log` 487, `source:upload` 165.
- Config file (`~/.hindsight/coding-agent.json`), verbatim:
  ```json
  {
    "serverMode": "self-hosted",
    "apiUrl": "http://127.0.0.1:8888",
    "bankId": "hermes-shared",
    "dynamicBankId": false
  }
  ```
- Example contaminated fact pair (tendcf, appearing in a bank read from a
  sudo-secretspec session): "Key abstraction boundaries in tendcf include..."
  stored once as `fact_type: observation` (`document_id: null`) and once as
  `fact_type: world` (`document_id: "repository-component-map"`) with an
  "Involving: tendcf ... " suffix — same content, twice.
- `hindsight_search_knowledge_pages` top score for an on-topic query was
  0.0164 (essentially noise-level).

## Operator Feedback

None yet — findings were just delivered in the same turn as this handoff
request. The operator's next message should contain their call on:
1. Fix the shared-bank config now, or leave it and accept current page
   quality?
2. File the upstream bug report (duplication + near-zero search relevance)
   first, or after the config fix?

## Where We're Going

1. **Get the operator's decision** on the bank-scoping question above before
   touching `~/.hindsight/coding-agent.json` — this is the single next
   action.
2. If told to fix it: edit `~/.hindsight/coding-agent.json` to drop the
   static `bankId` (or add `mapPathToBank` entries) so this repo gets its
   own `coding-agent::sudo-secretspec` bank, then trigger/wait for page
   regeneration and re-verify the same 5 pages read here.
3. Consider filing an upstream issue against
   `@vectorize-io/hindsight-coding-agents` / the Hindsight server for: (a)
   the observation/experience duplicate-storage pattern, (b) near-zero
   `hindsight_search_knowledge_pages` relevance on obviously-matching
   queries.
4. Optional: if richer Component-map/Conventions content is wanted, try
   `gitIngest: "full"` for this bank (currently message-only, 0/300 diffs
   ingested) — note this costs more tokens/API calls.

## Quick Start

```bash
# Re-check current page quality after any config change:
# (from within a Claude Code session in this repo, via the hindsight MCP tools)
#   hindsight_diagnose
#   hindsight_sync_status
#   hindsight_read_knowledge_page(<id>)  # for each of the 5 pages checked above

# Inspect/edit the shared config:
cat ~/.hindsight/coding-agent.json

# Re-read the saved finding:
cat ~/.claude/projects/-Users-djbclark-src-sudo-secretspec/memory/hindsight-bank-globally-shared.md
```
