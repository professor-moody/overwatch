# Roadmap

This is the current development roadmap for Overwatch. The
[Development Timeline](development-timeline.md) records what landed; this page
describes the completed reliability program and the candidate work that follows.

## Current delivery state

The reliability, workflow, and architecture program is being delivered as a
reviewed PR train. PR1 through PR15 are represented in the current release:

| Slice | Landed capability |
|---|---|
| PR1–PR4 | Non-destructive WAL recovery, parser/playbook correctness, dashboard operator correctness, and revisioned config/scope durability |
| PR5–PR6 | Explicit state versioning/migration and committed transaction-journal v2 recovery |
| PR7–PR9 | Durable agent coordination, recoverable process ownership, and truthful session resume lifecycle |
| PR10–PR11 | Transport-neutral application commands and shared dashboard contracts/projectors |
| PR12–PR14 | Durable playbook runs, hotspot/performance work, and semantic crash/browser CI gates |
| PR15 | Generated public tool/schema/archetype inventories, startup-safe shared-daemon defaults, and corrected architecture/recovery documentation |

PR15 closes the planned train. Runtime tool registration now generates the
public inventory and schema manifest, CI rejects drift, and the documentation
matches the shipped recovery, runtime, dashboard, session, and playbook
behavior.

## Post-refactor hardening delivery

The follow-on `ow-next` train keeps the shipped architecture but closes the
amplification and operating gaps found while dogfooding it:

| Slice | Delivery state |
|---|---|
| Operator recovery and planner reliability | Landed; dashboard reads remain available during config reconciliation and managed planners use durable, isolated ownership. |
| Bounded mutation transactions and hermetic runtime tests | Landed; high-frequency graph/coordination writes are delta-shaped and the supported Node matrix runs without shared artifact assumptions. |
| Crash-safe artifacts and authoritative application commands | Landed; external outputs commit through generation pointers and external mutations replay by idempotency identity. |
| One-daemon lifecycle and narrow agent/dashboard boundaries | Landed; setup, doctor, start, stop, restart, upgrade, and workspace ownership have explicit state-preserving contracts. |
| Durable agent handoff/work shaping | Landed; terminal tasks can hand off, split, and merge duplicate work without losing lineage or proof references. |
| Scale/soak gates | Landed; 50,000-task/collection budgets, mixed restart soak, WebSocket v2 keyed patches, and resource cleanup are required in CI. |
| Compatibility release | Landed in 0.2.0; evidenced internal paths are removed, public and persisted shims have a generated retirement ledger, and upgrade checks state/WAL readiness both before and after verified shutdown. |

The original PR1–PR15 train remains the architectural baseline; this follow-on
does not reopen its product decisions or weaken its recovery invariants.

## Operating model now

- Run one Overwatch daemon for an engagement. MCP, the dashboard, the terminal
  CLI, and managed headless agents are adapters over the same application
  commands and durable ownership records.
- `lean` is the default sub-agent prompt. Version 0.2.x retains
  `OVERWATCH_PROMPT_VARIANT=control`; its 0.3.0 removal gate is recorded in the
  [compatibility ledger](compatibility.md#subagent-control-prompt).
- Durable state is versioned and journaled. Unknown or incomplete recovery and
  unexplained config divergence fail into explicit read-only recovery rather
  than silently reseeding state.
- `get_state` is the operational briefing after compaction or restart. It is not
  a lossless export of every artifact; evidence, history, reports, tapes, and
  portable state are available through their dedicated read/export surfaces.
- The dashboard is an authenticated operator client, not a read-only graph
  viewer. Its mutations use the same validated command paths as MCP and the CLI.

## Efficacy & evidence program (in progress)

The current train answers the standing critique that Overwatch had strong
machinery but little signal about whether an engagement's **output** was solid —
verified vs. hypothesized, proof-backed vs. asserted. It is an outcome-honesty
program, delivered as small reviewed PRs, and it is measured cheaply alongside
(the engagement scorecard) rather than gated behind a full benchmark.

| Slice | Delivery state |
|---|---|
| Epistemic labels | Landed; `source_trust` (provenance) and `claim_state` (standing) are derived on the opt-in trust export, distinct from each other, with the canonical export/golden hash unchanged. |
| Engagement scorecard | Landed; ground-truth-free verification / proof-readiness / objective metrics in the JSON report and a Markdown "Evidence Integrity" section. |
| Semantic correctness | Landed; `exploited` requires a real exploitation signal (not the severity-derived `exploitable` flag), CVSS is vulnerability-only, and one canonical proof predicate is shared by the scorecard and finding-readiness. |
| Canonical frontier ranking | Landed; the engine ranks once into a split, explained `rank` that `next_task`, `get_state`, the dashboard, campaigns, and dispatch all share — no consumer re-sorts — and the previously-discarded KB/chain and `chain_score` signals are used. |
| Claim maturity gate | Landed (Phase 2a); objectives and pathfinding require a mature claim (not a rule inference, refuted edge, or stale credential) rather than bare `confidence >= 0.9`. |
| Orchestration measurement | Landed; material progress is a real before/after edge-ID delta over genuine offensive-access edge types. |

Candidate next slices in this program (not yet committed):

- **Claim lifecycle Phase 2b** — durable operator/agent validate-refute
  promotions, contradictory-evidence tracking, and validity periods, so maturity
  is asserted and corrected, not only derived.
- **Scorecard v2** — split dimensions (inventory coverage, attack-path
  validation, findings/objective proof-readiness, unsupported critical claims,
  refutation coverage, interventions, cost/time) surfaced through the shared
  report document model into HTML/PDF and the dashboard, not only JSON/Markdown.
- **OverwatchBench + replay policy lab** — versioned ground-truth scenarios and
  offline replay of stored frontier snapshots against candidate ranking
  policies. Scoped separately; the expensive track.

## After the reliability program

Further work should start from measured operator needs rather than reopening the
superseded reliability plan. Candidate tracks are:

- graph-delta plan previews for natural-language commands;
- richer per-task productivity and campaign OPSEC projections;
- deterministic runners for more reasoning-heavy archetypes;
- technique-preference policies and campaign-scoped dispatch limits;
- continued parser, inference, and target-surface coverage;
- paid real-model prompt evaluation on the scheduled/manual gate.

These are candidates, not commitments, and do not override recovery or data
integrity regressions discovered during operation.

## Delivery gates

Each change remains independently reviewable and must pass the relevant source,
integration, browser, package, generated-artifact, and strict-documentation
checks. The standing local gates include:

```bash
git diff --check
npx tsc --noEmit
npm run test:source
npm run build:dashboard-next
npm run check:docs
mkdocs build --strict
```

Backend-bearing changes also run stdio/HTTP and restart/crash suites; visible
operator changes run deterministic browser journeys.
