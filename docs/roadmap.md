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
| Scorecard v2 → HTML/PDF | Landed; split dimensions (inventory observation vs. attack-path validation, unsupported critical claims, refutation coverage, objective proof-backing) rendered from a shared model into a first-class "Evidence Integrity" section in Markdown, HTML, and PDF — not only JSON. Inventory excludes synthetic/claim nodes; a fully-refuted engagement is never suppressed. |
| Canonical edge-type registry | Landed; one metadata source (`edge-semantics.ts`) tags each edge type with roles (material_access / exploitation / credential_access / objective_default / host_access / topology / hypothesis). The objective, orchestration-measurement, scorecard, and path-analysis consumers derive their sets from it instead of four hand-maintained allowlists — retiring the drift class that had let topology edges count as offensive progress. |
| Claim lifecycle Phase 2b (backend) | Landed; durable operator/agent `promote_claim` (validate / refute / observe / exploited / stale) stored on the node/edge and honored by `claimState()` everywhere; `valid_until` validity windows that decay a promotion to `stale`; promotion-vs-evidence contradiction detection surfaced in the scorecard; and refuting a supporting claim un-achieves the objective it completed. Hardening tracked below (transactional command service, temporal objective model, withdraw + history, actionable contradictions). |

Claim lifecycle Phase 2b hardening — **landed:** the transactional, idempotent
`promote_claim` command service (atomic merge + audit + receipt, dedup by key);
refuting a target node (not just an access edge) un-achieves its objective; and
**actionable contradictions** (the scorecard names each contradicted promotion —
which claim, the conflict, the promotion's reason — not just a count).

Remaining hardening slices (not yet committed):

- **Withdraw + promotion history** — a `promote_claim` withdraw/clear op that
  durably reverts a claim to its derived state (needs an edge-attribute-unset
  journal path), plus retained promotion history rather than overwrite-only.
- **Temporal objective model + passive-expiry reconciliation** — distinguish
  `ever_achieved` / `currently_satisfied` / `lost_at` / `revoked_as_unproven`, so a
  claim that decays (a rotated credential → `stale`) reconciles the objective it
  supported without a promotion — while a settled milestone stays recorded.
  (Dogfooding confirmed these are coupled: a naive always-reconcile breaks
  milestone stability, so the temporal split is the right shape, not a shortcut.)
- **Supporting-chain proof-backing** — an objective is "proof-backed" only when the
  obtaining ACCESS/action chain carries evidence, not merely that its target node
  was observed to exist.
- **Exhaustive edge-type registry** — classify the remaining edge types and add an
  escape guard so a new material-access type can't silently fall through with no
  role.
- **Phase 2b-3 dashboard operator-correction** — invoke `promote_claim` from the
  graph node/edge drawer via a server action.
- **Live Engagement Quality dashboard** — the scorecard's split dimensions
  surfaced in the dashboard with trends, drill-down to weak claims, and one-click
  validation tasks. The report side has landed; the dashboard card plus the
  operator-intervention and cost/time-per-result metrics remain, and need a
  server endpoint (the live graph exports without `claim_state`) + data plumbing.
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
