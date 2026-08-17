# Changelog

All notable source releases are documented here. Overwatch follows semantic
versioning for public wire/configuration contracts and uses explicit persisted
state and journal versions for durable engagement data.

## [Unreleased]

The efficacy & evidence program — an outcome-honesty train that narrows the gap
between what Overwatch reports and what an engagement has actually proven. All
changes are additive/behavioral; no persisted-state, wire, or config contract
version changes.

### Added

- Epistemic labels derived on export: `source_trust` (observed | asserted |
  inferred — provenance) and `claim_state` (candidate → asserted → observed →
  validated → exploited, plus refuted / stale — current standing). Both ride the
  opt-in `exportGraph({ sourceTrust: true })` gate; the canonical export and its
  golden-replay hash are unchanged.
- An engagement scorecard (`computeEngagementScorecard`) — ground-truth-free
  quality metrics rendered as a first-class "Evidence Integrity" section from a
  shared model into **Markdown, HTML, and PDF** (a body section, not a post-footer
  append) and carried in the JSON report. Beyond the headline verified share it
  splits into legible dimensions: inventory observation coverage (assets only —
  synthetic/claim nodes excluded) vs. attack-path validation (access edges),
  unsupported critical claims, refutation / negative-testing coverage, proof-ready
  findings, and objective attainment plus how many objectives are proof-backed.
- Canonical frontier ranking: every item is annotated once, at the engine, with
  a split `rank` (priority_score / evidence_confidence / expected_value /
  expected_noise / explanation), so `next_task`, `get_state`, the dashboard,
  campaigns, and dispatch all read the same ordered, explained frontier.
- A canonical edge-type semantics registry (`edge-semantics.ts`): one metadata
  source tagging each edge type with roles (material_access / exploitation /
  credential_access / objective_default / host_access / topology / hypothesis),
  from which the objective, orchestration-measurement, scorecard, and
  path-analysis consumers derive their sets — retiring four hand-maintained
  allowlists that had drifted.
- Durable claim promotions (claim lifecycle Phase 2b, backend): a `promote_claim`
  tool records an operator/agent judgment (validate / refute / observe /
  exploited / stale) as a durable property `claimState()` honors above the
  derived signals. Promotions can carry a `valid_until` window (they decay to
  `stale` once elapsed; `refuted` is terminal); a promotion that conflicts with
  its own evidence is flagged in the scorecard (`contradicted_claims`); and
  refuting the claim that completed an objective un-achieves it.
- A `withdraw_claim` tool that durably clears a `promote_claim` judgment,
  reverting the claim to its derived standing (the clear is an explicit `null`
  merge so it survives WAL replay, not an `undefined` the journal would drop).
  Withdrawing re-reconciles objectives in both directions — clearing a
  refutation can re-complete an objective, clearing a positive verdict can
  un-complete one — and every promotion ever applied is retained in an
  append-only per-element `claim_promotion_history` (a withdrawal clears the
  effective promotion but never erases the record).
- A temporal objective model: alongside the settled `achieved` milestone, an
  objective now carries a live `currently_satisfied` state (plus `lost_at`),
  recomputed on every evaluation. A supporting claim that passively decays — a
  credential past its `valid_until`, a rotated credential — reconciles the live
  view WITHOUT needing a promotion, while the milestone stays recorded (a settled
  achievement is not erased by later decay; only an explicit refutation revokes
  it). `lost_at` stamps a genuine observed lapse (not a milestone the operator
  marked done that the graph never supported). The scorecard counts
  `currently_satisfied` and names lapsed milestones ("N of M achieved objectives
  lapsed — re-validate"); the operator prompt marks a lapsed objective `[LAPSED]`.
- A dashboard operator-correction surface for the claim lifecycle: the graph node
  drawer and edge panel can record or clear a claim judgment directly, through new
  authenticated `POST /api/claims/promote` and `POST /api/claims/withdraw`
  endpoints that route through the same transactional, idempotent
  `PromoteClaimCommandService` as the MCP tools. Edge actions target the real
  engine edge id and are hidden when the graph key is a synthesized fallback.
- The live dashboard graph (`GET /api/graph` and the state projection) now exports
  derived `claim_state` / `source_trust`, so the node drawer and edge panel show a
  node's or edge's **current claim standing** inline. It is computed once per graph
  revision (the projection is revision-cached), not on every poll; the canonical
  export and its golden-replay hash are unchanged.
- A live **Engagement Quality** scorecard in the dashboard: a `GET /api/scorecard`
  endpoint computes the same ground-truth-free scorecard the report renders — from
  the live graph, reusing the report's findings builder and objective
  proof-backing — and the Overview panel surfaces it as a card (verified claims,
  attack-path validation, proof-ready findings, objectives satisfied with lapsed
  milestones called out, unsupported critical claims, and actionable
  promotion-vs-evidence contradictions). Operators see engagement quality live
  without generating a report.

### Changed

- `claim_state: exploited` now requires a real exploitation signal (an explicit
  exploitation event or a confirmed EXPLOITS relationship), not the loosely
  severity-derived `exploitable` flag, which is only ever a `candidate`.
- CVSS (`cvss_score` / `cvss_vector` / `cvss_estimated`) is emitted only for
  vulnerability findings. Engagement achievements (captured hosts, reachable
  roles, credentials, cloud resources) are ranked by `engagement_risk`, never a
  fabricated CVSS.
- "Proof-ready" is one canonical predicate (`hasCapturedProof`) shared by the
  scorecard and finding-readiness: retrievable evidence (captured bytes or a
  matched-signal excerpt), not a bare command line or exit code.
- Objective **proof-backing** now requires the supporting chain: an objective is
  "proof-backed" only when the mature access edge that obtained it was created by
  an action that captured evidence — not merely that a node satisfying the target
  was observed to exist (a discovery scan on the target used to qualify, which
  over-reported proof). An objective with no inspectable target is still never
  proof-backed.
- Objective evaluation and path-start selection require **claim maturity**
  (`isMatureClaim`) instead of bare `confidence >= 0.9`: a rule inference, a
  refuted edge, or a stale/rotated credential no longer completes an objective
  or roots an attack path, while legitimately-confirmed access at 0.9–0.99 is
  unaffected.
- Frontier ranking no longer clamps the KB/chain confidence boost to 1.0 and now
  folds the attack-chain `chain_score` into expected value; both signals were
  previously discarded.
- Orchestration-eval material progress is measured as a real before/after
  edge-ID delta (an access edge between two already-known nodes now counts), and
  the access-edge set drops topology (`BACKED_BY`, `FEDERATES_WITH`) and the
  non-edge `CROSS_TIER_PIVOT`.

## 0.2.0 — 2026-07-18

This is the first explicit compatibility baseline after the reliability,
workflow, architecture, and post-refactor hardening programs.

### Added

- Non-destructive WAL recovery, versioned state migration, and transaction
  journal V2.
- Durable agents, campaigns, approvals, planner work, credential playbooks,
  process ownership, session descriptors, and application-command outcomes.
- One shared-daemon lifecycle for terminal Claude, the CLI, dashboard, and
  managed agents, including state-preserving setup, doctor, upgrade, and status.
- Dashboard contract registry, authenticated HTTP/WebSocket transport, keyed
  WebSocket V2 patches, deterministic browser journeys, and scale/soak gates.
- A generated compatibility ledger with explicit retirement criteria and
  claim-mapped CI evidence for every retired legacy surface.

### Changed

- `npm run upgrade` performs an early live migration-readiness check and a
  second authoritative frozen check after verified shutdown. A frozen-check
  failure attempts to restart the unchanged compiled daemon before any install
  or build; if another physical owner wins that compatibility handoff, startup
  fails closed without mutating engagement data.
  A cross-process reservation then protects the frozen state family through
  install/build and transfers ownership to the replacement runtime without an
  unowned writer gap.
- The bundled dashboard is a WebSocket V2 client. Server WebSocket V1 remains
  available for the documented compatibility window.

### Removed

- Bundled-dashboard consumption of WebSocket V1 state updates. The server
  continues to provide WebSocket V1 to older clients and reports an explicit
  upgrade diagnostic if the bundled V2 client reaches a V1 daemon.
- The unused internal `PendingActionQueue.abortByAgent()` wrapper; queue owners
  use canonical task identity through `abortByTask()`.

### Compatibility

- Existing V0/V1 state families remain readable and migrate only after a
  checksummed backup and complete replay.
- Agent identity, parser response, playbook projection, session rollback,
  hash-link redirects, dashboard HTTP V1, and WebSocket V1 compatibility remain supported. See
  [the compatibility policy](docs/compatibility.md).
