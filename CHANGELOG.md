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
