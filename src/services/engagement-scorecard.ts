// ============================================================
// Engagement scorecard — honest, ground-truth-free quality metrics
// ============================================================
// The external review's core critique was that Overwatch has no cheap signal for
// whether an engagement's output is actually *solid* — verified vs. hypothesized,
// proof-backed vs. asserted. This computes exactly that from data we already have:
// the derived claim_state on every node/edge (claim lifecycle Phase 1), the findings'
// evidence, and the objectives. No hidden ground truth, no lab — a number you can watch
// move as the system changes.
//
// Pure over an ExportedGraph that MUST be exported with { sourceTrust: true } so
// claim_state is populated; the caller owns that.

import type { ExportedGraph, ClaimState } from '../types.js';
import type { ReportFinding } from './report-generator.js';
import { hasCapturedProof } from './evidence-proof.js';
import { ATTACK_PATH_EDGE_TYPES } from './edge-semantics.js';

const CLAIM_STATES: ClaimState[] = ['candidate', 'asserted', 'observed', 'validated', 'exploited', 'refuted', 'stale'];
// "verified" = the claim is confirmed (observed/validated/exploited); "unverified" =
// recorded but unconfirmed (candidate/asserted). refuted/stale are terminal-other.

export interface ScorecardVerification {
  by_state: Record<ClaimState, number>;
  total: number;
  verified: number;
  unverified: number;
  refuted: number;
  stale: number;
  /** verified / (verified + unverified) — of the live positive claims, the share that is
   *  actually confirmed rather than merely recorded. 0 when there are no live claims. */
  verified_share: number;
}

export interface ScorecardFindings {
  total: number;
  /** Findings whose evidence carries a real proof handle — a command, a matched-signal
   *  excerpt, or an exit code — not just a narrative line. */
  proof_ready: number;
  proof_ready_share: number;
  /** Unverified version-matched CVE candidates (info-severity vulnerability findings) —
   *  present but not confirmed on target; tracked so they aren't mistaken for solid work. */
  unverified_cve_candidates: number;
}

/** Observation coverage of the discovered asset inventory (graph nodes). Separated from
 *  attack-path validation so a large host import can't inflate a single headline number
 *  while the escalation claims that matter stay unverified. */
export interface ScorecardInventoryCoverage {
  total: number;      // asset/inventory nodes carrying a claim_state
  observed: number;   // of those, mature (observed / validated / exploited)
  coverage: number;   // observed / total
}

/** Validation of the ATTACK PATH — the access/escalation edges (sessions, admin rights,
 *  owned/validated creds, replication rights, role assumption, exploitation). This is the
 *  number a reader should trust for "is the attack path real", distinct from inventory. */
export interface ScorecardAttackPathValidation {
  total: number;          // access/attack edges carrying a claim_state
  validated: number;      // of those, mature (observed / validated / exploited)
  validation_share: number;
}

/** Negative-testing coverage — how much of the graph's claims have actually been put to
 *  the test (validated, exploited, or refuted) rather than merely recorded. */
export interface ScorecardRefutation {
  tested: number;     // claims that were actively tested (validated + exploited + refuted)
  refuted: number;    // of those, disproven
  coverage: number;   // tested / total claims
}

export interface EngagementScorecard {
  verification: ScorecardVerification;
  findings: ScorecardFindings;
  /** Objective attainment AND how many of the achieved objectives are backed by captured
   *  evidence (`proof_ready`) — attainment alone can be an unproven graph state. */
  objectives: { total: number; achieved: number; proof_ready: number };
  // ---- v2 dimensions: the same evidence, split so one headline can't mask a weak spot ----
  /** Asset-inventory observation coverage (nodes). */
  inventory: ScorecardInventoryCoverage;
  /** Attack-path validation (access/escalation edges). */
  attack_paths: ScorecardAttackPathValidation;
  /** High/critical findings that carry no captured proof — the claims a reader should be
   *  most skeptical of. */
  unsupported_critical_claims: number;
  /** Negative-testing / refutation coverage across graph claims. */
  refutation: ScorecardRefutation;
}

/** Claim states that count as "confirmed enough" — mirrors isMatureClaim in source-trust. */
const MATURE_STATES: ReadonlySet<ClaimState> = new Set<ClaimState>(['observed', 'validated', 'exploited']);

/** Node types that are NOT asset inventory: `objective` is a synthetic goal marker and
 *  `vulnerability` is a claim ABOUT an asset (counted in findings/attack dimensions), not an
 *  asset itself. Counting them as inventory overstated observation coverage. */
const NON_ASSET_NODE_TYPES: ReadonlySet<string> = new Set(['objective', 'vulnerability']);


function share(numerator: number, denominator: number): number {
  return denominator > 0 ? Number((numerator / denominator).toFixed(4)) : 0;
}

/** True when a finding has retrievable proof — captured evidence bytes or a matched-signal
 *  excerpt. The canonical predicate lives in evidence-proof.ts and is shared with
 *  finding-readiness so the scorecard and the readiness rollup never disagree; a bare
 *  command line or exit code is methodology, not proof. Re-exported here for callers that
 *  reach for it via the scorecard. */
export const isProofReady = hasCapturedProof;

export function computeEngagementScorecard(
  graph: ExportedGraph,
  findings: ReportFinding[],
  objectives: ReadonlyArray<{ achieved?: boolean; proof_ready?: boolean }> = [],
): EngagementScorecard {
  const by_state = Object.fromEntries(CLAIM_STATES.map(s => [s, 0])) as Record<ClaimState, number>;
  const claims = [
    ...graph.nodes.map(n => n.properties.claim_state),
    ...graph.edges.map(e => e.properties.claim_state),
  ];
  let total = 0;
  for (const state of claims) {
    if (!state) continue; // graph not exported with sourceTrust — element is unclassified
    by_state[state] += 1;
    total += 1;
  }
  const verified = by_state.observed + by_state.validated + by_state.exploited;
  const unverified = by_state.candidate + by_state.asserted;

  const proof_ready = findings.filter(isProofReady).length;
  // An UNVERIFIED CVE candidate is specifically a version-matched-but-untested finding that
  // buildFindings demotes to info severity and titles "Unverified CVE candidate: …". Keying
  // only on (vulnerability + info) also swept in genuinely-informational vuln findings.
  const unverified_cve_candidates = findings.filter(
    f => f.category === 'vulnerability' && f.severity === 'info' && /unverified cve candidate/i.test(f.title ?? ''),
  ).length;

  // v2 — split the same claim_state signal by what the claim IS, so a big benign inventory
  // import can't mask unverified escalation. Inventory = nodes; attack paths = access edges.
  let invTotal = 0, invObserved = 0;
  for (const n of graph.nodes) {
    const s = n.properties.claim_state;
    if (!s || NON_ASSET_NODE_TYPES.has(String(n.properties.type ?? ''))) continue;
    invTotal += 1;
    if (MATURE_STATES.has(s)) invObserved += 1;
  }
  let apTotal = 0, apValidated = 0;
  for (const e of graph.edges) {
    const s = e.properties.claim_state;
    if (!s || !ATTACK_PATH_EDGE_TYPES.has(String(e.properties.type ?? ''))) continue;
    apTotal += 1;
    if (MATURE_STATES.has(s)) apValidated += 1;
  }
  const tested = by_state.validated + by_state.exploited + by_state.refuted;
  const unsupported_critical_claims = findings.filter(
    f => (f.severity === 'critical' || f.severity === 'high') && !isProofReady(f),
  ).length;

  return {
    verification: {
      by_state,
      total,
      verified,
      unverified,
      refuted: by_state.refuted,
      stale: by_state.stale,
      verified_share: share(verified, verified + unverified),
    },
    findings: {
      total: findings.length,
      proof_ready,
      proof_ready_share: share(proof_ready, findings.length),
      unverified_cve_candidates,
    },
    objectives: {
      total: objectives.length,
      achieved: objectives.filter(o => o.achieved === true).length,
      proof_ready: objectives.filter(o => o.proof_ready === true).length,
    },
    inventory: {
      total: invTotal,
      observed: invObserved,
      coverage: share(invObserved, invTotal),
    },
    attack_paths: {
      total: apTotal,
      validated: apValidated,
      validation_share: share(apValidated, apTotal),
    },
    unsupported_critical_claims,
    refutation: {
      tested,
      refuted: by_state.refuted,
      coverage: share(tested, total),
    },
  };
}

// ============================================================
// Presentation — one shared model rendered by every report format
// ============================================================
// The scorecard's "Evidence Integrity" section renders identically in Markdown, HTML/PDF,
// and (later) the dashboard from this single row model, so the formats never drift and no
// format-specific string is the source of truth.

export interface ScorecardRow {
  label: string;
  value: string;
}

const pct = (x: number): string => `${Math.round(x * 100)}%`;

/** True when the scorecard measured anything worth rendering (non-empty engagement, graph
 *  exported with claim_state). Renderers skip the section when this is false. */
export function scorecardHasContent(sc: EngagementScorecard): boolean {
  // verification.total counts ALL classified claims — including refuted/stale. An engagement
  // whose claims are entirely refuted/stale is exactly the case a reader most needs to see,
  // so it must not suppress the section (an earlier `verified + unverified` check did).
  return sc.verification.total > 0 || sc.findings.total > 0 || sc.objectives.total > 0;
}

/** The scorecard as an ordered list of display rows — the presentation-agnostic model each
 *  report format renders. Rows that would be trivially empty (no inventory, no refuted/stale)
 *  are omitted so the section stays legible. */
export function scorecardRows(sc: EngagementScorecard): ScorecardRow[] {
  const v = sc.verification;
  const live = v.verified + v.unverified;
  const rows: ScorecardRow[] = [];
  if (live > 0) {
    rows.push({ label: 'Graph claims verified', value: `${v.verified} of ${live} live claim(s) confirmed (${pct(v.verified_share)}); ${v.unverified} unverified` });
  }
  if (sc.inventory.total > 0) {
    rows.push({ label: 'Inventory observed', value: `${sc.inventory.observed} of ${sc.inventory.total} asset(s) confirmed (${pct(sc.inventory.coverage)})` });
  }
  if (sc.attack_paths.total > 0) {
    rows.push({ label: 'Attack path validated', value: `${sc.attack_paths.validated} of ${sc.attack_paths.total} access edge(s) validated (${pct(sc.attack_paths.validation_share)})` });
  }
  if (v.refuted > 0 || v.stale > 0) {
    rows.push({ label: 'Refuted / stale claims', value: `${v.refuted} refuted, ${v.stale} stale` });
  }
  if (v.total > 0) {
    rows.push({ label: 'Negative-testing coverage', value: `${sc.refutation.tested} of ${v.total} claim(s) tested (${pct(sc.refutation.coverage)}); ${sc.refutation.refuted} refuted` });
  }
  rows.push({ label: 'Findings proof-ready', value: `${sc.findings.proof_ready} of ${sc.findings.total} (${pct(sc.findings.proof_ready_share)}) carry captured proof` });
  if (sc.unsupported_critical_claims > 0) {
    rows.push({ label: 'Unsupported critical claims', value: `${sc.unsupported_critical_claims} high/critical finding(s) without captured proof` });
  }
  if (sc.findings.unverified_cve_candidates > 0) {
    rows.push({ label: 'Unverified CVE candidates', value: `${sc.findings.unverified_cve_candidates} (version-matched, not confirmed on target)` });
  }
  rows.push({
    label: 'Objectives achieved',
    value: sc.objectives.total > 0
      ? `${sc.objectives.achieved} of ${sc.objectives.total} (${sc.objectives.proof_ready} proof-backed)`
      : `${sc.objectives.achieved} of ${sc.objectives.total}`,
  });
  return rows;
}

/** The one-line framing that precedes the scorecard rows in every format. */
export const SCORECARD_INTRO =
  'A ground-truth-free read on how solid this engagement is: how much of what was recorded is actually confirmed, how much of the attack path is validated, and how much is proof-backed. These are quality signals, not findings.';
