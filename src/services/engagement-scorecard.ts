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

export interface EngagementScorecard {
  verification: ScorecardVerification;
  findings: ScorecardFindings;
  objectives: { total: number; achieved: number };
}

function share(numerator: number, denominator: number): number {
  return denominator > 0 ? Number((numerator / denominator).toFixed(4)) : 0;
}

/** True when a finding has at least one evidence entry carrying a concrete proof handle. */
export function isProofReady(finding: Pick<ReportFinding, 'evidence'>): boolean {
  return (finding.evidence ?? []).some(chain =>
    !!chain.command
    || (Array.isArray(chain.excerpts) && chain.excerpts.length > 0)
    || typeof chain.exit_code === 'number',
  );
}

export function computeEngagementScorecard(
  graph: ExportedGraph,
  findings: ReportFinding[],
  objectives: ReadonlyArray<{ achieved?: boolean }> = [],
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
  const unverified_cve_candidates = findings.filter(f => f.category === 'vulnerability' && f.severity === 'info').length;

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
    },
  };
}
