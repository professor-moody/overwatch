import { describe, expect, it } from 'vitest';
import { computeEngagementScorecard, isProofReady } from '../engagement-scorecard.js';
import type { ExportedGraph, NodeProperties, EdgeProperties, ClaimState } from '../../types.js';
import type { ReportFinding } from '../report-generator.js';

function graphOf(nodeStates: ClaimState[], edgeStates: ClaimState[] = []): ExportedGraph {
  return {
    nodes: nodeStates.map((claim_state, i) => ({ id: `n${i}`, properties: { claim_state } as unknown as NodeProperties })),
    edges: edgeStates.map((claim_state, i) => ({ id: `e${i}`, source: 'a', target: 'b', properties: { claim_state } as unknown as EdgeProperties })),
  };
}

function finding(over: Partial<ReportFinding>): ReportFinding {
  return {
    id: 'f', title: 'f', severity: 'high', category: 'vulnerability', description: '',
    affected_assets: [], evidence: [], remediation: '', risk_score: 5, ...over,
  } as ReportFinding;
}

describe('computeEngagementScorecard', () => {
  it('computes the verified share from claim_state across nodes AND edges', () => {
    const graph = graphOf(
      ['observed', 'validated', 'candidate', 'asserted', 'refuted', 'stale'],
      ['exploited', 'candidate'],
    );
    const sc = computeEngagementScorecard(graph, [], []);
    expect(sc.verification.total).toBe(8);
    expect(sc.verification.verified).toBe(3);     // observed + validated + exploited
    expect(sc.verification.unverified).toBe(3);   // candidate + asserted + candidate
    expect(sc.verification.refuted).toBe(1);
    expect(sc.verification.stale).toBe(1);
    expect(sc.verification.verified_share).toBeCloseTo(0.5, 4); // 3 / (3+3)
    expect(sc.verification.by_state.exploited).toBe(1);
  });

  it('leaves an unlabeled graph (exported without sourceTrust) at zero, never over-claiming', () => {
    const graph: ExportedGraph = { nodes: [{ id: 'n', properties: {} as NodeProperties }], edges: [] };
    const sc = computeEngagementScorecard(graph, [], []);
    expect(sc.verification.total).toBe(0);
    expect(sc.verification.verified_share).toBe(0);
  });

  it('counts proof-ready findings (command / excerpt / exit code), not narrative-only ones', () => {
    const findings = [
      finding({ id: 'a', evidence: [{ claim: 'x', command: 'nmap -sV 10.0.0.1' } as never] }),   // command → proof
      finding({ id: 'b', evidence: [{ claim: 'x', exit_code: 0 } as never] }),                   // exit code → proof
      finding({ id: 'c', evidence: [{ claim: 'x', excerpts: [{ snippet: 'open', byte_start: 0, byte_end: 4 }] } as never] }), // excerpt → proof
      finding({ id: 'd', evidence: [{ claim: 'narrative only' } as never] }),                    // no proof handle
      finding({ id: 'e', evidence: [] }),                                                         // nothing
    ];
    const sc = computeEngagementScorecard(graphOf([]), findings, []);
    expect(sc.findings.total).toBe(5);
    expect(sc.findings.proof_ready).toBe(3);
    expect(sc.findings.proof_ready_share).toBeCloseTo(0.6, 4);
  });

  it('counts unverified CVE candidates (info-severity vulnerability findings)', () => {
    const findings = [
      finding({ id: 'cand', severity: 'info', category: 'vulnerability' }),
      finding({ id: 'real', severity: 'high', category: 'vulnerability' }),
      finding({ id: 'host', severity: 'info', category: 'compromised_host' }), // info but not a vuln → not a CVE candidate
    ];
    expect(computeEngagementScorecard(graphOf([]), findings, []).findings.unverified_cve_candidates).toBe(1);
  });

  it('reports objective attainment', () => {
    const sc = computeEngagementScorecard(graphOf([]), [], [{ achieved: true }, { achieved: false }, {}]);
    expect(sc.objectives).toEqual({ total: 3, achieved: 1 });
  });

  it('isProofReady is the shared predicate', () => {
    expect(isProofReady({ evidence: [{ claim: 'x', command: 'id' } as never] })).toBe(true);
    expect(isProofReady({ evidence: [{ claim: 'x' } as never] })).toBe(false);
  });
});
