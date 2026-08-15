import { describe, expect, it } from 'vitest';
import { computeEngagementScorecard, isProofReady, scorecardRows, scorecardHasContent } from '../engagement-scorecard.js';
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

  it('counts proof-ready findings (captured bytes or matched excerpt), NOT command/exit-code metadata', () => {
    const findings = [
      finding({ id: 'a', evidence: [{ claim: 'x', stdout_evidence_id: 'ev-1' } as never] }),      // captured bytes → proof
      finding({ id: 'b', evidence: [{ claim: 'x', raw_output: '445/tcp open' } as never] }),        // inline raw → proof
      finding({ id: 'c', evidence: [{ claim: 'x', excerpts: [{ snippet: 'open', byte_start: 0, byte_end: 4 }] } as never] }), // matched excerpt → proof
      finding({ id: 'd', evidence: [{ claim: 'x', command: 'nmap -sV 10.0.0.1', exit_code: 0 } as never] }), // command + exit code only → methodology, NOT proof
      finding({ id: 'e', evidence: [{ claim: 'narrative only' } as never] }),                       // no proof handle
      finding({ id: 'f', evidence: [] }),                                                            // nothing
    ];
    const sc = computeEngagementScorecard(graphOf([]), findings, []);
    expect(sc.findings.total).toBe(6);
    expect(sc.findings.proof_ready).toBe(3);
    expect(sc.findings.proof_ready_share).toBeCloseTo(0.5, 4);
  });

  it('counts only real unverified CVE candidates (the demoted "Unverified CVE candidate" findings)', () => {
    const findings = [
      finding({ id: 'cand', severity: 'info', category: 'vulnerability', title: 'Unverified CVE candidate: CVE-2099-1' }),
      finding({ id: 'info-vuln', severity: 'info', category: 'vulnerability', title: 'Informational: verbose banner' }), // info vuln but NOT a CVE candidate
      finding({ id: 'real', severity: 'high', category: 'vulnerability', title: 'Vulnerability: CVE-2099-2' }),
      finding({ id: 'host', severity: 'info', category: 'compromised_host', title: 'x' }), // info but not a vuln
    ];
    expect(computeEngagementScorecard(graphOf([]), findings, []).findings.unverified_cve_candidates).toBe(1);
  });

  it('reports objective attainment AND proof-backing', () => {
    const sc = computeEngagementScorecard(graphOf([]), [], [
      { achieved: true, proof_ready: true },
      { achieved: true, proof_ready: false },
      { achieved: false },
      {},
    ]);
    expect(sc.objectives).toEqual({ total: 4, achieved: 2, proof_ready: 1 });
  });

  it('excludes synthetic/claim nodes (objective, vulnerability) from inventory coverage', () => {
    const graph: ExportedGraph = {
      nodes: [
        { id: 'h', properties: { type: 'host', claim_state: 'observed' } as unknown as NodeProperties },
        { id: 'v', properties: { type: 'vulnerability', claim_state: 'observed' } as unknown as NodeProperties }, // not an asset
        { id: 'o', properties: { type: 'objective', claim_state: 'candidate' } as unknown as NodeProperties },   // synthetic
      ],
      edges: [],
    };
    const sc = computeEngagementScorecard(graph, [], []);
    expect(sc.inventory.total).toBe(1);      // only the host
    expect(sc.inventory.observed).toBe(1);
  });

  it('still renders the section when every claim is refuted/stale (never suppressed)', () => {
    const sc = computeEngagementScorecard(graphOf(['refuted', 'stale']), [], []);
    expect(sc.verification.verified + sc.verification.unverified).toBe(0); // no "live" claims
    expect(scorecardHasContent(sc)).toBe(true);                            // ...but the section still shows
  });

  it('isProofReady is the shared captured-proof predicate — a bare command is not proof', () => {
    expect(isProofReady({ evidence: [{ claim: 'x', stdout_evidence_id: 'ev-1' } as never] })).toBe(true);
    expect(isProofReady({ evidence: [{ claim: 'x', command: 'id', exit_code: 0 } as never] })).toBe(false);
    expect(isProofReady({ evidence: [{ claim: 'x' } as never] })).toBe(false);
  });
});

describe('computeEngagementScorecard — v2 split dimensions', () => {
  it('splits inventory (nodes) from attack-path validation (access edges only)', () => {
    const graph: ExportedGraph = {
      nodes: [
        { id: 'n1', properties: { claim_state: 'observed' } as NodeProperties },
        { id: 'n2', properties: { claim_state: 'candidate' } as NodeProperties },
        { id: 'n3', properties: { claim_state: 'validated' } as NodeProperties },
      ],
      edges: [
        { id: 'e1', source: 'a', target: 'b', properties: { type: 'ADMIN_TO', claim_state: 'validated' } as unknown as EdgeProperties },
        { id: 'e2', source: 'a', target: 'b', properties: { type: 'HAS_SESSION', claim_state: 'candidate' } as unknown as EdgeProperties },
        { id: 'e3', source: 'a', target: 'b', properties: { type: 'RUNS', claim_state: 'observed' } as unknown as EdgeProperties }, // topology, not an attack edge
      ],
    };
    const sc = computeEngagementScorecard(graph, [], []);
    expect(sc.inventory.total).toBe(3);
    expect(sc.inventory.observed).toBe(2);                 // observed + validated
    expect(sc.inventory.coverage).toBeCloseTo(0.6667, 4);
    expect(sc.attack_paths.total).toBe(2);                 // ADMIN_TO + HAS_SESSION (RUNS excluded)
    expect(sc.attack_paths.validated).toBe(1);             // only the validated ADMIN_TO
    expect(sc.attack_paths.validation_share).toBeCloseTo(0.5, 4);
  });

  it('reports refutation coverage and unsupported critical claims', () => {
    const graph = graphOf(['validated', 'candidate', 'refuted']);
    const findings = [
      finding({ id: 'c1', severity: 'critical', category: 'vulnerability', evidence: [] }),                                   // no proof → unsupported
      finding({ id: 'h1', severity: 'high', category: 'compromised_host', evidence: [{ claim: 'x', stdout_evidence_id: 'ev' } as never] }), // proof → supported
      finding({ id: 'm1', severity: 'medium', category: 'webapp', evidence: [] }),                                            // not critical/high → ignored
    ];
    const sc = computeEngagementScorecard(graph, findings, []);
    expect(sc.unsupported_critical_claims).toBe(1);        // only c1
    expect(sc.refutation.tested).toBe(2);                  // validated + refuted
    expect(sc.refutation.refuted).toBe(1);
    expect(sc.refutation.coverage).toBeCloseTo(2 / 3, 4);
  });

  it('scorecardRows renders the split dimensions; scorecardHasContent gates the section', () => {
    const graph: ExportedGraph = {
      nodes: [{ id: 'n', properties: { claim_state: 'observed' } as NodeProperties }],
      edges: [{ id: 'e', source: 'a', target: 'b', properties: { type: 'ADMIN_TO', claim_state: 'candidate' } as unknown as EdgeProperties }],
    };
    const sc = computeEngagementScorecard(graph, [], []);
    const labels = scorecardRows(sc).map(r => r.label);
    expect(labels).toContain('Inventory observed');
    expect(labels).toContain('Attack path validated');
    expect(scorecardHasContent(sc)).toBe(true);
    // An entirely empty engagement has no section.
    expect(scorecardHasContent(computeEngagementScorecard(graphOf([]), [], []))).toBe(false);
  });
});
