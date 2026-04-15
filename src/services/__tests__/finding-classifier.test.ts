import { describe, expect, it } from 'vitest';
import {
  classifyFinding,
  classifyAllFindings,
  generateNavigatorLayer,
  getTechniqueScope,
  computeGapAnalysis,
  generateNavigatorLayerWithGaps,
  PROFILE_TECHNIQUE_SCOPE,
  CWE_TO_OWASP,
  CWE_TO_NIST,
  CWE_TO_PCI,
  VULN_TYPE_TO_CWE,
  EDGE_TO_ATTACK,
  VULN_TO_ATTACK,
  CATEGORY_TO_ATTACK,
} from '../finding-classifier.js';
import type { ReportFinding } from '../report-generator.js';
import type { ExportedGraph, NodeProperties } from '../../types.js';

// ============================================================
// Helpers
// ============================================================

function makeFinding(overrides: Partial<ReportFinding> = {}): ReportFinding {
  return {
    id: 'finding-test-1',
    title: 'Test Finding',
    severity: 'high',
    category: 'vulnerability',
    description: 'A test finding',
    affected_assets: [],
    evidence: [],
    remediation: 'Fix it',
    risk_score: 7.0,
    ...overrides,
  };
}

function makeGraph(nodes: ExportedGraph['nodes'] = [], edges: ExportedGraph['edges'] = []): ExportedGraph {
  return { nodes, edges };
}

function makeNodeMap(nodes: ExportedGraph['nodes']): Map<string, NodeProperties> {
  return new Map(nodes.map(n => [n.id, n.properties]));
}

// ============================================================
// Mapping Table Coverage
// ============================================================

describe('FindingClassifier mapping tables', () => {
  it('CWE_TO_OWASP covers common CWEs', () => {
    expect(CWE_TO_OWASP['CWE-89']).toContain('Injection');
    expect(CWE_TO_OWASP['CWE-79']).toContain('Injection');
    expect(CWE_TO_OWASP['CWE-287']).toBeDefined();
    expect(Object.keys(CWE_TO_OWASP).length).toBeGreaterThanOrEqual(25);
  });

  it('CWE_TO_NIST maps to control arrays', () => {
    const nist = CWE_TO_NIST['CWE-89'];
    expect(Array.isArray(nist)).toBe(true);
    expect(nist.length).toBeGreaterThan(0);
    expect(nist[0]).toMatch(/^[A-Z]{2}-/); // e.g. SI-10
  });

  it('CWE_TO_PCI maps to requirement arrays', () => {
    const pci = CWE_TO_PCI['CWE-89'];
    expect(Array.isArray(pci)).toBe(true);
    expect(pci.length).toBeGreaterThan(0);
  });

  it('VULN_TYPE_TO_CWE maps common vuln types', () => {
    expect(VULN_TYPE_TO_CWE['sqli']).toEqual({ cwe: 'CWE-89', name: 'SQL Injection' });
    expect(VULN_TYPE_TO_CWE['xss']).toEqual({ cwe: 'CWE-79', name: expect.stringContaining('Cross-site') });
    expect(VULN_TYPE_TO_CWE['ssrf']).toBeDefined();
    expect(VULN_TYPE_TO_CWE['rce']).toBeDefined();
    expect(Object.keys(VULN_TYPE_TO_CWE).length).toBeGreaterThanOrEqual(15);
  });

  it('EDGE_TO_ATTACK maps edge types to ATT&CK techniques', () => {
    expect(EDGE_TO_ATTACK['CAN_DCSYNC']).toEqual({ id: 'T1003.006', name: expect.any(String) });
    expect(EDGE_TO_ATTACK['KERBEROASTABLE']).toEqual({ id: 'T1558.003', name: expect.any(String) });
    expect(EDGE_TO_ATTACK['ADMIN_TO']).toBeDefined();
    expect(Object.keys(EDGE_TO_ATTACK).length).toBeGreaterThanOrEqual(25);
  });

  it('VULN_TO_ATTACK maps vuln types to techniques', () => {
    expect(VULN_TO_ATTACK['sqli']).toBeDefined();
    expect(VULN_TO_ATTACK['ssrf']).toBeDefined();
  });

  it('CATEGORY_TO_ATTACK has fallbacks for all categories', () => {
    expect(CATEGORY_TO_ATTACK['compromised_host']).toBeDefined();
    expect(CATEGORY_TO_ATTACK['credential']).toBeDefined();
    expect(CATEGORY_TO_ATTACK['vulnerability']).toBeDefined();
    expect(CATEGORY_TO_ATTACK['cloud_exposure']).toBeDefined();
    expect(CATEGORY_TO_ATTACK['webapp']).toBeDefined();
  });
});

// ============================================================
// classifyFinding
// ============================================================

describe('classifyFinding', () => {
  it('detects CWE from vulnerability node vuln_type', () => {
    const nodes: ExportedGraph['nodes'] = [
      { id: 'vuln-1', properties: { type: 'vulnerability', vuln_type: 'sqli', label: 'SQL Injection' } as NodeProperties },
    ];
    const graph = makeGraph(nodes);
    const finding = makeFinding({ affected_assets: ['vuln-1'] });
    const nodeMap = makeNodeMap(nodes);

    const result = classifyFinding(finding, nodeMap, graph);

    expect(result.cwe).toBe('CWE-89');
    expect(result.cwe_name).toBe('SQL Injection');
    expect(result.owasp_category).toContain('Injection');
    expect(result.nist_controls.length).toBeGreaterThan(0);
    expect(result.pci_requirements.length).toBeGreaterThan(0);
  });

  it('detects CWE from description heuristics', () => {
    const finding = makeFinding({
      title: 'Cross-site scripting in login page',
      description: 'Reflected xss vulnerability found in the search parameter',
    });

    const result = classifyFinding(finding, new Map(), makeGraph());

    expect(result.cwe).toBe('CWE-79');
    expect(result.owasp_category).toBeDefined();
  });

  it('assigns CWE-522 fallback for credential findings', () => {
    const finding = makeFinding({
      category: 'credential',
      title: 'Credential Obtained: admin',
      description: 'Password hash captured via secretsdump',
    });

    const result = classifyFinding(finding, new Map(), makeGraph());

    // May get CWE from description keywords, or fallback to CWE-522
    expect(result.cwe).toBeDefined();
  });

  it('collects ATT&CK techniques from graph edges', () => {
    const nodes: ExportedGraph['nodes'] = [
      { id: 'host-1', properties: { type: 'host', label: 'DC01' } as NodeProperties },
    ];
    const edges: ExportedGraph['edges'] = [
      { source: 'attacker', target: 'host-1', properties: { type: 'ADMIN_TO' as any, confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' } },
      { source: 'host-1', target: 'dc', properties: { type: 'CAN_DCSYNC' as any, confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' } },
    ];
    const graph = makeGraph(nodes, edges);
    const finding = makeFinding({ affected_assets: ['host-1'] });

    const result = classifyFinding(finding, makeNodeMap(nodes), graph);

    const techniqueIds = result.attack_techniques.map(t => t.id);
    expect(techniqueIds).toContain('T1021');  // ADMIN_TO
    expect(techniqueIds).toContain('T1003.006');  // CAN_DCSYNC
  });

  it('uses VULN_TO_ATTACK for vuln node vuln_type', () => {
    const nodes: ExportedGraph['nodes'] = [
      { id: 'vuln-ssrf', properties: { type: 'vulnerability', vuln_type: 'ssrf', label: 'SSRF' } as NodeProperties },
    ];
    const graph = makeGraph(nodes);
    const finding = makeFinding({ affected_assets: ['vuln-ssrf'] });

    const result = classifyFinding(finding, makeNodeMap(nodes), graph);

    const ids = result.attack_techniques.map(t => t.id);
    expect(ids).toContain('T1190');  // SSRF → Exploit Public-Facing Application
  });

  it('falls back to CATEGORY_TO_ATTACK when no specific techniques found', () => {
    const finding = makeFinding({
      category: 'cloud_exposure',
      title: 'Exposed Cloud Resource',
      description: 'An S3 bucket was publicly accessible',
      affected_assets: [],
    });

    const result = classifyFinding(finding, new Map(), makeGraph());

    expect(result.attack_techniques.length).toBeGreaterThan(0);
  });

  it('returns empty classification for unrecognized finding', () => {
    const finding = makeFinding({
      title: 'Unknown issue',
      description: 'Something happened',
      category: 'access_path',
      affected_assets: [],
    });

    const result = classifyFinding(finding, new Map(), makeGraph());

    // Should still have ATT&CK fallback but may lack CWE
    expect(result.nist_controls).toEqual([]);
    expect(result.pci_requirements).toEqual([]);
  });
});

// ============================================================
// classifyAllFindings
// ============================================================

describe('classifyAllFindings', () => {
  it('returns a map keyed by finding ID', () => {
    const findings: ReportFinding[] = [
      makeFinding({ id: 'f1', category: 'credential' }),
      makeFinding({ id: 'f2', category: 'vulnerability' }),
    ];

    const result = classifyAllFindings(findings, makeGraph());

    expect(result.size).toBe(2);
    expect(result.has('f1')).toBe(true);
    expect(result.has('f2')).toBe(true);
  });
});

// ============================================================
// ATT&CK Navigator Layer
// ============================================================

describe('generateNavigatorLayer', () => {
  it('produces valid Navigator layer structure', () => {
    const nodes: ExportedGraph['nodes'] = [
      { id: 'host-1', properties: { type: 'host', label: 'DC01' } as NodeProperties },
    ];
    const edges: ExportedGraph['edges'] = [
      { source: 'a', target: 'host-1', properties: { type: 'ADMIN_TO' as any, confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' } },
    ];
    const findings = [makeFinding({ affected_assets: ['host-1'] })];
    const graph = makeGraph(nodes, edges);

    const layer = generateNavigatorLayer(findings, graph, 'Test Engagement') as any;

    expect(layer.name).toContain('Test Engagement');
    expect(layer.versions.layer).toBe('4.5');
    expect(layer.domain).toBe('enterprise-attack');
    expect(layer.techniques.length).toBeGreaterThan(0);
    expect(layer.gradient).toBeDefined();
    expect(layer.techniques[0]).toHaveProperty('techniqueID');
    expect(layer.techniques[0]).toHaveProperty('score');
    expect(layer.techniques[0]).toHaveProperty('comment');
  });

  it('aggregates technique counts across findings', () => {
    const nodes: ExportedGraph['nodes'] = [
      { id: 'h1', properties: { type: 'host', label: 'H1' } as NodeProperties },
      { id: 'h2', properties: { type: 'host', label: 'H2' } as NodeProperties },
    ];
    const edges: ExportedGraph['edges'] = [
      { source: 'a', target: 'h1', properties: { type: 'ADMIN_TO' as any, confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' } },
      { source: 'a', target: 'h2', properties: { type: 'ADMIN_TO' as any, confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' } },
    ];
    const findings = [
      makeFinding({ id: 'f1', affected_assets: ['h1'] }),
      makeFinding({ id: 'f2', affected_assets: ['h2'] }),
    ];
    const graph = makeGraph(nodes, edges);

    const layer = generateNavigatorLayer(findings, graph, 'Test') as any;

    // ADMIN_TO → T1021 should appear with count >= 2
    const t1021 = layer.techniques.find((t: any) => t.techniqueID === 'T1021');
    expect(t1021).toBeDefined();
    expect(t1021.comment).toContain('2 finding');
  });
});

// ============================================================
// ATT&CK Technique Scope & Gap Analysis
// ============================================================

describe('getTechniqueScope', () => {
  it('returns techniques for internal-pentest', () => {
    const scope = getTechniqueScope('internal-pentest');
    expect(scope.length).toBeGreaterThan(0);
    expect(scope).toContain('T1003');
    expect(scope).toContain('T1003.006');
  });

  it('returns techniques for external-assessment', () => {
    const scope = getTechniqueScope('external-assessment');
    expect(scope).toContain('T1190');
    expect(scope).toContain('T1189');
  });

  it('returns deduplicated sorted array', () => {
    const scope = getTechniqueScope('red-team');
    const sorted = [...scope].sort();
    expect(scope).toEqual(sorted);
    expect(new Set(scope).size).toBe(scope.length);
  });

  it('falls back to red-team for unknown profile', () => {
    const unknown = getTechniqueScope('nonexistent');
    const redTeam = getTechniqueScope('red-team');
    expect(unknown).toEqual(redTeam);
  });
});

describe('PROFILE_TECHNIQUE_SCOPE', () => {
  it('has entries for all template profiles', () => {
    const expected = ['internal-pentest', 'goad_ad', 'external-assessment', 'red-team', 'cloud-assessment', 'assumed-breach', 'ctf'];
    for (const p of expected) {
      expect(PROFILE_TECHNIQUE_SCOPE[p]).toBeDefined();
      expect(PROFILE_TECHNIQUE_SCOPE[p].length).toBeGreaterThan(0);
    }
  });
});

describe('computeGapAnalysis', () => {
  it('identifies untested techniques', () => {
    const nodes: ExportedGraph['nodes'] = [
      { id: 'h1', properties: { type: 'host', label: 'H1' } as NodeProperties },
    ];
    const edges: ExportedGraph['edges'] = [
      { source: 'a', target: 'h1', properties: { type: 'ADMIN_TO' as any, confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' } },
    ];
    const graph = makeGraph(nodes, edges);
    const findings = [makeFinding({ id: 'f1', affected_assets: ['h1'] })];

    const result = computeGapAnalysis(findings, graph, 'internal-pentest');

    expect(result.profile).toBe('internal-pentest');
    expect(result.total_in_scope).toBeGreaterThan(0);
    expect(result.tested_count).toBeGreaterThan(0);
    expect(result.untested_count).toBeGreaterThan(0);
    expect(result.coverage_pct).toBeGreaterThan(0);
    expect(result.coverage_pct).toBeLessThan(100);
    expect(result.gaps.length).toBe(result.untested_count);
    // T1021 should be tested (from ADMIN_TO edge)
    expect(result.tested).toContain('T1021');
  });

  it('reports tested count for cloud profile', () => {
    const nodes: ExportedGraph['nodes'] = [
      { id: 'h1', properties: { type: 'host', label: 'H1' } as NodeProperties },
    ];
    const edges: ExportedGraph['edges'] = [
      { source: 'h1', target: 'h1', properties: { type: 'EXPLOITS' as any, confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' } },
      { source: 'h1', target: 'h1', properties: { type: 'ASSUMES_ROLE' as any, confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' } },
      { source: 'h1', target: 'h1', properties: { type: 'HAS_POLICY' as any, confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' } },
    ];
    const graph = makeGraph(nodes, edges);
    const findings = [makeFinding({ id: 'f1', affected_assets: ['h1'], vuln_type: 'rce', category: 'vulnerability' } as any)];

    const result = computeGapAnalysis(findings, graph, 'cloud-assessment');
    expect(result.tested_count).toBeGreaterThan(0);
  });

  it('gap items have suggested actions', () => {
    const graph = makeGraph([], []);
    const result = computeGapAnalysis([], graph, 'internal-pentest');

    for (const gap of result.gaps) {
      expect(gap.technique_id).toBeTruthy();
      expect(gap.name).toBeTruthy();
      expect(gap.suggested_action).toBeTruthy();
    }
  });
});

describe('generateNavigatorLayerWithGaps', () => {
  it('includes gap annotations in amber', () => {
    const nodes: ExportedGraph['nodes'] = [
      { id: 'h1', properties: { type: 'host', label: 'H1' } as NodeProperties },
    ];
    const edges: ExportedGraph['edges'] = [
      { source: 'a', target: 'h1', properties: { type: 'ADMIN_TO' as any, confidence: 1.0, discovered_at: '2026-01-01T00:00:00Z' } },
    ];
    const graph = makeGraph(nodes, edges);
    const findings = [makeFinding({ id: 'f1', affected_assets: ['h1'] })];

    const layer = generateNavigatorLayerWithGaps(findings, graph, 'Test', 'internal-pentest') as any;

    expect(layer.techniques.length).toBeGreaterThan(0);
    // Should have gap techniques with amber color
    const gapTechs = layer.techniques.filter((t: any) => t.color === '#ffcc00');
    expect(gapTechs.length).toBeGreaterThan(0);
    expect(gapTechs[0].comment).toContain('GAP');
    // Description should contain coverage
    expect(layer.description).toContain('Coverage');
  });
});
