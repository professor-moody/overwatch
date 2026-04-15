import { describe, expect, it } from 'vitest';
import {
  computeBaseScore,
  vectorToString,
  parseVectorString,
  estimateCvssFromContext,
} from '../cvss-calculator.js';
import type { CvssVector } from '../cvss-calculator.js';
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
    description: 'A test vulnerability finding',
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
// computeBaseScore — Known CVSS v3.1 Vectors
// Reference: https://www.first.org/cvss/calculator/3.1
// ============================================================

describe('computeBaseScore', () => {
  it('scores CVE-2021-44228 (Log4Shell) correctly', () => {
    // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0
    const vector: CvssVector = {
      attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N',
      userInteraction: 'N', scope: 'C',
      confidentialityImpact: 'H', integrityImpact: 'H', availabilityImpact: 'H',
    };
    expect(computeBaseScore(vector)).toBe(10.0);
  });

  it('scores a medium-severity vector correctly', () => {
    // CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N = 4.6
    const vector: CvssVector = {
      attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'L',
      userInteraction: 'R', scope: 'U',
      confidentialityImpact: 'L', integrityImpact: 'L', availabilityImpact: 'N',
    };
    const score = computeBaseScore(vector);
    expect(score).toBeGreaterThanOrEqual(4.0);
    expect(score).toBeLessThanOrEqual(5.0);
  });

  it('returns 0 for no-impact vector', () => {
    const vector: CvssVector = {
      attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N',
      userInteraction: 'N', scope: 'U',
      confidentialityImpact: 'N', integrityImpact: 'N', availabilityImpact: 'N',
    };
    expect(computeBaseScore(vector)).toBe(0);
  });

  it('scores a physical-access low-impact vector correctly', () => {
    // CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N
    const vector: CvssVector = {
      attackVector: 'P', attackComplexity: 'H', privilegesRequired: 'H',
      userInteraction: 'R', scope: 'U',
      confidentialityImpact: 'L', integrityImpact: 'N', availabilityImpact: 'N',
    };
    const score = computeBaseScore(vector);
    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThan(3.0);
  });

  it('handles scope=Changed correctly', () => {
    // Same vector with Changed scope should score higher
    const unchanged: CvssVector = {
      attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'L',
      userInteraction: 'N', scope: 'U',
      confidentialityImpact: 'L', integrityImpact: 'L', availabilityImpact: 'N',
    };
    const changed: CvssVector = { ...unchanged, scope: 'C' };

    const scoreU = computeBaseScore(unchanged);
    const scoreC = computeBaseScore(changed);
    expect(scoreC).toBeGreaterThan(scoreU);
  });
});

// ============================================================
// vectorToString / parseVectorString
// ============================================================

describe('vectorToString', () => {
  it('produces a valid CVSS 3.1 vector string', () => {
    const vector: CvssVector = {
      attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N',
      userInteraction: 'N', scope: 'C',
      confidentialityImpact: 'H', integrityImpact: 'H', availabilityImpact: 'H',
    };
    const vs = vectorToString(vector);
    expect(vs).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
  });
});

describe('parseVectorString', () => {
  it('parses a valid CVSS 3.1 vector', () => {
    const result = parseVectorString('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
    expect(result).not.toBeNull();
    expect(result!.attackVector).toBe('N');
    expect(result!.scope).toBe('C');
    expect(result!.confidentialityImpact).toBe('H');
  });

  it('handles CVSS 3.0 prefix', () => {
    const result = parseVectorString('CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N');
    expect(result).not.toBeNull();
    expect(result!.attackVector).toBe('L');
  });

  it('returns null for invalid vector', () => {
    expect(parseVectorString('not-a-vector')).toBeNull();
    expect(parseVectorString('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBeNull();
    expect(parseVectorString('CVSS:3.1/AV:N/AC:L')).toBeNull();
  });

  it('roundtrips with vectorToString', () => {
    const original: CvssVector = {
      attackVector: 'A', attackComplexity: 'H', privilegesRequired: 'L',
      userInteraction: 'R', scope: 'U',
      confidentialityImpact: 'L', integrityImpact: 'H', availabilityImpact: 'N',
    };
    const parsed = parseVectorString(vectorToString(original));
    expect(parsed).toEqual(original);
  });
});

// ============================================================
// estimateCvssFromContext
// ============================================================

describe('estimateCvssFromContext', () => {
  it('estimates network attack vector for webapp findings', () => {
    const nodes: ExportedGraph['nodes'] = [
      { id: 'webapp-1', properties: { type: 'webapp', label: 'https://app.test', url: 'https://app.test' } as NodeProperties },
    ];
    const finding = makeFinding({
      category: 'webapp',
      affected_assets: ['webapp-1'],
      description: 'Reflected XSS vulnerability found in the search parameter',
    });

    const result = estimateCvssFromContext(finding, makeGraph(nodes), makeNodeMap(nodes));

    expect(result.estimated).toBe(true);
    expect(result.vector.attackVector).toBe('N');
    expect(result.vector.userInteraction).toBe('R'); // XSS requires user interaction
    expect(result.score).toBeGreaterThan(0);
  });

  it('estimates high impact for compromised hosts', () => {
    const nodes: ExportedGraph['nodes'] = [
      { id: 'host-1', properties: { type: 'host', label: 'DC01', os: 'Windows Server 2019' } as NodeProperties },
    ];
    const finding = makeFinding({
      category: 'compromised_host',
      affected_assets: ['host-1'],
      description: 'Host compromised via lateral movement and admin session',
    });

    const result = estimateCvssFromContext(finding, makeGraph(nodes), makeNodeMap(nodes));

    expect(result.vector.confidentialityImpact).toBe('H');
    expect(result.vector.integrityImpact).toBe('H');
    expect(result.vector.availabilityImpact).toBe('H');
    expect(result.vector.scope).toBe('C'); // compromised host affects other components
    expect(result.score).toBeGreaterThanOrEqual(8.0);
  });

  it('sets user interaction for CSRF/phishing descriptions', () => {
    const finding = makeFinding({
      description: 'CSRF vulnerability allows account takeover via phishing link',
    });

    const result = estimateCvssFromContext(finding, makeGraph(), new Map());

    expect(result.vector.userInteraction).toBe('R');
  });

  it('detects privileged access from description', () => {
    const finding = makeFinding({
      category: 'credential',
      description: 'Admin password captured from memory dump, privileged account',
    });

    const result = estimateCvssFromContext(finding, makeGraph(), new Map());

    expect(result.vector.privilegesRequired).toBe('H');
  });

  it('sets scope=Changed for lateral movement', () => {
    const finding = makeFinding({
      description: 'Lateral movement from web server to database server via pivot',
    });

    const result = estimateCvssFromContext(finding, makeGraph(), new Map());

    expect(result.vector.scope).toBe('C');
  });

  it('returns a valid score in 0-10 range', () => {
    const finding = makeFinding();
    const result = estimateCvssFromContext(finding, makeGraph(), new Map());

    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(10);
  });
});
