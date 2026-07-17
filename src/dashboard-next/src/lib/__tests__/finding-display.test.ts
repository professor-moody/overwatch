import { describe, it, expect } from 'vitest';
import { findingVulnLabel, severityDiverseEntryFindings } from '../finding-display';
import { normalizeFindingsResponse, type FindingDto } from '../api';

function makeFinding(over: Partial<FindingDto>): FindingDto {
  return {
    id: 'f1',
    title: 'Finding',
    severity: 'high',
    category: 'vulnerability',
    description: 'desc',
    affected_assets: [],
    remediation: '',
    risk_score: 50,
    ...over,
  };
}

describe('findingVulnLabel', () => {
  it('normalizes the server classification DTO before rendering', () => {
    const response = normalizeFindingsResponse({
      findings: [{
        id: 'f-wire',
        title: 'XSS',
        severity: 'high',
        category: 'webapp',
        description: 'desc',
        affected_assets: ['web-1'],
        evidence: [],
        remediation: 'encode output',
        risk_score: 8,
        classification: {
          cwe: 'CWE-79',
          cwe_name: 'Cross-site Scripting',
          owasp_category: 'A03:2021 Injection',
          nist_controls: ['SI-10'],
          pci_requirements: ['6.2.4'],
          attack_techniques: [],
        },
      }],
      total: 1,
      severity_summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    });
    expect(response.findings[0].classification).toMatchObject({
      cwe: { id: 'CWE-79', name: 'Cross-site Scripting' },
      owasp_top_10: { id: 'A03:2021', name: 'A03:2021 Injection' },
      nist_800_53: [{ id: 'SI-10', name: 'SI-10' }],
      pci_dss: [{ id: '6.2.4', requirement: '6.2.4' }],
    });
  });

  it('uses the CWE name when the finding is classified', () => {
    const f = makeFinding({
      category: 'webapp',
      classification: { cwe: { id: 'CWE-79', name: 'Cross-site Scripting' } },
    });
    expect(findingVulnLabel(f)).toBe('Cross-site Scripting');
  });

  it('falls back to the category label when there is no CWE', () => {
    expect(findingVulnLabel(makeFinding({ category: 'credential' }))).toBe('Credential exposure');
  });

  it('falls back to the category label when classification has no cwe', () => {
    const f = makeFinding({
      category: 'access_path',
      classification: { owasp_top_10: { id: 'A01', name: 'Broken Access Control' } },
    });
    expect(findingVulnLabel(f)).toBe('Administrative path');
  });
});

describe('severityDiverseEntryFindings', () => {
  const f = (id: string, severity: FindingDto['severity'], asset = 'host-1') =>
    makeFinding({ id, severity, affected_assets: asset ? [asset] : [], risk_score: 1 });

  it('surfaces lower-severity findings even when highs dominate (risk-sorted input)', () => {
    const input = [
      ...Array.from({ length: 10 }, (_, i) => f(`h${i}`, 'high')),
      f('m1', 'medium'), f('l1', 'low'),
    ];
    const out = severityDiverseEntryFindings(input);
    expect(out.some(x => x.severity === 'medium')).toBe(true); // was crowded out by a top-N slice
    expect(out.some(x => x.severity === 'low')).toBe(true);
    expect(out.filter(x => x.severity === 'high').length).toBeLessThanOrEqual(3); // capped per severity
  });

  it('excludes findings with no navigable affected asset', () => {
    const out = severityDiverseEntryFindings([f('a', 'critical', ''), f('b', 'high', 'host-2')]);
    expect(out.map(x => x.id)).toEqual(['b']);
  });
});
