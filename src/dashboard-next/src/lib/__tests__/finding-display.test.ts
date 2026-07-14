import { describe, it, expect } from 'vitest';
import { findingVulnLabel, severityDiverseEntryFindings } from '../finding-display';
import type { FindingDto } from '../api';

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
