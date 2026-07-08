import { describe, it, expect } from 'vitest';
import { findingVulnLabel } from '../finding-display';
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
