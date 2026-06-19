import { describe, it, expect } from 'vitest';
import { assess } from '../../services/finding-readiness.js';
import type { ReportFinding } from '../../services/report-generator.js';

function mkFinding(overrides: Partial<ReportFinding> = {}): ReportFinding {
  return {
    id: 'f-1',
    title: 'Test finding',
    severity: 'high',
    category: 'vulnerability',
    description: 'desc',
    affected_assets: [],
    evidence: [],
    remediation: 'fix it',
    risk_score: 7,
    ...overrides,
  } as ReportFinding;
}

describe('get_finding_readiness assess()', () => {
  it('client_ready when a proof card backs the finding', () => {
    const r = assess(mkFinding({ proof_cards: [{ id: 'pc-1' } as never] }));
    expect(r.readiness).toBe('client_ready');
    expect(r.proof_cards).toBe(1);
    // No "no captured evidence" gap when client-ready.
    expect(r.gaps.some(g => g.includes('no captured evidence'))).toBe(false);
  });

  it('client_ready when an evidence chain cites captured bytes (stdout_evidence_id)', () => {
    const r = assess(mkFinding({
      affected_assets: ['10.0.0.1'],
      evidence: [{ claim: 'proof', stdout_evidence_id: 'ev-123' } as never],
    }));
    expect(r.readiness).toBe('client_ready');
    expect(r.captured_evidence).toBe(true);
  });

  it('needs_validation when there are chains/assets but no captured bytes', () => {
    const r = assess(mkFinding({
      affected_assets: ['10.0.0.1'],
      evidence: [{ claim: 'claimed but unproven' } as never],
    }));
    expect(r.readiness).toBe('needs_validation');
    expect(r.captured_evidence).toBe(false);
    expect(r.gaps).toContain('no captured evidence — run/parse the action that proves this finding');
  });

  it('draft when thin: no captured evidence, no chains, no affected assets', () => {
    const r = assess(mkFinding());
    expect(r.readiness).toBe('draft');
    expect(r.gaps).toContain('no affected assets linked');
    expect(r.gaps.some(g => g.includes('no captured evidence'))).toBe(true);
  });

  it('flags an unclassified finding (no CWE/OWASP/ATT&CK mapping)', () => {
    const unclassified = assess(mkFinding({ affected_assets: ['x'] }));
    expect(unclassified.classified).toBe(false);
    expect(unclassified.gaps.some(g => g.includes('unclassified'))).toBe(true);

    const classified = assess(mkFinding({ affected_assets: ['x'], classification: { cwe: 'CWE-79' } as never }));
    expect(classified.classified).toBe(true);
    expect(classified.gaps.some(g => g.includes('unclassified'))).toBe(false);
  });
});
