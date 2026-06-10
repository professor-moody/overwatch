import { afterEach, describe, expect, it } from 'vitest';
import { buildFindings, buildReportEvidenceModel } from '../report-generator.js';
import { buildActionPlan, buildExecutiveSummary } from '../report-deliverable.js';
import { createReportQaFixture, type ReportQaFixture } from '../report-qa-fixture.js';

const cleanups: Array<() => void> = [];

function fixture(): ReportQaFixture {
  const created = createReportQaFixture();
  cleanups.push(created.cleanup);
  return created;
}

afterEach(() => {
  while (cleanups.length > 0) {
    cleanups.pop()?.();
  }
});

function buildFixtureModel() {
  const qa = fixture();
  const config = qa.engine.getConfig();
  const graph = qa.engine.exportGraph();
  const history = qa.engine.getFullHistory();
  const evidenceLoader = (id: string) => qa.engine.getEvidenceStore().getRawOutput(id);
  const evidenceRecordLoader = (id: string) => qa.engine.getEvidenceStore().getRecord(id);
  const baseFindings = buildFindings(graph, history, config, { evidenceLoader, evidenceRecordLoader });
  const proofModel = buildReportEvidenceModel(baseFindings, { profile: 'client', includeEvidence: true });
  return { config, graph, findings: proofModel.findings, evidenceCount: proofModel.evidenceCount };
}

describe('report deliverable presentation model', () => {
  it('builds a client-readable executive summary with risk posture, objectives, evidence, and caveats', () => {
    const model = buildFixtureModel();
    const summary = buildExecutiveSummary({ ...model, profile: 'client', trustSignals: [{ id: 'sig-1', severity: 'warning', label: 'Parser caveat', source: 'activity' }] });

    expect(summary.profile).toBe('client');
    expect(['critical', 'elevated', 'moderate', 'low']).toContain(summary.risk_posture);
    expect(summary.headline).toMatch(/assessment identified/i);
    expect(summary.objective_summary).toContain('engagement objective');
    expect(summary.evidence_summary).toContain('cited evidence artifact');
    expect(summary.verification_summary).toContain('operator verification signal');
    expect(summary.top_risk_themes).toEqual(expect.arrayContaining(['credential exposure', 'application authorization']));
  });

  it('deduplicates action-plan groups across credential, app, host, cloud, and validation work', () => {
    const model = buildFixtureModel();
    const plan = buildActionPlan({ ...model, profile: 'client' });
    const ids = plan.map(item => item.id);

    expect(ids).toContain('credential-rotation');
    expect(ids).toContain('application-authorization');
    expect(ids).toContain('session-revocation');
    expect(ids).toContain('cloud-permissions');
    expect(ids).toContain('verification-backlog');
    expect(new Set(ids).size).toBe(ids.length);
    expect(plan.find(item => item.id === 'credential-rotation')?.related_findings.length).toBeGreaterThan(0);
    expect(plan.every(item => item.action && item.rationale && item.verification)).toBe(true);
  });

  it('uses short client report titles for top-level sections while preserving technical presentation detail', () => {
    const model = buildFixtureModel();
    const credential = model.findings.find(finding => finding.category === 'credential' && finding.title.includes('oidc_access_token'));

    expect(credential?.presentation?.short_title).toBe('OIDC token validated for authentication');
    expect(credential?.presentation?.short_title).not.toContain('repo:corp/benefits-portal');
    expect(credential?.presentation?.technical_context).toContain('repo:corp/benefits-portal');
  });
});
