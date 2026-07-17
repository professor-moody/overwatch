import { afterEach, describe, expect, it } from 'vitest';
import { assembleReport } from '../report-assembler.js';
import { isPdfRenderingAvailable, renderReportPdf } from '../report-pdf.js';
import { createReportQaFixture, REPORT_QA_SECRET_MARKERS, type ReportQaFixture } from '../report-qa-fixture.js';
import { PlaybookRunService } from '../playbook-run-service.js';

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

describe('report QA fixture outputs', () => {
  it('keeps playbook coverage aligned across Markdown, HTML, JSON, and client-safe output', () => {
    const qa = fixture();
    const runs = new PlaybookRunService(qa.engine);
    const opened = runs.open({
      definition: { definition_id: 'aws-credential', definition_version: 2, provider: 'aws', title: 'AWS credential expansion' },
      credential_id: 'cred-report-secret-id',
      normalized_inputs: {},
      steps: [{ step_id: 'identity', step: 1, description: 'Resolve identity', runner: 'run_tool', binary: 'aws', args: ['sts', 'get-caller-identity'], ready: true, status: 'ready' }],
    });
    const claim = runs.startStep(opened.run.run_id, 'identity');
    runs.finishAttempt(opened.run.run_id, 'identity', claim.attempt.attempt_id, {
      execution_outcome: 'succeeded', parse_outcome: 'partial',
      evidence_ids: ['ev-duplicate', 'ev-duplicate'],
      finding_ids: ['finding-duplicate', 'finding-duplicate'],
    });
    qa.engine.setPlaybookRuns([
      ...qa.engine.getPlaybookRuns(),
      { run_id: 'legacy-playbook-placeholder', status: 'pending' },
    ]);

    const markdown = assembleReport(qa.engine, qa.skills, { format: 'markdown', profile: 'operator' }).content;
    const html = assembleReport(qa.engine, qa.skills, { format: 'html', profile: 'operator' }).content;
    const json = JSON.parse(assembleReport(qa.engine, qa.skills, { format: 'json', profile: 'operator' }).content) as { playbooks: { total: number; partial: number; runs: Array<Record<string, unknown>> } };
    const client = JSON.parse(assembleReport(qa.engine, qa.skills, { format: 'json', profile: 'client', client_safe: true }).content) as { playbooks: { runs: Array<Record<string, unknown>> } };

    expect(markdown).toContain('[Credential Playbooks](#credential-playbooks)');
    expect(markdown).toContain(opened.run.run_id);
    expect(markdown).toContain('| partial | succeeded |');
    expect(html).toContain('id="credential-playbooks"');
    expect(html).toContain(opened.run.run_id);
    expect(json.playbooks).toMatchObject({ total: 1, partial: 1 });
    expect(json.playbooks.runs[0]).toMatchObject({ evidence_count: 1, finding_count: 1, report_status: 'partial' });
    expect(client.playbooks.runs[0]).not.toHaveProperty('credential_id');
    expect(client.playbooks.runs[0]).not.toHaveProperty('run_id');
  });

  it('renders client HTML with proof cards and no raw secret markers', () => {
    const qa = fixture();
    const clientHtml = assembleReport(qa.engine, qa.skills, {
      format: 'html',
      profile: 'client',
      client_safe: true,
      evidence_style: 'proof_cards',
      include_attack_paths: true,
      include_evidence: true,
      include_narrative: true,
    }).content;

    expect(clientHtml).toContain('class="proof-card"');
    expect(clientHtml).toContain('Action Plan');
    expect(clientHtml).not.toContain('<h2>Evidence Appendix</h2>');
    expect(clientHtml).not.toContain('class="proof-ref"');
    expect(clientHtml).not.toContain('href="#ev-');
    expect(clientHtml).toContain('Evidence metadata');
    expect(clientHtml).toContain('Raw output preview redacted');
    expect(clientHtml).toContain('Administrative cloud role is reachable');
    expect(clientHtml).toContain('Captured credential material');
    expect(clientHtml).not.toContain('<h2>Recommendations</h2>');
    expect(clientHtml).not.toContain('Cloud Identity:');
    expect(clientHtml).not.toContain('Cloud Resource:');
    expect(clientHtml).not.toContain('Credential Obtained:');
    expect(clientHtml).not.toContain('Web Application:');
    for (const marker of REPORT_QA_SECRET_MARKERS) {
      expect(clientHtml).not.toContain(marker);
    }
  });

  it('renders operator HTML and Markdown with evidence IDs, hashes, action IDs, and raw previews', () => {
    const qa = fixture();
    const operatorHtml = assembleReport(qa.engine, qa.skills, {
      format: 'html',
      profile: 'operator',
      evidence_style: 'proof_cards',
      include_attack_paths: true,
    }).content;
    const operatorMarkdown = assembleReport(qa.engine, qa.skills, {
      format: 'markdown',
      profile: 'operator',
      evidence_style: 'proof_cards',
      include_attack_paths: true,
    }).content;

    expect(operatorHtml).toContain('Raw preview');
    expect(operatorHtml).toContain('Evidence Appendix');
    expect(operatorHtml).toContain('Backup2024!');
    expect(operatorHtml).toContain(qa.evidenceIds.rdp.slice(0, 12));
    expect(operatorHtml).toContain('act-report-qa-rdp'.slice(0, 8));
    expect(operatorHtml).toContain('SHA-256');

    expect(operatorMarkdown).toContain('Raw preview');
    expect(operatorMarkdown).toContain('Backup2024!');
    expect(operatorMarkdown).toContain(qa.evidenceIds.rdp);
    expect(operatorMarkdown).toContain('act-report-qa-rdp');
    expect(operatorMarkdown).toContain('SHA-256');
  });

  it('renders JSON with profile metadata, trust signals, attack paths, and deduplicated appendix citations', () => {
    const qa = fixture();
    const operatorJson = JSON.parse(assembleReport(qa.engine, qa.skills, {
      format: 'json',
      profile: 'operator',
      evidence_style: 'proof_cards',
      include_attack_paths: true,
    }).content) as {
      report_profile: string;
      executive_summary?: { risk_posture?: string; headline?: string };
      action_plan?: Array<{ id: string; related_findings?: string[] }>;
      evidence_appendix: Array<{ evidence_id?: string; finding_ids?: string[] }>;
      trust_signals: unknown[];
      attack_paths?: unknown[];
    };
    const clientJsonText = assembleReport(qa.engine, qa.skills, {
      format: 'json',
      profile: 'client',
      client_safe: true,
      evidence_style: 'proof_cards',
      include_attack_paths: true,
    }).content;
    const clientJson = JSON.parse(clientJsonText) as {
      report_profile: string;
      executive_summary?: { risk_posture?: string; headline?: string };
      action_plan?: Array<{ id: string; related_findings?: string[] }>;
      evidence_appendix: unknown[];
      findings: Array<{ title: string; presentation?: { title?: string; summary?: string; impact?: string } }>;
    };

    expect(operatorJson.report_profile).toBe('operator');
    expect(operatorJson.executive_summary?.headline).toMatch(/assessment identified/i);
    expect(operatorJson.action_plan?.some(item => item.id === 'credential-rotation')).toBe(true);
    expect(operatorJson.evidence_appendix.length).toBeGreaterThan(0);
    expect(operatorJson.trust_signals.length).toBeGreaterThan(0);
    expect(operatorJson.attack_paths?.length ?? 0).toBeGreaterThan(0);
    const shared = operatorJson.evidence_appendix.find(entry => entry.evidence_id === qa.evidenceIds.shared);
    expect(shared?.finding_ids?.length).toBeGreaterThanOrEqual(2);

    expect(clientJson.report_profile).toBe('client');
    expect(clientJson.executive_summary?.risk_posture).toBeTruthy();
    expect(clientJson.action_plan?.some(item => item.id === 'application-authorization')).toBe(true);
    expect(clientJson.evidence_appendix.length).toBeGreaterThan(0);
    expect(clientJson.findings.some(f => f.presentation?.title?.includes('Administrative cloud role is reachable'))).toBe(true);
    expect(clientJson.findings.every(f => f.presentation?.title && f.presentation.summary && f.presentation.impact)).toBe(true);
    expect(clientJson.findings.map(f => f.presentation?.title).join('\n')).not.toContain('Credential Obtained:');
    for (const marker of REPORT_QA_SECRET_MARKERS) {
      expect(clientJsonText).not.toContain(marker);
    }
  });

  // Puppeteer render can exceed 30s under CI load (cold Chromium + parallel
  // suites). Give it headroom + one retry so a transient slow render doesn't
  // fail the run; a genuine hang still fails after the retry.
  it.skipIf(!isPdfRenderingAvailable().available)('renders the client HTML fixture to a PDF buffer', { timeout: 60_000, retry: 1 }, async () => {
    const qa = fixture();
    const clientHtml = assembleReport(qa.engine, qa.skills, {
      format: 'html',
      profile: 'client',
      client_safe: true,
      evidence_style: 'proof_cards',
    }).content;
    const pdf = await renderReportPdf(clientHtml, { format: 'A4', printBackground: true });
    expect(pdf.byteLength).toBeGreaterThan(1024);
    expect(pdf.subarray(0, 5).toString('ascii')).toBe('%PDF-');
  });
});
