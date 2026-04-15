import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

vi.mock('../../services/report-generator.js', () => ({
  generateFullReport: vi.fn(() => '# Test Report\n\nExecutive summary here.'),
  buildFindings: vi.fn(() => [
    { severity: 'critical', risk_score: 9.5, title: 'Critical Finding', remediation: 'Fix immediately\nDetails here', affected_assets: [], evidence: [], category: 'compromised_host' },
    { severity: 'high', risk_score: 7.0, title: 'High Finding', remediation: 'Patch system\nMore info', affected_assets: [], evidence: [], category: 'credential' },
    { severity: 'medium', risk_score: 4.5, title: 'Medium Finding', remediation: 'Review config', affected_assets: [], evidence: [], category: 'vulnerability' },
  ]),
  buildAttackNarrative: vi.fn(() => []),
  buildRemediationRanking: vi.fn(() => []),
}));

vi.mock('../../services/report-html.js', () => ({
  renderReportHtml: vi.fn(() => '<html><body><h1>Report</h1></body></html>'),
}));

vi.mock('../../services/finding-classifier.js', () => ({
  classifyAllFindings: vi.fn(() => new Map()),
  generateNavigatorLayer: vi.fn(() => ({})),
}));

vi.mock('../../services/retrospective.js', () => ({
  runRetrospective: vi.fn(() => ({
    inference_suggestions: [],
    skill_gaps: [],
    context_improvements: [],
    trace_quality: { total_actions: 0, traced_actions: 0, ratio: 0 },
  })),
  buildCredentialChains: vi.fn(() => []),
}));

vi.mock('fs', () => ({
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn(),
  existsSync: vi.fn(() => false),
}));

import { registerReportingTools } from '../reporting.js';
import { generateFullReport } from '../../services/report-generator.js';
import { renderReportHtml } from '../../services/report-html.js';

function buildHandlers() {
  const handlers: Record<string, (args: any) => Promise<any>> = {};
  const fakeServer = {
    registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
      handlers[name] = handler;
    },
  } as unknown as McpServer;

  const engine = {
    getConfig: vi.fn(() => ({
      id: 'test-engagement',
      name: 'Test Engagement',
      scope: { cidrs: ['10.0.0.0/24'], domains: ['test.local'], exclusions: [] },
      objectives: [],
      opsec: { name: 'pentest', max_noise: 0.7 },
    })),
    exportGraph: vi.fn(() => ({ nodes: [], edges: [] })),
    getFullHistory: vi.fn(() => []),
    getAllAgents: vi.fn(() => []),
    getInferenceRules: vi.fn(() => []),
  };

  const skills = {
    listSkills: vi.fn(() => []),
  };

  registerReportingTools(fakeServer, engine as any, skills as any);
  return { handlers, engine };
}

describe('generate_report tool', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns markdown format with severity summary', async () => {
    const { handlers } = buildHandlers();

    const result = await handlers.generate_report({
      format: 'markdown',
      include_evidence: true,
      include_narrative: true,
      include_retrospective: false,
      write_to_disk: false,
      output_dir: './reports/',
      theme: 'light',
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.format).toBe('markdown');
    expect(payload.findings_count).toBe(3);
    expect(payload.severity_summary.critical).toBe(1);
    expect(payload.severity_summary.high).toBe(1);
    expect(payload.severity_summary.medium).toBe(1);
    expect(payload.report_preview).toContain('# Test Report');
    expect(generateFullReport).toHaveBeenCalledTimes(1);
    expect(renderReportHtml).not.toHaveBeenCalled();
  });

  it('returns HTML format and calls renderReportHtml', async () => {
    const { handlers } = buildHandlers();

    const result = await handlers.generate_report({
      format: 'html',
      include_evidence: true,
      include_narrative: true,
      include_retrospective: false,
      write_to_disk: false,
      output_dir: './reports/',
      theme: 'dark',
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.format).toBe('html');
    expect(payload.report_preview).toContain('<html>');
    expect(renderReportHtml).toHaveBeenCalledTimes(1);
    expect(vi.mocked(renderReportHtml).mock.calls[0][1]).toEqual(
      expect.objectContaining({ theme: 'dark' }),
    );
  });

  it('calls engine methods to gather graph data', async () => {
    const { handlers, engine } = buildHandlers();

    await handlers.generate_report({
      format: 'markdown',
      include_evidence: true,
      include_narrative: false,
      include_retrospective: false,
      write_to_disk: false,
      output_dir: './reports/',
      theme: 'light',
    });

    expect(engine.getConfig).toHaveBeenCalled();
    expect(engine.exportGraph).toHaveBeenCalled();
    expect(engine.getFullHistory).toHaveBeenCalled();
    expect(engine.getAllAgents).toHaveBeenCalled();
  });
});
