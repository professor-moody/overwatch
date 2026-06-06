import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

vi.mock('../../services/report-assembler.js', () => ({
  assembleReport: vi.fn((_engine, _skills, opts) => ({
    format: opts.format,
    content: opts.format === 'html' ? '<html><body><h1>Report</h1></body></html>' : '# Test Report\n\nExecutive summary here.',
    findings_count: 3,
    evidence_count: 2,
    profile: opts.profile ?? (opts.client_safe ? 'client' : 'operator'),
    redaction_mode: opts.client_safe || opts.profile === 'client' ? 'client_safe' : 'operator',
    severity_summary: { critical: 1, high: 1, medium: 1, low: 0, info: 0 },
    navigator_layer: opts.include_attack_navigator ? { name: 'Navigator' } : undefined,
  })),
}));

vi.mock('fs', () => ({
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn(),
  existsSync: vi.fn(() => false),
}));

import { registerReportingTools } from '../reporting.js';
import { assembleReport } from '../../services/report-assembler.js';

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
    expect(assembleReport).toHaveBeenCalledTimes(1);
    expect(vi.mocked(assembleReport).mock.calls[0][2]).toEqual(expect.objectContaining({ format: 'markdown' }));
  });

  it('returns HTML format through the shared assembler', async () => {
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
    expect(assembleReport).toHaveBeenCalledTimes(1);
    expect(vi.mocked(assembleReport).mock.calls[0][2]).toEqual(
      expect.objectContaining({ format: 'html', theme: 'dark' }),
    );
  });

  it('passes render options to the shared assembler', async () => {
    const { handlers, engine } = buildHandlers();

    await handlers.generate_report({
      format: 'markdown',
      include_evidence: true,
      include_narrative: false,
      include_retrospective: false,
      write_to_disk: false,
      output_dir: './reports/',
      theme: 'light',
      profile: 'client',
      evidence_style: 'proof_cards',
    });

    expect(engine.getConfig).toHaveBeenCalled();
    expect(assembleReport).toHaveBeenCalledWith(
      engine,
      expect.anything(),
      expect.objectContaining({
        format: 'markdown',
        profile: 'client',
        evidence_style: 'proof_cards',
        include_narrative: false,
      }),
    );
  });
});
