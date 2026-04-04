import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerFindingTools } from '../findings.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-findings.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-findings',
    name: 'Findings Test Engagement',
    created_at: new Date().toISOString(),
    scope: {
      cidrs: ['10.10.10.0/24'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function cleanup(): void {
  try {
    if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
  } catch {}
}

describe('finding tools', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;

  beforeEach(() => {
    cleanup();
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    handlers = {};

    const fakeServer = {
      registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
        handlers[name] = handler;
      },
    } as unknown as McpServer;

    registerFindingTools(fakeServer, engine);
  });

  afterEach(() => {
    cleanup();
  });

  it('report_finding with a simple host node returns finding_id and counts', async () => {
    const result = await handlers.report_finding({
      agent_id: 'agent-1',
      tool_name: 'nmap',
      nodes: [
        { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', properties: { ip: '10.10.10.1' } },
      ],
      edges: [],
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.finding_id).toBeDefined();
    expect(payload.new_nodes).toBeInstanceOf(Array);
    expect(payload.new_edges).toBeInstanceOf(Array);
    expect(payload.new_nodes).toContain('host-10-10-10-1');
  });

  it('report_finding with evidence returns evidence_id', async () => {
    const result = await handlers.report_finding({
      agent_id: 'agent-evidence',
      tool_name: 'manual',
      nodes: [
        { id: 'host-10-10-10-2', type: 'host', label: '10.10.10.2', properties: { ip: '10.10.10.2' } },
      ],
      edges: [],
      evidence: { type: 'command_output', content: 'uid=0(root)' },
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.finding_id).toBeDefined();
    expect(payload.evidence_id).toBeDefined();
  });

  it('get_evidence with valid ID returns content', async () => {
    const finding = await handlers.report_finding({
      agent_id: 'agent-ev',
      tool_name: 'manual',
      nodes: [
        { id: 'host-10-10-10-3', type: 'host', label: '10.10.10.3', properties: { ip: '10.10.10.3' } },
      ],
      edges: [],
      evidence: { type: 'command_output', content: 'test evidence content' },
      raw_output: 'raw output here',
    });

    const findingPayload = JSON.parse(finding.content[0].text);
    const evidenceId = findingPayload.evidence_id;

    const result = await handlers.get_evidence({
      evidence_id: evidenceId,
      list_only: false,
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.evidence_id).toBe(evidenceId);
    expect(payload.content).toBe('test evidence content');
    expect(payload.raw_output).toBe('raw output here');
  });

  it('get_evidence with invalid ID returns error', async () => {
    const result = await handlers.get_evidence({
      evidence_id: 'nonexistent-evidence-id',
      list_only: false,
    });

    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.error).toContain('not found');
  });
});
