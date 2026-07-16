import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerFindingTools } from '../findings.js';
import type { EngagementConfig } from '../../types.js';

let testDir: string;
let testStateFile: string;

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

describe('finding tools', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;

  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'overwatch-findings-'));
    testStateFile = join(testDir, 'state.json');
    engine = new GraphEngine(makeConfig(), testStateFile);
    handlers = {};

    const fakeServer = {
      registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
        handlers[name] = handler;
      },
    } as unknown as McpServer;

    registerFindingTools(fakeServer, engine);
  });

  afterEach(() => {
    engine.dispose();
    rmSync(testDir, { recursive: true, force: true });
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

  it('keeps blob-first evidence orphaned but does not commit a finding reference when ingest fails', async () => {
    vi.spyOn(engine, 'ingestFinding').mockImplementationOnce(() => {
      throw new Error('synthetic ingest failure');
    });

    const result = await handlers.report_finding({
      agent_id: 'agent-failed-ingest',
      action_id: 'action-failed-ingest',
      tool_name: 'manual',
      nodes: [
        { id: 'host-failed-ingest', type: 'host', label: 'failed ingest', properties: { ip: '10.10.10.44' } },
      ],
      edges: [],
      evidence: { type: 'command_output', content: 'durable orphan candidate' },
    });

    expect(result.isError).toBe(true);
    expect(engine.getEvidenceStore().list({ action_id: 'action-failed-ingest' })).toHaveLength(1);
    expect(engine.getFullHistory().filter(entry =>
      entry.action_id === 'action-failed-ingest'
      && entry.event_type === 'finding_reported'
    )).toHaveLength(0);
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

  it('persists a reported finding to disk synchronously (no debounce window)', async () => {
    // M3: report_finding flushes immediately, so the node is on disk the instant
    // the call returns — a daemon crash in the next moment can't lose it. Under
    // the old debounced persist() the state file would NOT yet contain the node
    // (the write is scheduled ~100ms later), so reading it synchronously here
    // proves the flush happened.
    await handlers.report_finding({
      agent_id: 'agent-durable',
      tool_name: 'nmap',
      nodes: [{ id: 'host-durable-1', type: 'host', label: '10.10.10.9', properties: { ip: '10.10.10.9' } }],
      edges: [],
    });
    const onDisk = readFileSync(testStateFile, 'utf8');
    expect(onDisk).toContain('host-durable-1');
  });
});
