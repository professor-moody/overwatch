import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync, rmSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerAgentTools } from '../agents.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-submit-transcript.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-submit-transcript',
    name: 'submit_agent_transcript test',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: ['test.local'], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function cleanup(): void {
  try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch {}
  try { rmSync('./evidence-test-submit-transcript', { recursive: true, force: true }); } catch {}
}

function parse(result: any): any {
  return JSON.parse(result.content[0].text);
}

async function registerAgent(handlers: Record<string, any>, engine: GraphEngine, agent_id: string): Promise<string> {
  engine.addNode({
    id: 'host-10-10-10-1',
    type: 'host',
    label: '10.10.10.1',
    ip: '10.10.10.1',
    discovered_at: new Date().toISOString(),
    discovered_by: 'test',
    confidence: 1.0,
  });
  const result = await handlers.register_agent({
    agent_id,
    frontier_item_id: 'frontier-node-host-10-10-10-1',
    subgraph_node_ids: ['host-10-10-10-1'],
  });
  return parse(result).task_id;
}

describe('submit_agent_transcript', () => {
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
    registerAgentTools(fakeServer, engine);
  });

  afterEach(() => {
    cleanup();
  });

  it('stores transcript as evidence and emits a linked event', async () => {
    const task_id = await registerAgent(handlers, engine, 'agent-A');
    const transcript = '{"role":"user","text":"go"}\n{"role":"assistant","text":"done"}\n';

    const result = await handlers.submit_agent_transcript({
      agent_id: task_id,
      summary: 'Enumerated host, found nothing exploitable.',
      transcript_jsonl: transcript,
      key_finding_ids: ['fnd-1'],
    });
    const payload = parse(result);

    expect(result.isError).toBeFalsy();
    expect(payload.submitted).toBe(true);
    expect(payload.evidence_id).toBeTruthy();
    expect(payload.transcript_bytes).toBe(transcript.length);

    // Evidence content stored
    const stored = engine.getEvidenceStore().getContent(payload.evidence_id);
    expect(stored).toBe(transcript);

    // Event present and linked
    const events = engine.getFullHistory().filter(e => e.event_type === 'agent_transcript_submitted');
    expect(events.length).toBe(1);
    const ev = events[0];
    expect(ev.linked_agent_task_id).toBe(task_id);
    expect(ev.agent_id).toBe('agent-A');
    expect((ev.details as any).evidence_id).toBe(payload.evidence_id);
    expect((ev.details as any).summary).toBeTruthy();
    expect(ev.linked_finding_ids).toEqual(['fnd-1']);
  });

  it('works without a transcript blob (summary only)', async () => {
    const task_id = await registerAgent(handlers, engine, 'agent-B');
    const result = await handlers.submit_agent_transcript({
      agent_id: task_id,
      summary: 'Quick check, nothing to add.',
    });
    const payload = parse(result);
    expect(result.isError).toBeFalsy();
    expect(payload.submitted).toBe(true);
    expect(payload.evidence_id).toBeUndefined();
    expect(payload.transcript_bytes).toBe(0);

    const events = engine.getFullHistory().filter(e => e.event_type === 'agent_transcript_submitted');
    expect(events.length).toBe(1);
  });

  it('returns error when agent does not exist', async () => {
    const result = await handlers.submit_agent_transcript({
      agent_id: 'no-such-agent',
      summary: 'should fail',
    });
    expect(result.isError).toBe(true);
    expect(parse(result).error).toMatch(/not found/);
  });

  it('update_agent emits instrumentation_warning when closed without a transcript', async () => {
    const task_id = await registerAgent(handlers, engine, 'agent-C');
    const result = await handlers.update_agent({
      task_id,
      status: 'completed',
      summary: 'forgot to submit',
    });
    const payload = parse(result);
    expect(payload.updated).toBe(true);
    expect(payload.transcript_warning).toBeTruthy();

    const warnings = engine.getFullHistory().filter(e =>
      e.event_type === 'instrumentation_warning'
      && (e.details as any)?.warning === 'missing_agent_transcript',
    );
    expect(warnings.length).toBe(1);
    expect(warnings[0].linked_agent_task_id).toBe(task_id);
  });

  it('update_agent does NOT warn when transcript was submitted first', async () => {
    const task_id = await registerAgent(handlers, engine, 'agent-D');
    await handlers.submit_agent_transcript({
      agent_id: task_id,
      summary: 'wrap-up',
    });
    const result = await handlers.update_agent({
      task_id,
      status: 'completed',
    });
    const payload = parse(result);
    expect(payload.updated).toBe(true);
    expect(payload.transcript_warning).toBeUndefined();

    const warnings = engine.getFullHistory().filter(e =>
      e.event_type === 'instrumentation_warning'
      && (e.details as any)?.warning === 'missing_agent_transcript',
    );
    expect(warnings.length).toBe(0);
  });
});
