import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerAgentTools } from '../agents.js';
import type { EngagementConfig } from '../../types.js';

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
  let testDir: string;

  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'overwatch-submit-transcript-'));
    engine = new GraphEngine(makeConfig(), join(testDir, 'state.json'));
    handlers = {};
    const fakeServer = {
      registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
        handlers[name] = handler;
      },
    } as unknown as McpServer;
    registerAgentTools(fakeServer, engine);
  });

  afterEach(() => {
    engine.dispose();
    rmSync(testDir, { recursive: true, force: true });
  });

  it('register_agent accepts canonical agent_label and returns synchronized aliases', async () => {
    engine.addNode({
      id: 'host-canonical',
      type: 'host',
      label: '10.10.10.2',
      ip: '10.10.10.2',
      discovered_at: new Date().toISOString(),
      discovered_by: 'test',
      confidence: 1,
    });
    const result = await handlers.register_agent({
      agent_label: 'canonical-agent',
      frontier_item_id: 'frontier-node-host-canonical',
      subgraph_node_ids: ['host-canonical'],
    });
    const payload = parse(result);
    expect(payload).toMatchObject({
      task_id: expect.any(String),
      agent_label: 'canonical-agent',
      id: expect.any(String),
      agent_id: 'canonical-agent',
    });
    expect(payload.id).toBe(payload.task_id);
    expect(engine.getTask(payload.task_id)).toMatchObject({
      task_id: payload.task_id,
      agent_label: 'canonical-agent',
      id: payload.task_id,
      agent_id: 'canonical-agent',
    });
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

  it('rejects an ambiguous legacy label instead of selecting the newest task', async () => {
    for (const taskId of ['task-shared-a', 'task-shared-b']) {
      engine.registerAgent({
        id: taskId,
        agent_id: 'shared-label',
        assigned_at: new Date().toISOString(),
        status: 'running',
        frontier_item_id: `fi-${taskId}`,
        subgraph_node_ids: [],
      });
    }
    const result = await handlers.submit_agent_transcript({
      agent_id: 'shared-label',
      summary: 'must not guess',
    });
    expect(result.isError).toBe(true);
    expect(parse(result)).toMatchObject({
      error: 'Agent label is ambiguous: shared-label',
      candidate_task_ids: ['task-shared-a', 'task-shared-b'],
    });
    expect(engine.getFullHistory().filter(e => e.event_type === 'agent_transcript_submitted')).toEqual([]);
  });

  it('redelivers answered questions until the agent explicitly acknowledges them', async () => {
    const task_id = await registerAgent(handlers, engine, 'agent-question');
    const query = engine.getAgentQueryStore().add({
      owner_task_id: task_id,
      owner_agent_label: 'agent-question',
      question: 'left or right?',
    });
    engine.getAgentQueryStore().answer(query.query_id, 'left');

    const first = parse(await handlers.agent_heartbeat({ task_id }));
    expect(first.pending_answer).toMatchObject({
      query_id: query.query_id,
      answer: 'left',
    });
    expect(engine.getAgentQueryStore().get(query.query_id)?.delivered_at).toBeDefined();

    const second = parse(await handlers.agent_heartbeat({ task_id }));
    expect(second.pending_answer?.query_id).toBe(query.query_id);

    const acknowledged = parse(await handlers.agent_heartbeat({
      task_id,
      acknowledged_query_id: query.query_id,
    }));
    expect(acknowledged.acknowledged_query_id).toBe(query.query_id);
    expect(acknowledged.pending_answer).toBeUndefined();
    expect(engine.getAgentQueryStore().get(query.query_id)?.acknowledged_at).toBeDefined();
  });

  it('does not use another duplicate-label task transcript to satisfy close-out', async () => {
    for (const taskId of ['task-dupe-a', 'task-dupe-b']) {
      engine.registerAgent({
        id: taskId,
        agent_id: 'duplicate-label',
        assigned_at: new Date().toISOString(),
        status: 'running',
        frontier_item_id: `fi-${taskId}`,
        subgraph_node_ids: [],
      });
    }
    await handlers.submit_agent_transcript({
      task_id: 'task-dupe-a',
      summary: 'task A wrapped',
    });
    const result = parse(await handlers.update_agent({
      task_id: 'task-dupe-b',
      status: 'completed',
    }));
    expect(result.transcript_warning).toBeTruthy();
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
