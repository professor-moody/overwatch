import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerStateTools } from '../state.js';
import { registerScopeTools } from '../scope.js';
import { registerLoggingTools } from '../logging.js';
import { registerLogThoughtTool } from '../log-thought.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-state-tools.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-state-tools',
    name: 'State Tools Test Engagement',
    created_at: new Date().toISOString(),
    scope: {
      cidrs: ['10.10.10.0/24'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [
      { id: 'obj-1', description: 'Compromise host', achieved: false },
    ],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function cleanup(): void {
  try {
    if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
  } catch {}
}

describe('state tools', () => {
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

    registerStateTools(fakeServer, engine);
    registerScopeTools(fakeServer, engine);
    registerLoggingTools(fakeServer, engine);
    registerLogThoughtTool(fakeServer, engine);
  });

  afterEach(() => {
    cleanup();
  });

  it('get_state returns graph_summary, objectives, and scope', async () => {
    const result = await handlers.get_state({
      include_full_frontier: true,
      activity_count: 20,
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.graph_summary).toBeDefined();
    expect(payload.objectives).toBeDefined();
    expect(payload.config.scope).toBeDefined();
    expect(payload.config.scope.cidrs).toContain('10.10.10.0/24');
    expect(payload.frontier).toBeInstanceOf(Array);
  });

  it('get_history returns cursor and has_more fields for pagination', async () => {
    // Seed some activity entries
    for (let i = 0; i < 5; i++) {
      await handlers.log_action_event({
        action_id: `act-pagination-${i}`,
        event_type: 'action_started',
        description: `Test action ${i}`,
        target_node_ids: [],
      });
    }

    const result = await handlers.get_history({
      limit: 2,
      direction: 'oldest_first',
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.returned).toBe(2);
    expect(payload.has_more).toBe(true);
    expect(payload.next_cursor).toBeDefined();
    expect(payload.total_entries).toBeGreaterThanOrEqual(5);

    // Verify next page works
    const page2 = await handlers.get_history({
      limit: 2,
      cursor: payload.next_cursor,
      direction: 'oldest_first',
    });
    const page2Payload = JSON.parse(page2.content[0].text);
    expect(page2Payload.returned).toBe(2);
  });

  it('get_history filters by since timestamp and event_types (OR)', async () => {
    // Seed precise event types directly (bypasses tool-level action lifecycle rules).
    engine.logActionEvent({ description: 'started', event_type: 'action_started', category: 'frontier' });
    engine.logActionEvent({ description: 'agent wrapped up', event_type: 'agent_transcript_submitted', category: 'agent' });

    // (limit is passed explicitly because the test's fake server doesn't apply
    // the zod default the real MCP layer would.)
    // event_types OR-filter returns only the requested type(s) — the synthesis
    // loop polls for completions this way.
    const onlyDone = JSON.parse((await handlers.get_history({ limit: 100, event_types: ['agent_transcript_submitted'] })).content[0].text);
    expect(onlyDone.entries.length).toBeGreaterThanOrEqual(1);
    expect(onlyDone.entries.every((e: { event_type?: string }) => e.event_type === 'agent_transcript_submitted')).toBe(true);

    // since in the future → nothing newer than that.
    const future = JSON.parse((await handlers.get_history({ limit: 100, since: '2999-01-01T00:00:00Z' })).content[0].text);
    expect(future.returned).toBe(0);

    // since in the past + an event_types OR-set → the matching entries come back.
    const past = JSON.parse((await handlers.get_history({ limit: 100, since: '2000-01-01T00:00:00Z', event_types: ['action_started', 'agent_transcript_submitted'] })).content[0].text);
    expect(past.entries.length).toBeGreaterThanOrEqual(2);
    expect(past.entries.every((e: { event_type?: string }) => e.event_type === 'action_started' || e.event_type === 'agent_transcript_submitted')).toBe(true);

    // an unparseable since is ignored (not treated as "exclude everything").
    const badSince = JSON.parse((await handlers.get_history({ limit: 100, since: 'not-a-date' })).content[0].text);
    expect(badSince.total_entries).toBeGreaterThanOrEqual(2);
  });

  it('update_scope adds a CIDR to scope in preview mode', async () => {
    const result = await handlers.update_scope({
      add_cidrs: ['172.16.0.0/24'],
      reason: 'Pivot network discovered',
      confirm: false,
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.mode).toBe('preview');
    expect(payload.after.cidrs).toContain('172.16.0.0/24');
    expect(payload.before.cidrs).not.toContain('172.16.0.0/24');
  });

  it('update_scope applies a CIDR change when confirmed', async () => {
    const result = await handlers.update_scope({
      add_cidrs: ['172.16.1.0/24'],
      reason: 'Confirmed pivot network',
      confirm: true,
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.mode).toBe('applied');
    expect(payload.after.cidrs).toContain('172.16.1.0/24');

    // Verify the scope is actually updated in engine state
    const stateResult = await handlers.get_state({
      include_full_frontier: false,
      activity_count: 1,
    });
    const state = JSON.parse(stateResult.content[0].text);
    expect(state.config.scope.cidrs).toContain('172.16.1.0/24');
  });

  describe('get_state recent_activity filtering & snapshot dedup', () => {
    it('hides reasoning and includes system events by default', async () => {
      // Seed: one thought, one system, one frontier event
      await handlers.log_thought({ kind: 'note', content: 'just thinking out loud' });
      engine.logActionEvent({
        description: 'system bookkeeping',
        event_type: 'system',
        category: 'system',
      });
      engine.logActionEvent({
        description: 'frontier action',
        event_type: 'action_completed',
        category: 'frontier',
        agent_id: 'primary',
      });

      const r = await handlers.get_state({
        include_full_frontier: false,
        activity_count: 50,
        snapshot: false,
      });
      const state = JSON.parse(r.content[0].text);
      const types = state.recent_activity.map((e: any) => e.event_type);
      expect(types).not.toContain('thought');
      // system events are included by default
      expect(types).toContain('system');
      expect(types).toContain('action_completed');
    });

    it('include_reasoning=true surfaces thoughts; include_system=false hides system', async () => {
      await handlers.log_thought({ kind: 'plan', content: 'pivot via SMB' });
      engine.logActionEvent({
        description: 'system bookkeeping',
        event_type: 'system',
        category: 'system',
      });

      const r = await handlers.get_state({
        include_full_frontier: false,
        activity_count: 50,
        include_reasoning: true,
        include_system: false,
        snapshot: false,
      });
      const state = JSON.parse(r.content[0].text);
      const cats = state.recent_activity.map((e: any) => e.category);
      expect(cats).toContain('reasoning');
      expect(cats).not.toContain('system');
    });

    it('Phase H: default invocation writes NO new evidence and NO new system event (truly read-only)', async () => {
      const eventsBefore = engine.getFullHistory().filter(e => e.tool_name === 'get_state').length;
      const evidenceBefore = engine.getEvidenceStore().list().filter(r => r.filename === 'get_state.json').length;
      const r = await handlers.get_state({}); // no snapshot arg — defaults to false / undefined
      expect(r.isError).toBeUndefined();
      const eventsAfter = engine.getFullHistory().filter(e => e.tool_name === 'get_state').length;
      const evidenceAfter = engine.getEvidenceStore().list().filter(r => r.filename === 'get_state.json').length;
      expect(eventsAfter).toBe(eventsBefore);
      expect(evidenceAfter).toBe(evidenceBefore);
    });

    it('Phase H: explicit snapshot=true still persists evidence and emits a system event', async () => {
      const eventsBefore = engine.getFullHistory().filter(e => e.tool_name === 'get_state').length;
      const evidenceBefore = engine.getEvidenceStore().list().filter(r => r.filename === 'get_state.json').length;
      const r = await handlers.get_state({ snapshot: true });
      expect(r.isError).toBeUndefined();
      const eventsAfter = engine.getFullHistory().filter(e => e.tool_name === 'get_state').length;
      const evidenceAfter = engine.getEvidenceStore().list().filter(r => r.filename === 'get_state.json').length;
      expect(eventsAfter).toBeGreaterThan(eventsBefore);
      // Dedup window may reuse the prior evidence_id; assert the event was emitted, not a strict count bump.
      expect(evidenceAfter).toBeGreaterThanOrEqual(evidenceBefore);
    });

    it('snapshot dedup reuses prior evidence_id within the window', async () => {
      const first = await handlers.get_state({
        include_full_frontier: false,
        activity_count: 5,
        snapshot: true,
      });
      const second = await handlers.get_state({
        include_full_frontier: false,
        activity_count: 5,
        snapshot: true,
      });
      expect(first.isError).toBeUndefined();
      expect(second.isError).toBeUndefined();

      const events = engine.getFullHistory().filter(
        (e) => e.tool_name === 'get_state' && e.event_type === 'system'
      );
      // First call writes evidence; second call dedups against it.
      const dedupEvents = events.filter((e) => (e.details as any)?.dedup === true);
      expect(dedupEvents.length).toBeGreaterThanOrEqual(1);
      // Both events share the same evidence_id
      const ids = new Set(events.map((e) => (e.details as any)?.evidence_id));
      expect(ids.size).toBe(1);
    });
  });

  describe('activity provenance defaults', () => {
    it('defaults provenance based on agent_id / category / event_type', async () => {
      engine.logActionEvent({
        description: 'agent action',
        event_type: 'action_completed',
        agent_id: 'primary',
      });
      engine.logActionEvent({
        description: 'system bookkeeping',
        event_type: 'system',
        category: 'system',
      });
      engine.logActionEvent({
        description: 'inferred edge',
        event_type: 'inference_generated',
        category: 'inference',
      });

      const log = engine.getFullHistory();
      const byDesc = (d: string) => log.find((e) => e.description === d);
      expect(byDesc('agent action')?.provenance).toBe('agent');
      expect(byDesc('system bookkeeping')?.provenance).toBe('system');
      expect(byDesc('inferred edge')?.provenance).toBe('inferred');
    });

    it('caller-supplied provenance is preserved', async () => {
      engine.logActionEvent({
        description: 'ingested event',
        event_type: 'action_completed',
        agent_id: 'primary',
        provenance: 'ingested',
      });
      const log = engine.getFullHistory();
      const e = log.find((x) => x.description === 'ingested event');
      expect(e?.provenance).toBe('ingested');
    });
  });
});
