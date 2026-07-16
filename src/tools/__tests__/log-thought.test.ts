import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerLogThoughtTool } from '../log-thought.js';
import type { EngagementConfig } from '../../types.js';
import { cleanupTestPersistence } from '../../__tests__/helpers/cleanup-test-persistence.js';

const TEST_STATE_FILE = './state-test-log-thought.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-log-thought',
    name: 'log_thought test engagement',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/30'], domains: ['test.local'], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function cleanup(): void {
  cleanupTestPersistence(TEST_STATE_FILE);
  try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch {}
}

function parseTextResult(result: any): any {
  return JSON.parse(result.content[0].text);
}

describe('log_thought tool', () => {
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
    registerLogThoughtTool(fakeServer, engine);
  });

  afterEach(() => {
    engine.dispose();
    cleanup();
  });

  it('records a thought with default kind=note', async () => {
    const result = await handlers.log_thought({ thought: 'considering nmap sweep first' });
    const payload = parseTextResult(result);

    expect(result.isError).toBeFalsy();
    expect(payload.recorded).toBe(true);
    expect(payload.event_id).toBeTruthy();

    const events = engine.getFullHistory();
    const thought = events.find(e => e.event_id === payload.event_id);
    expect(thought).toBeTruthy();
    expect(thought!.event_type).toBe('thought');
    expect(thought!.category).toBe('reasoning');
    expect(thought!.description).toBe('considering nmap sweep first');
    expect((thought!.details as any).kind).toBe('note');
  });

  it('persists kind, alternatives, confidence, and tags in details', async () => {
    const result = await handlers.log_thought({
      thought: 'Picked kerberoast over spray to avoid lockout risk',
      kind: 'decision',
      considered_alternatives: ['password-spray', 'asreproast'],
      confidence: 0.75,
      tags: ['ad', 'opsec-conservative'],
    });
    const payload = parseTextResult(result);
    const event = engine.getFullHistory().find(e => e.event_id === payload.event_id)!;
    const details = event.details as any;
    expect(details.kind).toBe('decision');
    expect(details.considered_alternatives).toEqual(['password-spray', 'asreproast']);
    expect(details.confidence).toBe(0.75);
    expect(details.tags).toEqual(['ad', 'opsec-conservative']);
  });

  it('threads frontier_item_id and action_id through the event', async () => {
    const result = await handlers.log_thought({
      thought: 'plan to test SMB null session',
      kind: 'plan',
      frontier_item_id: 'frontier-fake-1',
      action_id: 'action-fake-1',
    });
    const payload = parseTextResult(result);
    const event = engine.getFullHistory().find(e => e.event_id === payload.event_id)!;
    expect(event.frontier_item_id).toBe('frontier-fake-1');
    expect(event.action_id).toBe('action-fake-1');
  });

  it('does not mutate the graph or create findings', async () => {
    const beforeNodes = engine.getFullHistory().length;
    await handlers.log_thought({ thought: 'just a thought' });
    const after = engine.getFullHistory();
    expect(after.length).toBe(beforeNodes + 1);
    // No nodes added
    expect(engine.getNodesByType('host').length).toBe(0);
  });
});
