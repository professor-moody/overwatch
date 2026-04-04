import { describe, it, expect } from 'vitest';
import Graph from 'graphology';
import type { OverwatchGraph } from '../engine-context.js';
import {
  EngineContext,
  MAX_ACTIVITY_LOG_ENTRIES,
  normalizeActivityLogEntry,
  tieredTruncate,
  isMilestoneEntry,
} from '../engine-context.js';

function makeGraph(): OverwatchGraph {
  return new (Graph as any)({ multi: true, type: 'directed', allowSelfLoops: true }) as OverwatchGraph;
}

function makeConfig(overrides: Record<string, unknown> = {}) {
  return {
    id: 'test-eng',
    name: 'Test',
    created_at: '2026-03-20T00:00:00Z',
    scope: { cidrs: ['10.10.10.0/28'], domains: ['test.local'], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7, blacklisted_techniques: [] },
    ...overrides,
  } as any;
}

function makeCtx(): EngineContext {
  return new EngineContext(makeGraph(), makeConfig(), '/tmp/test-state.json');
}

describe('EngineContext', () => {
  describe('logEvent', () => {
    it('returns an entry with generated event_id and timestamp', () => {
      const ctx = makeCtx();
      const entry = ctx.logEvent({ description: 'test event' });
      expect(entry.event_id).toBeDefined();
      expect(entry.timestamp).toBeDefined();
      expect(entry.description).toBe('test event');
    });

    it('appends entry to activityLog', () => {
      const ctx = makeCtx();
      ctx.logEvent({ description: 'one' });
      ctx.logEvent({ description: 'two' });
      expect(ctx.activityLog).toHaveLength(2);
      expect(ctx.activityLog[0].description).toBe('one');
      expect(ctx.activityLog[1].description).toBe('two');
    });

    it('stores frontier mapping when action_id and frontier_item_id are both present', () => {
      const ctx = makeCtx();
      ctx.logEvent({
        description: 'validated',
        action_id: 'act-1',
        frontier_item_id: 'fi-1',
        frontier_type: 'inferred_edge',
      });
      const cached = ctx.actionFrontierMap.get('act-1');
      expect(cached).toEqual({ frontier_item_id: 'fi-1', agent_id: undefined, frontier_type: 'inferred_edge' });
    });

    it('auto-threads frontier_item_id from actionFrontierMap when only action_id is given', () => {
      const ctx = makeCtx();
      ctx.logEvent({
        description: 'validated',
        action_id: 'act-2',
        frontier_item_id: 'fi-2',
        frontier_type: 'network_discovery',
      });

      const entry = ctx.logEvent({
        description: 'completed',
        action_id: 'act-2',
      });

      expect(entry.frontier_item_id).toBe('fi-2');
      expect(entry.frontier_type).toBe('network_discovery');
    });

    it('does not overwrite caller-supplied frontier_type when auto-threading', () => {
      const ctx = makeCtx();
      ctx.logEvent({
        description: 'validated',
        action_id: 'act-3',
        frontier_item_id: 'fi-3',
        frontier_type: 'inferred_edge',
      });

      const entry = ctx.logEvent({
        description: 'completed',
        action_id: 'act-3',
        frontier_type: 'network_pivot',
      });

      expect(entry.frontier_item_id).toBe('fi-3');
      expect(entry.frontier_type).toBe('network_pivot');
    });
  });

  describe('MAX_ACTIVITY_LOG_ENTRIES truncation', () => {
    it('truncates oldest ephemeral entries when log exceeds MAX_ACTIVITY_LOG_ENTRIES', () => {
      const ctx = makeCtx();
      for (let i = 0; i < MAX_ACTIVITY_LOG_ENTRIES + 50; i++) {
        ctx.logEvent({ description: `event-${i}` });
      }
      expect(ctx.activityLog).toHaveLength(MAX_ACTIVITY_LOG_ENTRIES);
      expect(ctx.activityLog[ctx.activityLog.length - 1].description).toBe(
        `event-${MAX_ACTIVITY_LOG_ENTRIES + 49}`,
      );
    });

    it('preserves milestone events during truncation', () => {
      const ctx = makeCtx();
      ctx.logEvent({ description: 'milestone-0', event_type: 'objective_achieved' });
      for (let i = 0; i < MAX_ACTIVITY_LOG_ENTRIES + 10; i++) {
        ctx.logEvent({ description: `ephemeral-${i}`, event_type: 'action_started' });
      }
      expect(ctx.activityLog).toHaveLength(MAX_ACTIVITY_LOG_ENTRIES);
      const milestones = ctx.activityLog.filter(e => e.event_type === 'objective_achieved');
      expect(milestones).toHaveLength(1);
      expect(milestones[0].description).toBe('milestone-0');
    });
  });

  describe('rebuildActionFrontierMap', () => {
    it('rebuilds mapping from activity log entries', () => {
      const ctx = makeCtx();
      ctx.logEvent({ description: 'a', action_id: 'act-a', frontier_item_id: 'fi-a' });
      ctx.logEvent({ description: 'b', action_id: 'act-b', frontier_item_id: 'fi-b', frontier_type: 'incomplete_node' });
      ctx.logEvent({ description: 'c' });

      ctx.actionFrontierMap.clear();
      expect(ctx.actionFrontierMap.size).toBe(0);

      ctx.rebuildActionFrontierMap();

      expect(ctx.actionFrontierMap.size).toBe(2);
      expect(ctx.actionFrontierMap.get('act-a')).toEqual({
        frontier_item_id: 'fi-a',
        agent_id: undefined,
        frontier_type: undefined,
      });
      expect(ctx.actionFrontierMap.get('act-b')).toEqual({
        frontier_item_id: 'fi-b',
        agent_id: undefined,
        frontier_type: 'incomplete_node',
      });
    });

    it('uses last occurrence when multiple entries share an action_id', () => {
      const ctx = makeCtx();
      ctx.logEvent({ description: 'first', action_id: 'dup', frontier_item_id: 'fi-old' });
      ctx.logEvent({ description: 'second', action_id: 'dup', frontier_item_id: 'fi-new', frontier_type: 'untested_edge' });

      ctx.actionFrontierMap.clear();
      ctx.rebuildActionFrontierMap();

      expect(ctx.actionFrontierMap.get('dup')).toEqual({
        frontier_item_id: 'fi-new',
        agent_id: undefined,
        frontier_type: 'untested_edge',
      });
    });
  });

  describe('log convenience method', () => {
    it('delegates to logEvent with description, agent_id, and extras', () => {
      const ctx = makeCtx();
      ctx.log('hello', 'agent-x', { category: 'finding', outcome: 'success' });
      expect(ctx.activityLog).toHaveLength(1);
      const e = ctx.activityLog[0];
      expect(e.description).toBe('hello');
      expect(e.agent_id).toBe('agent-x');
      expect(e.category).toBe('finding');
      expect(e.outcome).toBe('success');
    });
  });

  describe('invalidatePathGraph', () => {
    it('clears pathGraphCache and communityCache', () => {
      const ctx = makeCtx();
      ctx.pathGraphCache.set('default', makeGraph());
      ctx.communityCache = new Map([['node-1', 0]]);

      ctx.invalidatePathGraph();

      expect(ctx.pathGraphCache.size).toBe(0);
      expect(ctx.communityCache).toBeNull();
    });
  });

  describe('fireUpdateCallbacks', () => {
    it('invokes all registered callbacks with the detail', () => {
      const ctx = makeCtx();
      const received: any[] = [];
      ctx.updateCallbacks.push((d) => received.push(d));
      ctx.updateCallbacks.push((d) => received.push(d));

      const detail = { new_nodes: ['n1'] };
      ctx.fireUpdateCallbacks(detail);

      expect(received).toHaveLength(2);
      expect(received[0]).toBe(detail);
    });

    it('does not throw when a callback errors', () => {
      const ctx = makeCtx();
      ctx.updateCallbacks.push(() => { throw new Error('boom'); });
      ctx.updateCallbacks.push(() => {});

      expect(() => ctx.fireUpdateCallbacks({ new_nodes: [] })).not.toThrow();
    });
  });
});

describe('normalizeActivityLogEntry', () => {
  it('generates event_id and timestamp when not provided', () => {
    const entry = normalizeActivityLogEntry({ description: 'test' });
    expect(entry.event_id).toBeDefined();
    expect(entry.timestamp).toBeDefined();
  });

  it('preserves explicit event_id and timestamp', () => {
    const entry = normalizeActivityLogEntry({
      description: 'test',
      event_id: 'my-id',
      timestamp: '2026-01-01T00:00:00Z',
    });
    expect(entry.event_id).toBe('my-id');
    expect(entry.timestamp).toBe('2026-01-01T00:00:00Z');
  });

  it('derives outcome=success from result_classification=success', () => {
    const entry = normalizeActivityLogEntry({
      description: 'done',
      result_classification: 'success',
    });
    expect(entry.outcome).toBe('success');
  });

  it('derives outcome=failure from result_classification=failure', () => {
    const entry = normalizeActivityLogEntry({
      description: 'fail',
      result_classification: 'failure',
    });
    expect(entry.outcome).toBe('failure');
  });

  it('derives outcome=neutral from result_classification=partial', () => {
    const entry = normalizeActivityLogEntry({
      description: 'partial',
      result_classification: 'partial',
    });
    expect(entry.outcome).toBe('neutral');
  });

  it('derives outcome=neutral from result_classification=neutral', () => {
    const entry = normalizeActivityLogEntry({
      description: 'neutral',
      result_classification: 'neutral',
    });
    expect(entry.outcome).toBe('neutral');
  });

  it('derives outcome=failure from validation_result=invalid', () => {
    const entry = normalizeActivityLogEntry({
      description: 'invalid',
      validation_result: 'invalid',
    });
    expect(entry.outcome).toBe('failure');
  });

  it('derives outcome=neutral from validation_result=warning_only', () => {
    const entry = normalizeActivityLogEntry({
      description: 'warn',
      validation_result: 'warning_only',
    });
    expect(entry.outcome).toBe('neutral');
  });

  it('derives outcome=success from validation_result=valid', () => {
    const entry = normalizeActivityLogEntry({
      description: 'valid',
      validation_result: 'valid',
    });
    expect(entry.outcome).toBe('success');
  });

  it('result_classification takes precedence over validation_result', () => {
    const entry = normalizeActivityLogEntry({
      description: 'mixed',
      result_classification: 'failure',
      validation_result: 'valid',
    });
    expect(entry.outcome).toBe('failure');
  });

  it('preserves explicit outcome without deriving', () => {
    const entry = normalizeActivityLogEntry({
      description: 'explicit',
      outcome: 'neutral',
      result_classification: 'success',
    });
    expect(entry.outcome).toBe('neutral');
  });

  it('returns undefined outcome when no classification fields are set', () => {
    const entry = normalizeActivityLogEntry({ description: 'bare' });
    expect(entry.outcome).toBeUndefined();
  });
});

describe('isMilestoneEntry', () => {
  it('returns true for objective_achieved', () => {
    expect(isMilestoneEntry({ event_id: '1', timestamp: '', description: '', event_type: 'objective_achieved' })).toBe(true);
  });

  it('returns true for action_completed', () => {
    expect(isMilestoneEntry({ event_id: '1', timestamp: '', description: '', event_type: 'action_completed' })).toBe(true);
  });

  it('returns true for finding_ingested', () => {
    expect(isMilestoneEntry({ event_id: '1', timestamp: '', description: '', event_type: 'finding_ingested' })).toBe(true);
  });

  it('returns false for action_started', () => {
    expect(isMilestoneEntry({ event_id: '1', timestamp: '', description: '', event_type: 'action_started' })).toBe(false);
  });

  it('returns false for inference_generated', () => {
    expect(isMilestoneEntry({ event_id: '1', timestamp: '', description: '', event_type: 'inference_generated' })).toBe(false);
  });

  it('returns false for undefined event_type', () => {
    expect(isMilestoneEntry({ event_id: '1', timestamp: '', description: '' })).toBe(false);
  });
});

describe('tieredTruncate', () => {
  function entry(desc: string, eventType?: string, ts?: string): any {
    return {
      event_id: desc,
      timestamp: ts || `2026-01-01T00:00:${String(parseInt(desc.replace(/\D/g, '') || '0') % 60).padStart(2, '0')}Z`,
      description: desc,
      event_type: eventType,
    };
  }

  it('returns the log unchanged when within budget', () => {
    const log = [entry('a'), entry('b'), entry('c')];
    expect(tieredTruncate(log, 10)).toEqual(log);
  });

  it('keeps all milestone events when truncating', () => {
    const log = [
      entry('m1', 'objective_achieved', '2026-01-01T00:00:01Z'),
      entry('e1', 'action_started', '2026-01-01T00:00:02Z'),
      entry('e2', 'action_started', '2026-01-01T00:00:03Z'),
      entry('m2', 'finding_ingested', '2026-01-01T00:00:04Z'),
      entry('e3', 'inference_generated', '2026-01-01T00:00:05Z'),
    ];
    const result = tieredTruncate(log, 3);
    expect(result).toHaveLength(3);
    const descs = result.map(e => e.description);
    expect(descs).toContain('m1');
    expect(descs).toContain('m2');
  });

  it('drops oldest ephemeral entries first', () => {
    const log = [
      entry('e1', 'action_started', '2026-01-01T00:00:01Z'),
      entry('e2', 'action_started', '2026-01-01T00:00:02Z'),
      entry('m1', 'action_completed', '2026-01-01T00:00:03Z'),
      entry('e3', 'action_started', '2026-01-01T00:00:04Z'),
    ];
    const result = tieredTruncate(log, 3);
    expect(result).toHaveLength(3);
    const descs = result.map(e => e.description);
    expect(descs).toContain('m1');
    expect(descs).toContain('e3');
    expect(descs).not.toContain('e1');
  });

  it('preserves chronological order in output', () => {
    const log = [
      entry('e1', 'action_started', '2026-01-01T00:00:01Z'),
      entry('m1', 'action_completed', '2026-01-01T00:00:02Z'),
      entry('e2', 'action_started', '2026-01-01T00:00:03Z'),
      entry('e3', 'action_started', '2026-01-01T00:00:04Z'),
      entry('m2', 'finding_ingested', '2026-01-01T00:00:05Z'),
    ];
    const result = tieredTruncate(log, 4);
    for (let i = 1; i < result.length; i++) {
      expect(result[i].timestamp >= result[i - 1].timestamp).toBe(true);
    }
  });

  it('handles case where milestones alone exceed budget', () => {
    const log = [
      entry('m1', 'objective_achieved', '2026-01-01T00:00:01Z'),
      entry('m2', 'action_completed', '2026-01-01T00:00:02Z'),
      entry('m3', 'finding_ingested', '2026-01-01T00:00:03Z'),
    ];
    const result = tieredTruncate(log, 2);
    expect(result).toHaveLength(2);
    expect(result[0].description).toBe('m2');
    expect(result[1].description).toBe('m3');
  });
});

// ============================================================
// Regression: P1 — causal-linkage events promoted to milestone
// ============================================================
describe('isMilestoneEntry — causal-linkage events', () => {
  it('returns true for action_validated', () => {
    expect(isMilestoneEntry({ event_id: '1', timestamp: '', description: '', event_type: 'action_validated' })).toBe(true);
  });

  it('returns true for parse_output', () => {
    expect(isMilestoneEntry({ event_id: '1', timestamp: '', description: '', event_type: 'parse_output' })).toBe(true);
  });

  it('returns true for instrumentation_warning', () => {
    expect(isMilestoneEntry({ event_id: '1', timestamp: '', description: '', event_type: 'instrumentation_warning' })).toBe(true);
  });

  it('returns true for session_access_unconfirmed', () => {
    expect(isMilestoneEntry({ event_id: '1', timestamp: '', description: '', event_type: 'session_access_unconfirmed' })).toBe(true);
  });

  it('returns true for session_error', () => {
    expect(isMilestoneEntry({ event_id: '1', timestamp: '', description: '', event_type: 'session_error' })).toBe(true);
  });

  it('returns true for graph_corrected', () => {
    expect(isMilestoneEntry({ event_id: '1', timestamp: '', description: '', event_type: 'graph_corrected' })).toBe(true);
  });

  it('still returns false for action_started (ephemeral)', () => {
    expect(isMilestoneEntry({ event_id: '1', timestamp: '', description: '', event_type: 'action_started' })).toBe(false);
  });

  it('still returns false for inference_generated (ephemeral)', () => {
    expect(isMilestoneEntry({ event_id: '1', timestamp: '', description: '', event_type: 'inference_generated' })).toBe(false);
  });

  it('still returns false for agent_registered (ephemeral)', () => {
    expect(isMilestoneEntry({ event_id: '1', timestamp: '', description: '', event_type: 'agent_registered' })).toBe(false);
  });
});

describe('tieredTruncate — preserves causal-linkage events', () => {
  function entry(desc: string, eventType?: string, ts?: string): any {
    return {
      event_id: desc,
      timestamp: ts || '2026-01-01T00:00:00Z',
      description: desc,
      event_type: eventType,
    };
  }

  it('preserves action_validated and instrumentation_warning during truncation', () => {
    const log = [
      entry('val', 'action_validated', '2026-01-01T00:00:01Z'),
      entry('warn', 'instrumentation_warning', '2026-01-01T00:00:02Z'),
      entry('e1', 'action_started', '2026-01-01T00:00:03Z'),
      entry('e2', 'action_started', '2026-01-01T00:00:04Z'),
      entry('e3', 'action_started', '2026-01-01T00:00:05Z'),
    ];
    const result = tieredTruncate(log, 3);
    expect(result).toHaveLength(3);
    const descs = result.map(e => e.description);
    expect(descs).toContain('val');
    expect(descs).toContain('warn');
  });

  it('preserves session_error and session_access_unconfirmed during truncation', () => {
    const log = [
      entry('se', 'session_error', '2026-01-01T00:00:01Z'),
      entry('su', 'session_access_unconfirmed', '2026-01-01T00:00:02Z'),
      entry('e1', 'action_started', '2026-01-01T00:00:03Z'),
      entry('e2', 'action_started', '2026-01-01T00:00:04Z'),
      entry('e3', 'action_started', '2026-01-01T00:00:05Z'),
    ];
    const result = tieredTruncate(log, 3);
    expect(result).toHaveLength(3);
    const descs = result.map(e => e.description);
    expect(descs).toContain('se');
    expect(descs).toContain('su');
  });

  it('preserves parse_output during truncation', () => {
    const log = [
      entry('po', 'parse_output', '2026-01-01T00:00:01Z'),
      entry('e1', 'action_started', '2026-01-01T00:00:02Z'),
      entry('e2', 'action_started', '2026-01-01T00:00:03Z'),
    ];
    const result = tieredTruncate(log, 2);
    expect(result).toHaveLength(2);
    const descs = result.map(e => e.description);
    expect(descs).toContain('po');
  });
});

describe('actionFrontierMap — cross-agent collision guard', () => {
  it('caches agent_id alongside frontier mapping', () => {
    const ctx = makeCtx();
    ctx.logEvent({
      description: 'validated',
      action_id: 'act-x',
      frontier_item_id: 'fi-x',
      agent_id: 'agent-A',
    });
    const cached = ctx.actionFrontierMap.get('act-x');
    expect(cached?.agent_id).toBe('agent-A');
    expect(cached?.frontier_item_id).toBe('fi-x');
  });

  it('does not auto-thread when a different agent reuses the same action_id', () => {
    const ctx = makeCtx();
    // Agent A establishes mapping
    ctx.logEvent({
      description: 'validated by A',
      action_id: 'act-shared',
      frontier_item_id: 'fi-1',
      agent_id: 'agent-A',
    });

    // Agent B logs with same action_id but no frontier_item_id — should NOT inherit fi-1
    const entry = ctx.logEvent({
      description: 'completed by B',
      action_id: 'act-shared',
      agent_id: 'agent-B',
    });

    expect(entry.frontier_item_id).toBeUndefined();
  });

  it('auto-threads when the same agent logs with the same action_id', () => {
    const ctx = makeCtx();
    ctx.logEvent({
      description: 'validated by A',
      action_id: 'act-mine',
      frontier_item_id: 'fi-mine',
      agent_id: 'agent-A',
    });

    const entry = ctx.logEvent({
      description: 'completed by A',
      action_id: 'act-mine',
      agent_id: 'agent-A',
    });

    expect(entry.frontier_item_id).toBe('fi-mine');
  });

  it('logs instrumentation_warning when different agent overwrites frontier mapping', () => {
    const ctx = makeCtx();
    ctx.logEvent({
      description: 'validated by A',
      action_id: 'act-collision',
      frontier_item_id: 'fi-1',
      agent_id: 'agent-A',
    });

    // Agent B tries to associate a different frontier_item_id
    ctx.logEvent({
      description: 'validated by B',
      action_id: 'act-collision',
      frontier_item_id: 'fi-2',
      agent_id: 'agent-B',
    });

    // Original mapping should be preserved
    expect(ctx.actionFrontierMap.get('act-collision')?.frontier_item_id).toBe('fi-1');
    expect(ctx.actionFrontierMap.get('act-collision')?.agent_id).toBe('agent-A');

    // An instrumentation warning should have been logged
    const warnings = ctx.activityLog.filter(e => e.event_type === 'instrumentation_warning');
    expect(warnings.length).toBeGreaterThanOrEqual(1);
    expect(warnings[0].description).toContain('collision');
  });

  it('allows same agent to update its own frontier mapping', () => {
    const ctx = makeCtx();
    ctx.logEvent({
      description: 'first',
      action_id: 'act-update',
      frontier_item_id: 'fi-old',
      agent_id: 'agent-A',
    });
    ctx.logEvent({
      description: 'second',
      action_id: 'act-update',
      frontier_item_id: 'fi-new',
      agent_id: 'agent-A',
    });

    expect(ctx.actionFrontierMap.get('act-update')?.frontier_item_id).toBe('fi-new');
  });

  it('auto-threads when agent_id is undefined on one side', () => {
    const ctx = makeCtx();
    // Cache without agent_id (e.g., from a tool that doesn't track it)
    ctx.logEvent({
      description: 'validated',
      action_id: 'act-noagent',
      frontier_item_id: 'fi-noagent',
    });

    // Subsequent event without agent_id should inherit
    const entry = ctx.logEvent({
      description: 'completed',
      action_id: 'act-noagent',
    });
    expect(entry.frontier_item_id).toBe('fi-noagent');
  });
});
