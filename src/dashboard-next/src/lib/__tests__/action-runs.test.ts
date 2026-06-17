import { describe, it, expect } from 'vitest';
import { buildActionRuns, filterRuns, runLabel, type ActionRun } from '../action-runs';
import type { ActivityEntry } from '../types';

function entry(over: Partial<ActivityEntry> & Record<string, unknown>): ActivityEntry {
  return {
    id: over.id ?? `e-${Math.round((over.timestamp as string ?? '').length)}`,
    timestamp: '2026-06-17T00:00:00Z',
    event_type: 'system',
    description: '',
    ...over,
  } as ActivityEntry;
}

describe('buildActionRuns', () => {
  it('groups started + completed into one run with terminal status', () => {
    const runs = buildActionRuns([
      entry({ id: 's1', action_id: 'act_1', event_type: 'action_started', timestamp: '2026-06-17T00:00:01Z', details: { command: 'nmap -sV 10.0.0.5', binary: 'nmap', invoking_tool: 'run_tool' } }),
      entry({ id: 'c1', action_id: 'act_1', event_type: 'action_completed', timestamp: '2026-06-17T00:00:09Z', result_classification: 'success', agent_id: 'agent-recon-1', target_node_ids: ['host-1'], details: { exit_code: 0 } }),
    ]);
    expect(runs).toHaveLength(1);
    const r = runs[0];
    expect(r.actionId).toBe('act_1');
    expect(r.status).toBe('success');
    expect(r.tool).toBe('nmap');
    expect(r.command).toBe('nmap -sV 10.0.0.5');
    expect(r.agentId).toBe('agent-recon-1');
    expect(r.targets).toContain('host-1');
    expect(r.startedAt).toBe('2026-06-17T00:00:01Z');
  });

  it('marks an action with only a started event as running', () => {
    const runs = buildActionRuns([
      entry({ action_id: 'act_run', event_type: 'action_started', details: { binary: 'nuclei' } }),
    ]);
    expect(runs[0].status).toBe('running');
    expect(runs[0].tool).toBe('nuclei');
  });

  it('maps a failed terminal event to failure', () => {
    const runs = buildActionRuns([
      entry({ action_id: 'act_f', event_type: 'action_failed', details: { binary: 'curl' } }),
    ]);
    expect(runs[0].status).toBe('failure');
  });

  it('ignores non-lifecycle events and events without an action_id', () => {
    const runs = buildActionRuns([
      entry({ event_type: 'thought', description: 'thinking' }),
      entry({ event_type: 'finding_reported', action_id: undefined, description: 'found' }),
      entry({ action_id: 'act_x', event_type: 'action_completed', result_classification: 'partial', details: {} }),
    ]);
    expect(runs).toHaveLength(1);
    expect(runs[0].status).toBe('partial');
  });

  it('sorts runs newest-first by representative timestamp', () => {
    const runs = buildActionRuns([
      entry({ action_id: 'act_old', event_type: 'action_completed', timestamp: '2026-06-17T00:00:01Z', result_classification: 'success', details: {} }),
      entry({ action_id: 'act_new', event_type: 'action_completed', timestamp: '2026-06-17T00:05:00Z', result_classification: 'success', details: {} }),
    ]);
    expect(runs.map(r => r.actionId)).toEqual(['act_new', 'act_old']);
  });

  it('prefers top-level tool_name/command_repr when present', () => {
    const runs = buildActionRuns([
      entry({ action_id: 'act_t', event_type: 'action_completed', result_classification: 'success', tool_name: 'nmap', command_repr: 'nmap -A', details: {} } as never),
    ]);
    expect(runs[0].tool).toBe('nmap');
    expect(runs[0].command).toBe('nmap -A');
  });
});

describe('filterRuns', () => {
  const runs: ActionRun[] = [
    { actionId: 'act_1', tool: 'nmap', command: 'nmap -sV 10.0.0.5', status: 'success', agentId: 'agent-recon-1', targets: ['10.0.0.5'], timestamp: 't2', startedAt: null, description: '' },
    { actionId: 'act_2', tool: 'curl', command: 'curl https://x', status: 'failure', agentId: 'agent-web-1', targets: [], timestamp: 't1', startedAt: null, description: '' },
  ];

  it('filters by status', () => {
    expect(filterRuns(runs, { status: 'failure' }).map(r => r.actionId)).toEqual(['act_2']);
  });

  it('filters by free-text across tool/command/agent/target', () => {
    expect(filterRuns(runs, { search: '10.0.0.5' }).map(r => r.actionId)).toEqual(['act_1']);
    expect(filterRuns(runs, { search: 'curl' }).map(r => r.actionId)).toEqual(['act_2']);
    expect(filterRuns(runs, { search: 'agent-web' }).map(r => r.actionId)).toEqual(['act_2']);
  });

  it('returns all runs with no filters', () => {
    expect(filterRuns(runs, {})).toHaveLength(2);
  });
});

describe('runLabel', () => {
  it('prefers command, then tool, then description, then id', () => {
    expect(runLabel({ command: 'nmap -A', tool: 'nmap' } as ActionRun)).toBe('nmap -A');
    expect(runLabel({ command: null, tool: 'nmap' } as ActionRun)).toBe('nmap');
    expect(runLabel({ command: null, tool: null, description: 'desc', actionId: 'a' } as ActionRun)).toBe('desc');
    expect(runLabel({ command: null, tool: null, description: '', actionId: 'a' } as ActionRun)).toBe('a');
  });
});
