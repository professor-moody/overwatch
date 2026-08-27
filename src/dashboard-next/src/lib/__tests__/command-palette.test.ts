import { describe, it, expect } from 'vitest';
import { buildCommandItems, filterCommands, type PanelCommandDef } from '../command-palette';
import type { AgentInfo } from '../types';

const panels: PanelCommandDef[] = [
  { path: '/operate?view=active', label: 'Console', group: 'Operate' },
  { path: '/investigate?lens=topology', label: 'Graph', group: 'Investigate' },
  { path: '/review?view=readiness', label: 'Findings', group: 'Review' },
  { path: '/investigate?lens=paths', label: 'Attack Paths', group: 'Investigate' },
];
const agents = [
  { id: 'task-1', agent_id: 'recon-agent', status: 'running' } as unknown as AgentInfo,
];

describe('command-palette view-model', () => {
  it('builds panel + agent items with stable ids and hints', () => {
    const items = buildCommandItems({ panels, agents });
    expect(items).toHaveLength(5);
    const graph = items.find(i => i.label === 'Graph')!;
    expect(graph.kind).toBe('panel');
    expect(graph.path).toBe('/investigate?lens=topology');
    expect(graph.hint).toBe('Investigate');
    const agent = items.find(i => i.kind === 'agent')!;
    expect(agent.taskId).toBe('task-1');
    expect(agent.label).toBe('recon-agent');
    expect(agent.hint).toBe('running');
  });

  it('empty/whitespace query returns all items in built order (panels then agents)', () => {
    const items = buildCommandItems({ panels, agents });
    expect(filterCommands(items, '   ')).toEqual(items);
  });

  it('filters by substring on label AND hint, case-insensitive', () => {
    const items = buildCommandItems({ panels, agents });
    expect(filterCommands(items, 'GRA').map(i => i.label)).toEqual(['Graph']);
    // hint match: the group name reaches every Investigate panel.
    expect(filterCommands(items, 'investigate').map(i => i.label))
      .toEqual(expect.arrayContaining(['Graph', 'Attack Paths']));
    expect(filterCommands(items, 'review').map(i => i.label)).toEqual(['Findings']);
  });

  it('ranks a prefix match above a mid-string substring', () => {
    const items = buildCommandItems({
      panels: [
        { path: '/investigate?lens=paths', label: 'Attack Paths', group: 'Investigate' },
        { path: '/operate', label: 'Path Finder', group: 'Operate' },
      ],
      agents: [],
    });
    expect(filterCommands(items, 'path')[0].label).toBe('Path Finder');
  });

  it('matches an agent by its label so the operator can jump straight to it', () => {
    const items = buildCommandItems({ panels, agents });
    expect(filterCommands(items, 'recon').map(i => i.taskId)).toEqual(['task-1']);
  });

  it('returns nothing for a query that matches no item', () => {
    const items = buildCommandItems({ panels, agents });
    expect(filterCommands(items, 'zzzznope')).toEqual([]);
  });
});
