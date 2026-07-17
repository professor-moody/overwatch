import { describe, it, expect } from 'vitest';
import { buildMissionCard, sortMissionCards, groupMissionCards, type MissionCard } from '../agent-mission';
import type { AgentInfo, PendingAction, SessionInfo } from '../types';
import type { AgentQuery } from '../api';

const NOW = Date.UTC(2026, 5, 17, 12, 0, 0);

function agent(o: Partial<AgentInfo> = {}): AgentInfo {
  return { task_id: 'task-1', agent_label: 'recon-1', id: 'task-1', agent_id: 'recon-1', status: 'running', assigned_at: new Date(NOW - 10_000).toISOString(), queued: false, lifecycle: 'live', live: true, subgraph_node_ids: [], findings_count: 0, ...o };
}
function query(o: Partial<AgentQuery> = {}): AgentQuery {
  return { query_id: 'q1', task_id: 'task-1', agent_id: 'recon-1', question: 'go?', status: 'open', created_at: NOW, expires_at: NOW + 30 * 60_000, ...o };
}
function action(o: Partial<PendingAction> = {}): PendingAction {
  return { action_id: 'act-1', description: 'spray', submitted_at: new Date(NOW).toISOString(), ...o };
}
function session(o: Partial<SessionInfo> = {}): SessionInfo {
  return {
    id: 's1',
    kind: 'pty',
    transport: 'pty',
    state: 'connected',
    title: 'Shell',
    started_at: new Date(NOW).toISOString(),
    last_activity_at: new Date(NOW).toISOString(),
    capabilities: {},
    buffer_end_pos: 0,
    ...o,
  };
}

describe('buildMissionCard', () => {
  it('surfaces role/campaign/frontier/current action/findings/scope', () => {
    const card = buildMissionCard(agent({
      skill: 'enumeration', campaign_id: 'c1', campaign: { id: 'c1', name: 'Recon push', strategy: 'enumeration' },
      frontier_item_id: 'fi-9', current_action: 'nmap 10.0.0.5', findings_count: 3, subgraph_node_ids: ['n1', 'n2'],
      current_action_at: new Date(NOW - 5_000).toISOString(),
    }), { now: NOW });
    expect(card.role).toBe('enumeration');
    expect(card.campaignName).toBe('Recon push');
    expect(card.frontierItemId).toBe('fi-9');
    expect(card.currentAction).toBe('nmap 10.0.0.5');
    expect(card.findingsCount).toBe(3);
    expect(card.scopeNodeCount).toBe(2);
    expect(card.tone).toBe('running');
  });

  it('marks blocked + waiting-on-answer when the agent has an open question', () => {
    const card = buildMissionCard(agent(), { now: NOW, agentQueries: [query()] });
    expect(card.awaitingAnswer).toBe(true);
    expect(card.tone).toBe('blocked');
    expect(card.blocker).toBe('waiting on your answer');
  });

  it('ignores already-answered questions', () => {
    const card = buildMissionCard(agent(), { now: NOW, agentQueries: [query({ status: 'answered' })] });
    expect(card.awaitingAnswer).toBe(false);
    expect(card.tone).toBe('running');
  });

  it('marks blocked + waiting-on-approval when a pending action is attributed', () => {
    const card = buildMissionCard(agent(), { now: NOW, pendingActions: [action({
      task_id: 'task-1',
      agent_label: 'recon-1',
      agent_id: 'recon-1',
    })] });
    expect(card.pendingApproval).toBe(true);
    expect(card.blocker).toBe('waiting on approval');
    expect(card.tone).toBe('blocked');
  });

  it('attributes an approval by shared frontier_item_id when it lacks agent_id (validate_action path)', () => {
    // action() sets no agent_id; match on the frontier item the agent owns.
    const card = buildMissionCard(agent({ frontier_item_id: 'fi-7' }), { now: NOW, pendingActions: [action({ frontier_item_id: 'fi-7' })] });
    expect(card.pendingApproval).toBe(true);
    expect(card.blocker).toBe('waiting on approval');
  });

  it('does not attribute an unrelated approval (no agent_id, different frontier)', () => {
    const card = buildMissionCard(agent({ frontier_item_id: 'fi-7' }), { now: NOW, pendingActions: [action({ frontier_item_id: 'fi-other' })] });
    expect(card.pendingApproval).toBe(false);
  });

  it('answer outranks approval as the stated blocker', () => {
    const card = buildMissionCard(agent(), {
      now: NOW,
      agentQueries: [query()],
      pendingActions: [action({ task_id: 'task-1', agent_id: 'recon-1' })],
    });
    expect(card.blocker).toBe('waiting on your answer');
  });

  it('failed/interrupted agents read as failed with the result summary', () => {
    const card = buildMissionCard(agent({ status: 'failed', result_summary: 'timed out' }), { now: NOW });
    expect(card.tone).toBe('failed');
    expect(card.blocker).toBe('timed out');
    expect(card.currentAction).toBeUndefined();
    expect(card.freshness).toBe('none');
  });

  it('derives liveness from current_action_at', () => {
    expect(buildMissionCard(agent({ current_action_at: new Date(NOW - 10_000).toISOString() }), { now: NOW }).freshness).toBe('fresh');
    expect(buildMissionCard(agent({ current_action_at: new Date(NOW - 120_000).toISOString() }), { now: NOW }).freshness).toBe('recent');
    expect(buildMissionCard(agent({ current_action_at: new Date(NOW - 600_000).toISOString() }), { now: NOW }).freshness).toBe('quiet');
  });

  it('lists owned sessions via sessionsForAgent', () => {
    const card = buildMissionCard(agent(), {
      now: NOW,
      sessions: [
        session({ id: 'sx', claimed_by: 'task-1', agent_id: 'recon-1' }),
        session({ id: 'other', claimed_by: 'task-2', agent_id: 'web-2' }),
      ],
    });
    expect(card.ownedSessionIds).toEqual(['sx']);
  });
});

describe('sortMissionCards / groupMissionCards', () => {
  const cards = (): MissionCard[] => [
    buildMissionCard(agent({ id: 'a', agent_id: 'a', status: 'completed', campaign_id: 'c1', campaign: { id: 'c1', name: 'Beta', strategy: 'x' } }), { now: NOW }),
    buildMissionCard(agent({ id: 'b', agent_id: 'b', campaign_id: 'c1', campaign: { id: 'c1', name: 'Beta', strategy: 'x' } }), { now: NOW, agentQueries: [query({ task_id: 'b', agent_id: 'b' })] }),
    buildMissionCard(agent({ id: 'c', agent_id: 'c' }), { now: NOW }),
  ];

  it('floats attention (blocked) above running above done', () => {
    const sorted = sortMissionCards(cards());
    expect(sorted.map(c => c.id)).toEqual(['b', 'c', 'a']);
  });

  it('groups by campaign with Ungrouped last', () => {
    const groups = groupMissionCards(cards());
    expect(groups.map(g => g.name)).toEqual(['Beta', 'Ungrouped']);
    // Within Beta, blocked 'b' precedes done 'a'.
    expect(groups[0].cards.map(c => c.id)).toEqual(['b', 'a']);
    expect(groups[1].cards.map(c => c.id)).toEqual(['c']);
  });
});

describe('buildMissionCard — stuck detection', () => {
  const idle = (o: Partial<AgentInfo> = {}) => agent({
    status: 'running',
    assigned_at: new Date(NOW - 20 * 60_000).toISOString(),
    current_action_at: new Date(NOW - 20 * 60_000).toISOString(),
    ...o,
  });

  it('flags a heartbeating-but-idle running agent as stuck', () => {
    const card = buildMissionCard(idle(), { now: NOW });
    expect(card.tone).toBe('stuck');
    expect(card.blocker).toContain('may be stuck');
  });

  it('a just-started agent is running, not stuck', () => {
    const card = buildMissionCard(idle({ assigned_at: new Date(NOW - 60_000).toISOString(), current_action_at: new Date(NOW - 60_000).toISOString() }), { now: NOW });
    expect(card.tone).toBe('running');
  });

  it('blocked beats stuck (open question + idle → blocked)', () => {
    const card = buildMissionCard(idle(), { now: NOW, agentQueries: [query()] });
    expect(card.tone).toBe('blocked');
  });

  it('missing assigned_at → running, not stuck', () => {
    const card = buildMissionCard(agent({ status: 'running', current_action_at: new Date(NOW - 20 * 60_000).toISOString() }), { now: NOW });
    expect(card.tone).toBe('running');
  });

  it('no current_action_at (unattributable activity, e.g. shared label) → running, not stuck', () => {
    const card = buildMissionCard(agent({ status: 'running', assigned_at: new Date(NOW - 20 * 60_000).toISOString() }), { now: NOW });
    expect(card.tone).toBe('running');
  });

  it('sortMissionCards places stuck below blocked, above running', () => {
    const sorted = sortMissionCards([
      buildMissionCard(agent({ id: 'r', agent_id: 'run', status: 'running', current_action_at: new Date(NOW).toISOString() }), { now: NOW }),
      buildMissionCard(idle({ id: 's', agent_id: 'stuck' }), { now: NOW }),
      buildMissionCard(agent({ id: 'b', agent_id: 'blk' }), { now: NOW, agentQueries: [query({ task_id: 'b', agent_id: 'blk' })] }),
    ]);
    expect(sorted.map(c => c.tone)).toEqual(['blocked', 'stuck', 'running']);
  });
});
