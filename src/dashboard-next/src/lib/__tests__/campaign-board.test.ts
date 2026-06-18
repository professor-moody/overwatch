import { describe, it, expect } from 'vitest';
import type { MissionCard } from '../agent-mission';
import { laneForCard, buildCampaignBoard, BOARD_LANES } from '../campaign-board';

function card(overrides: Partial<MissionCard> = {}): MissionCard {
  return {
    id: overrides.id ?? `a-${Math.random().toString(36).slice(2, 8)}`,
    label: overrides.label ?? 'agent',
    status: 'running',
    freshness: 'fresh',
    ownedSessionIds: [],
    findingsCount: 0,
    pendingApproval: false,
    awaitingAnswer: false,
    tone: 'running',
    scopeNodeCount: 0,
    ...overrides,
  };
}

describe('laneForCard', () => {
  it('maps each state to its lane', () => {
    expect(laneForCard(card({ tone: 'failed' }))).toBe('failed');
    expect(laneForCard(card({ pendingApproval: true }))).toBe('needs_approval');
    expect(laneForCard(card({ awaitingAnswer: true }))).toBe('blocked');
    expect(laneForCard(card({ tone: 'done' }))).toBe('completed');
    expect(laneForCard(card({ tone: 'running', findingsCount: 3 }))).toBe('produced_finding');
    expect(laneForCard(card({ tone: 'idle' }))).toBe('planned');
    expect(laneForCard(card({ tone: 'running', findingsCount: 0 }))).toBe('running');
  });

  it('prioritizes attention/terminal states over running + findings', () => {
    // A failed agent that happened to produce findings is Failed, not Produced-Finding.
    expect(laneForCard(card({ tone: 'failed', findingsCount: 2 }))).toBe('failed');
    // Needs-You wins over a produced finding (operator must act first).
    expect(laneForCard(card({ tone: 'running', pendingApproval: true, findingsCount: 2 }))).toBe('needs_approval');
    // A completed agent with findings is Completed (terminal), not Produced-Finding.
    expect(laneForCard(card({ tone: 'done', findingsCount: 5 }))).toBe('completed');
  });
});

describe('buildCampaignBoard', () => {
  it('groups agents into per-campaign swimlanes, ungrouped last, bucketed by lane', () => {
    const cards = [
      card({ id: 'a1', campaignId: 'c1', campaignName: 'Alpha', tone: 'running' }),
      card({ id: 'a2', campaignId: 'c1', campaignName: 'Alpha', tone: 'failed' }),
      card({ id: 'a3', campaignId: 'c1', campaignName: 'Alpha', tone: 'running', findingsCount: 1 }),
      card({ id: 'b1', campaignId: 'c2', campaignName: 'Bravo', pendingApproval: true }),
      card({ id: 'u1', tone: 'idle' }), // ungrouped
    ];
    const board = buildCampaignBoard(cards);

    // Two named campaigns (alphabetical) + ungrouped last.
    expect(board.map(s => s.name)).toEqual(['Alpha', 'Bravo', 'Ungrouped']);

    const alpha = board[0];
    expect(alpha.total).toBe(3);
    expect(alpha.lanes.running.map(c => c.id)).toEqual(['a1']);
    expect(alpha.lanes.failed.map(c => c.id)).toEqual(['a2']);
    expect(alpha.lanes.produced_finding.map(c => c.id)).toEqual(['a3']);

    expect(board[1].lanes.needs_approval.map(c => c.id)).toEqual(['b1']);
    expect(board[2].lanes.planned.map(c => c.id)).toEqual(['u1']);
  });

  it('every lane id is covered by BOARD_LANES (board renders all columns)', () => {
    const laneIds = new Set(BOARD_LANES.map(l => l.id));
    const sample = buildCampaignBoard([card()])[0];
    for (const k of Object.keys(sample.lanes)) expect(laneIds.has(k as never)).toBe(true);
    expect(BOARD_LANES).toHaveLength(7);
  });
});
