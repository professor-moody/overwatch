import type { MissionCard } from './agent-mission';
import { groupMissionCards } from './agent-mission';

// Phase 4 (Mission Control) — a read-only board view of the multi-agent fleet:
// each campaign is a swimlane (row), its agents bucketed into status lanes
// (columns). Pure projection of the MissionCards the dashboard already builds —
// no new engine state. Answers "where is the work, per campaign?" at a glance.

export type BoardLane =
  | 'planned'
  | 'running'
  | 'needs_approval'
  | 'blocked'
  | 'produced_finding'
  | 'completed'
  | 'failed';

/** Lanes in left-to-right display order (planned → done → failed). */
export const BOARD_LANES: { id: BoardLane; label: string }[] = [
  { id: 'planned', label: 'Planned' },
  { id: 'running', label: 'Running' },
  { id: 'needs_approval', label: 'Needs You' },
  { id: 'blocked', label: 'Blocked' },
  { id: 'produced_finding', label: 'Produced Finding' },
  { id: 'completed', label: 'Completed' },
  { id: 'failed', label: 'Failed' },
];

/**
 * Assign an agent's mission card to exactly ONE board lane. Operator-attention
 * and terminal states win over "just running"; an agent that's still active but
 * has already produced findings surfaces in Produced Finding so wins are visible.
 * Priority: failed → needs-approval → blocked → completed → produced-finding →
 * planned (idle) → running.
 */
export function laneForCard(card: MissionCard): BoardLane {
  if (card.tone === 'failed') return 'failed';
  if (card.pendingApproval) return 'needs_approval';
  if (card.awaitingAnswer) return 'blocked';
  if (card.tone === 'done') return 'completed';
  if (card.findingsCount > 0) return 'produced_finding';
  if (card.tone === 'idle') return 'planned';
  return 'running';
}

export interface CampaignSwimlane {
  key: string;
  name: string;
  total: number;
  lanes: Record<BoardLane, MissionCard[]>;
}

function emptyLanes(): Record<BoardLane, MissionCard[]> {
  return { planned: [], running: [], needs_approval: [], blocked: [], produced_finding: [], completed: [], failed: [] };
}

/**
 * Build per-campaign swimlanes from mission cards, each bucketing its agents into
 * the board lanes. Reuses groupMissionCards (campaign grouping, ungrouped last);
 * within a lane the cards keep that grouping's attention-sorted order.
 */
export function buildCampaignBoard(cards: MissionCard[]): CampaignSwimlane[] {
  return groupMissionCards(cards).map(group => {
    const lanes = emptyLanes();
    for (const card of group.cards) lanes[laneForCard(card)].push(card);
    return { key: group.key, name: group.name, total: group.cards.length, lanes };
  });
}
