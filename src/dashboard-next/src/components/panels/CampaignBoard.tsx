import { useMemo } from 'react';
import { cn } from '../../lib/utils';
import { EmptyState } from '../shared';
import type { MissionCard, MissionTone } from '../../lib/agent-mission';
import { buildCampaignBoard, BOARD_LANES, type BoardLane } from '../../lib/campaign-board';
import { useNavigation } from '../../hooks/useNavigation';

// Read-only board: each campaign is a swimlane (row); its agents bucket into the
// status lanes (columns). Pure projection of MissionCards — no engine writes.

const TONE_DOT: Record<MissionTone, string> = {
  running: 'bg-accent',
  blocked: 'bg-warning',
  stuck: 'bg-purple', // distinct from blocked's amber — "alive but idle", not "waiting on you"
  failed: 'bg-destructive',
  done: 'bg-success',
  idle: 'bg-muted-foreground',
};

const LANE_ACCENT: Record<BoardLane, string> = {
  planned: 'text-muted-foreground',
  running: 'text-accent',
  needs_approval: 'text-warning',
  blocked: 'text-warning',
  produced_finding: 'text-success',
  completed: 'text-success',
  failed: 'text-destructive',
};

export function CampaignBoard({ cards }: { cards: MissionCard[] }) {
  const swimlanes = useMemo(() => buildCampaignBoard(cards), [cards]);

  if (cards.length === 0) {
    return <EmptyState message="No agents yet. Dispatch agents (Deploy / a campaign) to populate the board." className="m-3" />;
  }

  return (
    <div className="flex-1 min-h-0 overflow-auto space-y-4 pr-1">
      {swimlanes.map(lane => (
        <div key={lane.key} className="rounded border border-border bg-surface">
          <div className="flex items-center gap-2 border-b border-border px-3 py-2">
            <span className="text-sm font-medium text-foreground">{lane.name}</span>
            <span className="text-[10px] text-muted-foreground">{lane.total} agent{lane.total === 1 ? '' : 's'}</span>
          </div>
          <div className="flex gap-2 overflow-x-auto p-2">
            {BOARD_LANES.map(col => {
              const items = lane.lanes[col.id];
              return (
                <div key={col.id} className="min-w-[150px] flex-1">
                  <div className={cn('mb-1 flex items-center justify-between text-[10px] font-medium uppercase tracking-wide', LANE_ACCENT[col.id])}>
                    <span>{col.label}</span>
                    <span className="text-muted-foreground">{items.length}</span>
                  </div>
                  <div className="space-y-1">
                    {items.map(card => <BoardCard key={card.id} card={card} />)}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

function BoardCard({ card }: { card: MissionCard }) {
  const { navigateToAgent } = useNavigation();
  return (
    <button
      onClick={() => navigateToAgent(card.id)}
      title={`Open ${card.label} in Agents`}
      className="w-full rounded border border-border bg-elevated p-1.5 text-left text-[11px] hover:border-accent/40 hover:bg-hover/40"
    >
      <div className="flex items-center gap-1.5">
        <span className={cn('h-1.5 w-1.5 rounded-full flex-none', TONE_DOT[card.tone])} />
        <span className="truncate font-mono text-foreground">{card.label}</span>
        {card.findingsCount > 0 && (
          <span className="ml-auto flex-none text-[10px] text-success">{card.findingsCount}🏁</span>
        )}
      </div>
      {card.role && <div className="mt-0.5 truncate text-[10px] text-muted-foreground">{card.role}</div>}
      {card.blocker && <div className={cn('mt-0.5 truncate text-[10px]', card.tone === 'failed' ? 'text-destructive' : card.tone === 'stuck' ? 'text-purple' : 'text-warning')}>{card.blocker}</div>}
    </button>
  );
}
