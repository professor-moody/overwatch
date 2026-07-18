import { cn, formatElapsed } from '../../lib/utils';
import type { MissionCard as MissionCardModel, MissionTone } from '../../lib/agent-mission';

// Phase 5 (Mission Control) — the Fleet roster row. One compact card per agent
// that makes productive / blocked / failed obvious at a glance. View-model is
// built by lib/agent-mission.ts (tested); this is pure presentation.

// `blocked` (waiting on you) and `stuck` (alive but idle) are distinct states
// that need distinct triage — keep them on different hues, not two shades of one.
const TONE_DOT: Record<MissionTone, string> = {
  blocked: 'bg-warning',
  stuck: 'bg-purple',
  running: 'bg-success',
  failed: 'bg-destructive',
  done: 'bg-accent',
  idle: 'bg-muted',
};

const FRESHNESS_LABEL: Record<MissionCardModel['freshness'], string> = {
  fresh: 'live',
  recent: 'active',
  quiet: 'quiet',
  none: '',
};

export function MissionCard({
  card,
  active,
  batchMode,
  selected,
  elapsedMs,
  onClick,
  onToggleSelect,
  onCancel,
  onDismiss,
  onForceRemove,
}: {
  card: MissionCardModel;
  active: boolean;
  batchMode: boolean;
  selected: boolean;
  elapsedMs?: number;
  onClick: () => void;
  onToggleSelect: () => void;
  onCancel?: () => void;
  onDismiss?: () => void;
  onForceRemove?: () => void;
}) {
  const cancellable = card.status === 'running' || card.status === 'pending';
  return (
    <div
      data-testid="mission-card"
      onClick={onClick}
      className={cn(
        'cursor-pointer border-b border-border px-3 py-2 transition-colors last:border-b-0 hover:bg-hover/40',
        active && 'border-l-2 border-l-accent bg-accent/10',
        card.tone === 'blocked' && !active && 'border-l-2 border-l-warning/60',
        card.tone === 'stuck' && !active && 'border-l-2 border-l-purple/60',
      )}
    >
      <div className="flex items-center gap-2">
        {batchMode && (
          <input
            type="checkbox"
            checked={selected}
            onChange={e => { e.stopPropagation(); onToggleSelect(); }}
            onClick={e => e.stopPropagation()}
            className="accent-accent"
          />
        )}
        <span className={cn('h-2 w-2 flex-shrink-0 rounded-full', TONE_DOT[card.tone], card.tone === 'running' && card.freshness === 'fresh' && 'animate-pulse')} />
        <span className="min-w-0 flex-1 truncate font-mono text-xs text-foreground" title={card.label}>{card.label}</span>
        {card.findingsCount > 0 && <span className="flex-shrink-0 text-[10px] text-success">{card.findingsCount}f</span>}
        {cancellable && onCancel && (
          <button
            onClick={e => { e.stopPropagation(); onCancel(); }}
            className="flex-shrink-0 text-muted-foreground hover:text-destructive"
            title="Cancel agent"
          >
            ✕
          </button>
        )}
        {cancellable && onForceRemove && (
          <button
            onClick={e => { e.stopPropagation(); onForceRemove(); }}
            className="flex-shrink-0 text-[10px] text-muted-foreground hover:text-destructive"
            title="Force stop & remove — kills the process and clears the agent even if Cancel won't"
          >
            ⏻
          </button>
        )}
        {!cancellable && onDismiss && (
          <button
            onClick={e => { e.stopPropagation(); onDismiss(); }}
            className="flex-shrink-0 text-muted-foreground hover:text-destructive"
            title="Dismiss from roster"
          >
            ✕
          </button>
        )}
      </div>

      <div className="mt-0.5 flex items-center gap-2 pl-4 text-[10px]">
        {card.role && <span className="rounded bg-elevated px-1 py-0.5 text-muted-foreground">{card.role}</span>}
        {FRESHNESS_LABEL[card.freshness] && card.tone === 'running' && (
          <span className="text-muted-foreground">{FRESHNESS_LABEL[card.freshness]}</span>
        )}
        {elapsedMs != null && elapsedMs > 0 && <span className="text-muted-foreground">{formatElapsed(elapsedMs)}</span>}
        {card.ownedSessionIds.length > 0 && <span className="text-muted-foreground">{card.ownedSessionIds.length}🖥</span>}
      </div>

      {card.blocker && (
        <div className={cn('mt-1 truncate pl-4 text-[10px]', card.tone === 'failed' ? 'text-destructive' : card.tone === 'stuck' ? 'text-purple' : 'text-warning')} title={card.blocker}>
          {card.blocker}
        </div>
      )}
      {!card.blocker && card.currentAction && (
        <div className="mt-1 truncate pl-4 text-[10px] text-foreground/70" title={card.currentAction}>
          <span className="text-muted-foreground">doing: </span>{card.currentAction}
        </div>
      )}
    </div>
  );
}
