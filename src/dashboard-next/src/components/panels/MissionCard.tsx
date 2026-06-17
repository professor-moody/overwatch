import { cn, formatElapsed } from '../../lib/utils';
import type { MissionCard as MissionCardModel, MissionTone } from '../../lib/agent-mission';

// Phase 5 (Mission Control) — the Fleet roster row. One compact card per agent
// that makes productive / blocked / failed obvious at a glance. View-model is
// built by lib/agent-mission.ts (tested); this is pure presentation.

const TONE_DOT: Record<MissionTone, string> = {
  blocked: 'bg-warning',
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
}: {
  card: MissionCardModel;
  active: boolean;
  batchMode: boolean;
  selected: boolean;
  elapsedMs?: number;
  onClick: () => void;
  onToggleSelect: () => void;
  onCancel?: () => void;
}) {
  const cancellable = card.status === 'running' || card.status === 'pending';
  return (
    <div
      onClick={onClick}
      className={cn(
        'cursor-pointer border-b border-border px-3 py-2 transition-colors last:border-b-0 hover:bg-hover/40',
        active && 'border-l-2 border-l-accent bg-accent/10',
        card.tone === 'blocked' && !active && 'border-l-2 border-l-warning/60',
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
        <div className={cn('mt-1 truncate pl-4 text-[10px]', card.tone === 'failed' ? 'text-destructive' : 'text-warning')} title={card.blocker}>
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
