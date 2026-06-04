// ============================================================
// FocusBanner — neighborhood focus exit banner
// ============================================================

import { cn } from '../../lib/utils';

interface FocusBannerProps {
  focusNode: string | null;
  focusSize: number;
  label?: string | null;
  kind?: string | null;
  onFit: () => void;
  onExit: () => void;
  className?: string;
}

export function FocusBanner({ focusNode, focusSize, label, kind, onFit, onExit, className }: FocusBannerProps) {
  if (!focusNode && !label) return null;
  const title = label || 'Focused on';
  const showNode = focusNode && !title.includes(focusNode);

  return (
    <div className={cn('pointer-events-none max-w-[min(36rem,calc(100vw-20rem))] bg-accent/10 border border-accent/30 rounded-md px-4 py-1.5 flex items-center gap-3 text-xs shadow-lg', className)}>
      <span className="text-accent font-medium truncate">
        {kind && kind !== 'node' && <span className="uppercase tracking-wide text-[10px] mr-1.5">{kind}</span>}
        {title}{showNode && <> <span className="font-mono">{focusNode}</span></>}
      </span>
      <span className="text-muted-foreground flex-shrink-0">({focusSize} nodes)</span>
      <button onClick={onFit} className="pointer-events-auto px-2 py-0.5 rounded bg-accent/15 text-accent hover:bg-accent/25 transition-colors flex-shrink-0">
        Fit
      </button>
      <button onClick={onExit} className="pointer-events-auto px-2 py-0.5 rounded bg-accent/20 text-accent hover:bg-accent/30 transition-colors flex-shrink-0">
        Show All
      </button>
    </div>
  );
}
