// ============================================================
// FocusBanner — neighborhood focus exit banner
// ============================================================

interface FocusBannerProps {
  focusNode: string | null;
  focusSize: number;
  onExit: () => void;
}

export function FocusBanner({ focusNode, focusSize, onExit }: FocusBannerProps) {
  if (!focusNode) return null;

  return (
    <div className="absolute top-14 left-1/2 -translate-x-1/2 z-30 bg-accent/10 border border-accent/30 rounded-md px-4 py-1.5 flex items-center gap-3 text-xs">
      <span className="text-accent font-medium">
        Focused on <span className="font-mono">{focusNode}</span>
      </span>
      <span className="text-muted-foreground">({focusSize} nodes)</span>
      <button onClick={onExit} className="px-2 py-0.5 rounded bg-accent/20 text-accent hover:bg-accent/30 transition-colors">
        Show All
      </button>
    </div>
  );
}
