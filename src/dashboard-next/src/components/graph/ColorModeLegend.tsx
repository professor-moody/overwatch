import { useMemo } from 'react';
import type Graph from 'graphology';
import { TIER_COLORS, TIER_ORDER, type ColorMode } from '../../lib/graph-color';

// Small legend that states what node color currently encodes. Only shown when the
// graph is NOT colored by type — in type mode the NodeFilters swatches already serve
// as the legend. Prevents the type-colored NodeFilters chips from being misread as
// the graph's color when the graph is community/tier-colored.
export function ColorModeLegend({ colorMode, graph, graphVersion }: { colorMode: ColorMode; graph: Graph; graphVersion: number }) {
  const communityCount = useMemo(() => {
    if (colorMode !== 'community') return 0;
    const seen = new Set<number>();
    graph.forEachNode((_id, attrs) => {
      const c = (attrs as { community?: number }).community;
      if (typeof c === 'number') seen.add(c);
    });
    return seen.size;
    // graph is a stable ref → include graphVersion so the count refreshes as data grows.
  }, [colorMode, graph, graphVersion]);

  if (colorMode === 'type') return null;

  return (
    <div className="rounded border border-border bg-surface/95 px-2 py-1.5 text-[10px] text-muted-foreground shadow-sm">
      {colorMode === 'community' ? (
        <span>Node color = <span className="text-foreground">community</span>{communityCount > 0 ? ` (${communityCount} clusters)` : ''}</span>
      ) : (
        <div className="flex flex-col gap-1">
          <span>Node color = <span className="text-foreground">tier</span></span>
          <div className="flex flex-wrap gap-x-2 gap-y-0.5">
            {TIER_ORDER.filter(t => t !== 'unknown').map(t => (
              <span key={t} className="inline-flex items-center gap-1">
                <span className="h-2 w-2 rounded-full" style={{ backgroundColor: TIER_COLORS[t] }} />
                {t}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
