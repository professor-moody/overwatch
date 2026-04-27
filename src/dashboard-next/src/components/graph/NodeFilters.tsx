// ============================================================
// NodeFilters — type filter chips overlay
// ============================================================

import type Graph from 'graphology';
import { NODE_COLORS } from '../../lib/graph-constants';
import { getFriendlyNodeTypeLabel } from '../../lib/node-display';
import { cn } from '../../lib/utils';

interface NodeFiltersProps {
  graph: Graph;
  activeFilters: Set<string>;
  onToggle: (type: string) => void;
}

export function NodeFilters({ graph, activeFilters, onToggle }: NodeFiltersProps) {
  // Collect types with counts
  const typeCounts = new Map<string, number>();
  graph.forEachNode((_id, attrs) => {
    const t = (attrs.nodeType as string) || 'host';
    typeCounts.set(t, (typeCounts.get(t) || 0) + 1);
  });

  const types = [...typeCounts.entries()].sort((a, b) => b[1] - a[1]);

  if (types.length === 0) return null;

  return (
    <div className="absolute bottom-3 left-3 z-20 flex flex-wrap gap-1 max-w-[60%]">
      {types.map(([type, count]) => {
        const active = activeFilters.has(type);
        const color = NODE_COLORS[type] || '#888';
        return (
          <button
            key={type}
            onClick={() => onToggle(type)}
            className={cn(
              'flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] border transition-all',
              active
                ? 'border-border bg-surface/80 text-foreground'
                : 'border-transparent bg-surface/40 text-muted-foreground opacity-50',
            )}
            title={`${getFriendlyNodeTypeLabel(type)} (${count})`}
          >
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: active ? color : `${color}40` }} />
            <span>{count}</span>
          </button>
        );
      })}
    </div>
  );
}
