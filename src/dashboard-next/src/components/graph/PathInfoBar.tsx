// ============================================================
// PathInfoBar — shift-click path info banner
// ============================================================

import type Graph from 'graphology';
import { cn } from '../../lib/utils';

interface PathInfoBarProps {
  graph: Graph;
  pathSource: string | null;
  pathTarget: string | null;
  pathEdges: Set<string>;
  onClear: () => void;
  className?: string;
}

export function PathInfoBar({ graph, pathSource, pathTarget, pathEdges, onClear, className }: PathInfoBarProps) {
  if (!pathSource || !pathTarget || pathEdges.size === 0) return null;

  const srcLabel = graph.hasNode(pathSource) ? (graph.getNodeAttribute(pathSource, 'label') as string) || pathSource : pathSource;
  const tgtLabel = graph.hasNode(pathTarget) ? (graph.getNodeAttribute(pathTarget, 'label') as string) || pathTarget : pathTarget;

  const edgeTypes: string[] = [];
  for (const edge of pathEdges) {
    if (graph.hasEdge(edge)) {
      edgeTypes.push((graph.getEdgeAttribute(edge, 'edgeType') as string) || '?');
    }
  }

  return (
    <div className={cn('pointer-events-auto bg-surface/95 backdrop-blur border border-border rounded-md px-4 py-2 flex items-center gap-3 text-xs shadow-lg', className)}>
      <span className="text-foreground font-medium">{srcLabel} → {tgtLabel}</span>
      <span className="text-muted-foreground">({pathEdges.size} hops)</span>
      <span className="text-muted-foreground truncate max-w-60">{edgeTypes.join(' → ')}</span>
      <button onClick={onClear} className="text-muted-foreground hover:text-foreground ml-2" title="Clear path">✕</button>
    </div>
  );
}
