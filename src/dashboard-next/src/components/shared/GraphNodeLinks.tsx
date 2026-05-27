import { useNavigation } from '../../hooks/useNavigation';
import { cn } from '../../lib/utils';
import { FileText, Network } from 'lucide-react';
import type { GraphNavigationTarget } from '../../lib/graph-target';

export function GraphNodeLinks({
  nodeId,
  label,
  className,
  graphTarget,
}: {
  nodeId: string;
  label?: string;
  className?: string;
  graphTarget?: GraphNavigationTarget;
}) {
  const { navigateToGraphTarget, navigateToEvidence } = useNavigation();
  const target = graphTarget || { kind: 'node' as const, nodeId, hops: 2 };

  return (
    <span className={cn('inline-flex min-w-0 items-center gap-1 rounded border border-border bg-background/45 px-1.5 py-0.5 text-[10px] font-mono', className)}>
      {label && <span className="text-muted-foreground">{label}</span>}
      <span className="max-w-36 truncate text-foreground" title={nodeId}>{nodeId}</span>
      <button
        type="button"
        title={`Open ${nodeId} in graph`}
        onClick={(event) => {
          event.stopPropagation();
          navigateToGraphTarget(target);
        }}
        className="inline-flex h-5 w-5 items-center justify-center rounded text-accent hover:bg-accent/10"
      >
        <Network size={12} />
      </button>
      <button
        type="button"
        title={`Open evidence for ${nodeId}`}
        onClick={(event) => {
          event.stopPropagation();
          navigateToEvidence(nodeId);
        }}
        className="inline-flex h-5 w-5 items-center justify-center rounded text-accent hover:bg-accent/10"
      >
        <FileText size={12} />
      </button>
    </span>
  );
}
