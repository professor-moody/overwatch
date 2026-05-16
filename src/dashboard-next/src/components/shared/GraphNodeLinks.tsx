import { useNavigation } from '../../hooks/useNavigation';
import { cn } from '../../lib/utils';

export function GraphNodeLinks({
  nodeId,
  label,
  className,
}: {
  nodeId: string;
  label?: string;
  className?: string;
}) {
  const { navigateToGraph, navigateToEvidence } = useNavigation();

  return (
    <span className={cn('inline-flex items-center gap-1 text-[10px] font-mono', className)}>
      {label && <span className="text-muted-foreground">{label}</span>}
      <span className="rounded bg-elevated px-1.5 py-0.5 text-foreground">{nodeId}</span>
      <button
        onClick={(event) => {
          event.stopPropagation();
          navigateToGraph(nodeId, 2);
        }}
        className="rounded px-1 py-0.5 text-accent hover:bg-accent/10"
      >
        Graph
      </button>
      <button
        onClick={(event) => {
          event.stopPropagation();
          navigateToEvidence(nodeId);
        }}
        className="rounded px-1 py-0.5 text-accent hover:bg-accent/10"
      >
        Evidence
      </button>
    </span>
  );
}
