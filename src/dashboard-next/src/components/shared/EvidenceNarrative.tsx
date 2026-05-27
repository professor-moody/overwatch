import type { EvidenceNarrativeItem } from '../../lib/evidence-narrative';
import { formatTimestamp } from '../../lib/utils';
import { GraphNodeLinks } from './GraphNodeLinks';

export function EvidenceNarrative({
  items,
  empty = 'No supporting evidence chain found yet.',
}: {
  items: EvidenceNarrativeItem[];
  empty?: string;
}) {
  if (items.length === 0) {
    return <div className="text-xs text-muted-foreground">{empty}</div>;
  }

  return (
    <div className="space-y-2">
      {items.map(item => (
        <div key={item.id} className="rounded border border-border bg-elevated p-2">
          <div className="flex items-center justify-between gap-2">
            <GraphNodeLinks
              nodeId={item.node_id}
              label={item.label}
              graphTarget={{ kind: 'evidence', nodeId: item.node_id, label: `Evidence for ${item.label || item.node_id}` }}
            />
            <span className="text-[10px] text-muted-foreground">{item.count} event{item.count === 1 ? '' : 's'}</span>
          </div>
          {item.description && <div className="mt-1 text-xs text-muted-foreground line-clamp-2">{item.description}</div>}
          {item.latest && <div className="mt-1 text-[10px] text-muted-foreground">{formatTimestamp(item.latest)}</div>}
        </div>
      ))}
    </div>
  );
}
