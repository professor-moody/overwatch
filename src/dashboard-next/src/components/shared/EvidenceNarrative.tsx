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
        <div key={item.id} className="rounded border border-border bg-elevated p-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-[10px] font-semibold uppercase tracking-wide text-accent">{sourceKindLabel(item.source_kind)}</span>
            <span className="text-[10px] text-muted-foreground">{item.count} event{item.count === 1 ? '' : 's'}</span>
          </div>
          <div className="mt-1 text-xs font-medium text-foreground">
            Supports evidence for{' '}
            <GraphNodeLinks
              nodeId={item.node_id}
              label={item.label}
              graphTarget={{ kind: 'evidence', nodeId: item.node_id, label: `Evidence for ${item.label || item.node_id}` }}
              className="text-accent"
            />
          </div>
          {item.proof && <div className="mt-1 text-xs text-muted-foreground line-clamp-3">{item.proof}</div>}
          <div className="mt-2 flex flex-wrap gap-1.5 text-[10px] text-muted-foreground">
            {item.tool && <span className="rounded border border-border bg-background/50 px-1.5 py-0.5">{item.tool}</span>}
            {item.latest && <span className="rounded border border-border bg-background/50 px-1.5 py-0.5">{formatTimestamp(item.latest)}</span>}
          </div>
          {(item.action_id || item.event_type || item.description) && (
            <details className="mt-2">
              <summary className="cursor-pointer text-[10px] text-accent">Trace metadata</summary>
              <div className="mt-1 space-y-1 text-[10px] text-muted-foreground">
                {item.event_type && <div>Event: <span className="font-mono text-foreground">{item.event_type}</span></div>}
                {item.action_id && <div>Action: <span className="font-mono text-foreground break-all">{item.action_id}</span></div>}
                {item.description && <div>{item.description}</div>}
              </div>
            </details>
          )}
        </div>
      ))}
    </div>
  );
}

function sourceKindLabel(kind: EvidenceNarrativeItem['source_kind']): string {
  if (kind === 'command_output') return 'Command output';
  if (kind === 'parsed_result') return 'Parsed result';
  return 'Activity record';
}
