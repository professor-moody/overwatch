import type Graph from 'graphology';
import { EDGE_CATEGORIES, DEFAULT_EDGE_COLOR, NODE_COLORS } from '../../lib/graph-constants';
import { getNodeDisplayLabel } from '../../lib/node-display';
import { formatRelativeTime } from '../../lib/utils';
import { cn } from '../../lib/utils';

interface EdgeDetailPanelProps {
  graph: Graph;
  edgeId: string | null;
  onClose: () => void;
  onFocusNode: (nodeId: string, hops: number) => void;
}

export function EdgeDetailPanel({ graph, edgeId, onClose, onFocusNode }: EdgeDetailPanelProps) {
  if (!edgeId || !graph.hasEdge(edgeId)) return null;

  const attrs = graph.getEdgeAttributes(edgeId);
  const edgeType = (attrs.edgeType as string) || 'RELATED';
  const props = (attrs._props as Record<string, unknown>) || {};
  const source = graph.source(edgeId);
  const target = graph.target(edgeId);

  const sourceAttrs = graph.getNodeAttributes(source);
  const targetAttrs = graph.getNodeAttributes(target);
  const sourceProps = (sourceAttrs._props as Record<string, unknown>) || {};
  const targetProps = (targetAttrs._props as Record<string, unknown>) || {};
  const sourceLabel = getNodeDisplayLabel(sourceProps, source);
  const targetLabel = getNodeDisplayLabel(targetProps, target);
  const sourceType = (sourceAttrs.nodeType as string) || 'host';
  const targetType = (targetAttrs.nodeType as string) || 'host';

  const edgeColor = EDGE_CATEGORIES[edgeType] || DEFAULT_EDGE_COLOR;
  const confidence = props.confidence != null ? Number(props.confidence) : null;
  const discoveredAt = props.discovered_at as string | undefined;
  const discoveredBy = props.discovered_by as string | undefined;
  const inferredByRule = attrs.inferredByRule as string | undefined;

  const extraProps = Object.entries(props).filter(([k]) =>
    !['type', 'confidence', 'discovered_at', 'discovered_by'].includes(k)
  );

  return (
    <div className="pointer-events-auto absolute bottom-4 left-3 w-80 z-30 bg-surface border border-border rounded-lg shadow-xl text-xs">
      <div className="flex items-center justify-between px-3 py-2 border-b border-border">
        <div className="flex items-center gap-2">
          <span
            className="inline-block w-6 h-0.5 rounded-full flex-shrink-0"
            style={{ backgroundColor: edgeColor }}
          />
          <span
            className="font-mono px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wide"
            style={{ backgroundColor: `${edgeColor}20`, color: edgeColor }}
          >
            {edgeType}
          </span>
          {inferredByRule && (
            <span className="text-[10px] px-1 py-0.5 rounded bg-purple-dim text-purple border border-purple/20">
              inferred
            </span>
          )}
        </div>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground p-0.5" title="Close">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path d="M2 2l8 8M10 2l-8 8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
        </button>
      </div>

      <div className="px-3 py-2 space-y-2">
        <div className="flex items-center gap-2 min-w-0">
          <NodeChip
            nodeId={source}
            label={sourceLabel}
            type={sourceType}
            onClick={() => onFocusNode(source, 2)}
          />
          <span className="text-muted-foreground flex-shrink-0">→</span>
          <NodeChip
            nodeId={target}
            label={targetLabel}
            type={targetType}
            onClick={() => onFocusNode(target, 2)}
          />
        </div>

        <div className="grid grid-cols-2 gap-1.5">
          {confidence !== null && (
            <FactCell label="Confidence" value={`${Math.round(confidence * 100)}%`} tone={confidence >= 0.8 ? 'success' : confidence >= 0.5 ? 'warning' : 'muted'} />
          )}
          {discoveredAt && (
            <FactCell label="Discovered" value={formatRelativeTime(discoveredAt)} />
          )}
          {discoveredBy && (
            <FactCell label="By" value={discoveredBy} mono />
          )}
          {inferredByRule && (
            <FactCell label="Rule" value={inferredByRule} mono />
          )}
        </div>

        {extraProps.length > 0 && (
          <div className="space-y-0.5">
            {extraProps.slice(0, 4).map(([k, v]) => (
              <div key={k} className="flex items-start gap-2">
                <span className="text-muted-foreground w-20 flex-shrink-0 truncate">{k}</span>
                <span className="text-foreground break-all">{String(v)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function NodeChip({ nodeId, label, type, onClick }: { nodeId: string; label: string; type: string; onClick: () => void }) {
  const color = NODE_COLORS[type] || '#888';
  return (
    <button
      onClick={onClick}
      className="min-w-0 flex items-center gap-1 rounded border border-border bg-background/40 px-1.5 py-0.5 hover:border-accent/40 hover:bg-hover/30 transition-colors"
      title={nodeId}
    >
      <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: color }} />
      <span className="truncate text-[10px] text-foreground max-w-[7rem]">{label}</span>
    </button>
  );
}

function FactCell({ label, value, mono, tone }: { label: string; value: string; mono?: boolean; tone?: 'success' | 'warning' | 'muted' }) {
  return (
    <div className="rounded border border-border bg-elevated px-2 py-1 min-w-0">
      <div className="text-[9px] uppercase text-muted-foreground">{label}</div>
      <div className={cn(
        'text-[11px] truncate',
        mono && 'font-mono',
        tone === 'success' && 'text-success',
        tone === 'warning' && 'text-warning',
        !tone && 'text-foreground',
      )}>{value}</div>
    </div>
  );
}
