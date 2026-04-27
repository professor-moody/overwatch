// ============================================================
// NodeDetailDrawer — right-side node detail panel
// ============================================================

import { useState, useCallback } from 'react';
import type Graph from 'graphology';
import { NODE_COLORS, EDGE_CATEGORIES, DEFAULT_EDGE_COLOR } from '../../lib/graph-constants';
import { getNodeDisplayLabel, getNodeIdentityEntries, getFriendlyNodeTypeLabel } from '../../lib/node-display';
import { useNavigation } from '../../hooks/useNavigation';
import { correctGraph, type GraphCorrectionOperation } from '../../lib/api';
import { useToastStore } from '../../stores/toast-store';

interface NodeDetailDrawerProps {
  graph: Graph;
  nodeId: string | null;
  onClose: () => void;
  onFocus?: (nodeId: string, hops: number) => void;
  editMode?: boolean;
  onUndoPush?: (op: { reason: string; reverse: GraphCorrectionOperation[] }) => void;
}

export function NodeDetailDrawer({ graph, nodeId, onClose, onFocus, editMode, onUndoPush }: NodeDetailDrawerProps) {
  const { navigateToEvidence } = useNavigation();
  if (!nodeId || !graph.hasNode(nodeId)) return null;

  const attrs = graph.getNodeAttributes(nodeId);
  const props = (attrs._props as Record<string, unknown>) || {};
  const nodeType = (attrs.nodeType as string) || 'host';
  const label = getNodeDisplayLabel(props, nodeId);
  const entries = getNodeIdentityEntries(props, nodeId);

  // Collect connected edges grouped by type
  const edgeGroups = new Map<string, { count: number; peers: { id: string; label: string; type: string }[] }>();
  graph.forEachEdge(nodeId, (_edgeId, edgeAttrs, source, target) => {
    const edgeType = (edgeAttrs.edgeType as string) || 'RELATED';
    const peerId = source === nodeId ? target : source;
    const peerAttrs = graph.getNodeAttributes(peerId);
    const peerProps = (peerAttrs._props as Record<string, unknown>) || {};
    const peerLabel = getNodeDisplayLabel(peerProps, peerId);
    const peerType = (peerAttrs.nodeType as string) || 'host';

    if (!edgeGroups.has(edgeType)) edgeGroups.set(edgeType, { count: 0, peers: [] });
    const group = edgeGroups.get(edgeType)!;
    group.count++;
    if (group.peers.length < 5) group.peers.push({ id: peerId, label: peerLabel, type: peerType });
  });

  return (
    <div className="fixed right-0 top-12 bottom-0 w-80 bg-surface border-l border-border z-40 flex flex-col shadow-2xl">
      {/* Header */}
      <div className="px-4 py-3 border-b border-border flex-shrink-0">
        <div className="flex items-center justify-between mb-1">
          <span
            className="text-[10px] font-mono px-1.5 py-0.5 rounded uppercase tracking-wide"
            style={{ backgroundColor: `${NODE_COLORS[nodeType] || '#888'}20`, color: NODE_COLORS[nodeType] || '#888' }}
          >
            {getFriendlyNodeTypeLabel(nodeType).replace(/s$/, '')}
          </span>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground p-1" title="Close">
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <path d="M3 3l8 8M11 3l-8 8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
          </button>
        </div>
        <h3 className="text-sm font-semibold truncate" title={label}>{label}</h3>
        <div className="text-[10px] text-muted-foreground font-mono truncate mt-0.5">{nodeId}</div>
      </div>

      {/* Properties */}
      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4">
        {entries.length > 0 && (
          <div>
            <h4 className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">Properties</h4>
            <div className="space-y-1">
              {entries.map(e => (
                <div key={e.key} className="flex items-start gap-2 text-xs">
                  <span className="text-muted-foreground font-mono w-24 flex-shrink-0 truncate">{e.key}</span>
                  <span className="text-foreground break-all">{String(e.value)}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Edges */}
        {edgeGroups.size > 0 && (
          <div>
            <h4 className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">
              Edges ({graph.degree(nodeId)})
            </h4>
            <div className="space-y-2">
              {[...edgeGroups.entries()].sort((a, b) => b[1].count - a[1].count).map(([edgeType, group]) => (
                <div key={edgeType} className="text-xs">
                  <div className="flex items-center gap-1.5 mb-0.5">
                    <span
                      className="w-2 h-0.5 rounded-full inline-block"
                      style={{ backgroundColor: EDGE_CATEGORIES[edgeType] || DEFAULT_EDGE_COLOR }}
                    />
                    <span className="font-mono text-muted-foreground">{edgeType}</span>
                    <span className="text-muted ml-auto">×{group.count}</span>
                  </div>
                  <div className="pl-3.5 space-y-0.5">
                    {group.peers.map(p => (
                      <div key={p.id} className="flex items-center gap-1.5 text-[11px]">
                        <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: NODE_COLORS[p.type] || '#888' }} />
                        <span className="truncate text-foreground">{p.label}</span>
                      </div>
                    ))}
                    {group.count > 5 && (
                      <span className="text-muted text-[10px]">+{group.count - 5} more</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="px-4 py-2 border-t border-border flex flex-col gap-2">
        <div className="flex gap-2">
          <button
            onClick={() => onFocus?.(nodeId, 2)}
            className="flex-1 text-xs py-1.5 rounded bg-accent/10 text-accent hover:bg-accent/20 transition-colors"
          >
            Focus
          </button>
          <button
            onClick={() => navigateToEvidence(nodeId)}
            className="flex-1 text-xs py-1.5 rounded bg-elevated text-foreground hover:bg-hover transition-colors"
          >
            Evidence
          </button>
        </div>
        {editMode && (
          <AddEdgeInline graph={graph} sourceId={nodeId} onUndoPush={onUndoPush} />
        )}
      </div>
    </div>
  );
}

// ---- Add Edge (inline, edit mode) ----

function AddEdgeInline({ graph, sourceId, onUndoPush }: {
  graph: Graph;
  sourceId: string;
  onUndoPush?: (op: { reason: string; reverse: GraphCorrectionOperation[] }) => void;
}) {
  const [open, setOpen] = useState(false);
  const [targetId, setTargetId] = useState('');
  const [edgeType, setEdgeType] = useState('RELATED');
  const [loading, setLoading] = useState(false);
  const toast = useToastStore((s) => s.addToast);

  // Collect existing edge types for the dropdown
  const edgeTypes = new Set<string>();
  graph.forEachEdge((_e, attrs) => { edgeTypes.add((attrs.edgeType as string) || 'RELATED'); });
  const sortedTypes = [...edgeTypes].sort();

  // Collect node IDs for target search
  const allNodeIds: string[] = [];
  graph.forEachNode((id) => { allNodeIds.push(id); });

  const handleAdd = useCallback(async () => {
    if (!targetId.trim()) return;
    setLoading(true);
    try {
      // patch_node doesn't add edges — use the backend correct_graph
      // The backend supports drop_edge and replace_edge but not add_edge directly.
      // We use replace_edge as a workaround if needed, or we add via a different mechanism.
      // For now, use a patch_node approach to flag the intent.
      const op: GraphCorrectionOperation = {
        kind: 'patch_node',
        node_id: sourceId,
        patch: { [`_pending_edge_${Date.now()}`]: `${edgeType}:${targetId.trim()}` },
      };
      await correctGraph(`[console] Add edge: ${sourceId} --[${edgeType}]--> ${targetId.trim()}`, [op]);
      toast({ type: 'success', title: 'Edge flagged', message: `${sourceId} → ${targetId.trim()} (${edgeType})` });
      if (onUndoPush) {
        onUndoPush({
          reason: `Undo: add edge ${sourceId} → ${targetId.trim()}`,
          reverse: [{ kind: 'patch_node', node_id: sourceId, patch: { [`_pending_edge_${Date.now()}`]: undefined } }],
        });
      }
      setOpen(false);
      setTargetId('');
    } catch (err) {
      toast({ type: 'error', title: 'Failed', message: String(err) });
    } finally { setLoading(false); }
  }, [sourceId, targetId, edgeType, toast, onUndoPush]);

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="text-xs py-1.5 rounded border border-dashed border-border text-muted-foreground hover:text-foreground hover:border-accent/40 transition-colors"
      >
        + Add Edge
      </button>
    );
  }

  return (
    <div className="border border-border rounded p-2 space-y-2">
      <div className="text-[10px] text-muted-foreground">Add edge from <span className="font-mono text-accent">{sourceId}</span></div>
      <input
        value={targetId}
        onChange={(e) => setTargetId(e.target.value)}
        placeholder="Target node ID…"
        className="settings-input w-full text-xs"
        list="node-targets"
      />
      <datalist id="node-targets">
        {allNodeIds.slice(0, 100).map(id => <option key={id} value={id} />)}
      </datalist>
      <select value={edgeType} onChange={(e) => setEdgeType(e.target.value)} className="settings-input w-full text-xs">
        {sortedTypes.map(t => <option key={t} value={t}>{t}</option>)}
        <option value="RELATED">RELATED</option>
      </select>
      <div className="flex gap-2">
        <button onClick={handleAdd} disabled={loading} className="flex-1 text-xs py-1 rounded bg-accent/10 text-accent hover:bg-accent/20">
          {loading ? 'Adding…' : 'Add'}
        </button>
        <button onClick={() => setOpen(false)} className="flex-1 text-xs py-1 rounded bg-elevated text-muted-foreground hover:text-foreground">
          Cancel
        </button>
      </div>
    </div>
  );
}
