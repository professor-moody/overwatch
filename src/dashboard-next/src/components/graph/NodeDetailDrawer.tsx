// ============================================================
// NodeDetailDrawer - right-side operator inspector
// ============================================================

import { useEffect, useState, useCallback } from 'react';
import type Graph from 'graphology';
import { NODE_COLORS, EDGE_CATEGORIES, DEFAULT_EDGE_COLOR } from '../../lib/graph-constants';
import { getNodeDisplayLabel, getNodeIdentityEntries, getFriendlyNodeTypeLabel } from '../../lib/node-display';
import { useNavigation } from '../../hooks/useNavigation';
import { correctGraph, getEvidenceChains, getFindings, type FindingDto, type GraphCorrectionOperation } from '../../lib/api';
import { useToastStore } from '../../stores/toast-store';
import { useEngagementStore } from '../../stores/engagement-store';
import { deriveNodeRelationships } from '../../lib/relationships';
import { StatusPill } from '../shared/primitives';
import type { EvidenceChainResponse } from '../../lib/types';
import { computeActionRisk } from '../../lib/action-queue';
import { getFrontierPrimaryNodeId } from '../../lib/frontier-workspace';
import { cn, formatRelativeTime } from '../../lib/utils';
import { GraphNodeLinks } from '../shared/GraphNodeLinks';

interface NodeDetailDrawerProps {
  graph: Graph;
  nodeId: string | null;
  onClose: () => void;
  onFocus?: (nodeId: string, hops: number) => void;
  editMode?: boolean;
  onUndoPush?: (op: { reason: string; reverse: GraphCorrectionOperation[] }) => void;
}

type EvidenceStatus = 'idle' | 'loading' | 'ready' | 'empty' | 'error';

export function NodeDetailDrawer({ graph, nodeId, onClose, onFocus, editMode, onUndoPush }: NodeDetailDrawerProps) {
  const { navigateToEvidence, navigateToGraph, navigateToPanel } = useNavigation();
  const storeGraph = useEngagementStore(s => s.graph);
  const sessions = useEngagementStore(s => s.sessions);
  const pendingActions = useEngagementStore(s => s.pendingActions);
  const frontier = useEngagementStore(s => s.frontier);
  const [findings, setFindings] = useState<FindingDto[]>([]);
  const [evidence, setEvidence] = useState<EvidenceChainResponse | null>(null);
  const [evidenceStatus, setEvidenceStatus] = useState<EvidenceStatus>('idle');

  useEffect(() => {
    let cancelled = false;
    getFindings()
      .then(data => { if (!cancelled) setFindings(data.findings || []); })
      .catch(() => { if (!cancelled) setFindings([]); });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!nodeId) {
      setEvidence(null);
      setEvidenceStatus('idle');
      return;
    }
    let cancelled = false;
    setEvidence(null);
    setEvidenceStatus('loading');
    getEvidenceChains(nodeId)
      .then(data => {
        if (cancelled) return;
        setEvidence(data);
        setEvidenceStatus(data.count > 0 ? 'ready' : 'empty');
      })
      .catch(() => {
        if (cancelled) return;
        setEvidence(null);
        setEvidenceStatus('error');
      });
    return () => { cancelled = true; };
  }, [nodeId]);

  if (!nodeId || !graph.hasNode(nodeId)) return null;

  const attrs = graph.getNodeAttributes(nodeId);
  const props = (attrs._props as Record<string, unknown>) || {};
  const nodeType = (attrs.nodeType as string) || 'host';
  const label = getNodeDisplayLabel(props, nodeId);
  const entries = getNodeIdentityEntries(props, nodeId);
  const relationships = deriveNodeRelationships(nodeId, {
    graph: storeGraph,
    sessions,
    pendingActions,
    frontier,
    findings,
  });

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

  const edgeEntries = [...edgeGroups.entries()].sort((a, b) => b[1].count - a[1].count);
  const liveSessions = relationships.sessions.filter(session => session.state === 'connected').length;
  const selectedFacts = [
    { label: 'sessions', value: liveSessions ? `${liveSessions}/${relationships.sessions.length}` : relationships.sessions.length },
    { label: 'actions', value: relationships.pendingActions.length },
    { label: 'frontier', value: relationships.frontier.length },
    { label: 'findings', value: relationships.findings.length },
  ];

  return (
    <div className="fixed right-0 top-12 bottom-0 w-96 bg-surface border-l border-border z-40 flex flex-col shadow-2xl">
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
        <div className="mt-2 grid grid-cols-4 gap-1.5">
          {selectedFacts.map(fact => (
            <div key={fact.label} className="rounded border border-border bg-elevated/60 px-2 py-1">
              <div className="text-[9px] uppercase text-muted-foreground">{fact.label}</div>
              <div className="text-xs font-mono text-foreground">{fact.value}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4">
        <InspectorSection title="Summary">
          <div className="space-y-1.5 text-xs">
            {entries.slice(0, 5).map(entry => (
              <div key={entry.key} className="flex items-start gap-2">
                <span className="text-muted-foreground font-mono w-24 flex-shrink-0 truncate">{entry.key}</span>
                <span className="text-foreground break-all">{String(entry.value)}</span>
              </div>
            ))}
            {entries.length === 0 && <EmptyLine>No display properties on this node.</EmptyLine>}
          </div>
        </InspectorSection>

        <InspectorSection title="Relationships">
          <div className="grid grid-cols-2 gap-2 text-xs">
            <RelationshipLink label="Sessions" count={relationships.sessions.length} hot={liveSessions > 0} onClick={() => navigateToPanel('sessions')} />
            <RelationshipLink label="Actions" count={relationships.pendingActions.length} hot={relationships.pendingActions.length > 0} onClick={() => navigateToPanel('actions')} />
            <RelationshipLink label="Frontier" count={relationships.frontier.length} hot={relationships.frontier.length > 0} onClick={() => navigateToPanel('frontier', nodeId)} />
            <RelationshipLink label="Findings" count={relationships.findings.length} hot={relationships.findings.length > 0} onClick={() => navigateToPanel('findings')} />
          </div>
        </InspectorSection>

        <InspectorSection title="Sessions" count={relationships.sessions.length} actionLabel="Open" onAction={() => navigateToPanel('sessions')}>
          {relationships.sessions.length === 0 ? (
            <EmptyLine>No sessions tied to this node.</EmptyLine>
          ) : (
            <div className="space-y-1.5">
              {relationships.sessions.slice(0, 4).map(session => (
                <div key={session.id} className="rounded border border-border bg-background/40 px-2 py-1.5 text-xs">
                  <div className="flex items-center gap-2">
                    <StatusPill className={session.state === 'connected' ? 'bg-success/10 text-success' : 'bg-elevated text-muted-foreground'}>{session.state}</StatusPill>
                    <span className="truncate text-foreground">{session.title || session.id.slice(0, 8)}</span>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-x-2 gap-y-0.5 text-[10px] text-muted-foreground">
                    {session.kind && <span>{session.kind}</span>}
                    {session.transport && <span>{session.transport}</span>}
                    {session.owner && <span>{session.owner}</span>}
                    <span>{formatRelativeTime(session.last_activity_at || session.started_at || session.created_at)}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </InspectorSection>

        <InspectorSection title="Pending Actions" count={relationships.pendingActions.length} actionLabel="Open" onAction={() => navigateToPanel('actions')}>
          {relationships.pendingActions.length === 0 ? (
            <EmptyLine>No queued approvals target this node.</EmptyLine>
          ) : (
            <div className="space-y-1.5">
              {relationships.pendingActions.slice(0, 4).map(action => {
                const risk = computeActionRisk(action);
                return (
                  <div key={action.action_id} className="rounded border border-border bg-background/40 px-2 py-1.5 text-xs">
                    <div className="flex items-center gap-2">
                      <StatusPill className={risk.cls}>{risk.label}</StatusPill>
                      <span className="truncate text-foreground">{action.technique}</span>
                      <span className="ml-auto text-[10px] text-muted-foreground">{formatRelativeTime(action.submitted_at)}</span>
                    </div>
                    <div className="mt-1 text-[11px] text-muted-foreground line-clamp-2">{action.description}</div>
                  </div>
                );
              })}
            </div>
          )}
        </InspectorSection>

        <InspectorSection title="Frontier" count={relationships.frontier.length} actionLabel="Open" onAction={() => navigateToPanel('frontier', nodeId)}>
          {relationships.frontier.length === 0 ? (
            <EmptyLine>No frontier items reference this node.</EmptyLine>
          ) : (
            <div className="space-y-1.5">
              {relationships.frontier.slice(0, 4).map(item => {
                const primaryNode = getFrontierPrimaryNodeId(item);
                return (
                  <div key={item.frontier_item_id || item.id} className="rounded border border-border bg-background/40 px-2 py-1.5 text-xs">
                    <div className="flex items-center gap-2">
                      <StatusPill className="bg-accent/10 text-accent">{item.type.replace(/_/g, ' ')}</StatusPill>
                      <span className="font-mono text-foreground ml-auto">{(item.priority ?? 0).toFixed(1)}</span>
                    </div>
                    <div className="mt-1 text-[11px] text-muted-foreground line-clamp-2">{item.description}</div>
                    {primaryNode && <GraphNodeLinks nodeId={primaryNode} className="mt-1" />}
                  </div>
                );
              })}
            </div>
          )}
        </InspectorSection>

        <InspectorSection title="Evidence" count={evidence?.count ?? 0} actionLabel="Open" onAction={() => navigateToEvidence(nodeId)}>
          {evidenceStatus === 'loading' && <EmptyLine>Loading evidence chain...</EmptyLine>}
          {(evidenceStatus === 'empty' || evidenceStatus === 'error') && <EmptyLine>No evidence chain loaded for this node.</EmptyLine>}
          {evidenceStatus === 'ready' && evidence && (
            <div className="space-y-1.5">
              {evidence.chains.slice(0, 3).map(entry => (
                <div key={entry.activity_id} className="rounded border border-border bg-background/40 px-2 py-1.5 text-xs">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono text-muted-foreground">{formatRelativeTime(entry.timestamp)}</span>
                    <span className="truncate text-foreground">{entry.event_type}</span>
                  </div>
                  <div className="mt-1 text-[11px] text-muted-foreground line-clamp-2">{entry.description || entry.snippet}</div>
                </div>
              ))}
            </div>
          )}
        </InspectorSection>

        <InspectorSection title="Findings" count={relationships.findings.length} actionLabel="Open" onAction={() => navigateToPanel('findings')}>
          {relationships.findings.length === 0 ? (
            <EmptyLine>No findings currently affect this node.</EmptyLine>
          ) : (
            <div className="space-y-1.5">
              {relationships.findings.slice(0, 4).map(finding => (
                <div key={finding.id} className="rounded border border-border bg-background/40 px-2 py-1.5 text-xs">
                  <div className="flex items-center gap-2">
                    <StatusPill className={findingSeverityClass(finding.severity)}>{finding.severity}</StatusPill>
                    <span className="truncate text-foreground">{finding.title}</span>
                  </div>
                  <div className="mt-1 text-[11px] text-muted-foreground line-clamp-2">{finding.description}</div>
                </div>
              ))}
            </div>
          )}
        </InspectorSection>

        <InspectorSection title="Edges" count={graph.degree(nodeId)}>
          {edgeEntries.length === 0 ? (
            <EmptyLine>No graph edges on this node.</EmptyLine>
          ) : (
            <div className="space-y-2">
              {edgeEntries.map(([edgeType, group]) => (
                <div key={edgeType} className="text-xs">
                  <div className="flex items-center gap-1.5 mb-0.5">
                    <span
                      className="w-2 h-0.5 rounded-full inline-block"
                      style={{ backgroundColor: EDGE_CATEGORIES[edgeType] || DEFAULT_EDGE_COLOR }}
                    />
                    <span className="font-mono text-muted-foreground">{edgeType}</span>
                    <span className="text-muted ml-auto">x{group.count}</span>
                  </div>
                  <div className="pl-3.5 space-y-0.5">
                    {group.peers.map(peer => (
                      <button key={peer.id} onClick={() => navigateToGraph(peer.id, 2)} className="w-full flex items-center gap-1.5 text-[11px] hover:text-accent">
                        <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: NODE_COLORS[peer.type] || '#888' }} />
                        <span className="truncate text-foreground">{peer.label}</span>
                      </button>
                    ))}
                    {group.count > 5 && <span className="text-muted text-[10px]">+{group.count - 5} more</span>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </InspectorSection>

        {entries.length > 5 && (
          <InspectorSection title="Properties" count={entries.length}>
            <div className="space-y-1">
              {entries.slice(5).map(entry => (
                <div key={entry.key} className="flex items-start gap-2 text-xs">
                  <span className="text-muted-foreground font-mono w-24 flex-shrink-0 truncate">{entry.key}</span>
                  <span className="text-foreground break-all">{String(entry.value)}</span>
                </div>
              ))}
            </div>
          </InspectorSection>
        )}
      </div>

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
          <button
            onClick={() => navigateToPanel('frontier', nodeId)}
            className="flex-1 text-xs py-1.5 rounded bg-elevated text-foreground hover:bg-hover transition-colors"
          >
            Frontier
          </button>
        </div>
        {editMode && <AddEdgeInline graph={graph} sourceId={nodeId} onUndoPush={onUndoPush} />}
      </div>
    </div>
  );
}

function InspectorSection({
  title,
  count,
  children,
  actionLabel,
  onAction,
}: {
  title: string;
  count?: number;
  children: React.ReactNode;
  actionLabel?: string;
  onAction?: () => void;
}) {
  return (
    <section className="border-t border-border pt-3 first:border-t-0 first:pt-0">
      <div className="flex items-center justify-between gap-2 mb-2">
        <h4 className="text-[10px] uppercase tracking-wider text-muted-foreground">
          {title}
          {count !== undefined && <span className="font-normal ml-1">({count})</span>}
        </h4>
        {onAction && actionLabel && (
          <button onClick={onAction} className="text-[10px] text-accent hover:text-foreground">
            {actionLabel}
          </button>
        )}
      </div>
      {children}
    </section>
  );
}

function RelationshipLink({
  label,
  count,
  hot,
  onClick,
}: {
  label: string;
  count: number;
  hot?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'rounded border border-border bg-background/40 px-2 py-1.5 text-left transition-colors hover:border-accent/40 hover:bg-hover',
        hot && 'border-accent/30 bg-accent/5',
      )}
    >
      <div className="text-[10px] text-muted-foreground">{label}</div>
      <div className={cn('text-sm font-semibold', hot ? 'text-accent' : 'text-foreground')}>{count}</div>
    </button>
  );
}

function EmptyLine({ children }: { children: React.ReactNode }) {
  return <div className="text-[11px] text-muted-foreground">{children}</div>;
}

function findingSeverityClass(severity: FindingDto['severity']): string {
  if (severity === 'critical') return 'bg-destructive/20 text-destructive';
  if (severity === 'high') return 'bg-destructive/10 text-destructive';
  if (severity === 'medium') return 'bg-warning/10 text-warning';
  if (severity === 'low') return 'bg-accent/10 text-accent';
  return 'bg-elevated text-muted-foreground';
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

  const edgeTypes = new Set<string>();
  graph.forEachEdge((_edge, attrs) => { edgeTypes.add((attrs.edgeType as string) || 'RELATED'); });
  const sortedTypes = [...edgeTypes].sort();

  const allNodeIds: string[] = [];
  graph.forEachNode((id) => { allNodeIds.push(id); });

  const handleAdd = useCallback(async () => {
    if (!targetId.trim()) return;
    setLoading(true);
    try {
      const pendingKey = `_pending_edge_${Date.now()}`;
      const op: GraphCorrectionOperation = {
        kind: 'patch_node',
        node_id: sourceId,
        patch: { [pendingKey]: `${edgeType}:${targetId.trim()}` },
      };
      await correctGraph(`[console] Add edge: ${sourceId} --[${edgeType}]--> ${targetId.trim()}`, [op]);
      toast({ type: 'success', title: 'Edge flagged', message: `${sourceId} -> ${targetId.trim()} (${edgeType})` });
      onUndoPush?.({
        reason: `Undo: add edge ${sourceId} -> ${targetId.trim()}`,
        reverse: [{ kind: 'patch_node', node_id: sourceId, patch: { [pendingKey]: undefined } }],
      });
      setOpen(false);
      setTargetId('');
    } catch (err) {
      toast({ type: 'error', title: 'Failed', message: String(err) });
    } finally {
      setLoading(false);
    }
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
        placeholder="Target node ID..."
        className="settings-input w-full text-xs"
        list="node-targets"
      />
      <datalist id="node-targets">
        {allNodeIds.slice(0, 100).map(id => <option key={id} value={id} />)}
      </datalist>
      <select value={edgeType} onChange={(e) => setEdgeType(e.target.value)} className="settings-input w-full text-xs">
        {sortedTypes.map(type => <option key={type} value={type}>{type}</option>)}
        <option value="RELATED">RELATED</option>
      </select>
      <div className="flex gap-2">
        <button onClick={handleAdd} disabled={loading} className="flex-1 text-xs py-1 rounded bg-accent/10 text-accent hover:bg-accent/20">
          {loading ? 'Adding...' : 'Add'}
        </button>
        <button onClick={() => setOpen(false)} className="flex-1 text-xs py-1 rounded bg-elevated text-muted-foreground hover:text-foreground">
          Cancel
        </button>
      </div>
    </div>
  );
}
