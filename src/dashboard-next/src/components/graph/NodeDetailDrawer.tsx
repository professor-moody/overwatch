// ============================================================
// NodeDetailDrawer - right-side operator inspector
// ============================================================

import { useEffect, useState } from 'react';
import type Graph from 'graphology';
import { NODE_COLORS, EDGE_CATEGORIES, DEFAULT_EDGE_COLOR } from '../../lib/graph-constants';
import { getNodeDisplayLabel, getNodeIdentityEntries, getFriendlyNodeTypeLabel } from '../../lib/node-display';
import { useNavigation } from '../../hooks/useNavigation';
import { dispatchAgent, evidenceImageUrl, getEvidenceChains, getFindings, getTrustSignals, type FindingDto, type GraphCorrectionOperation, type TrustSignalDto } from '../../lib/api';
import { useToastStore } from '../../stores/toast-store';
import { useEngagementStore } from '../../stores/engagement-store';
import { deriveNodeRelationships } from '../../lib/relationships';
import { ActionButton, StatusPill } from '../shared/primitives';
import type { EvidenceChainResponse } from '../../lib/types';
import { computeActionRisk } from '../../lib/action-queue';
import { formatFrontierScore, getFrontierPrimaryNodeId } from '../../lib/frontier-workspace';
import { cn, formatRelativeTime } from '../../lib/utils';
import { GraphNodeLinks } from '../shared/GraphNodeLinks';
import { trustSignalsForNode } from '../../lib/trust-signals';
import { TrustSignalList } from '../shared/TrustSignals';
import { findingSummary, findingTitle } from '../../lib/finding-display';
import { AuthenticatedImage } from '../shared/AuthenticatedImage';

interface NodeDetailDrawerProps {
  graph: Graph;
  nodeId: string | null;
  onClose: () => void;
  onFocus?: (nodeId: string, hops: number) => void;
  editMode?: boolean;
  onUndoPush?: (op: { reason: string; reverse: GraphCorrectionOperation[] }) => void;
}

type EvidenceStatus = 'idle' | 'loading' | 'ready' | 'empty' | 'error';

export function NodeDetailDrawer({ graph, nodeId, onClose, onFocus }: NodeDetailDrawerProps) {
  const { navigateToEvidence, navigateToGraph, navigateToPanel } = useNavigation();
  const storeGraph = useEngagementStore(s => s.graph);
  const sessions = useEngagementStore(s => s.sessions);
  const pendingActions = useEngagementStore(s => s.pendingActions);
  const frontier = useEngagementStore(s => s.frontier);
  const [findings, setFindings] = useState<FindingDto[]>([]);
  const [trustSignals, setTrustSignals] = useState<TrustSignalDto[]>([]);
  const [evidence, setEvidence] = useState<EvidenceChainResponse | null>(null);
  const [evidenceStatus, setEvidenceStatus] = useState<EvidenceStatus>('idle');
  const [deploying, setDeploying] = useState(false);
  const addToast = useToastStore(s => s.addToast);

  useEffect(() => {
    let cancelled = false;
    getFindings()
      .then(data => { if (!cancelled) setFindings(data.findings || []); })
      .catch(() => { if (!cancelled) setFindings([]); });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!nodeId) {
      setTrustSignals([]);
      return;
    }
    let cancelled = false;
    getTrustSignals({ node_id: nodeId, limit: 25 })
      .then(data => { if (!cancelled) setTrustSignals(data.signals || []); })
      .catch(() => { if (!cancelled) setTrustSignals([]); });
    return () => { cancelled = true; };
  }, [nodeId]);

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
  const nodeTrustSignals = trustSignalsForNode(trustSignals, nodeId, relationships.findings.map(finding => finding.id));

  // Deploy an agent to explore THIS node — works on any node, not just frontier
  // items. Archetype is auto-selected from the node type server-side; the deployed
  // agent grounds in prior actions on this node (get_agent_context) before acting.
  const deployHere = async () => {
    if (deploying) return;
    setDeploying(true);
    try {
      const res = await dispatchAgent({ target_node_ids: [nodeId] });
      if (res.dispatched) {
        addToast({ type: 'success', title: 'Agent deployed', message: `exploring ${label}` });
      } else if (res.existing_agent_id) {
        addToast({ type: 'warning', title: 'Already being worked', message: `by ${res.existing_agent_id}` });
      } else if (res.reason === 'dispatch_cap_exceeded') {
        addToast({ type: 'warning', title: 'Dispatch cap reached', message: 'too many agents running — retry when one frees up' });
      } else {
        addToast({ type: 'error', title: 'Not deployed', message: res.reason || 'dispatch refused' });
      }
    } catch (err) {
      addToast({ type: 'error', title: 'Deploy failed', message: err instanceof Error ? err.message : String(err) });
    } finally {
      setDeploying(false);
    }
  };

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
    // Collect ALL peers (not just the first 5) so a high-degree node — e.g. a domain
    // with 30+ SUBDOMAIN_OF edges — is fully legible here instead of only in raw tool
    // output. The EdgeGroup renderer collapses to 5 with an expand + filter.
    group.peers.push({ id: peerId, label: peerLabel, type: peerType });
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
    <div className="fixed right-0 top-12 bottom-0 w-[min(24rem,calc(100vw-3rem))] bg-surface border-l border-border z-40 flex flex-col shadow-2xl">
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
        <div className="text-[10px] text-muted-foreground font-mono break-all mt-0.5">{nodeId}</div>
        <div className="mt-2 grid grid-cols-4 gap-1.5">
          {selectedFacts.map(fact => (
            <div key={fact.label} className="rounded border border-border bg-elevated/60 px-2 py-1">
              <div className="text-[9px] uppercase text-muted-foreground">{fact.label}</div>
              <div className="text-xs font-mono text-foreground">{fact.value}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4 overscroll-contain">
        <InspectorSection title="Summary">
          <div className="space-y-1.5 text-xs">
            {entries.slice(0, 5).map((entry, index) => (
              <div key={`${entry.key}-${index}`} className="flex items-start gap-2">
                <span className="text-muted-foreground font-mono w-24 flex-shrink-0 truncate">{entry.key}</span>
                <span className="text-foreground break-all">{String(entry.value)}</span>
              </div>
            ))}
            {entries.length === 0 && <EmptyLine>No display properties on this node.</EmptyLine>}
          </div>
        </InspectorSection>

        {nodeType === 'webapp' && typeof props.screenshot_evidence_id === 'string' && props.screenshot_evidence_id && (
          <InspectorSection title="Screenshot">
            <AuthenticatedImage
              src={evidenceImageUrl(props.screenshot_evidence_id)}
              alt={`Screenshot of ${String(props.url ?? nodeId)}`}
              loading="lazy"
              linkToFullSize
              className="w-full max-h-96 object-contain rounded border border-border bg-black/20"
            />
          </InspectorSection>
        )}

        <InspectorSection title="Relationships">
          <div className="grid grid-cols-2 gap-2 text-xs">
            <RelationshipLink label="Sessions" count={relationships.sessions.length} hot={liveSessions > 0} onClick={() => navigateToPanel('sessions')} />
            <RelationshipLink label="Actions" count={relationships.pendingActions.length} hot={relationships.pendingActions.length > 0} onClick={() => navigateToPanel('actions')} />
            <RelationshipLink label="Frontier" count={relationships.frontier.length} hot={relationships.frontier.length > 0} onClick={() => navigateToPanel('frontier', nodeId)} />
            <RelationshipLink label="Findings" count={relationships.findings.length} hot={relationships.findings.length > 0} onClick={() => navigateToPanel('findings')} />
          </div>
        </InspectorSection>

        <InspectorSection title="Trust Signals" count={nodeTrustSignals.length}>
          {nodeTrustSignals.length === 0 ? (
            <EmptyLine>No parser, path, IAM, or scoring caveats reference this node.</EmptyLine>
          ) : (
            <TrustSignalList signals={nodeTrustSignals.slice(0, 5)} />
          )}
        </InspectorSection>

        <InspectorSection title="Sessions" count={relationships.sessions.length} actionLabel="Open" onAction={() => navigateToPanel('sessions')}>
          {relationships.sessions.length === 0 ? (
            <EmptyLine>No sessions tied to this node.</EmptyLine>
          ) : (
            <div className="space-y-1.5">
              {relationships.sessions.slice(0, 4).map((session, index) => (
                <button key={`${session.id}-${index}`} onClick={() => navigateToPanel('sessions', session.id)} className="w-full text-left rounded border border-border bg-background/40 px-2 py-1.5 text-xs hover:border-accent/40 hover:bg-hover/30 transition-colors">
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
                </button>
              ))}
            </div>
          )}
        </InspectorSection>

        <InspectorSection title="Pending Actions" count={relationships.pendingActions.length} actionLabel="Open" onAction={() => navigateToPanel('actions')}>
          {relationships.pendingActions.length === 0 ? (
            <EmptyLine>No queued approvals target this node.</EmptyLine>
          ) : (
            <div className="space-y-1.5">
              {relationships.pendingActions.slice(0, 4).map((action, index) => {
                const risk = computeActionRisk(action);
                return (
                  <div key={`${action.action_id}-${index}`} className="rounded border border-border bg-background/40 px-2 py-1.5 text-xs">
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
              {relationships.frontier.slice(0, 4).map((item, index) => {
                const primaryNode = getFrontierPrimaryNodeId(item);
                return (
                  <div key={`${item.id}-${index}`} className="rounded border border-border bg-background/40 px-2 py-1.5 text-xs">
                    <div className="flex items-center gap-2">
                      <StatusPill className="bg-accent/10 text-accent">{item.type.replace(/_/g, ' ')}</StatusPill>
                      <span className="font-mono text-foreground ml-auto">{formatFrontierScore(item)}</span>
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
              {evidence.chains.slice(0, 3).map((entry, index) => (
                <div key={`${entry.activity_id}-${index}`} className="rounded border border-border bg-background/40 px-2 py-1.5 text-xs">
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
              {relationships.findings.slice(0, 4).map((finding, index) => (
                <button key={`${finding.id}-${index}`} onClick={() => navigateToPanel('findings', finding.id)} className="w-full text-left rounded border border-border bg-background/40 px-2 py-1.5 text-xs hover:border-accent/40 hover:bg-hover/30 transition-colors">
                  <div className="flex items-center gap-2">
                    <StatusPill className={findingSeverityClass(finding.severity)}>{finding.severity}</StatusPill>
                    <span className="truncate text-foreground">{findingTitle(finding)}</span>
                  </div>
                  <div className="mt-1 text-[11px] text-muted-foreground line-clamp-2">{findingSummary(finding)}</div>
                </button>
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
                <EdgeGroup key={edgeType} edgeType={edgeType} group={group} onPeer={(id) => navigateToGraph(id, 2)} />
              ))}
            </div>
          )}
        </InspectorSection>

        {entries.length > 5 && (
          <InspectorSection title="Properties" count={entries.length}>
            <div className="space-y-1">
              {entries.slice(5).map((entry, index) => (
                <div key={`${entry.key}-${index + 5}`} className="flex items-start gap-2 text-xs">
                  <span className="text-muted-foreground font-mono w-24 flex-shrink-0 truncate">{entry.key}</span>
                  <span className="text-foreground break-all">{String(entry.value)}</span>
                </div>
              ))}
            </div>
          </InspectorSection>
        )}
      </div>

      <div className="flex-shrink-0 px-4 py-2 border-t border-border bg-surface/95 flex flex-col gap-2">
        <ActionButton
          onClick={deployHere}
          variant="primary"
          disabled={deploying}
          className="w-full"
        >
          {deploying ? 'Deploying…' : 'Deploy agent here'}
        </ActionButton>
        <div className="flex gap-2">
          <ActionButton
            onClick={() => onFocus?.(nodeId, 2)}
            variant="ghost"
            className="flex-1 text-accent"
          >
            Focus
          </ActionButton>
          <ActionButton
            onClick={() => navigateToEvidence(nodeId)}
            variant="secondary"
            className="flex-1"
          >
            Evidence
          </ActionButton>
          <ActionButton
            onClick={() => navigateToPanel('frontier', nodeId)}
            variant="secondary"
            className="flex-1"
          >
            Frontier
          </ActionButton>
        </div>
      </div>
    </div>
  );
}

/** One edge-type group in the inspector. Collapsed shows the first few peers; a
 *  high-degree group (e.g. a domain's 30+ subdomains) expands to show every peer,
 *  with a filter box once the list is long — so all neighbours are legible here. */
function EdgeGroup({ edgeType, group, onPeer }: {
  edgeType: string;
  group: { count: number; peers: { id: string; label: string; type: string }[] };
  onPeer: (id: string) => void;
}) {
  const COLLAPSED = 5;
  const RENDER_CAP = 200; // bound the DOM even for a node with thousands of edges
  const [expanded, setExpanded] = useState(false);
  const [filter, setFilter] = useState('');
  const q = filter.trim().toLowerCase();
  const matched = q
    ? group.peers.filter(p => p.label.toLowerCase().includes(q) || p.id.toLowerCase().includes(q))
    : group.peers;
  const visible = expanded ? matched.slice(0, RENDER_CAP) : matched.slice(0, COLLAPSED);
  const hidden = matched.length - visible.length;

  return (
    <div className="text-xs">
      <div className="flex items-center gap-1.5 mb-0.5">
        <span className="w-2 h-0.5 rounded-full inline-block" style={{ backgroundColor: EDGE_CATEGORIES[edgeType] || DEFAULT_EDGE_COLOR }} />
        <span className="font-mono text-muted-foreground">{edgeType}</span>
        <span className="text-muted ml-auto">x{group.count}</span>
      </div>
      {expanded && group.peers.length > 12 && (
        <input
          value={filter}
          onChange={e => setFilter(e.target.value)}
          placeholder={`Filter ${group.count}…`}
          className="mb-1 ml-3.5 w-[calc(100%-0.875rem)] rounded border border-border bg-surface px-1.5 py-0.5 text-[11px] outline-none focus:border-accent"
        />
      )}
      <div className="pl-3.5 space-y-0.5">
        {visible.map((peer, index) => (
          <button key={`${peer.id}-${index}`} onClick={() => onPeer(peer.id)} className="w-full flex items-center gap-1.5 text-[11px] hover:text-accent">
            <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: NODE_COLORS[peer.type] || '#888' }} />
            <span className="truncate text-foreground">{peer.label}</span>
          </button>
        ))}
        {matched.length === 0 && <span className="text-muted text-[10px]">No matches.</span>}
        {!expanded && hidden > 0 && (
          <button onClick={() => setExpanded(true)} className="text-[10px] text-accent hover:text-foreground">+ show all {matched.length}</button>
        )}
        {expanded && hidden > 0 && (
          <span className="text-muted text-[10px]">showing {visible.length} of {matched.length} — filter to narrow</span>
        )}
        {expanded && group.peers.length > COLLAPSED && (
          <button onClick={() => { setExpanded(false); setFilter(''); }} className="text-[10px] text-accent hover:text-foreground">show less</button>
        )}
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
