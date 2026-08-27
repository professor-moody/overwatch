import { lazy, Suspense, useEffect, useMemo, useState } from 'react';
import { Network, Search } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router';
import { useEngagementStore } from '../../stores/engagement-store';
import { useDashboardUiStore } from '../../stores/dashboard-ui-store';
import { NODE_COLORS } from '../../lib/graph-constants';
import { cn } from '../../lib/utils';
import { deriveNodeRelationships } from '../../lib/relationships';
import type { EvidenceChainResponse } from '../../lib/types';
import type { FindingDto } from '../../lib/api';
import * as api from '../../lib/api';
import { buildWorkspacePath, INVESTIGATE_LENSES, type InvestigateLens, setSelectionParams } from '../../lib/workspace-navigation';
import { useWorkspaceInspectorAdapters, type WorkspaceInspectorAdapter } from '../layout/WorkspaceInspectorRegistry';
import {
  ActionButton,
  StatusPill,
  WorkspaceEmpty,
  WorkspaceHeader,
  WorkspaceInspector,
  WorkspaceRow,
  WorkspaceTabs,
} from '../shared/primitives';
import { CredentialInspector, CredentialsLens, IdentityLens, NativePathInspector, PathsLens } from './NativeInvestigateLenses';

const GraphPage = lazy(() => import('../graph/GraphPage').then(module => ({ default: module.GraphPage })));
const ENTITY_INSPECTOR_TABS = ['summary', 'relationships', 'proof', 'activity', 'findings', 'actions'] as const;
const CREDENTIAL_INSPECTOR_TABS = ['summary', 'relationships', 'activity', 'actions'] as const;

function isLens(value: string | null): value is InvestigateLens {
  return !!value && (INVESTIGATE_LENSES as readonly string[]).includes(value);
}

function LensLoading() {
  return <div className="flex min-h-56 items-center justify-center text-xs text-muted-foreground"><span className="workspace-pulse">Loading investigation…</span></div>;
}

export function InvestigateWorkspace() {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialized = useEngagementStore(state => state.initialized);
  const graph = useEngagementStore(state => state.graph);
  const requested = searchParams.get('lens');
  const lens: InvestigateLens = isLens(requested) ? requested : 'topology';
  const selectedEntity = searchParams.get('kind') || searchParams.get('entity');
  const selectedId = searchParams.get('item');
  const selectedPathNodes = searchParams.get('nodes') || '';
  const selectedPathEdges = searchParams.get('edges') || '';
  const selectedNode = selectedId && (selectedEntity === 'node' || selectedEntity === 'credential')
    ? graph.nodes.find(node => node.id === selectedId) ?? null
    : null;
  const selectedPath = useMemo(() => selectedId && selectedEntity === 'path'
    ? {
        id: selectedId,
        nodeIds: selectedPathNodes.split(',').filter(Boolean),
        edgeIds: selectedPathEdges.split(',').filter(Boolean),
      }
    : null,
  [selectedEntity, selectedId, selectedPathEdges, selectedPathNodes]);

  const setLens = (nextLens: InvestigateLens) => {
    const next = new URLSearchParams(searchParams);
    next.set('lens', nextLens);
    setSearchParams(next);
  };

  const tabs: Array<{ value: InvestigateLens; label: string; count?: number }> = [
    { value: 'topology', label: 'Topology', count: graph.nodes.length },
    { value: 'assets', label: 'Assets' },
    { value: 'identity', label: 'Identity' },
    { value: 'credentials', label: 'Credentials', count: graph.nodes.filter(node => node.type === 'credential').length },
    { value: 'paths', label: 'Paths' },
  ];

  const entityAdapter = useMemo<WorkspaceInspectorAdapter>(() => ({
    resolved: initialized,
    available: Boolean(selectedNode && selectedNode.type !== 'credential'),
    tabs: ENTITY_INSPECTOR_TABS.map(value => ({ value, label: value[0].toUpperCase() + value.slice(1) })),
    defaultTab: 'summary',
    render: ({ tab, setTab, close }) => selectedNode && selectedNode.type !== 'credential'
      ? <EntityInspector node={selectedNode} tab={tab || 'summary'} onTabChange={setTab} onClose={close} />
      : null,
  }), [initialized, selectedNode]);
  const credentialAdapter = useMemo<WorkspaceInspectorAdapter>(() => ({
    resolved: initialized,
    available: Boolean(selectedNode?.type === 'credential'),
    tabs: CREDENTIAL_INSPECTOR_TABS.map(value => ({ value, label: value[0].toUpperCase() + value.slice(1) })),
    defaultTab: 'summary',
    render: ({ tab, setTab, close }) => selectedNode?.type === 'credential'
      ? <CredentialInspector credential={selectedNode} tab={tab || 'summary'} onTabChange={setTab} onClose={close} />
      : null,
  }), [initialized, selectedNode]);
  const pathAdapter = useMemo<WorkspaceInspectorAdapter>(() => ({
    resolved: initialized,
    available: Boolean(selectedPath),
    render: ({ close }) => selectedPath ? <NativePathInspector path={selectedPath} onClose={close} /> : null,
  }), [initialized, selectedPath]);
  const investigateInspectorAdapters = useMemo(() => lens === 'topology'
    ? { path: pathAdapter }
    : { node: entityAdapter, credential: credentialAdapter, path: pathAdapter },
  [credentialAdapter, entityAdapter, lens, pathAdapter]);
  useWorkspaceInspectorAdapters(investigateInspectorAdapters);

  return (
    <div className="flex min-h-0 min-w-0 w-full flex-1 flex-col overflow-hidden bg-background">
      <WorkspaceHeader
        eyebrow="Environment"
        title="Investigate"
        description="Trace assets, identity, credentials, and attack paths without losing graph context."
      >
        <WorkspaceTabs value={lens} options={tabs} onChange={setLens} ariaLabel="Investigate lenses" />
      </WorkspaceHeader>

      <div className="relative flex min-h-0 flex-1">
        <section className="min-w-0 flex-1 overflow-hidden">
          <Suspense fallback={<LensLoading />}>
            {lens === 'topology' && <GraphPage embedded />}
            <AssetsLens active={lens === 'assets'} />
            <IdentityLens active={lens === 'identity'} />
            <CredentialsLens active={lens === 'credentials'} />
            <PathsLens active={lens === 'paths'} />
          </Suspense>
        </section>
      </div>
    </div>
  );
}

function AssetsLens({ active = true }: { active?: boolean }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const graph = useEngagementStore(state => state.graph);
  const [query, setQuery] = useState('');
  const [type, setType] = useState('');
  const [sort, setSort] = useState<'label' | 'type' | 'confidence' | 'findings'>('label');
  const selected = searchParams.get('item');
  const types = useMemo(() => [...new Set(graph.nodes.map(node => node.type))].sort(), [graph.nodes]);
  const nodes = useMemo(() => {
    const q = query.trim().toLowerCase();
    return graph.nodes.filter(node => {
      if (type && node.type !== type) return false;
      if (!q) return true;
      return `${node.label || ''} ${node.id} ${node.type}`.toLowerCase().includes(q);
    }).map(node => {
      const edges = graph.edges.filter(edge => edge.source === node.id || edge.target === node.id);
      const findingCount = edges.filter(edge => edge.type === 'VULNERABLE_TO' || edge.type === 'EXPLOITS').length + (node.finding_id ? 1 : 0);
      const reachable = edges.some(edge => ['HAS_SESSION', 'ADMIN_TO', 'VALID_ON', 'CAN_REACH', 'POLICY_ALLOWS'].includes(edge.type));
      return { node, findingCount, reachable };
    }).sort((left, right) => {
      if (sort === 'findings') return right.findingCount - left.findingCount || String(left.node.label || left.node.id).localeCompare(String(right.node.label || right.node.id));
      if (sort === 'confidence') return (right.node.confidence || 0) - (left.node.confidence || 0);
      if (sort === 'type') return left.node.type.localeCompare(right.node.type) || String(left.node.label || left.node.id).localeCompare(String(right.node.label || right.node.id));
      return String(left.node.label || left.node.id).localeCompare(String(right.node.label || right.node.id));
    });
  }, [graph.edges, graph.nodes, query, sort, type]);

  return (
    <div className={cn('h-full min-h-0 flex-col', active ? 'flex' : 'hidden')}>
      <div className="flex h-12 flex-shrink-0 items-center gap-2 border-b border-border-subtle px-4">
        <div className="relative min-w-0 flex-1 max-w-lg">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
          <input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search assets by label, ID, or type" className="h-8 w-full rounded-md border border-border bg-surface pl-8 pr-3 text-xs outline-none focus:border-accent" />
        </div>
        <select value={type} onChange={event => setType(event.target.value)} className="settings-input h-8 min-w-36">
          <option value="">All types</option>
          {types.map(value => <option key={value} value={value}>{value.replaceAll('_', ' ')}</option>)}
        </select>
        <select aria-label="Sort assets" value={sort} onChange={event => setSort(event.target.value as typeof sort)} className="settings-input h-8 min-w-32"><option value="label">Sort: label</option><option value="type">Sort: type</option><option value="confidence">Sort: confidence</option><option value="findings">Sort: findings</option></select>
        <span className="text-[10px] tabular-nums text-muted-foreground">{nodes.length} assets</span>
      </div>
      <div className="grid h-8 grid-cols-[minmax(14rem,1fr)_7rem_6rem_6rem_5rem] items-center gap-3 border-b border-border-subtle px-3 text-[9px] font-medium uppercase tracking-[0.12em] text-muted-foreground"><span>Asset</span><span>Type</span><span>Trust</span><span>Access</span><span className="text-right">Findings</span></div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {nodes.length === 0 ? <WorkspaceEmpty title="No matching assets" detail="Adjust the search or type filter." /> : nodes.map(({ node, findingCount, reachable }) => (
          <WorkspaceRow
            key={node.id}
            selected={selected === node.id}
            onClick={() => setSearchParams(setSelectionParams(searchParams, { kind: node.type === 'credential' ? 'credential' : 'node', id: node.id }))}
          >
            <span className="h-2.5 w-2.5 flex-shrink-0 rounded-sm" style={{ backgroundColor: NODE_COLORS[node.type] || '#8a889a' }} />
            <div className="min-w-0 flex-1">
              <div className="truncate text-xs font-medium text-foreground">{node.label || node.id}</div>
              <div className="mt-0.5 truncate font-mono text-[9px] text-muted-foreground">{node.id}</div>
            </div>
            <span className="w-28 truncate text-[10px] text-muted-foreground">{node.type.replaceAll('_', ' ')}</span>
            <span className="w-24 truncate text-[10px] text-muted-foreground">{String(node.source_trust || (node.inferred ? 'inferred' : 'asserted'))}</span>
            <span className="w-24 text-[10px] text-muted-foreground">{reachable ? 'reachable' : 'unreached'}</span>
            <span className="w-16 text-right font-mono text-[10px] text-foreground">{findingCount}</span>
          </WorkspaceRow>
        ))}
      </div>
    </div>
  );
}

function EntityInspector({ node, tab, onTabChange, onClose }: { node: ReturnType<typeof useEngagementStore.getState>['graph']['nodes'][number]; tab: string; onTabChange: (tab: string) => void; onClose: () => void }) {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const setLauncherOpen = useDashboardUiStore(state => state.setStartWorkOpen);
  const graph = useEngagementStore(state => state.graph);
  const sessions = useEngagementStore(state => state.sessions);
  const pendingActions = useEngagementStore(state => state.pendingActions);
  const frontier = useEngagementStore(state => state.frontier);
  const [findings, setFindings] = useState<FindingDto[]>([]);
  const [evidence, setEvidence] = useState<EvidenceChainResponse | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const properties = Object.entries(node).filter(([key, value]) => !['id', 'label', 'type', 'confidence', 'properties'].includes(key) && value !== undefined && value !== null && typeof value !== 'object').slice(0, 12);
  const relationships = useMemo(() => deriveNodeRelationships(node.id, { graph, sessions, pendingActions, frontier, findings }), [findings, frontier, graph, node.id, pendingActions, sessions]);
  const graphRelations = useMemo(() => graph.edges.filter(edge => edge.source === node.id || edge.target === node.id).map(edge => ({ edge, peer: graph.nodes.find(candidate => candidate.id === (edge.source === node.id ? edge.target : edge.source)) })), [graph.edges, graph.nodes, node.id]);

  useEffect(() => {
    let cancelled = false;
    setLoadError(null);
    Promise.all([api.getFindings(), api.getEvidenceChains(node.id)])
      .then(([findingData, evidenceData]) => {
        if (cancelled) return;
        setFindings(findingData.findings || []);
        setEvidence(evidenceData);
      })
      .catch(cause => { if (!cancelled) setLoadError(cause instanceof Error ? cause.message : 'Context could not be loaded.'); });
    return () => { cancelled = true; };
  }, [node.id]);

  return (
    <WorkspaceInspector
      label="Asset inspector"
      title={String(node.label || node.id)}
      identifier={node.id}
      tabs={ENTITY_INSPECTOR_TABS.map(value => ({ value, label: value[0].toUpperCase() + value.slice(1) }))}
      activeTab={tab}
      onTabChange={onTabChange}
      onClose={onClose}
    >
      {loadError && <div role="alert" className="mb-3 border-l-2 border-warning pl-2 text-[9px] text-warning">Last-good graph context remains visible. {loadError}</div>}
      {tab === 'summary' && <>
          <div className="flex items-start gap-3">
            <span className="mt-1 h-3 w-3 flex-shrink-0 rounded-sm" style={{ backgroundColor: NODE_COLORS[node.type] || '#8a889a' }} />
            <div className="min-w-0"><h2 className="break-words text-sm font-semibold text-foreground">{node.label || node.id}</h2></div>
          </div>
          <div className="mt-4 flex flex-wrap gap-1.5"><StatusPill tone="accent">{node.type.replaceAll('_', ' ')}</StatusPill><StatusPill tone="muted">{Math.round((node.confidence || 0) * 100)}% confidence</StatusPill></div>
          <div className="mt-5 flex flex-wrap gap-1.5">
            <ActionButton variant="primary" onClick={() => navigate(buildWorkspacePath({ workspace: 'investigate', lens: 'topology', selection: { kind: 'node', id: node.id }, context: { node: node.id } }))}><Network className="h-3 w-3" /> Show in topology</ActionButton>
            <ActionButton onClick={() => {
              setLauncherOpen(true);
              navigate(buildWorkspacePath({ workspace: 'operate', view: 'active', selection: { kind: 'node', id: node.id } }));
            }}>Start work</ActionButton>
          </div>
          {properties.length > 0 && <div className="mt-5 border-t border-border-subtle pt-3"><div className="mb-2 text-[10px] uppercase tracking-[0.14em] text-muted-foreground">Metadata</div><div className="space-y-2">{properties.map(([key, value]) => <div key={key} className="grid grid-cols-[7rem_1fr] gap-2 text-[10px]"><span className="text-muted-foreground">{key.replaceAll('_', ' ')}</span><span className="break-all text-foreground">{String(value)}</span></div>)}</div></div>}
      </>}
      {tab === 'relationships' && <div className="space-y-1">{graphRelations.length ? graphRelations.map(({ edge, peer }) => <button key={edge.id} type="button" onClick={() => peer && navigate(buildWorkspacePath({ workspace: 'investigate', lens: 'topology', selection: { kind: 'node', id: peer.id }, context: { node: peer.id } }))} className="flex w-full items-start gap-2 border-b border-border-subtle py-2 text-left"><StatusPill tone={edge.inferred ? 'warning' : 'muted'}>{edge.type.replaceAll('_', ' ')}</StatusPill><span className="min-w-0 flex-1 truncate text-[10px] text-foreground">{peer?.label || peer?.id || 'Missing graph peer'}</span><span className="font-mono text-[8px] text-muted-foreground">{Math.round((edge.confidence || 0) * 100)}%</span></button>) : <WorkspaceEmpty title="No recorded relationships" detail="Graph edges for this entity will appear here." />}</div>}
      {tab === 'proof' && <div className="space-y-2">{evidence?.chains.length ? evidence.chains.map((entry, index) => <div key={`${entry.activity_id}:${index}`} className="border-l border-border-subtle pl-2"><div className="text-[10px] text-foreground">{entry.description || entry.event_type}</div><div className="mt-0.5 font-mono text-[8px] text-muted-foreground">{entry.evidence_id || entry.activity_id} · {entry.source_trust || 'unknown trust'}</div><div className="mt-1 line-clamp-3 font-mono text-[9px] text-muted-foreground">{entry.snippet || 'No excerpt loaded.'}</div>{entry.action_id && <button type="button" onClick={() => navigate(buildWorkspacePath({ workspace: 'investigate', lens: isLens(searchParams.get('lens')) ? searchParams.get('lens') as InvestigateLens : 'assets', selection: { kind: 'node', id: node.id }, tab: 'proof', drawer: { kind: 'run', item: entry.action_id } }))} className="mt-1 text-[9px] text-accent hover:underline">Open producing run</button>}</div>) : <WorkspaceEmpty title="No proof chain" detail="Captured evidence connected to this entity will appear here." />}</div>}
      {tab === 'activity' && <div className="space-y-1">{evidence?.chains.length ? evidence.chains.map((entry, index) => <div key={`${entry.activity_id}:activity:${index}`} className="border-b border-border-subtle py-2"><div className="text-[10px] text-foreground">{(entry.event_type || 'activity').replaceAll('_', ' ')}</div><div className="mt-0.5 text-[9px] text-muted-foreground">{entry.description || entry.snippet}</div><div className="mt-1 font-mono text-[8px] text-muted-foreground">{entry.timestamp}</div></div>) : <WorkspaceEmpty title="No linked activity" detail="Action and evidence activity for this entity will appear here." />}</div>}
      {tab === 'findings' && <div className="space-y-1">{relationships.findings.length ? relationships.findings.map(finding => <button key={finding.id} type="button" onClick={() => navigate(buildWorkspacePath({ workspace: 'review', view: 'readiness', selection: { kind: 'finding', id: finding.id } }))} className="block w-full border-b border-border-subtle py-2 text-left"><div className="flex items-center gap-2"><StatusPill tone={finding.severity === 'critical' || finding.severity === 'high' ? 'danger' : 'warning'}>{finding.severity}</StatusPill><span className="min-w-0 flex-1 truncate text-[10px] text-foreground">{finding.title || finding.id}</span></div><div className="mt-1 font-mono text-[8px] text-muted-foreground">{finding.id}</div></button>) : <WorkspaceEmpty title="No linked findings" detail="Findings that affect this entity will appear here." />}</div>}
      {tab === 'actions' && <div className="space-y-3"><div className="flex flex-wrap gap-2"><ActionButton variant="primary" onClick={() => { setLauncherOpen(true); navigate(buildWorkspacePath({ workspace: 'operate', view: 'active', selection: { kind: 'node', id: node.id } })); }}>Start work</ActionButton><ActionButton onClick={() => navigate(buildWorkspacePath({ workspace: 'operate', view: 'ready', selection: { kind: 'frontier', id: node.id } }))}>Open Frontier</ActionButton></div>{relationships.pendingActions.length ? relationships.pendingActions.map(action => <button key={action.action_id} type="button" onClick={() => navigate(buildWorkspacePath({ workspace: 'operate', view: 'attention', selection: { kind: 'approval', id: action.action_id } }))} className="block w-full border-b border-border-subtle py-2 text-left"><div className="text-[10px] text-foreground">{action.technique}</div><div className="mt-0.5 line-clamp-2 text-[9px] text-muted-foreground">{action.description}</div></button>) : <WorkspaceEmpty title="No pending actions" detail="There are no approval-gated actions tied to this entity." />}</div>}
    </WorkspaceInspector>
  );
}
