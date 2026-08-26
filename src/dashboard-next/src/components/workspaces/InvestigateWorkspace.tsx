import { lazy, Suspense, useEffect, useMemo, useState } from 'react';
import { Network, Search } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router';
import { useEngagementStore } from '../../stores/engagement-store';
import { useDashboardUiStore } from '../../stores/dashboard-ui-store';
import { NODE_COLORS } from '../../lib/graph-constants';
import { INVESTIGATE_LENSES, type InvestigateLens, setSelectionParams } from '../../lib/workspace-navigation';
import {
  ActionButton,
  StatusPill,
  WorkspaceEmpty,
  WorkspaceHeader,
  WorkspaceInspector,
  WorkspaceRow,
  WorkspaceTabs,
} from '../shared/primitives';

const GraphPage = lazy(() => import('../graph/GraphPage').then(module => ({ default: module.GraphPage })));
const IdentityPanel = lazy(() => import('../panels/IdentityPanel').then(module => ({ default: module.IdentityPanel })));
const CredentialsPanel = lazy(() => import('../panels/CredentialsPanel').then(module => ({ default: module.CredentialsPanel })));
const AttackPathsPanel = lazy(() => import('../panels/AttackPathsPanel').then(module => ({ default: module.AttackPathsPanel })));

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
  const selectedNode = selectedId && (selectedEntity === 'node' || selectedEntity === 'credential')
    ? graph.nodes.find(node => node.id === selectedId) ?? null
    : null;
  const selectedPath = selectedId && selectedEntity === 'path'
    ? {
        id: selectedId,
        nodeIds: (searchParams.get('nodes') || '').split(',').filter(Boolean),
        edgeIds: (searchParams.get('edges') || '').split(',').filter(Boolean),
      }
    : null;

  useEffect(() => {
    if (!initialized || !selectedId || (selectedEntity !== 'node' && selectedEntity !== 'credential') || selectedNode) return;
    setSearchParams(setSelectionParams(searchParams, null), { replace: true });
  }, [initialized, searchParams, selectedEntity, selectedId, selectedNode, setSearchParams]);

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

  return (
    <div className="flex min-h-0 flex-1 flex-col bg-background">
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
            {lens === 'assets' && <AssetsLens />}
            {lens === 'identity' && <div className="h-full overflow-y-auto p-4 lg:p-5"><IdentityPanel embedded /></div>}
            {lens === 'credentials' && <div className="h-full overflow-y-auto p-4 lg:p-5"><CredentialsPanel embedded /></div>}
            {lens === 'paths' && <div className="h-full overflow-y-auto p-4 lg:p-5"><AttackPathsPanel embedded /></div>}
          </Suspense>
        </section>
        {lens !== 'topology' && selectedNode && (
          <EntityInspector node={selectedNode} onClose={() => setSearchParams(setSelectionParams(searchParams, null), { replace: true })} />
        )}
        {selectedPath && (
          <PathInspector path={selectedPath} onClose={() => setSearchParams(setSelectionParams(searchParams, null), { replace: true })} />
        )}
      </div>
    </div>
  );
}

function AssetsLens() {
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
    <div className="flex h-full min-h-0 flex-col">
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

function PathInspector({ path, onClose }: { path: { id: string; nodeIds: string[]; edgeIds: string[] }; onClose: () => void }) {
  const navigate = useNavigate();
  const graph = useEngagementStore(state => state.graph);
  const labels = path.nodeIds.map(id => graph.nodes.find(node => node.id === id)?.label || id);
  const edges = path.edgeIds.map(id => graph.edges.find(edge => edge.id === id)).filter(Boolean);
  const confidence = edges.length > 0 ? edges.reduce((product, edge) => product * (edge?.confidence ?? 1), 1) : null;
  const assumptions = edges.filter(edge => edge?.inferred || edge?.source_trust === 'inferred').length;
  return <WorkspaceInspector label="Path inspector" title={labels[labels.length - 1] || 'Attack path'} identifier={path.id} onClose={onClose}>
    <div className="space-y-4">
      <div><div className="text-[10px] uppercase tracking-[0.14em] text-muted-foreground">Route</div><div className="mt-2 space-y-1.5">{labels.map((label, index) => <div key={`${path.nodeIds[index]}-${index}`} className="flex items-center gap-2 text-[11px]"><span className="w-5 text-right font-mono text-[9px] text-muted">{index + 1}</span><span className="truncate text-foreground">{label}</span></div>)}</div></div>
      <div className="grid grid-cols-[7rem_1fr] gap-y-2 border-t border-border-subtle pt-3 text-[11px]"><span className="text-muted-foreground">Hops</span><span>{Math.max(0, path.nodeIds.length - 1)}</span><span className="text-muted-foreground">Confidence</span><span>{confidence === null ? 'Unavailable' : `${Math.round(confidence * 100)}%`}</span><span className="text-muted-foreground">Assumptions</span><span>{assumptions}</span></div>
      <ActionButton variant="primary" onClick={() => navigate(`/investigate?lens=topology&kind=path&item=${encodeURIComponent(path.id)}&nodes=${encodeURIComponent(path.nodeIds.join(','))}&edges=${encodeURIComponent(path.edgeIds.join(','))}`)}>Show in topology</ActionButton>
    </div>
  </WorkspaceInspector>;
}

function EntityInspector({ node, onClose }: { node: ReturnType<typeof useEngagementStore.getState>['graph']['nodes'][number]; onClose: () => void }) {
  const navigate = useNavigate();
  const setLauncherOpen = useDashboardUiStore(state => state.setStartWorkOpen);
  const properties = Object.entries(node).filter(([key, value]) => !['id', 'label', 'type', 'confidence', 'properties'].includes(key) && value !== undefined && value !== null && typeof value !== 'object').slice(0, 12);
  return (
    <WorkspaceInspector label="Asset inspector" title={String(node.label || node.id)} identifier={node.id} onClose={onClose}>
          <div className="flex items-start gap-3">
            <span className="mt-1 h-3 w-3 flex-shrink-0 rounded-sm" style={{ backgroundColor: NODE_COLORS[node.type] || '#8a889a' }} />
            <div className="min-w-0"><h2 className="break-words text-sm font-semibold text-foreground">{node.label || node.id}</h2></div>
          </div>
          <div className="mt-4 flex flex-wrap gap-1.5"><StatusPill tone="accent">{node.type.replaceAll('_', ' ')}</StatusPill><StatusPill tone="muted">{Math.round((node.confidence || 0) * 100)}% confidence</StatusPill></div>
          <div className="mt-5 flex flex-wrap gap-1.5">
            <ActionButton variant="primary" onClick={() => navigate(`/investigate?lens=topology&entity=node&item=${encodeURIComponent(node.id)}&node=${encodeURIComponent(node.id)}`)}><Network className="h-3 w-3" /> Show in topology</ActionButton>
            <ActionButton onClick={() => {
              setLauncherOpen(true);
              navigate(`/operate?view=active&kind=node&item=${encodeURIComponent(node.id)}`);
            }}>Start work</ActionButton>
          </div>
          {properties.length > 0 && <div className="mt-5 border-t border-border-subtle pt-3"><div className="mb-2 text-[10px] uppercase tracking-[0.14em] text-muted-foreground">Metadata</div><div className="space-y-2">{properties.map(([key, value]) => <div key={key} className="grid grid-cols-[7rem_1fr] gap-2 text-[10px]"><span className="text-muted-foreground">{key.replaceAll('_', ' ')}</span><span className="break-all text-foreground">{String(value)}</span></div>)}</div></div>}
    </WorkspaceInspector>
  );
}
