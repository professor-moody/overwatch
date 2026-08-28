import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Copy, Eye, EyeOff, Network, Plus, Search, X } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router';
import * as api from '../../lib/api';
import {
  ATTACK_PATH_GROUPS,
  attackPathLaneCounts,
  filterDisplayAttackPaths,
  normalizeApiAttackPath,
  normalizeComputedAttackPath,
  pathHops,
  type AttackPathLaneFilter,
  type DisplayAttackPath,
} from '../../lib/attack-path-workspace';
import { computeWorkspacePaths } from '../../lib/computed-paths';
import {
  credentialExpiry,
  credentialReachTargets,
  formatExpiryLabel,
  getCredentialKindLabel,
  getCredentialMaterialKind,
  getEffectiveCredentialStatus,
  isCredentialReachable,
} from '../../lib/credential-display';
import { buildIdentityProviderGroups, buildIdentityTokenSummaries } from '../../lib/identity-inventory';
import {
  groupPlaybookRunsByCredential,
  preparedExecutionIsClaimed,
  type PreparedExecution,
} from '../../lib/credential-playbooks';
import type { ExportedNode, PlaybookRun } from '../../lib/types';
import { buildWorkspacePath, setSelectionParams } from '../../lib/workspace-navigation';
import { cn, formatRelativeTime } from '../../lib/utils';
import { useEngagementStore } from '../../stores/engagement-store';
import { ActionButton, StatusPill, WorkspaceEmpty, WorkspaceInspector, WorkspaceRow } from '../shared/primitives';

export function IdentityLens({ active = true }: { active?: boolean }) {
  const graph = useEngagementStore(state => state.graph);
  const [searchParams, setSearchParams] = useSearchParams();
  const [query, setQuery] = useState('');
  const [validity, setValidity] = useState<'all' | 'usable' | 'blocked'>('all');
  const selected = searchParams.get('item');
  const groups = useMemo(() => buildIdentityProviderGroups(graph.nodes, graph.edges), [graph.edges, graph.nodes]);
  const tokens = useMemo(() => buildIdentityTokenSummaries(graph.nodes), [graph.nodes]);
  const q = query.trim().toLowerCase();

  const rows = useMemo(() => {
    const result: Array<{
      kind: 'provider' | 'principal' | 'application' | 'token';
      node: ExportedNode;
      provider: string;
      relation: string;
      status: string;
      expires?: string;
    }> = [];
    for (const group of groups) {
      result.push({ kind: 'provider', node: group.idp, provider: String(group.idp.label || group.idp.id), relation: `${group.applications.length} applications · ${group.principals.length} principals · ${group.federatedDomains.length} federations`, status: String(group.idp.federation_mode || 'active') });
      for (const principal of group.principals) result.push({ kind: 'principal', node: principal, provider: String(group.idp.label || group.idp.id), relation: String(principal.username || principal.label || principal.id), status: String(principal.validity || principal.status || 'observed'), expires: typeof principal.valid_until === 'string' ? principal.valid_until : undefined });
      for (const application of group.applications) result.push({ kind: 'application', node: application, provider: String(group.idp.label || group.idp.id), relation: String(application.app_name || application.label || application.id), status: String(application.status || 'observed') });
    }
    for (const token of tokens) result.push({ kind: 'token', node: token.node, provider: token.audience || 'Token relationship', relation: token.user || token.kind, status: token.status, expires: token.expires });
    return result.filter(row => {
      if (validity === 'usable' && /blocked|expired|invalid/i.test(row.status)) return false;
      if (validity === 'blocked' && !/blocked|expired|invalid/i.test(row.status)) return false;
      if (!q) return true;
      return [row.node.label, row.node.id, row.provider, row.relation, row.status].filter(Boolean).join(' ').toLowerCase().includes(q);
    });
  }, [groups, q, tokens, validity]);

  return (
    <div className={cn('h-full min-h-0 flex-col', active ? 'flex' : 'hidden')} data-testid="identity-lens">
      <div className="flex h-12 flex-shrink-0 items-center gap-2 border-b border-border-subtle px-4">
        <SearchInput value={query} onChange={setQuery} placeholder="Principal, application, or identity provider" />
        <select value={validity} onChange={event => setValidity(event.target.value as typeof validity)} className="h-8 rounded border border-border-subtle bg-surface px-2 text-[10px] outline-none"><option value="all">All validity</option><option value="usable">Usable</option><option value="blocked">Blocked / expired</option></select>
        <span className="ml-auto text-[10px] tabular-nums text-muted-foreground">{groups.length} IdPs · {rows.length} entities</span>
      </div>
      <div className="grid h-8 flex-shrink-0 grid-cols-[minmax(12rem,1fr)_7rem_minmax(10rem,1fr)_8rem_8rem] items-center gap-3 border-b border-border-subtle px-3 text-[9px] font-medium uppercase tracking-[0.12em] text-muted-foreground"><span>Identity</span><span>Kind</span><span>Provider / relationship</span><span>Validity</span><span>Expiry</span></div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {rows.length === 0 ? <WorkspaceEmpty title="No matching identity data" detail={graph.nodes.length ? 'Adjust the identity filters.' : 'Identity providers, principals, and token relationships will appear as the graph grows.'} /> : rows.map(row => (
          <WorkspaceRow key={`${row.kind}:${row.node.id}`} selected={selected === row.node.id} onClick={() => setSearchParams(setSelectionParams(searchParams, { kind: row.node.type === 'credential' ? 'credential' : 'node', id: row.node.id }))}>
            <div className="min-w-0 flex-1"><div className="truncate text-xs font-medium text-foreground">{row.node.label || row.relation || row.node.id}</div><div className="truncate font-mono text-[9px] text-muted-foreground">{row.node.id}</div></div>
            <span className="w-28 truncate text-[10px] capitalize text-muted-foreground">{row.kind}</span>
            <span className="min-w-0 flex-1 truncate text-[10px] text-muted-foreground">{row.provider}{row.kind !== 'provider' ? ` · ${row.relation}` : ''}</span>
            <StatusPill tone={/blocked|expired|invalid/i.test(row.status) ? 'warning' : 'success'}>{row.status}</StatusPill>
            <span className="w-28 truncate font-mono text-[9px] text-muted-foreground">{row.expires || '-'}</span>
          </WorkspaceRow>
        ))}
      </div>
    </div>
  );
}

type CredentialFilter = 'all' | 'reachable' | 'unverified' | 'expiring';

export function CredentialsLens({ active = true }: { active?: boolean }) {
  const graph = useEngagementStore(state => state.graph);
  const playbooks = useEngagementStore(state => state.playbookRuns);
  const [searchParams, setSearchParams] = useSearchParams();
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<CredentialFilter>('all');
  const [sort, setSort] = useState<'recent' | 'kind' | 'status'>('recent');
  const selected = searchParams.get('item');
  const byCredential = useMemo(() => groupPlaybookRunsByCredential(playbooks), [playbooks]);
  const now = Date.now();
  const credentials = useMemo(() => graph.nodes.filter(node => node.type === 'credential').filter(node => {
    const status = getEffectiveCredentialStatus(node, now);
    const reachable = status !== 'expired' && isCredentialReachable(node, graph.edges);
    if (filter === 'reachable' && !reachable) return false;
    if (filter === 'unverified' && reachable) return false;
    if (filter === 'expiring' && credentialExpiry(node, now)?.urgency !== 'soon') return false;
    const q = query.trim().toLowerCase();
    if (!q) return true;
    return [node.label, node.id, node.cred_material_kind, node.cred_user, node.cred_audience].filter(Boolean).join(' ').toLowerCase().includes(q);
  }).sort((left, right) => {
    if (sort === 'kind') return getCredentialKindLabel(left).localeCompare(getCredentialKindLabel(right));
    if (sort === 'status') return String(getEffectiveCredentialStatus(left, now)).localeCompare(String(getEffectiveCredentialStatus(right, now)));
    return String(right.discovered_at || '').localeCompare(String(left.discovered_at || ''));
  }), [filter, graph.edges, graph.nodes, now, query, sort]);

  return (
    <div className={cn('h-full min-h-0 flex-col', active ? 'flex' : 'hidden')} data-testid="credentials-lens">
      <div className="flex h-12 flex-shrink-0 items-center gap-2 border-b border-border-subtle px-4">
        <SearchInput value={query} onChange={setQuery} placeholder="Credential label, kind, principal, audience" />
        <select value={filter} onChange={event => setFilter(event.target.value as CredentialFilter)} className="h-8 rounded border border-border-subtle bg-surface px-2 text-[10px] outline-none"><option value="all">All credentials</option><option value="reachable">Reachable</option><option value="unverified">Unverified</option><option value="expiring">Expiring soon</option></select>
        <select value={sort} onChange={event => setSort(event.target.value as typeof sort)} className="h-8 rounded border border-border-subtle bg-surface px-2 text-[10px] outline-none"><option value="recent">Newest first</option><option value="kind">By kind</option><option value="status">By status</option></select>
        <span className="ml-auto text-[10px] tabular-nums text-muted-foreground">{credentials.length} credentials</span>
      </div>
      <div className="grid h-8 flex-shrink-0 grid-cols-[minmax(13rem,1.2fr)_8rem_7rem_7rem_8rem_minmax(9rem,1fr)] items-center gap-3 border-b border-border-subtle px-3 text-[9px] font-medium uppercase tracking-[0.12em] text-muted-foreground"><span>Credential</span><span>Kind</span><span>Validity</span><span>Reachability</span><span>Expiry</span><span>Provenance / playbook</span></div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {credentials.length === 0 ? <WorkspaceEmpty title="No matching credentials" detail={graph.nodes.some(node => node.type === 'credential') ? 'Adjust the credential filters.' : 'Captured credentials will appear here, masked by default.'} /> : credentials.map(credential => {
          const status = getEffectiveCredentialStatus(credential, now) || 'unknown';
          const targets = status !== 'expired' ? credentialReachTargets(credential, graph.edges) : [];
          const expiry = credentialExpiry(credential, now);
          const run = byCredential.get(credential.id)?.[0];
          const provenance = String(credential.source_label || credential.source || credential.discovered_by || credential.finding_id || 'graph observation');
          return <WorkspaceRow key={credential.id} selected={selected === credential.id} onClick={() => setSearchParams(setSelectionParams(searchParams, { kind: 'credential', id: credential.id }))}>
            <div className="min-w-0 flex-1"><div className="truncate text-xs font-medium text-foreground">{credential.label || credential.id}</div><div className="truncate font-mono text-[9px] text-muted-foreground">{credential.id}</div></div>
            <span className="w-32 truncate text-[10px] text-muted-foreground">{getCredentialKindLabel(getCredentialMaterialKind(credential))}</span>
            <StatusPill tone={status === 'active' ? 'success' : status === 'expired' ? 'danger' : 'warning'}>{status}</StatusPill>
            <span className={cn('w-28 text-[10px]', targets.length ? 'text-warning' : 'text-muted-foreground')}>{targets.length ? `${targets.length} targets` : 'unverified'}</span>
            <span className={cn('w-32 truncate font-mono text-[9px]', expiry?.urgency === 'expired' ? 'text-destructive' : expiry?.urgency === 'soon' ? 'text-warning' : 'text-muted-foreground')}>{expiry ? formatExpiryLabel(expiry) : '-'}</span>
            <span className="min-w-0 flex-1 truncate text-[9px] text-muted-foreground">{provenance}{run ? ` · ${run.definition.title} · ${run.status}` : ' · no playbook'}</span>
          </WorkspaceRow>;
        })}
      </div>
    </div>
  );
}

export function PathsLens({ active = true }: { active?: boolean }) {
  const graph = useEngagementStore(state => state.graph);
  const objectives = useEngagementStore(state => state.objectives);
  const [searchParams, setSearchParams] = useSearchParams();
  const [query, setQuery] = useState('');
  const [optimize, setOptimize] = useState<'confidence' | 'stealth'>('confidence');
  const [maxHops, setMaxHops] = useState(8);
  const [lane, setLane] = useState<AttackPathLaneFilter>('all');
  const [builderOpen, setBuilderOpen] = useState(false);
  const [customPaths, setCustomPaths] = useState<DisplayAttackPath[]>([]);
  const selected = searchParams.get('item');
  const byId = useMemo(() => new Map(graph.nodes.map(node => [node.id, node])), [graph.nodes]);
  const computed = useMemo(() => computeWorkspacePaths(graph.nodes, graph.edges, optimize, maxHops, byId).map(path => normalizeComputedAttackPath(path, byId)).filter((path): path is DisplayAttackPath => Boolean(path)), [byId, graph.edges, graph.nodes, maxHops, optimize]);
  const allPaths = useMemo(() => [...customPaths, ...computed.filter(path => !customPaths.some(custom => custom.id === path.id))], [computed, customPaths]);
  const counts = useMemo(() => attackPathLaneCounts(allPaths), [allPaths]);
  const paths = useMemo(() => filterDisplayAttackPaths(allPaths, lane).filter(path => !query.trim() || [path.headline, path.reason, path.source.label, path.target.label, ...path.rawEdgeTypes].join(' ').toLowerCase().includes(query.trim().toLowerCase())), [allPaths, lane, query]);

  const selectPath = (path: DisplayAttackPath) => {
    const next = setSelectionParams(searchParams, { kind: 'path', id: path.id });
    next.set('nodes', path.nodeIds.join(','));
    next.set('edges', path.edgeIds.join(','));
    setSearchParams(next);
  };

  return (
    <div className={cn('h-full min-h-0 min-w-0 w-full overflow-hidden flex-col', active ? 'flex' : 'hidden')} data-testid="paths-lens">
      <div className="grid min-h-12 flex-shrink-0 grid-cols-2 items-center gap-2 border-b border-border-subtle px-4 py-2 xl:grid-cols-[minmax(16rem,1fr)_auto_auto_auto_auto]">
        <SearchInput value={query} onChange={setQuery} placeholder="Source, objective, edge, or assumption" className="col-span-2 max-w-none xl:col-span-1 xl:max-w-lg" />
        <select value={optimize} onChange={event => setOptimize(event.target.value as typeof optimize)} className="h-8 min-w-0 rounded border border-border-subtle bg-surface px-2 text-[10px] outline-none"><option value="confidence">Optimize confidence</option><option value="stealth">Optimize stealth</option></select>
        <label className="flex h-8 items-center gap-1 rounded border border-border-subtle bg-surface px-2 text-[9px] text-muted-foreground">Hops <input type="number" min={1} max={25} value={maxHops} onChange={event => setMaxHops(Math.max(1, Math.min(25, Number(event.target.value) || 8)))} className="w-8 bg-transparent font-mono text-foreground outline-none" /></label>
        <select value={lane} onChange={event => setLane(event.target.value as AttackPathLaneFilter)} className="h-8 min-w-0 rounded border border-border-subtle bg-surface px-2 text-[10px] outline-none"><option value="all">All lanes ({counts.all})</option>{ATTACK_PATH_GROUPS.map(group => <option key={group.key} value={group.key}>{group.label} ({counts[group.key]})</option>)}</select>
        <ActionButton variant="primary" onClick={() => setBuilderOpen(true)}><Plus className="h-3 w-3" />Custom path</ActionButton>
      </div>
      <div className="grid h-8 flex-shrink-0 grid-cols-[minmax(16rem,1.3fr)_6rem_7rem_7rem_minmax(11rem,1fr)] items-center gap-3 border-b border-border-subtle px-3 text-[9px] font-medium uppercase tracking-[0.12em] text-muted-foreground"><span>Route</span><span>Hops</span><span>Confidence</span><span>OPSEC</span><span>Objective / assumptions</span></div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {paths.length === 0 ? <WorkspaceEmpty title="No paths for this view" detail={objectives.length ? 'Change the optimization, lane, or hop limit; custom routes remain available.' : 'Define objectives or mark high-value targets to surface routes from current access.'} /> : paths.map(path => {
          const assumptions = path.edges.filter(edge => graph.edges.find(candidate => candidate.id === edge.id)?.inferred).length;
          return <WorkspaceRow key={path.id} selected={selected === path.id} onClick={() => selectPath(path)}>
            <div className="min-w-0 flex-1"><div className="truncate text-xs font-medium text-foreground">{path.headline}</div><div className="mt-0.5 truncate text-[9px] text-muted-foreground">{path.nodes.map(node => node.label).join(' → ')}</div></div>
            <span className="w-24 font-mono text-[10px] text-foreground">{path.hopCount}</span>
            <span className="w-28 font-mono text-[10px] text-foreground">{Math.round(path.totalConfidence * 100)}%</span>
            <StatusPill tone={path.riskTone === 'danger' ? 'danger' : path.riskTone === 'warning' ? 'warning' : 'success'}>{path.riskLabel}</StatusPill>
            <span className="min-w-0 flex-1 truncate text-[9px] text-muted-foreground">{path.target.label} · {assumptions} assumption{assumptions === 1 ? '' : 's'} · {path.edges.length} evidence hops</span>
          </WorkspaceRow>;
        })}
      </div>
      {builderOpen && <CustomPathBuilder nodes={graph.nodes} byId={byId} initialFrom={searchParams.get('from') || ''} initialTo={searchParams.get('to') || ''} initialObjective={searchParams.get('objective') || ''} onClose={() => setBuilderOpen(false)} onResult={results => { setCustomPaths(results); if (results[0]) selectPath(results[0]); setBuilderOpen(false); }} />}
    </div>
  );
}

function CustomPathBuilder({ nodes, byId, initialFrom, initialTo, initialObjective, onClose, onResult }: { nodes: ExportedNode[]; byId: Map<string, ExportedNode>; initialFrom: string; initialTo: string; initialObjective: string; onClose: () => void; onResult: (paths: DisplayAttackPath[]) => void }) {
  const [from, setFrom] = useState(initialFrom);
  const [to, setTo] = useState(initialTo);
  const [objective, setObjective] = useState(initialObjective);
  const [optimize, setOptimize] = useState<'confidence' | 'stealth' | 'balanced'>('confidence');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.findPaths({ from: from || undefined, to: to || undefined, objective: objective || undefined, optimize, max: 8 });
      const paths = response.paths.map(path => normalizeApiAttackPath(path, byId)).filter((path): path is DisplayAttackPath => Boolean(path));
      if (!paths.length) setError(response.warnings?.join('; ') || 'No route connects the selected endpoints.');
      else onResult(paths);
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Path analysis failed.'); }
    finally { setLoading(false); }
  };
  return <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-6" role="dialog" aria-modal="true" aria-label="Custom path builder"><div className="w-full max-w-2xl rounded-lg border border-border bg-elevated p-4 shadow-2xl"><div className="flex items-start gap-3"><div className="min-w-0 flex-1"><div className="text-sm font-semibold text-foreground">Custom attack path</div><div className="mt-1 text-[10px] text-muted-foreground">Choose a complete source/target pair or a canonical objective. The server ranks the result.</div></div><button type="button" onClick={onClose} className="rounded p-1 text-muted-foreground hover:bg-hover hover:text-foreground"><X className="h-4 w-4" /></button></div><div className="mt-4 grid gap-3 sm:grid-cols-2"><NodeSelect label="From" value={from} onChange={setFrom} nodes={nodes} /><NodeSelect label="To" value={to} onChange={setTo} nodes={nodes} /><label className="flex flex-col gap-1 text-[10px] text-muted-foreground">Objective ID<input value={objective} onChange={event => setObjective(event.target.value)} className="h-8 rounded border border-border-subtle bg-background px-2 font-mono text-[10px] text-foreground outline-none focus:border-accent/50" placeholder="optional objective" /></label><label className="flex flex-col gap-1 text-[10px] text-muted-foreground">Optimization<select value={optimize} onChange={event => setOptimize(event.target.value as typeof optimize)} className="h-8 rounded border border-border-subtle bg-background px-2 text-[10px] text-foreground outline-none"><option value="confidence">Confidence</option><option value="stealth">Stealth</option><option value="balanced">Balanced</option></select></label></div>{error && <div className="mt-3 flex items-start gap-2 text-[10px] text-warning"><AlertTriangle className="mt-0.5 h-3 w-3" />{error}</div>}<div className="mt-4 flex justify-end gap-2"><ActionButton onClick={onClose}>Cancel</ActionButton><ActionButton variant="primary" disabled={loading || !(objective || (from && to))} onClick={() => void run()}>{loading ? 'Finding…' : 'Find paths'}</ActionButton></div></div></div>;
}

function NodeSelect({ label, value, onChange, nodes }: { label: string; value: string; onChange: (value: string) => void; nodes: ExportedNode[] }) {
  return <label className="flex flex-col gap-1 text-[10px] text-muted-foreground">{label}<select value={value} onChange={event => onChange(event.target.value)} className="h-8 min-w-0 rounded border border-border-subtle bg-background px-2 text-[10px] text-foreground outline-none"><option value="">Select node…</option>{nodes.map(node => <option key={node.id} value={node.id}>{node.label || node.id} · {node.type}</option>)}</select></label>;
}

export function CredentialInspector({ credential, tab, onTabChange, onClose }: { credential: ExportedNode; tab: string; onTabChange: (tab: string) => void; onClose: () => void }) {
  const navigate = useNavigate();
  const connected = useEngagementStore(state => state.connected);
  const graph = useEngagementStore(state => state.graph);
  const playbooks = useEngagementStore(state => state.playbookRuns);
  const setPlaybooks = useEngagementStore(state => state.setPlaybookRuns);
  const [revealed, setRevealed] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [prepared, setPrepared] = useState<PreparedExecution | null>(null);
  const availableTabs = ['summary', 'relationships', 'activity', 'actions'];
  const credentialRuns = useMemo(() => playbooks.filter(run => run.credential_id === credential.id).sort((left, right) => right.updated_at.localeCompare(left.updated_at)), [credential.id, playbooks]);
  const status = getEffectiveCredentialStatus(credential, Date.now()) || 'unknown';
  const targets = credentialReachTargets(credential, graph.edges);
  const value = typeof credential.cred_value === 'string' ? credential.cred_value : '';
  const expiry = credentialExpiry(credential);

  useEffect(() => { setRevealed(false); setPrepared(null); }, [credential.id]);
  useEffect(() => { if (!connected) setRevealed(false); }, [connected]);
  useEffect(() => {
    setPrepared(current => current && preparedExecutionIsClaimed(current, playbooks) ? current : null);
  }, [playbooks]);

  const updateRun = (run: PlaybookRun) => setPlaybooks([...playbooks.filter(candidate => candidate.run_id !== run.run_id), run].sort((left, right) => right.updated_at.localeCompare(left.updated_at)));
  const act = async (key: string, operation: () => Promise<PlaybookRun | { run: PlaybookRun; execution: Record<string, unknown> }>) => {
    setBusy(key); setError(null);
    try {
      const result = await operation();
      const claim = result as { run?: PlaybookRun; execution?: Record<string, unknown> };
      const run = claim.run || result as PlaybookRun;
      updateRun(run);
      if (claim.execution) setPrepared({ run_id: run.run_id, step_id: String(claim.execution.playbook_step_id || ''), attempt_id: String(claim.execution.playbook_attempt_id || ''), execution: claim.execution });
      else setPrepared(null);
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Playbook action failed.'); }
    finally { setBusy(null); }
  };

  return <WorkspaceInspector label="Credential inspector" title={String(credential.label || credential.id)} identifier={credential.id} tabs={availableTabs.map(value => ({ value, label: value[0].toUpperCase() + value.slice(1) }))} activeTab={tab} onTabChange={onTabChange} onClose={onClose}>
    {tab === 'summary' && <div className="space-y-4">
      <div className="flex flex-wrap gap-1.5"><StatusPill tone="accent">{getCredentialKindLabel(getCredentialMaterialKind(credential))}</StatusPill><StatusPill tone={status === 'active' ? 'success' : status === 'expired' ? 'danger' : 'warning'}>{status}</StatusPill><StatusPill tone={targets.length ? 'warning' : 'muted'}>{targets.length ? `${targets.length} reachable targets` : 'unverified reachability'}</StatusPill></div>
      <div className="space-y-2 border-t border-border-subtle pt-3 text-[10px]"><InspectorFact label="Principal" value={String(credential.cred_user || '-')} mono /><InspectorFact label="Audience" value={String(credential.cred_audience || '-')} mono /><InspectorFact label="Expiry" value={expiry ? formatExpiryLabel(expiry) : '-'} /><InspectorFact label="Provenance" value={String(credential.source_label || credential.source || credential.finding_id || 'graph observation')} /></div>
      {value && <div className="border-t border-border-subtle pt-3"><div className="mb-1 text-[9px] font-medium uppercase tracking-[0.14em] text-muted-foreground">Credential value</div><div className="flex items-start gap-2 rounded border border-border-subtle bg-background p-2"><code className="min-w-0 flex-1 break-all font-mono text-[10px] text-foreground">{revealed ? value : '••••••••••••••••'}</code><button type="button" onClick={() => setRevealed(show => !show)} className="rounded p-1 text-muted-foreground hover:bg-hover hover:text-foreground" title={revealed ? 'Hide credential' : 'Reveal credential'}>{revealed ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}</button><button type="button" disabled={!revealed} onClick={() => void navigator.clipboard?.writeText(value)} className="rounded p-1 text-muted-foreground hover:bg-hover hover:text-foreground disabled:opacity-30" title="Copy revealed credential"><Copy className="h-3.5 w-3.5" /></button></div><div className="mt-1 text-[9px] text-muted-foreground">Reveal and copy are separate. Reveal resets when context or transport changes.</div></div>}
      <ActionButton onClick={() => navigate(buildWorkspacePath({ workspace: 'investigate', lens: 'topology', selection: { kind: 'credential', id: credential.id }, context: { node: credential.id } }))}><Network className="h-3 w-3" />Show in topology</ActionButton>
    </div>}
    {tab === 'relationships' && <div><div className="mb-2 text-[9px] font-medium uppercase tracking-[0.14em] text-muted-foreground">Reachable through this credential</div>{targets.length ? <div className="space-y-1">{targets.map(id => <button key={id} type="button" onClick={() => navigate(buildWorkspacePath({ workspace: 'investigate', lens: 'topology', selection: { kind: 'node', id }, context: { node: id } }))} className="block w-full truncate border-b border-border-subtle px-1 py-2 text-left text-[10px] text-accent">{graph.nodes.find(node => node.id === id)?.label || id}<span className="ml-2 font-mono text-[8px] text-muted-foreground">{id}</span></button>)}</div> : <WorkspaceEmpty title="No validated reachability" detail="The credential remains available for validation or a dependency-aware playbook." />}</div>}
    {tab === 'activity' && <div className="space-y-1">{credentialRuns.length ? credentialRuns.map(run => <div key={run.run_id} className="border-b border-border-subtle py-2"><div className="text-[10px] text-foreground">{run.definition.title}</div><div className="font-mono text-[8px] text-muted-foreground">{run.run_id} · {run.status} · {formatRelativeTime(run.updated_at)}</div></div>) : <WorkspaceEmpty title="No playbook activity" detail="No durable credential playbook has been created for this credential." />}</div>}
    {tab === 'actions' && <PlaybookActions runs={credentialRuns} busy={busy} error={error} prepared={prepared} onAction={act} />}
  </WorkspaceInspector>;
}

function PlaybookActions({ runs, busy, error, prepared, onAction }: { runs: PlaybookRun[]; busy: string | null; error: string | null; prepared: PreparedExecution | null; onAction: (key: string, operation: () => Promise<PlaybookRun | { run: PlaybookRun; execution: Record<string, unknown> }>) => Promise<void> }) {
  if (!runs.length) return <WorkspaceEmpty title="No durable playbook" detail="Deploy a matching credential or cloud agent, or expand the credential through the canonical API. New execution semantics are not inferred here." />;
  return <div className="space-y-3">{runs.map(run => <section key={run.run_id} className="border-b border-border-subtle pb-3"><div className="flex items-center gap-2"><div className="min-w-0 flex-1"><div className="truncate text-[10px] font-medium text-foreground">{run.definition.title}</div><div className="truncate font-mono text-[8px] text-muted-foreground">{run.run_id} · {run.status}</div></div>{run.status === 'interrupted' && <ActionButton size="xs" disabled={Boolean(busy)} onClick={() => void onAction(`resume:${run.run_id}`, () => api.resumePlaybookRun(run.run_id))}>Resume</ActionButton>}</div><div className="mt-2 space-y-1">{run.steps.map(step => { const key = `${run.run_id}:${step.step_id}`; const attempt = step.attempts.at(-1); const claimed = step.attempts.find(candidate => candidate.status === 'claimed'); return <div key={step.step_id} className="rounded border border-border-subtle bg-background/50 p-2"><div className="flex items-start gap-2"><StatusPill tone={step.status === 'succeeded' ? 'success' : step.status === 'failed' || step.status === 'interrupted' ? 'warning' : 'muted'}>{step.status}</StatusPill><span className="min-w-0 flex-1 text-[9px] leading-4 text-foreground">{step.ordinal}. {step.description}</span></div>{step.blocked_reason && <div className="mt-1 text-[8px] text-muted-foreground">{step.blocked_reason}</div>}<div className="mt-2 flex flex-wrap gap-1">{step.status === 'pending' && !attempt && <ActionButton size="xs" disabled={Boolean(busy)} onClick={() => void onAction(`start:${key}`, () => api.startPlaybookStep(run.run_id, step.step_id))}>Prepare</ActionButton>}{(step.status === 'failed' || step.status === 'interrupted' || (step.status === 'pending' && Boolean(attempt))) && <ActionButton size="xs" disabled={Boolean(busy)} onClick={() => void onAction(`retry:${key}`, () => api.retryPlaybookStep(run.run_id, step.step_id))}>Prepare retry</ActionButton>}{claimed && <ActionButton size="xs" variant="ghost" disabled={Boolean(busy)} onClick={() => void onAction(`release:${key}`, () => api.interruptPlaybookAttempt(run.run_id, step.step_id, 'Prepared dashboard claim released by operator'))}>Release claim</ActionButton>}{['pending', 'blocked', 'failed', 'interrupted'].includes(step.status) && <ActionButton size="xs" variant="ghost" disabled={Boolean(busy)} onClick={() => void onAction(`skip:${key}`, () => api.skipPlaybookStep(run.run_id, step.step_id, 'Skipped from native credential inspector'))}>Skip</ActionButton>}</div></div>; })}</div></section>)}{prepared && <div className="rounded border border-accent/30 bg-accent/5 p-2"><div className="flex items-center gap-2"><span className="min-w-0 flex-1 text-[9px] text-accent">Execution descriptor prepared and claimed.</span><ActionButton size="xs" onClick={() => void navigator.clipboard?.writeText(JSON.stringify(prepared.execution, null, 2))}>Copy input</ActionButton></div><div className="mt-1 break-all font-mono text-[8px] text-muted-foreground">{prepared.run_id} · {prepared.step_id} · {prepared.attempt_id}</div><div className="mt-1 text-[8px] leading-4 text-muted-foreground">Copying does not execute it. Preserve its stable command identity and release the claim if it will not run.</div></div>}{error && <div className="text-[9px] text-destructive">{error}</div>}</div>;
}

export function NativePathInspector({ path, onClose }: { path: { id: string; nodeIds: string[]; edgeIds: string[] }; onClose: () => void }) {
  const navigate = useNavigate();
  const graph = useEngagementStore(state => state.graph);
  const nodes = path.nodeIds.map(id => graph.nodes.find(node => node.id === id)).filter((node): node is ExportedNode => Boolean(node));
  const edges = path.edgeIds.map(id => graph.edges.find(edge => edge.id === id)).filter(Boolean);
  const display = normalizeComputedAttackPath({ nodes: path.nodeIds, edge_types: edges.map(edge => edge!.type), edge_ids: path.edgeIds, total_confidence: edges.reduce((value, edge) => value * (edge?.confidence ?? 1), 1), total_opsec_noise: edges.reduce((value, edge) => value + (typeof edge?.opsec_noise === 'number' ? edge.opsec_noise : 0.3), 0) }, new Map(graph.nodes.map(node => [node.id, node])));
  const hops = display ? pathHops(display) : [];
  return <WorkspaceInspector label="Path inspector" title={display?.headline || nodes.at(-1)?.label || 'Attack path'} identifier={path.id} onClose={onClose}><div className="space-y-4"><div className="flex flex-wrap gap-1.5">{display && <><StatusPill tone={display.totalConfidence >= 0.8 ? 'success' : 'warning'}>{Math.round(display.totalConfidence * 100)}% confidence</StatusPill><StatusPill tone={display.riskTone === 'danger' ? 'danger' : display.riskTone === 'warning' ? 'warning' : 'success'}>{display.riskLabel}</StatusPill><StatusPill tone="muted">{display.hopCount} hops</StatusPill></>}</div><div><div className="mb-2 text-[9px] font-medium uppercase tracking-[0.14em] text-muted-foreground">Route and assumptions</div><div className="space-y-2">{hops.map((hop, index) => <div key={`${hop.from.id}:${hop.to.id}:${index}`} className="border-l border-border-subtle pl-2"><div className="text-[10px] text-foreground">{hop.from.label} <span className="text-muted-foreground">{hop.phrase}</span> {hop.to.label}</div><div className="mt-0.5 font-mono text-[8px] text-muted-foreground">{hop.edge.rawType}{graph.edges.find(edge => edge.id === hop.edge.id)?.inferred ? ' · inferred assumption' : ' · captured/claimed relationship'}</div></div>)}</div></div><ActionButton variant="primary" onClick={() => navigate(buildWorkspacePath({ workspace: 'investigate', lens: 'topology', selection: { kind: 'path', id: path.id }, context: { nodes: path.nodeIds.join(','), edges: path.edgeIds.join(',') } }))}><Network className="h-3 w-3" />Show in topology</ActionButton></div></WorkspaceInspector>;
}

function SearchInput({ value, onChange, placeholder, className }: { value: string; onChange: (value: string) => void; placeholder: string; className?: string }) {
  return <label className={cn('flex h-8 min-w-32 max-w-lg flex-[1_1_16rem] items-center gap-2 rounded border border-border-subtle bg-surface px-2.5 focus-within:border-accent/50', className)}><Search className="h-3.5 w-3.5 text-muted-foreground" /><input value={value} onChange={event => onChange(event.target.value)} placeholder={placeholder} className="min-w-0 flex-1 bg-transparent text-[10px] outline-none placeholder:text-muted" /></label>;
}

function InspectorFact({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return <div className="grid grid-cols-[6.5rem_1fr] gap-2"><span className="text-muted-foreground">{label}</span><span className={cn('break-all text-foreground', mono && 'font-mono')}>{value}</span></div>;
}
