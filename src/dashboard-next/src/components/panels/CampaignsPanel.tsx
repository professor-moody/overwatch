import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { Columns3, Copy, LayoutList, Pause, Play, Plus, RefreshCw, Send, Square } from 'lucide-react';
import { useEngagementStore } from '../../stores/engagement-store';
import { cn, formatRelativeTime } from '../../lib/utils';
import { EmptyState, OpsecGauge } from '../shared';
import { DataRow, FilterBar, PageHeader, PanelSection, StatusPill } from '../shared/primitives';
import {
  campaignAction,
  cloneCampaign,
  createCampaign,
  dispatchCampaign,
  getAgentQueries,
  getCampaigns,
  type AgentQuery,
} from '../../lib/api';
import type { Campaign, FrontierItem } from '../../lib/types';
import { buildMissionCard } from '../../lib/agent-mission';
import { POLL } from '../../lib/polling';
import { CampaignBoard } from './CampaignBoard';
import {
  campaignItemNodeLabel,
  campaignLifecycleActions,
  deriveCampaignPreviewMetrics,
  filterCampaignFrontierItems,
  isCampaignDispatchReady,
  resolveCampaignItems,
} from '../../lib/campaign-workspace';
import { getFrontierKey } from '../../lib/frontier-workspace';
import { GraphNodeLinks } from '../shared/GraphNodeLinks';

const STATUS_ORDER: Record<Campaign['status'], number> = {
  active: 0,
  paused: 1,
  draft: 2,
  completed: 3,
  aborted: 4,
};

export function CampaignsPanel() {
  const campaigns = useEngagementStore((s) => s.campaigns);
  const frontier = useEngagementStore((s) => s.frontier);
  const agents = useEngagementStore((s) => s.agents);
  const sessions = useEngagementStore((s) => s.sessions);
  const pendingActions = useEngagementStore((s) => s.pendingActions);
  const [selectedId, setSelectedId] = useState<string | null>(campaigns[0]?.id || null);
  const [mode, setMode] = useState<'detail' | 'builder'>('detail');
  const [view, setView] = useState<'list' | 'board'>('list');
  const [query, setQuery] = useState('');
  const [agentQueries, setAgentQueries] = useState<AgentQuery[]>([]);

  // Board view buckets agents into per-campaign lanes; agent→operator questions
  // drive the "Needs You"/Blocked lanes, so fetch them while the board is shown
  // (live via the WS push + a poll, mirroring AgentsPanel).
  const loadAgentQueries = useCallback(async () => {
    try {
      const { queries } = await getAgentQueries();
      setAgentQueries(queries || []);
    } catch { /* transient */ }
  }, []);
  useEffect(() => {
    if (view !== 'board') return;
    void loadAgentQueries();
    const onUpdate = () => void loadAgentQueries();
    window.addEventListener('overwatch-agent-query-update', onUpdate);
    const timer = setInterval(() => void loadAgentQueries(), POLL.AGENTS_MS);
    return () => {
      window.removeEventListener('overwatch-agent-query-update', onUpdate);
      clearInterval(timer);
    };
  }, [view, loadAgentQueries]);

  const missionCards = useMemo(
    () => agents.map(a => buildMissionCard(a, { sessions, pendingActions, agentQueries })),
    [agents, sessions, pendingActions, agentQueries],
  );

  const sortedCampaigns = useMemo(() => {
    const q = query.trim().toLowerCase();
    return [...campaigns]
      .sort((a, b) => (STATUS_ORDER[a.status] ?? 9) - (STATUS_ORDER[b.status] ?? 9) || a.name.localeCompare(b.name))
      .filter(campaign => !q || [
        campaign.id,
        campaign.name,
        campaign.strategy,
        campaign.status,
      ].some(value => value.toLowerCase().includes(q)));
  }, [campaigns, query]);

  const selectedCampaign = campaigns.find(campaign => campaign.id === selectedId) || sortedCampaigns[0] || null;
  const activeCount = campaigns.filter(campaign => campaign.status === 'active').length;
  const draftCount = campaigns.filter(campaign => campaign.status === 'draft').length;

  const refresh = useCallback(async () => {
    try {
      const data = await getCampaigns();
      useEngagementStore.setState({ campaigns: data.campaigns || [] });
    } catch { /* keep current campaigns visible */ }
  }, []);

  return (
    <div className="h-[calc(100vh-7rem)] min-h-[680px] flex flex-col gap-4">
      <PageHeader
        title="Campaigns"
        meta={`(${campaigns.length} total · ${activeCount} active · ${draftCount} drafts)`}
        actions={(
          <FilterBar>
            <div className="inline-flex rounded border border-border bg-elevated p-0.5">
              <ViewToggle active={view === 'list'} onClick={() => setView('list')} icon={<LayoutList className="h-3.5 w-3.5" />} label="Campaigns" />
              <ViewToggle active={view === 'board'} onClick={() => setView('board')} icon={<Columns3 className="h-3.5 w-3.5" />} label="Board" />
            </div>
            {view === 'list' && (
              <input
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="Filter campaigns..."
                className="settings-input w-56"
              />
            )}
            <button onClick={refresh} className="text-xs px-2 py-1 rounded bg-elevated border border-border text-muted-foreground hover:text-foreground inline-flex items-center gap-1">
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </button>
            <button onClick={() => { setView('list'); setMode('builder'); }} className="settings-save-btn inline-flex items-center gap-1">
              <Plus className="h-3.5 w-3.5" />
              New Campaign
            </button>
          </FilterBar>
        )}
      />

      {view === 'board' ? (
        <PanelSection className="flex-1 min-h-0 flex flex-col">
          <CampaignBoard cards={missionCards} />
        </PanelSection>
      ) : (
      <div className="grid grid-cols-[minmax(340px,420px)_1fr] gap-4 flex-1 min-h-0">
        <PanelSection className="p-0 overflow-hidden min-h-0 flex flex-col">
          <div className="grid grid-cols-3 border-b border-border text-center text-xs">
            <CampaignStat label="Active" value={activeCount} tone="success" />
            <CampaignStat label="Drafts" value={draftCount} tone="accent" />
            <CampaignStat label="Frontier" value={frontier.length} />
          </div>
          <div className="overflow-y-auto p-2 space-y-1.5">
            {sortedCampaigns.length === 0 ? (
              <EmptyState message={campaigns.length === 0 ? 'No campaigns yet.' : 'No campaigns match the filter.'} />
            ) : sortedCampaigns.map(campaign => (
              <CampaignRow
                key={campaign.id}
                campaign={campaign}
                selected={selectedCampaign?.id === campaign.id && mode === 'detail'}
                onSelect={() => { setSelectedId(campaign.id); setMode('detail'); }}
              />
            ))}
          </div>
        </PanelSection>

        {mode === 'builder' ? (
          <CampaignBuilder frontier={frontier} onCancel={() => setMode('detail')} onCreated={(campaign) => {
            setSelectedId(campaign.id);
            setMode('detail');
            refresh();
          }} />
        ) : selectedCampaign ? (
          <CampaignDetail campaign={selectedCampaign} frontier={frontier} onRefresh={refresh} />
        ) : (
          <PanelSection>
            <EmptyState message="Select a campaign or build one from Frontier items." />
          </PanelSection>
        )}
      </div>
      )}
    </div>
  );
}

function ViewToggle({ active, onClick, icon, label }: { active: boolean; onClick: () => void; icon: ReactNode; label: string }) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'inline-flex items-center gap-1 rounded px-2 py-1 text-xs',
        active ? 'bg-accent/15 text-accent' : 'text-muted-foreground hover:text-foreground',
      )}
    >
      {icon}
      {label}
    </button>
  );
}

function CampaignRow({ campaign, selected, onSelect }: { campaign: Campaign; selected: boolean; onSelect: () => void }) {
  const pct = campaign.completion_pct ?? 0;
  return (
    <DataRow onClick={onSelect} className={cn('p-2.5', selected && 'border-accent/50 bg-accent/5')}>
      <div className="flex items-start gap-2">
        <StatusDot status={campaign.status} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium truncate">{campaign.name || campaign.id}</span>
            <StatusPill className={statusClass(campaign.status)}>{campaign.status}</StatusPill>
          </div>
          <div className="mt-0.5 text-[10px] text-muted-foreground truncate">
            {campaign.strategy} · {campaign.items?.length ?? 0} items · {campaign.agents_active ?? 0}/{campaign.agents_total ?? 0} agents
          </div>
          <div className="mt-2 h-1 bg-elevated rounded overflow-hidden">
            <div className="h-full bg-accent rounded" style={{ width: `${Math.min(100, pct)}%` }} />
          </div>
        </div>
        <span className="text-[10px] text-muted-foreground font-mono">{pct}%</span>
      </div>
    </DataRow>
  );
}

function CampaignDetail({ campaign, frontier, onRefresh }: { campaign: Campaign; frontier: FrontierItem[]; onRefresh: () => void }) {
  const [dispatchOpen, setDispatchOpen] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const actions = campaignLifecycleActions(campaign);
  const ready = isCampaignDispatchReady(campaign);
  const itemDetails = useMemo(() => resolveCampaignItems(campaign.items || [], frontier), [campaign.items, frontier]);
  const metrics = deriveCampaignPreviewMetrics(itemDetails);

  const runLifecycleAction = async (action: typeof actions[number]['action']) => {
    setBusy(action);
    try {
      await campaignAction(campaign.id, action);
      onRefresh();
    } catch { /* leave current state visible */ }
    finally { setBusy(null); }
  };

  const clone = async () => {
    setBusy('clone');
    try {
      await cloneCampaign(campaign.id);
      onRefresh();
    } catch { /* silent */ }
    finally { setBusy(null); }
  };

  return (
    <div className="min-w-0 min-h-0 flex flex-col gap-3 overflow-y-auto">
      <PanelSection>
        <div className="flex items-start gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 mb-2">
              <StatusPill className={statusClass(campaign.status)}>{campaign.status}</StatusPill>
              <span className="text-xs text-muted-foreground">{campaign.strategy}</span>
              {campaign.parent_id && <StatusPill className="bg-elevated text-muted-foreground">child</StatusPill>}
            </div>
            <h3 className="text-base font-semibold truncate">{campaign.name || campaign.id}</h3>
            <div className="text-[11px] text-muted-foreground font-mono truncate">{campaign.id}</div>
          </div>
          <div className="flex flex-wrap justify-end gap-1.5">
            {actions.map(action => (
              <button
                key={action.action}
                onClick={() => runLifecycleAction(action.action)}
                disabled={busy === action.action}
                className={cn('text-xs px-2 py-1 rounded border inline-flex items-center gap-1 disabled:opacity-50', actionToneClass(action.tone))}
              >
                {actionIcon(action.action)}
                {busy === action.action ? 'Working...' : action.label}
              </button>
            ))}
            <button
              onClick={() => setDispatchOpen(prev => !prev)}
              disabled={!ready}
              className="text-xs px-2 py-1 rounded bg-accent/10 text-accent border border-accent/20 hover:bg-accent/20 disabled:opacity-40 disabled:cursor-not-allowed inline-flex items-center gap-1"
            >
              <Send className="h-3.5 w-3.5" />
              Dispatch
            </button>
            <button onClick={clone} disabled={busy === 'clone'} className="text-xs px-2 py-1 rounded bg-elevated text-muted-foreground border border-border hover:text-foreground inline-flex items-center gap-1">
              <Copy className="h-3.5 w-3.5" />
              Clone
            </button>
          </div>
        </div>

        <div className="mt-3 grid grid-cols-2 lg:grid-cols-5 gap-2 text-xs">
          <DetailFact label="Items" value={String((campaign.items || []).length)} />
          <DetailFact label="Agents" value={`${campaign.agents_active ?? 0}/${campaign.agents_total ?? metrics.expectedAgentCount}`} />
          <DetailFact label="Priority" value={metrics.maxPriority.toFixed(1)} />
          <DetailFact label="Avg Noise" value={metrics.avgNoise.toFixed(2)} />
          <DetailFact label="Started" value={campaign.started_at ? formatRelativeTime(campaign.started_at) : '—'} />
        </div>

        {!ready && (campaign.status === 'draft' || campaign.status === 'active') && (
          <div className="mt-3 rounded border border-warning/20 bg-warning/10 p-2 text-xs text-warning">
            Dispatch needs at least one Frontier item. Build or clone a campaign with selected items before launching agents.
          </div>
        )}
      </PanelSection>

      {dispatchOpen && <DispatchPanel campaign={campaign} onDone={() => { setDispatchOpen(false); onRefresh(); }} />}

      {campaign.opsec && (
        <OpsecGauge
          budget={campaign.opsec}
          title="Campaign Noise"
          caption="This campaign's noise as a share of the global budget — recommended approach is engagement-wide."
        />
      )}

      <PanelSection title="Dispatch Preview">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-2 text-xs mb-3">
          <DetailFact label="Expected Agents" value={String(metrics.expectedAgentCount)} />
          <DetailFact label="Unique Nodes" value={String(metrics.nodeIds.length)} />
          <DetailFact label="Findings" value={String(campaign.findings_count ?? 0)} />
          <DetailFact label="Completion" value={`${campaign.completion_pct ?? 0}%`} />
        </div>
        <div className="flex flex-wrap gap-1.5">
          {metrics.nodeIds.slice(0, 10).map(nodeId => <GraphNodeLinks key={nodeId} nodeId={nodeId} />)}
          {metrics.nodeIds.length > 10 && <span className="text-[10px] text-muted-foreground">+{metrics.nodeIds.length - 10} more</span>}
        </div>
      </PanelSection>

      <PanelSection title="Frontier Items" meta={`(${campaign.items?.length ?? 0})`}>
        {(campaign.items || []).length === 0 ? (
          <EmptyState message="No Frontier items are attached to this campaign." />
        ) : (
          <div className="space-y-1.5">
            {itemDetails.map(item => (
              <CampaignItemRow key={getFrontierKey(item)} item={item} />
            ))}
            {itemDetails.length === 0 && (
              <div className="text-xs text-muted-foreground">Frontier details for this campaign are not in the current filtered state.</div>
            )}
          </div>
        )}
      </PanelSection>
    </div>
  );
}

function CampaignBuilder({ frontier, onCancel, onCreated }: {
  frontier: FrontierItem[];
  onCancel: () => void;
  onCreated: (campaign: Campaign) => void;
}) {
  const [name, setName] = useState('');
  const [strategy, setStrategy] = useState<Campaign['strategy']>('custom');
  const [search, setSearch] = useState('');
  const [type, setType] = useState('');
  const [node, setNode] = useState('');
  const [minPriority, setMinPriority] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [creating, setCreating] = useState(false);

  const filtered = useMemo(() => filterCampaignFrontierItems(frontier, {
    search,
    type: type || undefined,
    node,
    minPriority,
  }), [frontier, search, type, node, minPriority]);
  const selectedItems = useMemo(() => frontier.filter(item => selected.has(getFrontierKey(item))), [frontier, selected]);
  const metrics = useMemo(() => deriveCampaignPreviewMetrics(selectedItems), [selectedItems]);

  const submit = async () => {
    if (!name.trim() || selected.size === 0) return;
    setCreating(true);
    try {
      const campaign = await createCampaign({
        name: name.trim(),
        strategy,
        item_ids: selectedItems.map(getFrontierKey),
      });
      onCreated(campaign);
    } catch { /* keep builder open */ }
    finally { setCreating(false); }
  };

  return (
    <div className="min-w-0 min-h-0 flex flex-col gap-3 overflow-y-auto">
      <PanelSection title="Campaign Builder">
        <div className="grid grid-cols-2 gap-3">
          <label className="text-xs text-muted-foreground">
            Name
            <input value={name} onChange={e => setName(e.target.value)} className="settings-input mt-1 w-full" placeholder="Credential validation wave" />
          </label>
          <label className="text-xs text-muted-foreground">
            Strategy
            <select value={strategy} onChange={e => setStrategy(e.target.value as Campaign['strategy'])} className="settings-input mt-1 w-full">
              <option value="custom">Custom</option>
              <option value="credential_spray">Credential Spray</option>
              <option value="enumeration">Enumeration</option>
              <option value="post_exploitation">Post Exploitation</option>
              <option value="network_discovery">Network Discovery</option>
            </select>
          </label>
        </div>
      </PanelSection>

      <PanelSection title="Frontier Selection" meta={`(${selected.size} selected)`}>
        <FilterBar className="mb-3">
          <input value={search} onChange={e => setSearch(e.target.value)} className="settings-input w-56" placeholder="Search item, node, type..." />
          <input value={node} onChange={e => setNode(e.target.value)} className="settings-input w-44" placeholder="Node filter..." />
          <select value={type} onChange={e => setType(e.target.value)} className="settings-input w-auto text-xs">
            <option value="">All types</option>
            <option value="incomplete_node">Incomplete</option>
            <option value="untested_edge">Untested</option>
            <option value="inferred_edge">Inferred</option>
            <option value="network_discovery">Network</option>
            <option value="credential_test">Credential</option>
          </select>
          <label className="text-[11px] text-muted-foreground inline-flex items-center gap-1">
            Min priority
            <input type="number" min={0} step={0.5} value={minPriority} onChange={e => setMinPriority(Number(e.target.value) || 0)} className="settings-input w-20" />
          </label>
        </FilterBar>

        <div className="max-h-[330px] overflow-y-auto space-y-1.5">
          {filtered.length === 0 ? (
            <EmptyState message="No Frontier items match these filters." />
          ) : filtered.map(item => {
            const id = getFrontierKey(item);
            const checked = selected.has(id);
            return (
              <DataRow
                key={id}
                onClick={() => setSelected(prev => {
                  const next = new Set(prev);
                  checked ? next.delete(id) : next.add(id);
                  return next;
                })}
                className={cn('p-2.5', checked && 'border-accent/50 bg-accent/5')}
              >
                <div className="flex items-start gap-2">
                  <input readOnly type="checkbox" checked={checked} className="mt-0.5 accent-accent" />
                  <div className="min-w-0 flex-1">
                    <div className="text-xs text-foreground line-clamp-2">{item.description}</div>
                    <div className="mt-1 flex flex-wrap gap-1 text-[10px] text-muted-foreground">
                      <span>{item.type}</span>
                      <span>priority {(item.priority ?? 0).toFixed(1)}</span>
                      <span>noise {(item.opsec_noise ?? 0).toFixed(2)}</span>
                      <span className="font-mono">{campaignItemNodeLabel(item)}</span>
                    </div>
                  </div>
                </div>
              </DataRow>
            );
          })}
        </div>
      </PanelSection>

      <PanelSection title="Launch Preview">
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-2 text-xs">
          <DetailFact label="Selected" value={String(metrics.selectedCount)} />
          <DetailFact label="Expected Agents" value={String(metrics.expectedAgentCount)} />
          <DetailFact label="Max Priority" value={metrics.maxPriority.toFixed(1)} />
          <DetailFact label="Avg Noise" value={metrics.avgNoise.toFixed(2)} />
          <DetailFact label="Nodes" value={String(metrics.nodeIds.length)} />
        </div>
        <div className="mt-3 flex justify-end gap-2">
          <button onClick={onCancel} className="text-xs px-3 py-1 rounded bg-elevated text-muted-foreground border border-border hover:text-foreground">Cancel</button>
          <button onClick={submit} disabled={!name.trim() || selected.size === 0 || creating} className="settings-save-btn disabled:opacity-50">
            {creating ? 'Creating...' : 'Create Draft'}
          </button>
        </div>
      </PanelSection>
    </div>
  );
}

function DispatchPanel({ campaign, onDone }: { campaign: Campaign; onDone: () => void }) {
  const [maxAgents, setMaxAgents] = useState(3);
  const [scopeHops, setScopeHops] = useState(1);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    try {
      await dispatchCampaign(campaign.id, {
        max_agents: maxAgents,
        hops: scopeHops,
      });
      onDone();
    } catch { /* leave dispatch panel open */ }
    finally { setBusy(false); }
  };

  return (
    <PanelSection title="Explicit Dispatch Gate">
      {/* Throttle-seconds control removed: it was never wired server-side (the dispatch
          helper has no throttle option), so it silently did nothing. Concurrency is
          bounded by Max agents. */}
      <div className="grid grid-cols-2 gap-3">
        <label className="text-xs text-muted-foreground">
          Max agents
          <input type="number" min={1} max={20} value={maxAgents} onChange={e => setMaxAgents(parseInt(e.target.value, 10) || 1)} className="settings-input mt-1 w-full" />
        </label>
        <label className="text-xs text-muted-foreground">
          Scope hops
          <input type="number" min={0} max={5} value={scopeHops} onChange={e => setScopeHops(parseInt(e.target.value, 10) || 0)} className="settings-input mt-1 w-full" />
        </label>
      </div>
      <div className="mt-3 rounded border border-warning/20 bg-warning/10 p-2 text-xs text-warning">
        Dispatch launches agents from the campaign through the existing backend path. Individual action approval remains terminal-forward.
      </div>
      <div className="mt-3 flex justify-end">
        <button onClick={submit} disabled={busy} className="settings-save-btn disabled:opacity-50 inline-flex items-center gap-1">
          <Send className="h-3.5 w-3.5" />
          {busy ? 'Dispatching...' : 'Dispatch Agents'}
        </button>
      </div>
    </PanelSection>
  );
}

function CampaignItemRow({ item }: { item: FrontierItem }) {
  return (
    <div className="rounded border border-border bg-background/40 p-2">
      <div className="text-xs text-foreground line-clamp-2">{item.description}</div>
      <div className="mt-1 flex flex-wrap gap-1.5 text-[10px] text-muted-foreground">
        <StatusPill className="bg-elevated text-muted-foreground">{item.type}</StatusPill>
        <span>priority {(item.priority ?? 0).toFixed(1)}</span>
        <span>noise {(item.opsec_noise ?? 0).toFixed(2)}</span>
        <span className="font-mono">{campaignItemNodeLabel(item)}</span>
      </div>
    </div>
  );
}

function CampaignStat({ label, value, tone }: { label: string; value: number; tone?: 'success' | 'accent' }) {
  return (
    <div className="py-2 border-r border-border last:border-r-0">
      <div className={cn('text-base font-semibold tabular-nums', tone === 'success' && 'text-success', tone === 'accent' && 'text-accent')}>{value}</div>
      <div className="text-[10px] text-muted-foreground">{label}</div>
    </div>
  );
}

function DetailFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border border-border bg-elevated px-2 py-1.5 min-w-0">
      <div className="text-[10px] text-muted-foreground">{label}</div>
      <div className="text-xs text-foreground truncate">{value}</div>
    </div>
  );
}

function StatusDot({ status }: { status: Campaign['status'] }) {
  return <span className={cn('mt-1.5 w-2 h-2 rounded-full flex-shrink-0', dotClass(status))} />;
}

function statusClass(status: Campaign['status']): string {
  if (status === 'active') return 'bg-success/10 text-success';
  if (status === 'paused') return 'bg-warning/10 text-warning';
  if (status === 'aborted') return 'bg-destructive/10 text-destructive';
  if (status === 'completed') return 'bg-accent/10 text-accent';
  return 'bg-elevated text-muted-foreground';
}

function dotClass(status: Campaign['status']): string {
  if (status === 'active') return 'bg-success';
  if (status === 'paused') return 'bg-warning';
  if (status === 'aborted') return 'bg-destructive';
  if (status === 'completed') return 'bg-accent';
  return 'bg-muted';
}

function actionToneClass(tone: 'success' | 'warning' | 'destructive' | 'muted'): string {
  if (tone === 'success') return 'bg-success/10 text-success border-success/20 hover:bg-success/20';
  if (tone === 'warning') return 'bg-warning/10 text-warning border-warning/20 hover:bg-warning/20';
  if (tone === 'destructive') return 'bg-destructive/10 text-destructive border-destructive/20 hover:bg-destructive/20';
  return 'bg-elevated text-muted-foreground border-border hover:text-foreground';
}

function actionIcon(action: 'activate' | 'pause' | 'resume' | 'abort' | 'complete') {
  if (action === 'pause') return <Pause className="h-3.5 w-3.5" />;
  if (action === 'abort' || action === 'complete') return <Square className="h-3.5 w-3.5" />;
  return <Play className="h-3.5 w-3.5" />;
}
