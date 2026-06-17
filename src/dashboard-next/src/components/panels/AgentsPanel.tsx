import { useState, useEffect, useMemo, useCallback, useRef, type RefObject } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useEngagementStore } from '../../stores/engagement-store';
import { useToastStore } from '../../stores/toast-store';
import { useNavigation } from '../../hooks/useNavigation';
import * as api from '../../lib/api';
import type { AgentInfo, Campaign, AgentConsoleEvent, AgentConsoleKind } from '../../lib/types';
import { buildOperatorConsoleEvents } from '../../lib/operator-console';
import { getFrontierNodeIds, getFrontierKey } from '../../lib/frontier-workspace';
import { POLL } from '../../lib/polling';
import { OperatorCommandBar } from './OperatorCommandBar';
import { cn, formatElapsed, formatTimestamp } from '../../lib/utils';
import { ActionButton, FilterBar, InspectorDrawer, MetricTile, PageHeader, PanelSection, StatusPill } from '../shared/primitives';

const STRATEGY_ICONS: Record<string, string> = {
  credential_spray: '🔑',
  enumeration: '🔍',
  post_exploitation: '⚡',
  network_discovery: '🌐',
  custom: '⚙',
};

const STATUS_ORDER: Record<string, number> = {
  running: 0, pending: 1, failed: 2, interrupted: 3, completed: 4,
};

type ConsoleFilter = 'all' | 'primary' | 'subagents' | AgentConsoleKind | 'errors';
type AgentContext = { subgraph?: { nodes?: { id: string; properties?: Record<string, unknown> }[]; edges?: unknown[] } };

const CONSOLE_FILTERS: Array<{ value: ConsoleFilter; label: string }> = [
  { value: 'all', label: 'All' },
  { value: 'primary', label: 'Primary' },
  { value: 'subagents', label: 'Subagents' },
  { value: 'command', label: 'Commands' },
  { value: 'thought', label: 'Thoughts' },
  { value: 'action', label: 'Actions' },
  { value: 'finding', label: 'Findings' },
  { value: 'approval', label: 'Approvals' },
  { value: 'session', label: 'Sessions' },
  { value: 'errors', label: 'Errors' },
];

function sortAgents(list: AgentInfo[]): AgentInfo[] {
  return [...list].sort((a, b) => (STATUS_ORDER[a.status] ?? 5) - (STATUS_ORDER[b.status] ?? 5));
}

function isScrolledNearBottom(el: HTMLElement | null, threshold = 48): boolean {
  if (!el) return true;
  return el.scrollHeight - el.scrollTop - el.clientHeight <= threshold;
}

export function AgentsPanel() {
  const agents = useEngagementStore((s) => s.agents);
  const initialized = useEngagementStore((s) => s.initialized);
  const connected = useEngagementStore((s) => s.connected);
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [activeAgentId, setActiveAgentId] = useState<string>('all');
  const [activeContext, setActiveContext] = useState<AgentContext | null>(null);
  const [drawerAgent, setDrawerAgent] = useState<AgentInfo | null>(null);
  const [drawerContext, setDrawerContext] = useState<AgentContext | null>(null);
  const [consoleEvents, setConsoleEvents] = useState<AgentConsoleEvent[]>([]);
  const [consoleFilter, setConsoleFilter] = useState<ConsoleFilter>('all');
  const [consolePaused, setConsolePaused] = useState(false);
  const [consoleFollowing, setConsoleFollowing] = useState(true);
  const [consoleSearch, setConsoleSearch] = useState('');
  const consoleEndRef = useRef<HTMLDivElement | null>(null);
  const consoleScrollRef = useRef<HTMLDivElement | null>(null);
  const [showDispatch, setShowDispatch] = useState(false);
  const [showBulkDispatch, setShowBulkDispatch] = useState(false);
  const { navigateToGraph, navigateToCampaign, navigateToPanel } = useNavigation();
  const setStoreAgents = useEngagementStore((s) => s.setAgents);

  const refreshAgents = useCallback(async () => {
    try {
      const data = await api.getAgents();
      setStoreAgents(data.agents || []);
      setSelectedIds(prev => {
        const validIds = new Set((data.agents || []).map((a: AgentInfo) => a.id));
        const next = new Set([...prev].filter(id => validIds.has(id)));
        return next.size !== prev.size ? next : prev;
      });
    } catch { /* silent */ }
  }, [setStoreAgents]);

  // Safety net: pull fresh agent state on mount in case the WS full_state
  // arrived before this panel mounted (or before the backend was patched
  // to include `agents` in EngagementState). Cheap — single GET.
  useEffect(() => { refreshAgents(); }, [refreshAgents]);

  // Campaign groups
  const { groups, ungrouped } = useMemo(() => {
    const g = new Map<string, { name: string; strategy: string; agents: AgentInfo[] }>();
    const ug: AgentInfo[] = [];
    for (const a of agents) {
      const cid = a.campaign_id || a.campaign?.id;
      if (cid) {
        if (!g.has(cid)) g.set(cid, { name: a.campaign?.name || cid, strategy: a.campaign?.strategy || '', agents: [] });
        g.get(cid)!.agents.push(a);
      } else { ug.push(a); }
    }
    return { groups: g, ungrouped: ug };
  }, [agents]);

  const running = agents.filter(a => a.status === 'running');
  const completed = agents.filter(a => a.status === 'completed');
  const failed = agents.filter(a => a.status === 'failed' || a.status === 'interrupted');
  // Select by task id OR agent label so deep-links from other panels (e.g. a
  // SessionRow chip carrying the agent label) resolve.
  const activeAgent = activeAgentId === 'all'
    ? null
    : agents.find(agent => agent.id === activeAgentId || agent.agent_id === activeAgentId) || null;

  useEffect(() => {
    if (activeAgentId !== 'all' && !activeAgent) setActiveAgentId('all');
  }, [activeAgent, activeAgentId]);

  // Honor the ?item=<id|label> deep-link convention every sibling panel uses,
  // so cross-links into the Operator console select the targeted agent.
  const [searchParams] = useSearchParams();
  useEffect(() => {
    const item = searchParams.get('item');
    if (item && agents.some(a => a.id === item || a.agent_id === item)) {
      setActiveAgentId(item);
    }
  }, [searchParams, agents]);

  const toggleGroup = (gid: string) => {
    setCollapsedGroups(prev => { const n = new Set(prev); n.has(gid) ? n.delete(gid) : n.add(gid); return n; });
  };

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  };

  const selectAll = () => {
    if (selectedIds.size === agents.length) setSelectedIds(new Set());
    else setSelectedIds(new Set(agents.map(a => a.id)));
  };

  const cancelAgent = async (id: string) => {
    try { await api.cancelAgent(id); await refreshAgents(); } catch { /* silent */ }
  };

  const batchCancel = async () => {
    const cancellable = agents.filter(a => selectedIds.has(a.id) && (a.status === 'running' || a.status === 'pending'));
    await Promise.allSettled(cancellable.map(a => api.cancelAgent(a.id)));
    setSelectedIds(new Set());
    await refreshAgents();
  };

  const cancelGroup = async (gid: string) => {
    const group = gid === '__ungrouped__'
      ? agents.filter(a => !a.campaign_id && !a.campaign?.id)
      : agents.filter(a => (a.campaign_id || a.campaign?.id) === gid);
    const cancellable = group.filter(a => a.status === 'running' || a.status === 'pending');
    await Promise.allSettled(cancellable.map(a => api.cancelAgent(a.id)));
    await refreshAgents();
  };

  useEffect(() => {
    let cancelled = false;
    if (!activeAgent) {
      setActiveContext(null);
      return () => { cancelled = true; };
    }
    api.getAgentContext(activeAgent.id)
      .then(ctx => { if (!cancelled) setActiveContext(ctx as AgentContext); })
      .catch(() => { if (!cancelled) setActiveContext(null); });
    return () => { cancelled = true; };
  }, [activeAgent?.id]);

  const loadConsole = useCallback(async () => {
    try {
      if (activeAgent) {
        const data = await api.getAgentConsole(activeAgent.id, { limit: 140 });
        setConsoleEvents(data.events || []);
      } else {
        const data = await api.getHistory({ limit: 300 });
        setConsoleEvents(buildOperatorConsoleEvents(data.entries || [], { agents, limit: 180 }));
      }
    } catch {
      setConsoleEvents([]);
    }
  }, [activeAgent?.id, agents]);

  useEffect(() => { loadConsole(); }, [loadConsole]);

  useEffect(() => {
    if (consolePaused) return;
    // The live WS push now carries primary/dashboard attribution (3A.3), so this
    // poll is just reconciliation behind the push — keep it brisk for the primary
    // cockpit view, slower for a single-agent drawer.
    const timer = setInterval(() => {
      if (connected) void loadConsole();
    }, activeAgent ? POLL.CONSOLE_DRAWER_MS : POLL.CONSOLE_PRIMARY_MS);
    return () => clearInterval(timer);
  }, [activeAgent, connected, consolePaused, loadConsole]);

  useEffect(() => {
    let refreshTimer: ReturnType<typeof setTimeout> | null = null;
    const handleUpdate = (event: Event) => {
      if (consolePaused) return;
      const detail = (event as CustomEvent<{ events?: AgentConsoleEvent[] }>).detail;
      const all = detail?.events || [];
      if (all.length === 0) return;
      if (!activeAgent) {
        // The primary cockpit is rendered by the CLIENT builder
        // (buildOperatorConsoleEvents off /api/history). The WS payload is built
        // by the SERVER builder, which titles/labels the same event_id slightly
        // differently — merging it would flip rows on every poll. So in the
        // primary view the push is just a "something changed" signal: debounce a
        // re-fetch so the client builder stays the single source of truth.
        if (!refreshTimer) refreshTimer = setTimeout(() => { refreshTimer = null; void loadConsole(); }, 400);
        return;
      }
      // Per-agent drawer: both the poll (getAgentConsole) and the WS push use the
      // SERVER builder, so merging is consistent — no flip.
      const incoming = all.filter(item => item.agent_id === activeAgent.id || item.agent_id === activeAgent.agent_id);
      if (incoming.length === 0) return;
      setConsoleEvents(prev => mergeConsoleEvents(prev, incoming));
    };
    window.addEventListener('overwatch-agent-console-update', handleUpdate);
    return () => {
      window.removeEventListener('overwatch-agent-console-update', handleUpdate);
      if (refreshTimer) clearTimeout(refreshTimer);
    };
  }, [activeAgent, consolePaused, loadConsole]);

  const scrollConsoleToBottom = useCallback(() => {
    requestAnimationFrame(() => {
      const el = consoleScrollRef.current;
      if (!el) return;
      el.scrollTop = el.scrollHeight;
    });
  }, []);

  useEffect(() => {
    if (!consolePaused && consoleFollowing) scrollConsoleToBottom();
  }, [consoleEvents, consolePaused, consoleFollowing, scrollConsoleToBottom]);

  const visibleConsoleEvents = useMemo(() => {
    const q = consoleSearch.trim().toLowerCase();
    return consoleEvents.filter(event => {
      if (consoleFilter === 'errors' && event.severity !== 'error' && event.severity !== 'warning') return false;
      if (consoleFilter === 'primary' && event.source_kind !== 'primary') return false;
      if (consoleFilter === 'subagents' && event.source_kind !== 'subagent') return false;
      if (!['all', 'errors', 'primary', 'subagents'].includes(consoleFilter) && event.kind !== consoleFilter) return false;
      if (!q) return true;
      return [
        event.title,
        event.summary,
        event.agent_id,
        event.source_label,
        event.source_kind,
        event.status,
        event.links?.action_id,
        event.links?.frontier_item_id,
        event.links?.evidence_id,
        event.links?.session_id,
        ...(event.links?.node_ids || []),
      ].some(value => typeof value === 'string' && value.toLowerCase().includes(q));
    });
  }, [consoleEvents, consoleFilter, consoleSearch]);

  const openDetail = async (agent: AgentInfo) => {
    setDrawerAgent(agent);
    try {
      const ctx = activeAgent?.id === agent.id && activeContext
        ? activeContext
        : await api.getAgentContext(agent.id);
      setDrawerContext(ctx as AgentContext);
    } catch {
      setDrawerContext(null);
    }
  };

  return (
    <div className="h-[calc(100vh-7rem)] min-h-[720px] space-y-4 overflow-hidden">
      <PageHeader
        title="Operator Console"
        meta={activeAgent ? `subagent ${activeAgent.agent_id || activeAgent.id}` : 'primary operator + subagents'}
        actions={(
          <FilterBar>
          <div className="flex gap-2 text-xs">
            <span className="text-success">{running.length} running</span>
            <span className="text-muted-foreground">{completed.length} done</span>
            {failed.length > 0 && <span className="text-destructive">{failed.length} failed</span>}
          </div>
          <ActionButton
            onClick={() => setShowDispatch(true)}
            variant="ghost"
            className="text-accent"
          >
            Dispatch Subagent
          </ActionButton>
          <ActionButton
            onClick={() => setShowBulkDispatch(true)}
            variant="purple"
          >
            Bulk from Frontier
          </ActionButton>
          </FilterBar>
        )}
      />

      {/* NL operator command bar — primary console view only (a subagent drawer
          steers one agent; the cockpit command bar acts across the engagement). */}
      {!activeAgent && <OperatorCommandBar />}

      {/* Batch bar */}
      {selectedIds.size > 0 && (
        <div className="bg-accent-dim border border-accent/30 rounded-md px-3 py-2 flex items-center gap-3 text-xs">
          <span className="text-accent font-medium">{selectedIds.size} selected</span>
          <ActionButton onClick={batchCancel} variant="danger" size="xs">
            Cancel Selected
          </ActionButton>
          <ActionButton onClick={() => setSelectedIds(new Set())} variant="ghost" size="xs">
            Deselect
          </ActionButton>
        </div>
      )}

      {!initialized ? (
        <div className="text-sm text-muted-foreground animate-pulse">Loading…</div>
      ) : (
        <div className="grid h-[calc(100%-4.25rem)] min-h-0 grid-cols-1 gap-4 xl:grid-cols-[minmax(260px,330px)_minmax(0,1fr)_minmax(280px,360px)]">
          <AgentRoster
            agents={agents}
            groups={groups}
            ungrouped={ungrouped}
            activeAgentId={activeAgentId}
            selectedIds={selectedIds}
            collapsedGroups={collapsedGroups}
            onSelectAllOutput={() => setActiveAgentId('all')}
            onSelectAgent={(agent) => setActiveAgentId(agent.id)}
            onToggleSelect={toggleSelect}
            onSelectAll={selectAll}
            onToggleGroup={toggleGroup}
            onCancelAgent={cancelAgent}
            onCancelGroup={cancelGroup}
            onOpenDetail={openDetail}
          />

          <AgentOutputConsole
            activeAgent={activeAgent}
            events={visibleConsoleEvents}
            totalEvents={consoleEvents.length}
            filter={consoleFilter}
            search={consoleSearch}
            paused={consolePaused}
            following={consoleFollowing}
            endRef={consoleEndRef}
            scrollRef={consoleScrollRef}
            onFilterChange={setConsoleFilter}
            onSearchChange={setConsoleSearch}
            onTogglePaused={() => {
              const nextPaused = !consolePaused;
              setConsolePaused(nextPaused);
              if (!nextPaused) {
                setConsoleFollowing(true);
                void loadConsole().then(scrollConsoleToBottom);
              }
            }}
            onScroll={() => setConsoleFollowing(isScrolledNearBottom(consoleScrollRef.current))}
            onJumpLatest={() => {
              setConsoleFollowing(true);
              scrollConsoleToBottom();
            }}
            onRefresh={loadConsole}
            onNavigateGraph={(nodeId) => navigateToGraph(nodeId, 1)}
            onNavigatePanel={navigateToPanel}
          />

          <AgentContextPanel
            agent={activeAgent}
            context={activeContext}
            onOpenDetail={activeAgent ? () => openDetail(activeAgent) : undefined}
            onCancel={activeAgent && (activeAgent.status === 'running' || activeAgent.status === 'pending')
              ? () => cancelAgent(activeAgent.id)
              : undefined}
            onNavigateGraph={(nodeId) => navigateToGraph(nodeId, 1)}
            onNavigateCampaign={navigateToCampaign}
          />
        </div>
      )}

      {/* Detail Drawer */}
      {drawerAgent && (
        <AgentDetailDrawer
          agent={drawerAgent}
          context={drawerContext}
          onClose={() => { setDrawerAgent(null); setDrawerContext(null); }}
          onCancel={() => { cancelAgent(drawerAgent.id); setDrawerAgent(null); }}
          onNavigateGraph={(nodeId) => navigateToGraph(nodeId, 1)}
          onNavigateCampaign={(cid) => navigateToCampaign(cid)}
          onNavigatePanel={navigateToPanel}
        />
      )}

      {/* Dispatch Modal */}
      {showDispatch && (
        <DispatchModal
          onClose={() => setShowDispatch(false)}
          onDispatched={() => { setShowDispatch(false); refreshAgents(); }}
        />
      )}

      {/* Bulk Frontier Dispatch Modal */}
      {showBulkDispatch && (
        <BulkFrontierDispatchModal
          onClose={() => setShowBulkDispatch(false)}
          onDispatched={() => { setShowBulkDispatch(false); refreshAgents(); }}
        />
      )}
    </div>
  );
}

// ---- Agent Workbench ----

function AgentRoster({
  agents,
  groups,
  ungrouped,
  activeAgentId,
  selectedIds,
  collapsedGroups,
  onSelectAllOutput,
  onSelectAgent,
  onToggleSelect,
  onSelectAll,
  onToggleGroup,
  onCancelAgent,
  onCancelGroup,
  onOpenDetail,
}: {
  agents: AgentInfo[];
  groups: Map<string, { name: string; strategy: string; agents: AgentInfo[] }>;
  ungrouped: AgentInfo[];
  activeAgentId: string;
  selectedIds: Set<string>;
  collapsedGroups: Set<string>;
  onSelectAllOutput: () => void;
  onSelectAgent: (agent: AgentInfo) => void;
  onToggleSelect: (id: string) => void;
  onSelectAll: () => void;
  onToggleGroup: (id: string) => void;
  onCancelAgent: (id: string) => void;
  onCancelGroup: (id: string) => void;
  onOpenDetail: (agent: AgentInfo) => void;
}) {
  const running = agents.filter(agent => agent.status === 'running').length;
  const failed = agents.filter(agent => agent.status === 'failed' || agent.status === 'interrupted').length;

  return (
    <PanelSection className="min-h-0 overflow-hidden p-0 flex flex-col">
      <div className="border-b border-border p-3">
        <div className="flex items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-foreground">Operator Sources</h3>
            <p className="mt-0.5 text-[11px] text-muted-foreground">The primary model stays pinned; subagents are secondary filters.</p>
          </div>
          <StatusPill tone={failed > 0 ? 'danger' : running > 0 ? 'success' : 'muted'}>
            {running} live
          </StatusPill>
        </div>
      </div>

      <div className="border-b border-border p-2">
        <button
          onClick={onSelectAllOutput}
          className={cn(
            'w-full rounded-md border px-3 py-2 text-left transition-colors',
            activeAgentId === 'all'
              ? 'border-accent/60 bg-accent/10'
              : 'border-border bg-background/40 hover:bg-hover/40',
          )}
        >
          <div className="flex items-center justify-between gap-2">
            <span className="text-sm font-medium text-foreground">Primary Operator</span>
            <span className="text-[10px] text-muted-foreground">{agents.length} subagents</span>
          </div>
          <div className="mt-1 text-[11px] text-muted-foreground">Main model output and unassigned operator activity.</div>
        </button>

        <label className="mt-2 flex items-center gap-2 text-xs text-muted-foreground px-1 cursor-pointer">
          <input
            type="checkbox"
            checked={selectedIds.size === agents.length && agents.length > 0}
            onChange={onSelectAll}
            className="accent-accent"
          />
          Select all subagents for batch controls
        </label>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="px-3 pb-1 pt-2 text-[10px] uppercase tracking-wider text-muted-foreground">Subagents</div>
        {[...groups.entries()].map(([cid, group]) => {
          const isCollapsed = collapsedGroups.has(cid);
          const runningCount = group.agents.filter(a => a.status === 'running').length;
          const hasRunning = group.agents.some(a => a.status === 'running' || a.status === 'pending');
          const icon = STRATEGY_ICONS[group.strategy] || '⚙';

          return (
            <div key={cid} className="border-b border-border">
              <button
                onClick={() => onToggleGroup(cid)}
                className="w-full px-3 py-2 flex items-center gap-2 text-xs hover:bg-hover transition-colors"
              >
                <span className="text-muted-foreground">{isCollapsed ? '▸' : '▾'}</span>
                <span>{icon}</span>
                <span className="font-medium text-foreground flex-1 text-left truncate">{group.name}</span>
                <span className="text-muted-foreground">{runningCount}/{group.agents.length}</span>
                {hasRunning && (
                  <span
                    onClick={e => { e.stopPropagation(); onCancelGroup(cid); }}
                    className="px-1.5 py-0.5 rounded text-destructive hover:bg-destructive/10 cursor-pointer"
                  >
                    Cancel
                  </span>
                )}
              </button>
              {!isCollapsed && sortAgents(group.agents).map(agent => (
                <AgentCard
                  key={agent.id}
                  agent={agent}
                  active={activeAgentId === agent.id}
                  selected={selectedIds.has(agent.id)}
                  onToggleSelect={() => onToggleSelect(agent.id)}
                  onCancel={() => onCancelAgent(agent.id)}
                  onClick={() => onSelectAgent(agent)}
                  onOpenDetail={() => onOpenDetail(agent)}
                />
              ))}
            </div>
          );
        })}

        {ungrouped.length > 0 && (
          <div className="border-b border-border">
            <button
              onClick={() => onToggleGroup('__ungrouped__')}
              className="w-full px-3 py-2 flex items-center gap-2 text-xs hover:bg-hover transition-colors"
            >
              <span className="text-muted-foreground">{collapsedGroups.has('__ungrouped__') ? '▸' : '▾'}</span>
              <span className="font-medium text-foreground flex-1 text-left">Ungrouped</span>
              <span className="text-muted-foreground">{ungrouped.length}</span>
            </button>
            {!collapsedGroups.has('__ungrouped__') && sortAgents(ungrouped).map(agent => (
              <AgentCard
                key={agent.id}
                agent={agent}
                active={activeAgentId === agent.id}
                selected={selectedIds.has(agent.id)}
                onToggleSelect={() => onToggleSelect(agent.id)}
                onCancel={() => onCancelAgent(agent.id)}
                onClick={() => onSelectAgent(agent)}
                onOpenDetail={() => onOpenDetail(agent)}
              />
            ))}
          </div>
        )}
        {agents.length === 0 && (
          <div className="mx-2 mb-2 rounded border border-dashed border-border bg-background/40 p-3 text-xs text-muted-foreground">
            No subagents active. The primary operator stream remains available.
          </div>
        )}
      </div>
    </PanelSection>
  );
}

function AgentOutputConsole({
  activeAgent,
  events,
  totalEvents,
  filter,
  search,
  paused,
  following,
  endRef,
  scrollRef,
  onFilterChange,
  onSearchChange,
  onTogglePaused,
  onScroll,
  onJumpLatest,
  onRefresh,
  onNavigateGraph,
  onNavigatePanel,
}: {
  activeAgent: AgentInfo | null;
  events: AgentConsoleEvent[];
  totalEvents: number;
  filter: ConsoleFilter;
  search: string;
  paused: boolean;
  following: boolean;
  endRef: RefObject<HTMLDivElement | null>;
  scrollRef: RefObject<HTMLDivElement | null>;
  onFilterChange: (filter: ConsoleFilter) => void;
  onSearchChange: (value: string) => void;
  onTogglePaused: () => void;
  onScroll: () => void;
  onJumpLatest: () => void;
  onRefresh: () => void;
  onNavigateGraph: (nodeId: string) => void;
  onNavigatePanel: ReturnType<typeof useNavigation>['navigateToPanel'];
}) {
  return (
    <PanelSection className="min-h-0 overflow-hidden p-0 flex flex-col border-accent/20">
      <div className="border-b border-border p-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h3 className="text-base font-semibold text-foreground">Operator Output</h3>
              <StatusPill tone={paused ? 'warning' : following ? 'success' : 'muted'}>
                {paused ? 'paused' : following ? 'following' : 'reading'}
              </StatusPill>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              {activeAgent
                ? `Filtered to subagent ${activeAgent.agent_id || activeAgent.id}.`
                : 'Primary model output plus subagent events, derived from Activity without duplicating raw output.'}
            </p>
          </div>
          <div className="flex flex-wrap justify-end gap-1.5">
            {!following && !paused && (
              <ActionButton onClick={onJumpLatest} variant="ghost" size="xs">
                Jump to latest
              </ActionButton>
            )}
            <ActionButton onClick={onTogglePaused} variant={paused ? 'warning' : 'secondary'} size="xs">
              {paused ? 'Resume' : 'Pause'}
            </ActionButton>
            <ActionButton onClick={onRefresh} variant="secondary" size="xs">
              Refresh
            </ActionButton>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2">
          <input
            value={search}
            onChange={event => onSearchChange(event.target.value)}
            placeholder="Filter output..."
            className="settings-input flex-1 min-w-48"
          />
          <div className="flex flex-wrap gap-1">
            {CONSOLE_FILTERS.map(option => (
              <button
                key={option.value}
                onClick={() => onFilterChange(option.value)}
                className={cn(
                  'rounded px-2 py-1 text-[10px] transition-colors',
                  filter === option.value
                    ? 'bg-accent text-accent-foreground'
                    : 'bg-elevated text-muted-foreground hover:text-foreground',
                )}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div ref={scrollRef} onScroll={onScroll} className="min-h-0 flex-1 overflow-y-auto bg-background/30 p-3">
        {events.length === 0 ? (
          <div className="flex h-full min-h-64 items-center justify-center rounded border border-dashed border-border text-sm text-muted-foreground">
            {totalEvents === 0 ? 'No operator output yet.' : 'No output matches the current filters.'}
          </div>
        ) : (
          <div className="space-y-2">
            {events.map(event => (
              <AgentConsoleRow
                key={event.id}
                event={event}
                prominent
                onNavigateGraph={onNavigateGraph}
                onNavigatePanel={onNavigatePanel}
              />
            ))}
            <div ref={endRef} />
          </div>
        )}
      </div>
    </PanelSection>
  );
}

// Per-agent lifecycle steering (Phase 3B). One-click directives routed through
// the validated /api/agents/:id/directive → executeOps path. Targeted kinds
// (narrow_scope/skip_types/prioritize) + free-text instruction come via the
// per-agent NL box in Stage 2.
function AgentSteeringControls({ taskId, onIssued }: { taskId: string; onIssued?: () => void }) {
  const addToast = useToastStore(s => s.addToast);
  const [busy, setBusy] = useState<string | null>(null);
  const issue = async (kind: api.DirectiveKind) => {
    setBusy(kind);
    try {
      const res = await api.issueDirective(taskId, kind);
      addToast({ type: res.ok ? 'success' : 'warning', title: `Directive: ${kind}`, message: res.ok ? 'issued — agent honors it on its next heartbeat' : 'not applied' });
      onIssued?.();
    } catch (err) {
      addToast({ type: 'error', title: `Directive failed: ${kind}`, message: err instanceof Error ? err.message : String(err) });
    } finally { setBusy(null); }
  };
  return (
    <div className="mt-3">
      <div className="mb-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">Steer</div>
      <div className="flex flex-wrap gap-1.5">
        <ActionButton size="xs" variant="warning" disabled={!!busy} onClick={() => issue('pause')}>Pause</ActionButton>
        <ActionButton size="xs" variant="success" disabled={!!busy} onClick={() => issue('resume')}>Resume</ActionButton>
        <ActionButton size="xs" variant="danger" disabled={!!busy} onClick={() => issue('stop')}>Stop</ActionButton>
      </div>
    </div>
  );
}

// Live summary of the engagement's agent fleet shown when no sub-agent is
// selected (replaces the old static stub). Reads the store directly.
function PrimaryOperatorPanel() {
  const agents = useEngagementStore(s => s.agents);
  const pendingActions = useEngagementStore(s => s.pendingActions);
  const campaigns = useEngagementStore(s => s.campaigns);
  const recentActivity = useEngagementStore(s => s.recentActivity);
  const { navigateToPanel } = useNavigation();

  const running = agents.filter(a => a.status === 'running').length;
  const queued = agents.filter(a => a.status === 'pending').length;
  const done = agents.filter(a => a.status === 'completed').length;
  const failed = agents.filter(a => a.status === 'failed').length;
  const activeCampaigns = campaigns.filter(c => c.status === 'active').length;
  const latestPrimary = [...recentActivity].reverse().find(
    e => e.event_type !== 'heartbeat' && (e.source_kind === 'primary' || (!e.agent_id && e.source_kind !== 'subagent')),
  );

  return (
    <PanelSection className="min-h-0 overflow-y-auto">
      <h3 className="text-sm font-semibold text-foreground">Primary Operator</h3>
      <p className="mt-1 text-xs text-muted-foreground">
        The primary model orchestrates; sub-agents are dispatched workers. Select one to inspect &amp; steer it.
      </p>

      <div className="mt-3 grid grid-cols-2 gap-2">
        <MetricTile label="Running" value={running} accent={running > 0} onClick={() => navigateToPanel('agents')} />
        <MetricTile label="Queued" value={queued} />
        <MetricTile label="Completed" value={done} />
        <MetricTile label="Failed" value={failed} />
      </div>

      <div className="mt-3 space-y-2 rounded border border-border bg-background/40 p-3 text-xs">
        <button onClick={() => navigateToPanel('actions')} className="flex w-full items-center justify-between hover:text-accent">
          <span className="text-muted-foreground">Pending approvals</span>
          <StatusPill tone={pendingActions.length ? 'warning' : 'muted'}>{String(pendingActions.length)}</StatusPill>
        </button>
        <button onClick={() => navigateToPanel('campaigns')} className="flex w-full items-center justify-between hover:text-accent">
          <span className="text-muted-foreground">Active campaigns</span>
          <StatusPill tone={activeCampaigns ? 'accent' : 'muted'}>{String(activeCampaigns)}</StatusPill>
        </button>
      </div>

      {latestPrimary && (
        <div className="mt-3">
          <div className="mb-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">Latest primary activity</div>
          <div className="rounded border border-border bg-background/40 p-2 text-xs text-foreground/90">{latestPrimary.description}</div>
        </div>
      )}
    </PanelSection>
  );
}

function AgentContextPanel({
  agent,
  context,
  onOpenDetail,
  onCancel,
  onNavigateGraph,
  onNavigateCampaign,
}: {
  agent: AgentInfo | null;
  context: AgentContext | null;
  onOpenDetail?: () => void;
  onCancel?: () => void;
  onNavigateGraph: (nodeId: string) => void;
  onNavigateCampaign: (campaignId: string) => void;
}) {
  if (!agent) {
    return <PrimaryOperatorPanel />;
  }

  const elapsed = agent.elapsed_ms
    ? formatElapsed(agent.elapsed_ms)
    : agent.completed_at && agent.assigned_at
      ? formatElapsed(new Date(agent.completed_at).getTime() - new Date(agent.assigned_at).getTime())
      : '—';
  const subgraphNodes = context?.subgraph?.nodes || [];

  return (
    <PanelSection className="min-h-0 overflow-y-auto">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="truncate text-sm font-semibold text-foreground">{agent.agent_id || agent.id}</h3>
          <p className="mt-0.5 font-mono text-[10px] text-muted-foreground break-all">{agent.id}</p>
        </div>
        <StatusPill tone={agent.status === 'running' ? 'success' : agent.status === 'failed' ? 'danger' : agent.status === 'completed' ? 'accent' : 'muted'}>
          {agent.status}
        </StatusPill>
      </div>

      <div className="mt-3 flex flex-wrap gap-1.5">
        {onOpenDetail && <ActionButton onClick={onOpenDetail} size="xs" variant="secondary">Inspect</ActionButton>}
        {onCancel && <ActionButton onClick={onCancel} size="xs" variant="danger">Cancel</ActionButton>}
        {agent.campaign_id && (
          <ActionButton onClick={() => onNavigateCampaign(agent.campaign_id!)} size="xs" variant="ghost">
            Campaign
          </ActionButton>
        )}
      </div>

      {agent.status === 'running' && <AgentSteeringControls taskId={agent.id} />}

      <div className="mt-4 space-y-2">
        <DetailRow label="Elapsed" value={elapsed} />
        {agent.skill && <DetailRow label="Skill" value={agent.skill} />}
        {agent.frontier_item_id && <DetailRow label="Frontier" value={agent.frontier_item_id} mono />}
        {agent.result_summary && <DetailRow label="Result" value={agent.result_summary} />}
        <DetailRow label="Scope" value={`${(agent.subgraph_node_ids || agent.scope_node_ids || []).length} nodes`} />
      </div>

      {subgraphNodes.length > 0 && (
        <div className="mt-4">
          <div className="mb-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">Scoped Nodes</div>
          <div className="space-y-1">
            {subgraphNodes.slice(0, 12).map(node => (
              <button
                key={node.id}
                onClick={() => onNavigateGraph(node.id)}
                className="block w-full truncate rounded bg-elevated/60 px-2 py-1 text-left text-xs text-accent hover:bg-hover"
                title={node.id}
              >
                {String(node.properties?.label || node.id)}
              </button>
            ))}
            {subgraphNodes.length > 12 && (
              <div className="text-[10px] text-muted-foreground">and {subgraphNodes.length - 12} more</div>
            )}
          </div>
        </div>
      )}
    </PanelSection>
  );
}

// ---- Agent Card ----

function AgentCard({
  agent,
  active,
  selected,
  onToggleSelect,
  onCancel,
  onClick,
  onOpenDetail,
}: {
  agent: AgentInfo;
  active: boolean;
  selected: boolean;
  onToggleSelect: () => void;
  onCancel: () => void;
  onClick: () => void;
  onOpenDetail: () => void;
}) {
  const cancellable = agent.status === 'running' || agent.status === 'pending';
  const elapsed = agent.elapsed_ms ? formatElapsed(agent.elapsed_ms) : '';
  const summary = agent.result_summary
    ? (agent.result_summary.length > 80 ? agent.result_summary.slice(0, 77) + '…' : agent.result_summary)
    : '';

  // Compute findings/min rate for running agents
  const rate = agent.status === 'running' && agent.elapsed_ms && agent.elapsed_ms > 60_000 && agent.findings_count
    ? ((agent.findings_count / agent.elapsed_ms) * 60_000).toFixed(1)
    : null;

  return (
    <div
      onClick={onClick}
      className={cn(
        'px-3 py-2 border-b border-border last:border-b-0 hover:bg-hover/50 transition-colors cursor-pointer',
        active && 'bg-accent/10 border-l-2 border-l-accent',
      )}
    >
      <div className="flex items-center gap-2">
        <input
          type="checkbox"
          checked={selected}
          onChange={e => { e.stopPropagation(); onToggleSelect(); }}
          onClick={e => e.stopPropagation()}
          className="accent-accent"
        />
        <span className={cn(
          'w-2 h-2 rounded-full flex-shrink-0',
          agent.status === 'running' && 'bg-success animate-pulse',
          agent.status === 'completed' && 'bg-accent',
          agent.status === 'failed' && 'bg-destructive',
          agent.status === 'interrupted' && 'bg-warning',
          agent.status === 'pending' && 'bg-muted',
        )} />
        <span className="text-xs font-mono text-muted-foreground truncate" title={agent.agent_id || agent.id}>{agent.agent_id || agent.id}</span>
        <button
          onClick={e => { e.stopPropagation(); onOpenDetail(); }}
          className="ml-auto rounded px-1.5 py-0.5 text-[10px] text-muted-foreground hover:bg-hover hover:text-foreground"
        >
          Inspect
        </button>
        {cancellable && (
          <button
            onClick={e => { e.stopPropagation(); onCancel(); }}
            className="text-muted-foreground hover:text-destructive text-xs"
            title="Cancel"
          >
            ✕
          </button>
        )}
      </div>
      <div className="flex items-center gap-2 mt-0.5 ml-6 text-xs">
        <span className={cn(
          'font-medium',
          agent.status === 'running' && 'text-success',
          agent.status === 'completed' && 'text-accent',
          agent.status === 'failed' && 'text-destructive',
          agent.status === 'interrupted' && 'text-warning',
          agent.status === 'pending' && 'text-muted-foreground',
        )}>
          {agent.status}
        </span>
        {agent.skill && <span className="text-muted-foreground bg-elevated px-1 py-0.5 rounded text-[10px]">{agent.skill}</span>}
        {elapsed && <span className="text-muted-foreground">{elapsed}</span>}
        {agent.findings_count != null && agent.findings_count > 0 && (
          <span className="text-success text-[10px]">{agent.findings_count} findings</span>
        )}
        {rate && <span className="text-accent text-[10px]">{rate}/min</span>}
      </div>
      {summary && <div className="text-[10px] text-muted-foreground mt-1 ml-6 truncate">{summary}</div>}
    </div>
  );
}

// ---- Agent Detail Drawer ----

function AgentDetailDrawer({
  agent,
  context,
  onClose,
  onCancel,
  onNavigateGraph,
  onNavigateCampaign,
  onNavigatePanel,
}: {
  agent: AgentInfo;
  context: { subgraph?: { nodes?: { id: string; properties?: Record<string, unknown> }[]; edges?: unknown[] } } | null;
  onClose: () => void;
  onCancel: () => void;
  onNavigateGraph: (nodeId: string) => void;
  onNavigateCampaign?: (campaignId: string) => void;
  onNavigatePanel: ReturnType<typeof useNavigation>['navigateToPanel'];
}) {
  const cancellable = agent.status === 'running' || agent.status === 'pending';
  const elapsed = agent.elapsed_ms
    ? formatElapsed(agent.elapsed_ms)
    : agent.completed_at && agent.assigned_at
      ? formatElapsed(new Date(agent.completed_at).getTime() - new Date(agent.assigned_at).getTime())
      : '—';

  const subgraphNodes = context?.subgraph?.nodes || [];

  const [consoleEvents, setConsoleEvents] = useState<AgentConsoleEvent[]>([]);
  const [consoleFilter, setConsoleFilter] = useState<ConsoleFilter>('all');
  const [consolePaused, setConsolePaused] = useState(false);
  const [consoleFollowing, setConsoleFollowing] = useState(true);
  const consoleEndRef = useRef<HTMLDivElement | null>(null);
  const consoleScrollRef = useRef<HTMLDivElement | null>(null);

  const loadConsole = useCallback(async () => {
    try {
      const data = await api.getAgentConsole(agent.id, { limit: 80 });
      setConsoleEvents(data.events || []);
    } catch {
      setConsoleEvents([]);
    }
  }, [agent.id]);

  useEffect(() => { loadConsole(); }, [loadConsole]);

  useEffect(() => {
    const handleUpdate = (event: Event) => {
      if (consolePaused) return;
      const detail = (event as CustomEvent<{ events?: AgentConsoleEvent[] }>).detail;
      const incoming = (detail?.events || []).filter(item =>
        item.agent_id === agent.id || item.agent_id === agent.agent_id,
      );
      if (incoming.length === 0) return;
      setConsoleEvents(prev => mergeConsoleEvents(prev, incoming));
    };
    window.addEventListener('overwatch-agent-console-update', handleUpdate);
    return () => window.removeEventListener('overwatch-agent-console-update', handleUpdate);
  }, [agent.id, agent.agent_id, consolePaused]);

  const scrollConsoleToBottom = useCallback(() => {
    requestAnimationFrame(() => {
      const el = consoleScrollRef.current;
      if (!el) return;
      el.scrollTop = el.scrollHeight;
    });
  }, []);

  useEffect(() => {
    if (!consolePaused && consoleFollowing) scrollConsoleToBottom();
  }, [consoleEvents, consolePaused, consoleFollowing, scrollConsoleToBottom]);

  const visibleConsoleEvents = useMemo(() => {
    return consoleEvents.filter(event => {
      if (consoleFilter === 'all') return true;
      if (consoleFilter === 'errors') return event.severity === 'error' || event.severity === 'warning';
      return event.kind === consoleFilter;
    });
  }, [consoleEvents, consoleFilter]);

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/30" onClick={onClose} />
      <InspectorDrawer
        title={agent.agent_id || agent.id}
        subtitle={agent.id}
        onClose={onClose}
        className="z-50"
        footer={cancellable && (
          <ActionButton
            onClick={onCancel}
            variant="danger"
            className="w-full"
          >
            Cancel Agent
          </ActionButton>
        )}
      >
        <div className="mb-3 flex items-center gap-2">
            <span className={cn(
              'w-2 h-2 rounded-full',
              agent.status === 'running' && 'bg-success',
              agent.status === 'completed' && 'bg-accent',
              agent.status === 'failed' && 'bg-destructive',
            )} />
            <StatusPill className={agent.status === 'completed' ? 'bg-accent/10 text-accent' : agent.status === 'running' ? 'bg-success/10 text-success' : agent.status === 'failed' ? 'bg-destructive/10 text-destructive' : 'bg-elevated text-muted-foreground'}>
              {agent.status}
            </StatusPill>
        </div>

        {agent.status === 'running' && <AgentSteeringControls taskId={agent.id} onIssued={loadConsole} />}

        <div className="space-y-3">
          <DetailRow label="Status" value={agent.status} />
          <DetailRow label="Task ID" value={agent.id} mono />
          {agent.assigned_at && <DetailRow label="Assigned" value={new Date(agent.assigned_at).toLocaleString()} />}
          <DetailRow label="Elapsed" value={elapsed} />
          {agent.skill && <DetailRow label="Skill" value={agent.skill} />}
          {agent.frontier_item_id && <DetailRow label="Frontier Item" value={agent.frontier_item_id} mono />}
          {agent.campaign_id && (
            <div className="flex items-center gap-2">
              <DetailRow label="Campaign" value={agent.campaign_id} mono />
              <button onClick={() => onNavigateCampaign?.(agent.campaign_id!)} className="text-[10px] text-accent hover:underline">view</button>
            </div>
          )}
          {agent.result_summary && <DetailRow label="Result" value={agent.result_summary} />}
          <DetailRow label="Scope Nodes" value={String((agent.subgraph_node_ids || agent.scope_node_ids || []).length)} />

          {subgraphNodes.length > 0 && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Scoped Subgraph</div>
              <div className="text-xs text-muted-foreground mb-1">
                {subgraphNodes.length} nodes, {context?.subgraph?.edges?.length || 0} edges
              </div>
              <div className="space-y-0.5">
                {subgraphNodes.slice(0, 10).map(n => (
                  <button
                    key={n.id}
                    onClick={() => onNavigateGraph(n.id)}
                    className="block text-xs text-accent hover:underline truncate"
                  >
                    {String(n.properties?.label || n.id)}
                  </button>
                ))}
                {subgraphNodes.length > 10 && (
                  <span className="text-[10px] text-muted-foreground">… and {subgraphNodes.length - 10} more</span>
                )}
              </div>
            </div>
          )}

          <div>
            <div className="mb-2 flex items-center justify-between gap-2">
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
                Live Agent Console ({visibleConsoleEvents.length}/{consoleEvents.length})
              </div>
              <div className="flex gap-1">
                <button
                  onClick={() => {
                    const nextPaused = !consolePaused;
                    setConsolePaused(nextPaused);
                    if (!nextPaused) {
                      setConsoleFollowing(true);
                      void loadConsole().then(scrollConsoleToBottom);
                    }
                  }}
                  className={cn(
                    'rounded border border-border px-1.5 py-0.5 text-[10px] hover:bg-hover',
                    consolePaused ? 'text-warning bg-warning/10' : 'text-muted-foreground',
                  )}
                >
                  {consolePaused ? 'Resume' : 'Pause'}
                </button>
                {!consoleFollowing && !consolePaused && (
                  <button
                    onClick={() => {
                      setConsoleFollowing(true);
                      scrollConsoleToBottom();
                    }}
                    className="rounded border border-border px-1.5 py-0.5 text-[10px] text-accent hover:bg-hover"
                  >
                    Latest
                  </button>
                )}
                <button
                  onClick={loadConsole}
                  className="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground hover:bg-hover"
                >
                  Refresh
                </button>
              </div>
            </div>
            <div className="mb-2 flex flex-wrap gap-1">
              {CONSOLE_FILTERS.map(filter => (
                <button
                  key={filter.value}
                  onClick={() => setConsoleFilter(filter.value)}
                  className={cn(
                    'rounded px-1.5 py-0.5 text-[10px] transition-colors',
                    consoleFilter === filter.value
                      ? 'bg-accent text-accent-foreground'
                      : 'bg-elevated text-muted-foreground hover:text-foreground',
                  )}
                >
                  {filter.label}
                </button>
              ))}
            </div>
            {visibleConsoleEvents.length === 0 ? (
              <div className="rounded border border-border bg-background/40 px-3 py-4 text-center text-xs text-muted-foreground">
                No agent console events yet.
              </div>
            ) : (
              <div
                ref={consoleScrollRef}
                onScroll={() => setConsoleFollowing(isScrolledNearBottom(consoleScrollRef.current))}
                className="max-h-72 space-y-1 overflow-y-auto rounded border border-border bg-background/30 p-1.5"
              >
                {visibleConsoleEvents.map(event => (
                  <AgentConsoleRow
                    key={event.id}
                    event={event}
                    onNavigateGraph={onNavigateGraph}
                    onNavigatePanel={onNavigatePanel}
                  />
                ))}
                <div ref={consoleEndRef} />
              </div>
            )}
          </div>
        </div>
      </InspectorDrawer>
    </>
  );
}

function mergeConsoleEvents(current: AgentConsoleEvent[], incoming: AgentConsoleEvent[]): AgentConsoleEvent[] {
  const byId = new Map(current.map(event => [event.id, event]));
  for (const event of incoming) byId.set(event.id, event);
  return [...byId.values()]
    .sort((a, b) => a.timestamp.localeCompare(b.timestamp))
    .slice(-120);
}

function AgentConsoleRow({
  event,
  prominent,
  onNavigateGraph,
  onNavigatePanel,
}: {
  event: AgentConsoleEvent;
  prominent?: boolean;
  onNavigateGraph: (nodeId: string) => void;
  onNavigatePanel: ReturnType<typeof useNavigation>['navigateToPanel'];
}) {
  const [rawOpen, setRawOpen] = useState(false);
  const links = event.links;

  return (
    <div className={cn('rounded border bg-surface p-2 text-xs', prominent && 'p-3', consoleBorderClass(event.severity))}>
      <div className="flex items-start gap-2">
        <span className="w-12 flex-shrink-0 font-mono text-[10px] text-muted-foreground">{formatTimestamp(event.timestamp)}</span>
        <span className={cn('mt-1 h-1.5 w-1.5 flex-shrink-0 rounded-full', consoleDotClass(event.severity))} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-medium text-foreground">{event.title}</span>
            {event.source_label && (
              <span className={cn('rounded px-1 py-0.5 text-[10px]', sourceKindClass(event.source_kind))}>
                {event.source_label}
              </span>
            )}
            <span className="rounded bg-elevated px-1 py-0.5 text-[10px] text-muted-foreground">{event.kind}</span>
            {event.status && <span className="rounded bg-background px-1 py-0.5 text-[10px] text-muted-foreground">{event.status}</span>}
          </div>
          <div className="mt-1 whitespace-pre-wrap break-words text-muted-foreground">{event.summary}</div>
          {links && (
            <div className="mt-1.5 flex flex-wrap gap-1">
              {links.action_id && <ConsoleLinkButton label={`action ${shortId(links.action_id)}`} onClick={() => onNavigatePanel('actions')} />}
              {links.frontier_item_id && <ConsoleLinkButton label={`frontier ${shortId(links.frontier_item_id)}`} onClick={() => onNavigatePanel('frontier')} />}
              {links.evidence_id && <ConsoleLinkButton label={`evidence ${shortId(links.evidence_id)}`} onClick={() => onNavigatePanel('evidence')} />}
              {links.session_id && <ConsoleLinkButton label={`session ${shortId(links.session_id)}`} onClick={() => onNavigatePanel('sessions', links.session_id)} />}
              {(links.finding_ids || []).slice(0, 2).map(findingId => (
                <ConsoleLinkButton key={findingId} label={`finding ${shortId(findingId)}`} onClick={() => onNavigatePanel('findings', findingId)} />
              ))}
              {(links.node_ids || []).slice(0, 3).map(nodeId => (
                <ConsoleLinkButton key={nodeId} label={nodeId} onClick={() => onNavigateGraph(nodeId)} />
              ))}
            </div>
          )}
          {event.raw && (
            <div className="mt-1.5">
              <button
                onClick={() => setRawOpen(value => !value)}
                className="text-[10px] text-muted-foreground hover:text-foreground"
              >
                {rawOpen ? 'Hide raw details' : 'Raw details'}
              </button>
              {rawOpen && (
                <pre className="mt-1 max-h-36 overflow-auto rounded bg-background p-2 text-[10px] text-muted-foreground">
                  {JSON.stringify(event.raw, null, 2)}
                </pre>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ConsoleLinkButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="max-w-full truncate rounded bg-accent/10 px-1.5 py-0.5 font-mono text-[10px] text-accent hover:bg-accent/20"
      title={label}
    >
      {label}
    </button>
  );
}

function consoleBorderClass(severity: AgentConsoleEvent['severity']): string {
  if (severity === 'error') return 'border-destructive/40';
  if (severity === 'warning') return 'border-warning/40';
  if (severity === 'success') return 'border-success/30';
  return 'border-border';
}

function consoleDotClass(severity: AgentConsoleEvent['severity']): string {
  if (severity === 'error') return 'bg-destructive';
  if (severity === 'warning') return 'bg-warning';
  if (severity === 'success') return 'bg-success';
  return 'bg-accent';
}

function sourceKindClass(sourceKind: AgentConsoleEvent['source_kind']): string {
  if (sourceKind === 'primary') return 'bg-accent/10 text-accent';
  if (sourceKind === 'subagent') return 'bg-purple-dim text-purple';
  if (sourceKind === 'runner') return 'bg-success/10 text-success';
  if (sourceKind === 'dashboard') return 'bg-warning/10 text-warning';
  return 'bg-elevated text-muted-foreground';
}

function shortId(value: string): string {
  return value.length > 10 ? value.slice(0, 10) : value;
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start gap-2 text-xs">
      <span className="text-muted-foreground w-24 flex-shrink-0">{label}</span>
      <span className={cn('text-foreground break-all', mono && 'font-mono text-[10px]')}>{value}</span>
    </div>
  );
}

// ---- Dispatch Modal ----

function DispatchModal({ onClose, onDispatched }: { onClose: () => void; onDispatched: () => void }) {
  const [nodeIds, setNodeIds] = useState<string[]>([]);
  const [nodeInput, setNodeInput] = useState('');
  const [skill, setSkill] = useState('');
  const [campaignId, setCampaignId] = useState('');
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [dispatching, setDispatching] = useState(false);
  const addToast = useToastStore(s => s.addToast);

  useEffect(() => {
    api.getCampaigns().then(d => setCampaigns(d.campaigns || [])).catch(() => {});
  }, []);

  const addNodeId = () => {
    const id = nodeInput.trim();
    if (id && !nodeIds.includes(id)) { setNodeIds([...nodeIds, id]); setNodeInput(''); }
  };

  const dispatch = async () => {
    if (nodeIds.length === 0) return;
    setDispatching(true);
    try {
      const res = await api.dispatchAgent({
        target_node_ids: nodeIds,
        skill: skill || undefined,
        campaign_id: campaignId || undefined,
      });
      addToast({
        type: res.dispatched ? 'success' : 'warning',
        title: res.dispatched ? 'Agent dispatched' : 'Not dispatched',
        message: res.dispatched ? res.task?.agent_id : res.reason,
      });
      if (res.dispatched) onDispatched();
    } catch (err) {
      addToast({ type: 'error', title: 'Dispatch failed', message: err instanceof Error ? err.message : String(err) });
    } finally { setDispatching(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" onClick={onClose}>
      <div className="absolute inset-0 bg-black/40" />
      <div className="relative bg-surface border border-border rounded-lg p-5 w-96 shadow-xl" onClick={e => e.stopPropagation()}>
        <h3 className="text-sm font-semibold mb-3">Dispatch Agent</h3>

        <div className="space-y-3">
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Target Nodes</label>
            <div className="flex gap-1 flex-wrap mb-1">
              {nodeIds.map(id => (
                <span key={id} className="text-[10px] px-1.5 py-0.5 rounded bg-elevated text-foreground flex items-center gap-1">
                  {id.slice(0, 16)}
                  <button onClick={() => setNodeIds(nodeIds.filter(x => x !== id))} className="text-muted-foreground hover:text-foreground">✕</button>
                </span>
              ))}
            </div>
            <div className="flex gap-1">
              <input
                value={nodeInput}
                onChange={e => setNodeInput(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addNodeId(); } }}
                placeholder="Node ID…"
                className="flex-1 text-xs px-2 py-1 bg-elevated border border-border rounded text-foreground placeholder:text-muted-foreground"
              />
              <button onClick={addNodeId} className="text-xs px-2 py-1 rounded bg-accent/10 text-accent">Add</button>
            </div>
          </div>

          <div>
            <label className="text-xs text-muted-foreground block mb-1">Skill (optional)</label>
            <input
              value={skill}
              onChange={e => setSkill(e.target.value)}
              placeholder="e.g. credential_spray"
              className="w-full text-xs px-2 py-1 bg-elevated border border-border rounded text-foreground placeholder:text-muted-foreground"
            />
          </div>

          <div>
            <label className="text-xs text-muted-foreground block mb-1">Campaign (optional)</label>
            <select
              value={campaignId}
              onChange={e => setCampaignId(e.target.value)}
              className="w-full text-xs px-2 py-1 bg-elevated border border-border rounded text-foreground"
            >
              <option value="">None</option>
              {campaigns.map(c => <option key={c.id} value={c.id}>{c.name || c.id}</option>)}
            </select>
          </div>
        </div>

        <div className="flex justify-end gap-2 mt-4">
          <button onClick={onClose} className="text-xs px-3 py-1.5 rounded border border-border text-muted-foreground hover:text-foreground">Cancel</button>
          <button
            onClick={dispatch}
            disabled={nodeIds.length === 0 || dispatching}
            className="text-xs px-3 py-1.5 rounded bg-accent text-background hover:bg-accent/90 disabled:opacity-50"
          >
            {dispatching ? 'Dispatching…' : 'Dispatch'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---- Bulk Frontier Dispatch Modal ----

function BulkFrontierDispatchModal({ onClose, onDispatched }: { onClose: () => void; onDispatched: () => void }) {
  const frontier = useEngagementStore((s) => s.frontier);
  const [selectedItemIds, setSelectedItemIds] = useState<Set<string>>(new Set());
  const [skill, setSkill] = useState('');
  const [dispatching, setDispatching] = useState(false);
  const addToast = useToastStore(s => s.addToast);

  const topItems = frontier.slice(0, 20);

  const toggleItem = (id: string) => {
    setSelectedItemIds(prev => {
      const n = new Set(prev);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  };

  const selectAll = () => {
    if (selectedItemIds.size === topItems.length) {
      setSelectedItemIds(new Set());
    } else {
      setSelectedItemIds(new Set(topItems.map(i => i.frontier_item_id || i.id)));
    }
  };

  const dispatchAll = async () => {
    if (selectedItemIds.size === 0) return;
    setDispatching(true);
    const selected = topItems.filter(i => selectedItemIds.has(getFrontierKey(i)));
    try {
      const results = await Promise.allSettled(
        selected.map(item => {
          const nodeIds = getFrontierNodeIds(item);
          if (nodeIds.length === 0) return Promise.reject(new Error('no node ids'));
          // frontier_item_id links the lease so the dashboard traces the item.
          return api.dispatchAgent({
            target_node_ids: nodeIds,
            skill: skill || undefined,
            frontier_item_id: getFrontierKey(item),
          });
        })
      );
      // A fulfilled promise can still be a 409 lease-conflict (dispatched:false);
      // count only genuinely-dispatched agents.
      const ok = results.filter(r => r.status === 'fulfilled' && r.value?.dispatched).length;
      const failed = results.length - ok;
      addToast({
        type: failed === 0 ? 'success' : ok === 0 ? 'error' : 'warning',
        title: `Dispatched ${ok}/${results.length} agent(s)`,
        message: failed > 0 ? `${failed} skipped (lease conflict or no scope)` : undefined,
      });
      onDispatched();
    } catch (err) {
      addToast({ type: 'error', title: 'Bulk dispatch failed', message: err instanceof Error ? err.message : String(err) });
    } finally { setDispatching(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" onClick={onClose}>
      <div className="absolute inset-0 bg-black/40" />
      <div className="relative bg-surface border border-border rounded-lg p-5 w-[28rem] max-h-[80vh] flex flex-col shadow-xl" onClick={e => e.stopPropagation()}>
        <h3 className="text-sm font-semibold mb-1">Bulk Dispatch from Frontier</h3>
        <p className="text-[10px] text-muted-foreground mb-3">Select frontier items to dispatch as parallel agents.</p>

        <div className="flex items-center gap-2 mb-2">
          <label className="flex items-center gap-1 text-xs text-muted-foreground cursor-pointer">
            <input
              type="checkbox"
              checked={selectedItemIds.size === topItems.length && topItems.length > 0}
              onChange={selectAll}
              className="accent-accent"
            />
            Select all ({topItems.length})
          </label>
          <span className="flex-1" />
          <span className="text-xs text-accent font-medium">{selectedItemIds.size} selected</span>
        </div>

        <div className="flex-1 overflow-y-auto space-y-1 mb-3 max-h-64">
          {topItems.map((item) => {
            const itemId = item.frontier_item_id || item.id;
            return (
              <label
                key={itemId}
                className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-hover transition-colors cursor-pointer text-xs"
              >
                <input
                  type="checkbox"
                  checked={selectedItemIds.has(itemId)}
                  onChange={() => toggleItem(itemId)}
                  className="accent-accent"
                />
                <span className={cn(
                  'px-1 py-0.5 rounded text-[10px] font-medium flex-shrink-0',
                  item.type === 'inferred_edge' ? 'bg-purple-dim text-purple' :
                  item.type === 'untested_edge' ? 'bg-warning/10 text-warning' :
                  item.type === 'network_discovery' ? 'bg-accent-dim text-accent' :
                  'bg-elevated text-muted-foreground',
                )}>
                  {item.type.replace(/_/g, ' ')}
                </span>
                <span className="text-muted-foreground truncate flex-1">{item.description}</span>
                <span className="font-mono text-foreground flex-shrink-0">{(item.priority ?? 0).toFixed(1)}</span>
              </label>
            );
          })}
          {topItems.length === 0 && <p className="text-xs text-muted-foreground text-center py-4">No frontier items available.</p>}
        </div>

        <div>
          <label className="text-xs text-muted-foreground block mb-1">Skill (optional)</label>
          <input
            value={skill}
            onChange={e => setSkill(e.target.value)}
            placeholder="e.g. enumeration"
            className="w-full text-xs px-2 py-1 bg-elevated border border-border rounded text-foreground placeholder:text-muted-foreground mb-3"
          />
        </div>

        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="text-xs px-3 py-1.5 rounded border border-border text-muted-foreground hover:text-foreground">Cancel</button>
          <button
            onClick={dispatchAll}
            disabled={selectedItemIds.size === 0 || dispatching}
            className="text-xs px-3 py-1.5 rounded bg-purple text-background hover:bg-purple/90 disabled:opacity-50"
          >
            {dispatching ? 'Dispatching…' : `Dispatch ${selectedItemIds.size} Agent${selectedItemIds.size !== 1 ? 's' : ''}`}
          </button>
        </div>
      </div>
    </div>
  );
}
