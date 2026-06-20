import { useState, useEffect, useMemo, useCallback, useRef, type RefObject } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useEngagementStore } from '../../stores/engagement-store';
import { useToastStore } from '../../stores/toast-store';
import { useNavigation } from '../../hooks/useNavigation';
import * as api from '../../lib/api';
import type { AgentInfo, AgentConsoleEvent, AgentConsoleKind } from '../../lib/types';
import { buildOperatorConsoleEvents } from '../../lib/operator-console';
import { sessionsForAgent } from '../../lib/session-workspace';
import { buildMissionCard, groupMissionCards } from '../../lib/agent-mission';
import { buildAgentThread } from '../../lib/agent-thread';
import { threadConsoleEvents, type ActivityThread } from '../../lib/activity-threads';
import { getFrontierNodeIds, getFrontierKey } from '../../lib/frontier-workspace';
import { POLL } from '../../lib/polling';
import { ContextualCommandBar } from './ContextualCommandBar';
import { AttentionQueue } from './AttentionQueue';
import { MissionCard } from './MissionCard';
import { AgentThread } from './AgentThread';
import { AddTargetsModal } from './AddTargetsModal';
import { DeployModal } from './DeployModal';
import { cn, formatElapsed, formatTimestamp } from '../../lib/utils';
import { ActionButton, FilterBar, MetricTile, PageHeader, PanelSection, StatusPill } from '../shared/primitives';

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

// Activity is newest-first (most recent at the top), so "at the newest end" means
// scrolled near the TOP. Following keeps the viewport pinned there.
function isScrolledNearTop(el: HTMLElement | null, threshold = 48): boolean {
  if (!el) return true;
  return el.scrollTop <= threshold;
}

export function AgentsPanel() {
  const agents = useEngagementStore((s) => s.agents);
  const initialized = useEngagementStore((s) => s.initialized);
  const connected = useEngagementStore((s) => s.connected);
  const sessions = useEngagementStore((s) => s.sessions);
  const pendingActions = useEngagementStore((s) => s.pendingActions);
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [activeAgentId, setActiveAgentId] = useState<string>('all');
  const [activeContext, setActiveContext] = useState<AgentContext | null>(null);
  const [consoleEvents, setConsoleEvents] = useState<AgentConsoleEvent[]>([]);
  const [consoleFilter, setConsoleFilter] = useState<ConsoleFilter>('all');
  const [consolePaused, setConsolePaused] = useState(false);
  const [consoleFollowing, setConsoleFollowing] = useState(true);
  const [consoleSearch, setConsoleSearch] = useState('');
  const consoleScrollRef = useRef<HTMLDivElement | null>(null);
  const [showDispatch, setShowDispatch] = useState(false);
  const [showBulkDispatch, setShowBulkDispatch] = useState(false);
  const [showAddTargets, setShowAddTargets] = useState(false);
  const [batchMode, setBatchMode] = useState(false);
  const [agentQueries, setAgentQueries] = useState<api.AgentQuery[]>([]);
  const { navigateToGraph, navigateToCampaign, navigateToPanel } = useNavigation();
  const setStoreAgents = useEngagementStore((s) => s.setAgents);

  // Agent→operator questions feed both the Attention Queue and Mission Card
  // "awaiting answer" badges; fetch once here (live via the WS push + a poll).
  const loadAgentQueries = useCallback(async () => {
    try {
      const { queries } = await api.getAgentQueries();
      setAgentQueries(queries || []);
    } catch { /* transient */ }
  }, []);
  useEffect(() => {
    void loadAgentQueries();
    const onUpdate = () => void loadAgentQueries();
    window.addEventListener('overwatch-agent-query-update', onUpdate);
    const timer = setInterval(() => void loadAgentQueries(), POLL.AGENTS_MS);
    return () => {
      window.removeEventListener('overwatch-agent-query-update', onUpdate);
      clearInterval(timer);
    };
  }, [loadAgentQueries]);

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
  const running = agents.filter(a => a.status === 'running');
  const completed = agents.filter(a => a.status === 'completed');
  const failed = agents.filter(a => a.status === 'failed' || a.status === 'interrupted');

  // Mission Cards: the operator-shaped per-agent view-model, grouped by campaign.
  const missionGroups = useMemo(
    () => groupMissionCards(agents.map(a => buildMissionCard(a, { sessions, pendingActions, agentQueries }))),
    [agents, sessions, pendingActions, agentQueries],
  );
  const elapsedById = useMemo(() => {
    const m = new Map<string, number | undefined>();
    for (const a of agents) m.set(a.id, a.elapsed_ms);
    return m;
  }, [agents]);
  // Select by task id OR agent label so deep-links from other panels (e.g. a
  // SessionRow chip carrying the agent label) resolve.
  const activeAgent = activeAgentId === 'all'
    ? null
    : agents.find(agent => agent.id === activeAgentId || agent.agent_id === activeAgentId) || null;

  // The focused agent's conversation: its (already agent-scoped) console events
  // interleaved with its open questions. Empty when no agent is focused.
  const agentThreadEntries = useMemo(
    () => activeAgent
      ? buildAgentThread(consoleEvents, agentQueries, {
          agentId: activeAgent.id,
          agentLabel: activeAgent.agent_id || activeAgent.id,
          limit: 200,
        })
      : [],
    [activeAgent, consoleEvents, agentQueries],
  );

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

  const cancelAgent = async (id: string) => {
    try { await api.cancelAgent(id); await refreshAgents(); } catch { /* silent */ }
  };

  const fleetAddToast = useToastStore(s => s.addToast);
  const fleetAction = async (kind: 'pause' | 'resume' | 'stop') => {
    try {
      const res = await api.fleetDirective(kind);
      // Warn (not green-success) on partial application or an empty fleet — the
      // operator must not believe a fleet-wide Stop fully landed when it didn't.
      const clean = res.total > 0 && res.applied === res.total;
      fleetAddToast({
        type: clean ? 'success' : 'warning',
        title: `Fleet ${kind}`,
        message: res.total === 0 ? 'no running agents' : `applied to ${res.applied}/${res.total} running agent(s)`,
      });
      await refreshAgents();
    } catch (err) {
      fleetAddToast({ type: 'error', title: `Fleet ${kind} failed`, message: err instanceof Error ? err.message : String(err) });
    }
  };

  const batchCancel = async () => {
    const cancellable = agents.filter(a => selectedIds.has(a.id) && (a.status === 'running' || a.status === 'pending'));
    await Promise.allSettled(cancellable.map(a => api.cancelAgent(a.id)));
    setSelectedIds(new Set());
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

  const scrollConsoleToNewest = useCallback(() => {
    requestAnimationFrame(() => {
      const el = consoleScrollRef.current;
      if (!el) return;
      el.scrollTop = 0; // newest is at the top
    });
  }, []);

  useEffect(() => {
    if (!consolePaused && consoleFollowing) scrollConsoleToNewest();
    // agentThreadEntries is in the deps so a newly-arrived question (which changes
    // the thread via agentQueries, not consoleEvents) still follows to the newest.
  }, [consoleEvents, agentThreadEntries, consolePaused, consoleFollowing, scrollConsoleToNewest]);

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

  return (
    // Single page scroll: the panel flows inside <main>'s scroll (OperatorLayout),
    // so nothing is trapped in a fixed-height box that clips. The command bar +
    // "Needs you" queue stick at the top (top-12 mirrors <main>'s pt-12 toolbar
    // offset); the Fleet roster sticks at xl; only the Activity stream keeps its
    // own bounded inner scroll (live-tailing would otherwise yank the whole page).
    <div className="flex flex-col gap-3">
      {/* Cap the sticky band well under the viewport so the fleet/activity grid
          below is always reachable. The "Needs you" queue is compact-by-default and
          self-bounds its expanded list; this is the belt-and-suspenders guarantee
          that header + command + queue can never claim the whole screen. */}
      <div className="sticky top-12 z-20 flex max-h-[60vh] flex-col gap-3 overflow-y-auto bg-background pb-2">
      <PageHeader
        title="Operator Console"
        meta={activeAgent ? `focused on ${activeAgent.agent_id || activeAgent.id}` : 'fleet overview'}
        actions={(
          <FilterBar>
          <div className="flex gap-2 text-xs">
            <span className="text-success">{running.length} running</span>
            <span className="text-muted-foreground">{completed.length} done</span>
            {failed.length > 0 && <span className="text-destructive">{failed.length} failed</span>}
          </div>
          {running.length > 0 && (
            <div className="flex items-center gap-1" title="Steer all running agents">
              <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Fleet</span>
              <ActionButton onClick={() => fleetAction('pause')} variant="warning" size="xs">Pause all</ActionButton>
              <ActionButton onClick={() => fleetAction('resume')} variant="success" size="xs">Resume all</ActionButton>
              <ActionButton onClick={() => fleetAction('stop')} variant="danger" size="xs">Stop all</ActionButton>
            </div>
          )}
          <ActionButton
            onClick={() => setShowAddTargets(true)}
            variant="secondary"
          >
            Add Targets
          </ActionButton>
          <ActionButton
            onClick={() => setShowDispatch(true)}
            variant="ghost"
            className="text-accent"
          >
            Deploy
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

      {/* One contextual command box — Engagement (NL) or the focused Agent
          (instruct), via a scope pill. Replaces the separate global command bar
          and per-agent Tell box. */}
      <ContextualCommandBar
        focusedAgent={activeAgent}
        onAgentCommandSent={() => { void loadConsole(); void loadAgentQueries(); }}
      />

      {/* One "Needs you" queue — approvals (act inline) + agent questions
          (answer inline) + failed agents, prioritized, one item expanded. Hides
          itself when nothing is waiting. */}
      <AttentionQueue
        agentQueries={agentQueries}
        onAnswered={loadAgentQueries}
        onSelectAgent={(taskId) => setActiveAgentId(taskId)}
        onTriageAll={() => navigateToPanel('actions')}
      />

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
      </div>

      {!initialized ? (
        <div className="text-sm text-muted-foreground animate-pulse">Loading…</div>
      ) : (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(260px,330px)_minmax(0,1fr)] xl:items-start">
          {/* LEFT (Monitor): the Fleet — Mission Cards grouped by campaign. */}
          <MissionRoster
            groups={missionGroups}
            agentCount={agents.length}
            activeAgentId={activeAgentId}
            selectedIds={selectedIds}
            collapsedGroups={collapsedGroups}
            batchMode={batchMode}
            elapsedById={elapsedById}
            onToggleBatch={() => { setBatchMode(v => !v); setSelectedIds(new Set()); }}
            onSelectAllOutput={() => setActiveAgentId('all')}
            onSelectAgent={(id) => setActiveAgentId(id)}
            onToggleSelect={toggleSelect}
            onToggleGroup={toggleGroup}
            onCancelAgent={cancelAgent}
          />

          {/* MAIN: focused agent (detail + steer, top) over its activity stream
              (bottom). With no agent selected, the top is the fleet overview and
              the bottom is the full operator stream. Flows in the page scroll;
              only the Activity stream below is a bounded live-tail region. */}
          <div className="flex min-w-0 flex-col gap-4">
            <AgentContextPanel
              agent={activeAgent}
              context={activeContext}
              onCancel={activeAgent && (activeAgent.status === 'running' || activeAgent.status === 'pending')
                ? () => cancelAgent(activeAgent.id)
                : undefined}
              onNavigateGraph={(nodeId) => navigateToGraph(nodeId, 1)}
              onNavigateCampaign={navigateToCampaign}
            />

            {activeAgent ? (
              /* Focused agent → its CONVERSATION: commands, actions+results,
                 findings, and inline-answerable questions, top to bottom. */
              <AgentThread
                agentLabel={activeAgent.agent_id || activeAgent.id}
                entries={agentThreadEntries}
                totalEntries={consoleEvents.length}
                paused={consolePaused}
                following={consoleFollowing}
                scrollRef={consoleScrollRef}
                onTogglePaused={() => {
                  const nextPaused = !consolePaused;
                  setConsolePaused(nextPaused);
                  if (!nextPaused) {
                    setConsoleFollowing(true);
                    void loadConsole().then(scrollConsoleToNewest);
                  }
                }}
                onScroll={() => setConsoleFollowing(isScrolledNearTop(consoleScrollRef.current))}
                onJumpLatest={() => { setConsoleFollowing(true); scrollConsoleToNewest(); }}
                onRefresh={() => { void loadConsole(); void loadAgentQueries(); }}
                onAnswered={loadAgentQueries}
                onNavigateGraph={(nodeId) => navigateToGraph(nodeId, 1)}
                onNavigatePanel={navigateToPanel}
              />
            ) : (
              /* No agent selected → the full operator stream (threaded). */
              <AgentOutputConsole
                activeAgent={activeAgent}
                events={visibleConsoleEvents}
                totalEvents={consoleEvents.length}
                filter={consoleFilter}
                search={consoleSearch}
                paused={consolePaused}
                following={consoleFollowing}
                scrollRef={consoleScrollRef}
                onFilterChange={setConsoleFilter}
                onSearchChange={setConsoleSearch}
                onTogglePaused={() => {
                  const nextPaused = !consolePaused;
                  setConsolePaused(nextPaused);
                  if (!nextPaused) {
                    setConsoleFollowing(true);
                    void loadConsole().then(scrollConsoleToNewest);
                  }
                }}
                onScroll={() => setConsoleFollowing(isScrolledNearTop(consoleScrollRef.current))}
                onJumpLatest={() => {
                  setConsoleFollowing(true);
                  scrollConsoleToNewest();
                }}
                onRefresh={loadConsole}
                onNavigateGraph={(nodeId) => navigateToGraph(nodeId, 1)}
                onNavigatePanel={navigateToPanel}
              />
            )}
          </div>
        </div>
      )}

      {/* Deploy Modal — recommended-or-chosen agent type at a target (Phase 5c) */}
      {showDispatch && (
        <DeployModal
          onClose={() => setShowDispatch(false)}
          onDeployed={() => { setShowDispatch(false); refreshAgents(); }}
        />
      )}

      {/* Bulk Frontier Dispatch Modal */}
      {showBulkDispatch && (
        <BulkFrontierDispatchModal
          onClose={() => setShowBulkDispatch(false)}
          onDispatched={() => { setShowBulkDispatch(false); refreshAgents(); }}
        />
      )}

      {/* Add Targets Modal — live scope entry mid-engagement (Phase 4c) */}
      {showAddTargets && (
        <AddTargetsModal onClose={() => setShowAddTargets(false)} />
      )}
    </div>
  );
}

// ---- Fleet roster (Mission Cards) ----

function MissionRoster({
  groups,
  agentCount,
  activeAgentId,
  selectedIds,
  collapsedGroups,
  batchMode,
  elapsedById,
  onToggleBatch,
  onSelectAllOutput,
  onSelectAgent,
  onToggleSelect,
  onToggleGroup,
  onCancelAgent,
}: {
  groups: import('../../lib/agent-mission').MissionGroup[];
  agentCount: number;
  activeAgentId: string;
  selectedIds: Set<string>;
  collapsedGroups: Set<string>;
  batchMode: boolean;
  elapsedById: Map<string, number | undefined>;
  onToggleBatch: () => void;
  onSelectAllOutput: () => void;
  onSelectAgent: (id: string) => void;
  onToggleSelect: (id: string) => void;
  onToggleGroup: (id: string) => void;
  onCancelAgent: (id: string) => void;
}) {
  const liveCount = groups.reduce((n, g) => n + g.cards.filter(c => c.tone === 'running' || c.tone === 'blocked' || c.tone === 'stuck').length, 0);
  const failedCount = groups.reduce((n, g) => n + g.cards.filter(c => c.tone === 'failed').length, 0);

  return (
    // Bounded so a long fleet scrolls within the card instead of bloating the
    // column; flows in the page scroll (xl:items-start keeps it from stretching
    // to the taller right column). Not sticky — a fixed sticky offset can't track
    // the variable-height command/"Needs you" band above it.
    <PanelSection className="flex max-h-[calc(100vh-9rem)] flex-col overflow-hidden p-0">
      <div className="border-b border-border p-3">
        <div className="flex items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-foreground">Fleet</h3>
            <p className="mt-0.5 text-[11px] text-muted-foreground">Select an agent to focus it.</p>
          </div>
          <div className="flex items-center gap-1.5">
            <StatusPill tone={failedCount > 0 ? 'danger' : liveCount > 0 ? 'success' : 'muted'}>{liveCount} live</StatusPill>
            <button
              onClick={onToggleBatch}
              className={cn('rounded px-1.5 py-0.5 text-[10px]', batchMode ? 'bg-accent/15 text-accent' : 'text-muted-foreground hover:text-foreground')}
              title="Toggle batch selection"
            >
              Batch
            </button>
          </div>
        </div>
      </div>

      <div className="border-b border-border p-2">
        <button
          onClick={onSelectAllOutput}
          className={cn(
            'w-full rounded-md border px-3 py-2 text-left transition-colors',
            activeAgentId === 'all' ? 'border-accent/60 bg-accent/10' : 'border-border bg-background/40 hover:bg-hover/40',
          )}
        >
          <div className="flex items-center justify-between gap-2">
            <span className="text-sm font-medium text-foreground">Primary &amp; full stream</span>
            <span className="text-[10px] text-muted-foreground">{agentCount} agents</span>
          </div>
          <div className="mt-1 text-[11px] text-muted-foreground">Fleet overview + the full operator activity stream.</div>
        </button>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto">
        {groups.map(group => {
          const isCollapsed = collapsedGroups.has(group.key);
          const groupLive = group.cards.filter(c => c.tone === 'running' || c.tone === 'blocked' || c.tone === 'stuck').length;
          return (
            <div key={group.key} className="border-b border-border">
              <button
                onClick={() => onToggleGroup(group.key)}
                className="flex w-full items-center gap-2 px-3 py-2 text-xs transition-colors hover:bg-hover"
              >
                <span className="text-muted-foreground">{isCollapsed ? '▸' : '▾'}</span>
                <span className="flex-1 truncate text-left font-medium text-foreground">{group.name}</span>
                <span className="text-muted-foreground">{groupLive}/{group.cards.length}</span>
              </button>
              {!isCollapsed && group.cards.map(card => (
                <MissionCard
                  key={card.id}
                  card={card}
                  active={activeAgentId === card.id}
                  batchMode={batchMode}
                  selected={selectedIds.has(card.id)}
                  elapsedMs={elapsedById.get(card.id)}
                  onClick={() => onSelectAgent(card.id)}
                  onToggleSelect={() => onToggleSelect(card.id)}
                  onCancel={() => onCancelAgent(card.id)}
                />
              ))}
            </div>
          );
        })}
        {agentCount === 0 && (
          <div className="mx-2 my-2 rounded border border-dashed border-border bg-background/40 p-3 text-xs text-muted-foreground">
            No subagents active. The primary operator stream remains available above.
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
    // Bounded live-tail region: max-h keeps it within the viewport so follow-to-
    // top scrolls inside this box (the deliberate single exception to single-
    // scroll) instead of yanking the whole page.
    <PanelSection className="flex max-h-[calc(100vh-11rem)] flex-col overflow-hidden p-0 border-accent/20">
      <div className="border-b border-border p-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h3 className="text-base font-semibold text-foreground">{activeAgent ? 'Agent activity' : 'Activity'}</h3>
              <StatusPill tone={paused ? 'warning' : following ? 'success' : 'muted'}>
                {paused ? 'paused' : following ? 'following' : 'reading'}
              </StatusPill>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              {activeAgent
                ? `Filtered to ${activeAgent.agent_id || activeAgent.id}.`
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
            {/* Newest first: threadConsoleEvents already sorts newest→oldest, so
                render it directly (no reverse). Follow-to-top is handled by
                scrollConsoleToNewest (scrollTop = 0) on the scroll container. */}
            {threadConsoleEvents(events).map(thread => (
              <ConsoleThreadRow
                key={thread.id}
                thread={thread}
                onNavigateGraph={onNavigateGraph}
                onNavigatePanel={onNavigatePanel}
              />
            ))}
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
// One-click lifecycle steering for the focused agent. Free-text instruction
// ("Tell …") now lives in the ContextualCommandBar (Agent scope), so this is
// just the quick verbs.
function AgentSteeringControls({ taskId }: { taskId: string }) {
  const addToast = useToastStore(s => s.addToast);
  const [busy, setBusy] = useState<string | null>(null);
  const issue = async (kind: api.DirectiveKind) => {
    setBusy(kind);
    try {
      const res = await api.issueDirective(taskId, kind);
      addToast({ type: res.ok ? 'success' : 'warning', title: `Directive: ${kind}`, message: res.ok ? 'issued — agent honors it on its next heartbeat' : 'not applied' });
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
    <PanelSection dense>
      <h3 className="text-sm font-semibold text-foreground">Fleet overview</h3>
      <p className="mt-1 text-xs text-muted-foreground">
        The primary model orchestrates; sub-agents are dispatched workers. Select one on the left to focus &amp; steer it.
      </p>

      {/* 4-up at xl so Completed/Failed never wrap to a clipped second row. */}
      <div className="mt-3 grid grid-cols-2 gap-2 xl:grid-cols-4">
        <MetricTile dense label="Running" value={running} accent={running > 0} onClick={() => navigateToPanel('agents')} />
        <MetricTile dense label="Queued" value={queued} />
        <MetricTile dense label="Completed" value={done} />
        <MetricTile dense label="Failed" value={failed} />
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
  onCancel,
  onNavigateGraph,
  onNavigateCampaign,
}: {
  agent: AgentInfo | null;
  context: AgentContext | null;
  onCancel?: () => void;
  onNavigateGraph: (nodeId: string) => void;
  onNavigateCampaign: (campaignId: string) => void;
}) {
  const sessions = useEngagementStore(s => s.sessions);
  const { navigateToSession } = useNavigation();

  if (!agent) {
    return <PrimaryOperatorPanel />;
  }

  const elapsed = agent.elapsed_ms
    ? formatElapsed(agent.elapsed_ms)
    : agent.completed_at && agent.assigned_at
      ? formatElapsed(new Date(agent.completed_at).getTime() - new Date(agent.assigned_at).getTime())
      : '—';
  const subgraphNodes = context?.subgraph?.nodes || [];
  const ownedSessions = sessionsForAgent(sessions, agent);

  return (
    <PanelSection dense>
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
        {onCancel && <ActionButton onClick={onCancel} size="xs" variant="danger">Cancel</ActionButton>}
        {ownedSessions.length > 0 && (
          <ActionButton onClick={() => navigateToSession(ownedSessions[0].id)} size="xs" variant="secondary">
            Open session →{ownedSessions.length > 1 ? ` (${ownedSessions.length})` : ''}
          </ActionButton>
        )}
        {agent.campaign_id && (
          <ActionButton onClick={() => onNavigateCampaign(agent.campaign_id!)} size="xs" variant="ghost">
            Campaign
          </ActionButton>
        )}
      </div>

      {agent.status === 'running' && <AgentSteeringControls taskId={agent.id} />}

      <div className="mt-4 space-y-2">
        {agent.status === 'running' && agent.current_action && <DetailRow label="Doing" value={agent.current_action} />}
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

function mergeConsoleEvents(current: AgentConsoleEvent[], incoming: AgentConsoleEvent[]): AgentConsoleEvent[] {
  const byId = new Map(current.map(event => [event.id, event]));
  for (const event of incoming) byId.set(event.id, event);
  return [...byId.values()]
    .sort((a, b) => a.timestamp.localeCompare(b.timestamp))
    .slice(-120);
}

// A threaded activity row: a single event renders as-is; a multi-event action
// lifecycle (directive→ack→started→completed) collapses to its latest event with
// an "N steps" expander revealing the earlier steps compactly.
function ConsoleThreadRow({
  thread,
  onNavigateGraph,
  onNavigatePanel,
}: {
  thread: ActivityThread;
  onNavigateGraph: (nodeId: string) => void;
  onNavigatePanel: ReturnType<typeof useNavigation>['navigateToPanel'];
}) {
  const [open, setOpen] = useState(false);
  if (!thread.threaded) {
    return <AgentConsoleRow event={thread.latest} prominent onNavigateGraph={onNavigateGraph} onNavigatePanel={onNavigatePanel} />;
  }
  const earlier = thread.events.slice(0, -1);
  return (
    <div>
      <AgentConsoleRow event={thread.latest} prominent onNavigateGraph={onNavigateGraph} onNavigatePanel={onNavigatePanel} />
      <button
        onClick={() => setOpen(o => !o)}
        className="ml-14 mt-0.5 text-[10px] text-muted-foreground hover:text-foreground"
      >
        {open ? 'Hide steps' : `${thread.count} steps in this action`}
      </button>
      {open && (
        <div className="ml-14 mt-1 space-y-1 border-l border-border pl-2">
          {earlier.map(event => (
            <AgentConsoleRow key={event.id} event={event} onNavigateGraph={onNavigateGraph} onNavigatePanel={onNavigatePanel} />
          ))}
        </div>
      )}
    </div>
  );
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
