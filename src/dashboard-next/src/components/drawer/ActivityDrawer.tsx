import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CirclePause,
  CirclePlay,
  Copy,
  Link2,
  Radio,
  RefreshCw,
  Search,
} from 'lucide-react';
import { useNavigate } from 'react-router';
import * as api from '../../lib/api';
import {
  ACTIVITY_FILTERS,
  collectNewConsoleEventIds,
  filterActivityThreads,
  mergeConsoleEvents,
  threadConsoleEvents,
  type ActivityFilter,
  type ActivityThread,
} from '../../lib/activity-threads';
import type { ActionExplanation, AgentConsoleEvent, AgentConsoleKind } from '../../lib/types';
import { cn, formatRelativeTime, formatTimestamp } from '../../lib/utils';
import { useEngagementStore } from '../../stores/engagement-store';
import { buildWorkspacePath } from '../../lib/workspace-navigation';
import { StatusPill } from '../shared/primitives';
import { ExecutionOutputView } from './ExecutionOutputView';

const INITIAL_LIMIT = 200;
const MAX_LIMIT = 1000;

export function ActivityDrawer({
  mode = 'compact',
  selectedItem,
  onSelect,
  onOpenRun,
}: {
  mode?: 'compact' | 'focus';
  selectedItem?: string;
  onSelect: (item: string | null) => void;
  onOpenRun: (actionId: string) => void;
}) {
  const connected = useEngagementStore(state => state.connected);
  const [events, setEvents] = useState<AgentConsoleEvent[]>([]);
  const [limit, setLimit] = useState(INITIAL_LIMIT);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<ActivityFilter>('all');
  const [paused, setPaused] = useState(false);
  const [follow, setFollow] = useState(true);
  const [unseen, setUnseen] = useState(0);
  const [loading, setLoading] = useState(true);
  const [stale, setStale] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [directActionId, setDirectActionId] = useState<string | null>(null);
  const [directSelectionLoading, setDirectSelectionLoading] = useState(false);
  const listRef = useRef<HTMLDivElement | null>(null);
  const initializedSelection = useRef(false);
  const knownEventIds = useRef(new Set<string>());
  const hasLoadedTimeline = useRef(false);
  const reconcileGeneration = useRef(0);
  const suppressNextAnnouncement = useRef(false);
  const liveControl = useRef({ paused, follow, search });
  liveControl.current = { paused, follow, search };

  const acceptEvents = useCallback((incoming: AgentConsoleEvent[], announce: boolean) => {
    if (incoming.length === 0) return;
    const newIds = collectNewConsoleEventIds(knownEventIds.current, incoming);
    for (const event of incoming) knownEventIds.current.add(event.id);
    setEvents(current => mergeConsoleEvents(current, incoming, limit));

    if (!announce || newIds.length === 0) return;
    const controls = liveControl.current;
    if (controls.paused || !controls.follow || controls.search.trim()) {
      setUnseen(value => value + newIds.length);
      return;
    }
    window.requestAnimationFrame(() => listRef.current?.scrollTo({ top: 0, behavior: 'smooth' }));
  }, [limit]);

  const reconcile = useCallback(async () => {
    const generation = ++reconcileGeneration.current;
    const announce = hasLoadedTimeline.current && !suppressNextAnnouncement.current;
    suppressNextAnnouncement.current = false;
    setLoading(true);
    try {
      const response = await api.getOperatorConsole({ limit });
      if (generation !== reconcileGeneration.current) return;
      acceptEvents(response.events || [], announce);
      hasLoadedTimeline.current = true;
      setStale(false);
      setError(null);
    } catch (cause) {
      if (generation !== reconcileGeneration.current) return;
      setStale(true);
      setError(cause instanceof Error ? cause.message : 'The operator timeline could not be reconciled.');
    } finally {
      if (generation === reconcileGeneration.current) setLoading(false);
    }
  }, [acceptEvents, limit]);

  useEffect(() => {
    void reconcile();
    const timer = window.setInterval(() => {
      if (connected) void reconcile();
    }, 10_000);
    return () => window.clearInterval(timer);
  }, [connected, reconcile]);

  useEffect(() => {
    const receive = (event: Event) => {
      const detail = (event as CustomEvent<{ events?: AgentConsoleEvent[] }>).detail;
      const incoming = detail?.events || [];
      acceptEvents(incoming, true);
    };
    window.addEventListener('overwatch-agent-console-update', receive);
    return () => window.removeEventListener('overwatch-agent-console-update', receive);
  }, [acceptEvents]);

  useEffect(() => {
    if (!connected) setStale(true);
  }, [connected]);

  const threads = useMemo(() => threadConsoleEvents(events), [events]);
  const filtered = useMemo(() => filterActivityThreads(threads, filter, search), [filter, search, threads]);
  const selected = useMemo(() => selectedItem ? threads.find(thread => thread.id === selectedItem) ?? null : null, [selectedItem, threads]);

  useEffect(() => {
    if (loading || !selectedItem || selected) {
      setDirectActionId(null);
      setDirectSelectionLoading(false);
      return;
    }
    let cancelled = false;
    setDirectSelectionLoading(true);
    void api.getActionOutput(selectedItem, 1024)
      .then(() => { if (!cancelled) setDirectActionId(selectedItem); })
      .catch(() => { if (!cancelled) onSelect(null); })
      .finally(() => { if (!cancelled) setDirectSelectionLoading(false); });
    return () => { cancelled = true; };
  }, [loading, onSelect, selected, selectedItem]);

  useEffect(() => {
    if (loading || initializedSelection.current) return;
    initializedSelection.current = true;
    if (selectedItem && !threads.some(thread => thread.id === selectedItem)) return;
    if (!selectedItem && filtered[0]) onSelect(filtered[0].id);
  }, [filtered, loading, onSelect, selectedItem, threads]);

  const resumeNewest = (clearSearch: boolean) => {
    liveControl.current = { paused: false, follow: true, search: clearSearch ? '' : search };
    setPaused(false);
    setFollow(true);
    setUnseen(0);
    if (clearSearch) setSearch('');
    listRef.current?.scrollTo({ top: 0, behavior: 'smooth' });
    void reconcile();
  };

  const togglePaused = () => {
    if (paused) {
      resumeNewest(false);
      return;
    }
    liveControl.current = { ...liveControl.current, paused: true, follow: false };
    setPaused(true);
    setFollow(false);
  };

  const changeSearch = (value: string) => {
    const shouldFollow = !value && !paused && (listRef.current?.scrollTop ?? 0) <= 36;
    liveControl.current = { paused, follow: shouldFollow ? true : value ? false : follow, search: value };
    setSearch(value);
    if (value) setFollow(false);
    else if (shouldFollow) {
      setFollow(true);
      setUnseen(0);
    }
  };

  const toggleFollow = () => {
    if (!follow) {
      resumeNewest(false);
      return;
    }
    liveControl.current = { ...liveControl.current, follow: false };
    setFollow(false);
  };

  const handleListScroll = (scrollTop: number) => {
    if (scrollTop > 36 && follow) {
      liveControl.current = { ...liveControl.current, follow: false };
      setFollow(false);
    } else if (scrollTop <= 36 && !paused && !search.trim()) {
      liveControl.current = { ...liveControl.current, follow: true };
      setFollow(true);
      setUnseen(0);
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col" data-testid="activity-drawer">
      <div className="flex min-h-10 flex-shrink-0 items-center gap-2 border-b border-border-subtle px-2">
        <label className="flex h-7 min-w-[170px] flex-1 items-center gap-1.5 rounded border border-border-subtle bg-background/60 px-2 focus-within:border-accent/50 sm:max-w-72">
          <Search className="h-3 w-3 text-muted-foreground" />
          <input
            value={search}
            onChange={event => changeSearch(event.target.value)}
            placeholder="Search operator activity"
            aria-label="Search operator activity"
            className="min-w-0 flex-1 bg-transparent text-[10px] outline-none placeholder:text-muted"
          />
        </label>
        <div className="hidden min-w-0 flex-1 items-center gap-1 overflow-x-auto lg:flex" role="tablist" aria-label="Activity filters">
          {ACTIVITY_FILTERS.map(option => (
            <button key={option.id} type="button" role="tab" aria-selected={filter === option.id} onClick={() => setFilter(option.id)} className={cn('h-7 flex-shrink-0 rounded px-2 text-[9px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/70', filter === option.id ? 'bg-elevated text-foreground' : 'text-muted-foreground hover:bg-hover hover:text-foreground')}>{option.label}</button>
          ))}
        </div>
        <select value={filter} onChange={event => setFilter(event.target.value as ActivityFilter)} className="h-7 max-w-36 rounded border border-border-subtle bg-background px-2 text-[10px] text-foreground outline-none lg:hidden" aria-label="Activity filter">
          {ACTIVITY_FILTERS.map(option => <option key={option.id} value={option.id}>{option.label}</option>)}
        </select>
        <span className="hidden whitespace-nowrap text-[9px] tabular-nums text-muted-foreground xl:inline">{filtered.length} / {threads.length}</span>
        <button type="button" onClick={togglePaused} disabled={!connected} className={cn('flex h-7 items-center gap-1 rounded px-2 text-[9px] disabled:opacity-40', paused ? 'bg-warning/10 text-warning' : 'text-muted-foreground hover:bg-hover hover:text-foreground')} title={paused ? 'Resume live updates' : 'Pause live updates'}>
          {paused ? <CirclePlay className="h-3 w-3" /> : <CirclePause className="h-3 w-3" />}{paused ? 'Resume' : 'Pause'}
        </button>
        <button type="button" onClick={toggleFollow} disabled={paused || Boolean(search)} className={cn('flex h-7 items-center gap-1 rounded px-2 text-[9px] disabled:opacity-40', follow ? 'bg-accent/10 text-accent' : 'text-muted-foreground hover:bg-hover hover:text-foreground')} title="Follow newest activity"><Radio className="h-3 w-3" />Follow</button>
        <button type="button" onClick={() => void reconcile()} className="flex h-7 w-7 items-center justify-center rounded text-muted-foreground hover:bg-hover hover:text-foreground" title="Reconcile activity"><RefreshCw className={cn('h-3 w-3', loading && 'animate-spin')} /></button>
      </div>

      {(stale || error) && (
        <div className="flex flex-shrink-0 items-center gap-2 border-b border-warning/20 bg-warning/5 px-3 py-1 text-[10px] text-warning">
          <AlertTriangle className="h-3 w-3" />
          <span className="min-w-0 flex-1 truncate">{connected ? (error || 'Timeline reconciliation is stale.') : 'Disconnected - showing the last good operator timeline.'}</span>
        </div>
      )}

      {unseen > 0 && (
        <button type="button" onClick={() => resumeNewest(true)} className="flex h-7 flex-shrink-0 items-center justify-center gap-1.5 border-b border-accent/20 bg-accent/5 text-[10px] font-medium text-accent hover:bg-accent/10" aria-live="polite">
          <Radio className="h-3 w-3" />{unseen} new event{unseen === 1 ? '' : 's'} · return to newest
        </button>
      )}

      <div className="flex min-h-0 flex-1">
        <div className="flex w-[clamp(300px,31vw,360px)] flex-shrink-0 flex-col border-r border-border-subtle">
          <div
            ref={listRef}
            onScroll={event => handleListScroll(event.currentTarget.scrollTop)}
            className="min-h-0 flex-1 overflow-y-auto"
          >
            {loading && events.length === 0 ? (
              <DrawerState title="Loading activity" detail="Reading the canonical operator console…" />
            ) : filtered.length === 0 ? (
              <DrawerState title={threads.length ? 'No matching activity' : 'No activity yet'} detail={threads.length ? 'Change the filter or search query.' : 'Actions, decisions, findings, sessions, and system events will appear here.'} />
            ) : filtered.map(thread => (
              <ActivityRow key={thread.id} thread={thread} selected={thread.id === selectedItem} onSelect={() => onSelect(thread.id)} />
            ))}
          </div>
          {events.length >= limit && limit < MAX_LIMIT && (
            <button type="button" onClick={() => { suppressNextAnnouncement.current = true; setLimit(value => Math.min(MAX_LIMIT, value + 200)); }} className="h-7 flex-shrink-0 border-t border-border-subtle text-[9px] text-muted-foreground hover:bg-hover hover:text-foreground">Load older activity</button>
          )}
        </div>

        <div className="min-w-0 flex-1">
          {selected ? <ActivityDetail key={selected.id} thread={selected} onOpenRun={onOpenRun} compact={mode === 'compact'} />
            : directActionId ? <DirectActionDetail actionId={directActionId} onOpenRun={onOpenRun} compact={mode === 'compact'} />
              : directSelectionLoading ? <DrawerState title="Resolving activity" detail="Checking durable action history for this selection…" />
                : <DrawerState title="Select activity" detail="Inspect lifecycle steps, context, reasoning, command, and captured output without leaving this timeline." />}
        </div>
      </div>
    </div>
  );
}

function DirectActionDetail({ actionId, onOpenRun, compact }: { actionId: string; onOpenRun: (actionId: string) => void; compact: boolean }) {
  return <div className="grid h-full min-h-0 min-w-0 grid-cols-[minmax(0,1fr)] grid-rows-[auto_minmax(0,1fr)] overflow-hidden"><div className="border-b border-border-subtle bg-surface/40 px-3 py-2"><div className="text-xs font-medium text-foreground">Durable action</div><div className="mt-0.5 font-mono text-[9px] text-muted-foreground">{actionId}</div><div className="mt-1 text-[10px] text-muted-foreground">This action is outside the currently loaded timeline window. Its durable command and output remain available directly.</div></div><ExecutionOutputView actionId={actionId} onOpenInRuns={onOpenRun} compact={compact} /></div>;
}

function ActivityRow({ thread, selected, onSelect }: { thread: ActivityThread; selected: boolean; onSelect: () => void }) {
  const latest = thread.latest;
  const context = latest.links?.node_ids?.[0] || latest.links?.session_id || latest.links?.frontier_item_id;
  return (
    <button type="button" onClick={onSelect} className={cn('relative flex min-h-[66px] w-full min-w-0 gap-2 border-b border-border-subtle px-2.5 py-2 text-left transition-colors [contain-intrinsic-size:66px] [content-visibility:auto] hover:bg-hover/45 focus-visible:z-10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent/70', selected && 'bg-accent/[0.08] before:absolute before:inset-y-2 before:left-0 before:w-0.5 before:bg-accent')}>
      <SeverityCue severity={thread.severity} />
      <div className="min-w-0 flex-1">
        <div className="flex min-w-0 items-center gap-1.5">
          <span className="w-14 flex-shrink-0 font-mono text-[9px] tabular-nums text-muted-foreground">{formatTimestamp(latest.timestamp)}</span>
          <span className="min-w-0 flex-1 truncate text-[10px] font-medium text-foreground">{latest.title}</span>
          {thread.count > 1 && <span className="rounded bg-elevated px-1 text-[8px] tabular-nums text-muted-foreground">{thread.count} steps</span>}
          {latest.status && <span className="hidden text-[8px] text-muted-foreground xl:inline">{latest.status}</span>}
        </div>
        <div className="mt-0.5 truncate text-[9px] leading-4 text-muted-foreground">{latest.summary || latest.source_label || latest.kind}</div>
        <div className="mt-0.5 flex min-w-0 items-center gap-1.5 text-[8px] text-muted">
          <span className="truncate">{latest.source_label || latest.agent_id || latest.source_kind || 'system'}</span>
          {context && <span className="min-w-0 truncate font-mono">· {context}</span>}
          <span className="ml-auto flex-shrink-0">{formatRelativeTime(latest.timestamp)}</span>
          {latest.links?.evidence_id && <span title="Evidence linked">◆</span>}
          {(latest.links?.finding_ids?.length || 0) > 0 && <span title="Finding linked">▲</span>}
        </div>
      </div>
    </button>
  );
}

function SeverityCue({ severity }: { severity: ActivityThread['severity'] }) {
  if (severity === 'error') return <span className="mt-1 text-[10px] font-bold text-destructive" title="Failure">×</span>;
  if (severity === 'warning') return <span className="mt-1 text-[10px] font-bold text-warning" title="Warning">!</span>;
  if (severity === 'success') return <span className="mt-1 text-[10px] font-bold text-success" title="Success">✓</span>;
  return <span className="mt-1 text-[10px] text-muted-foreground" title="Information">•</span>;
}

function ActivityDetail({ thread, onOpenRun, compact }: { thread: ActivityThread; onOpenRun: (actionId: string) => void; compact: boolean }) {
  const navigate = useNavigate();
  const actionId = thread.events.find(event => event.links?.action_id)?.links?.action_id;
  const [explanation, setExplanation] = useState<ActionExplanation | null>(null);
  const [metadataOpen, setMetadataOpen] = useState(false);

  useEffect(() => {
    if (!actionId) {
      setExplanation(null);
      return;
    }
    let cancelled = false;
    api.explainAction(actionId)
      .then(value => { if (!cancelled) setExplanation(value); })
      .catch(() => { if (!cancelled) setExplanation(null); });
    return () => { cancelled = true; };
  }, [actionId]);

  return (
    <div className="grid h-full min-h-0 min-w-0 grid-cols-[minmax(0,1fr)] grid-rows-[minmax(44px,0.4fr)_minmax(0,1.6fr)] overflow-hidden">
      <div className="min-h-0 overflow-y-auto border-b border-border-subtle bg-surface/40 px-3 py-2">
        <div className="flex min-w-0 items-start gap-2">
          <SeverityCue severity={thread.severity} />
          <div className="min-w-0 flex-1">
            <div className="text-xs font-medium text-foreground">{thread.latest.title}</div>
            <div className="mt-0.5 text-[10px] leading-4 text-muted-foreground">{thread.latest.summary || 'No operator summary was projected for this event.'}</div>
          </div>
          <StatusPill tone={severityTone(thread.severity)}>{thread.latest.status || thread.severity}</StatusPill>
          <button type="button" onClick={() => void navigator.clipboard?.writeText(thread.id)} className="rounded p-1 text-muted-foreground hover:bg-hover hover:text-foreground" title="Copy activity identifier"><Copy className="h-3 w-3" /></button>
        </div>

        <div className="mt-2 grid gap-3 xl:grid-cols-2">
          <section>
            <div className="mb-1 text-[9px] font-medium uppercase tracking-[0.14em] text-muted-foreground">Lifecycle</div>
            <div className="space-y-0.5">
              {thread.events.map((event, index) => (
                <div key={event.id} className="flex min-w-0 items-start gap-2 text-[9px] leading-4">
                  <span className="w-12 flex-shrink-0 font-mono text-muted">{formatTimestamp(event.timestamp)}</span>
                  <span className={cn('mt-1 h-1.5 w-1.5 flex-shrink-0 rounded-full', event.severity === 'error' ? 'bg-destructive' : event.severity === 'warning' ? 'bg-warning' : event.severity === 'success' ? 'bg-success' : 'bg-muted-foreground')} />
                  <span className="min-w-0 flex-1"><span className="text-foreground">{event.title}</span>{event.summary && event.summary !== event.title && <span className="text-muted-foreground"> · {event.summary}</span>}</span>
                  <span className="text-muted">{index + 1}/{thread.events.length}</span>
                </div>
              ))}
            </div>
          </section>

          <section>
            <div className="mb-1 text-[9px] font-medium uppercase tracking-[0.14em] text-muted-foreground">Context and reasoning</div>
            <div className="space-y-1 text-[9px] leading-4 text-muted-foreground">
              <div><span className="text-muted">Source</span> <span className="text-foreground">{thread.latest.source_label || thread.latest.agent_id || thread.latest.source_kind || 'system'}</span></div>
              {explanation?.validation && <div><span className="text-muted">Validation</span> <span className="text-foreground">{explanation.validation.validation_result || 'recorded'}</span>{(explanation.validation.warnings?.length || 0) > 0 && <span className="text-warning"> · {explanation.validation.warnings!.join('; ')}</span>}</div>}
              {explanation?.approval && <div><span className="text-muted">Approval</span> <span className="text-foreground">{explanation.approval.approval_status || (explanation.approval.auto_approved ? 'auto-approved' : 'recorded')}</span>{explanation.approval.operator_notes && <span> · {explanation.approval.operator_notes}</span>}</div>}
              {explanation?.log_thought_chain?.[0] && <div><span className="text-muted">Why</span> <span className="text-foreground">{explanation.log_thought_chain.map(item => item.description).join(' → ')}</span></div>}
              {(explanation?.considered_alternatives?.length || 0) > 0 && <div><span className="text-muted">Alternatives</span> {explanation!.considered_alternatives.join('; ')}</div>}
              <ContextLinks events={thread.events} navigate={navigate} onOpenRun={onOpenRun} />
            </div>
          </section>
        </div>

        <button type="button" onClick={() => setMetadataOpen(value => !value)} className="mt-2 flex items-center gap-1 text-[9px] text-muted-foreground hover:text-foreground">{metadataOpen ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}Raw event metadata</button>
        {metadataOpen && <pre className="mt-1 max-h-44 overflow-auto rounded border border-border-subtle bg-background p-2 font-mono text-[9px] leading-4 text-muted-foreground">{JSON.stringify(thread.events.map(event => ({ ...event, raw: event.raw })), null, 2)}</pre>}
      </div>

      <div className="min-h-0 min-w-0 overflow-hidden">
        {actionId ? <ExecutionOutputView actionId={actionId} onOpenInRuns={onOpenRun} compact={compact} /> : <EventContext thread={thread} />}
      </div>
    </div>
  );
}

function ContextLinks({ events, navigate, onOpenRun }: { events: AgentConsoleEvent[]; navigate: ReturnType<typeof useNavigate>; onOpenRun: (actionId: string) => void }) {
  const links = events.map(event => event.links).filter(Boolean);
  const actionId = links.find(link => link?.action_id)?.action_id;
  const sessionId = links.find(link => link?.session_id)?.session_id;
  const evidenceId = links.find(link => link?.evidence_id)?.evidence_id;
  const findings = [...new Set(links.flatMap(link => link?.finding_ids || []))];
  const nodes = [...new Set(links.flatMap(link => link?.node_ids || []))];
  if (!actionId && !sessionId && !evidenceId && findings.length === 0 && nodes.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-1 pt-0.5">
      <Link2 className="h-3 w-3 text-muted" />
      {actionId && <button type="button" onClick={() => onOpenRun(actionId)} className="rounded bg-accent/10 px-1.5 text-accent">Run {actionId.slice(0, 10)}</button>}
      {sessionId && <button type="button" onClick={() => navigate(buildWorkspacePath({ workspace: 'operate', drawer: { kind: 'sessions', item: sessionId } }))} className="rounded bg-purple-dim px-1.5 text-purple">Session {sessionId.slice(0, 10)}</button>}
      {evidenceId && <button type="button" onClick={() => navigate(buildWorkspacePath({ workspace: 'review', view: 'proof', selection: { kind: 'evidence', id: evidenceId } }))} className="rounded bg-elevated px-1.5 text-foreground">Evidence {evidenceId.slice(0, 10)}</button>}
      {findings.map(id => <button key={id} type="button" onClick={() => navigate(buildWorkspacePath({ workspace: 'review', view: 'readiness', selection: { kind: 'finding', id }, tab: 'proof' }))} className="rounded bg-warning/10 px-1.5 text-warning">Finding {id.slice(0, 10)}</button>)}
      {nodes.map(id => <button key={id} type="button" onClick={() => navigate(buildWorkspacePath({ workspace: 'investigate', lens: 'topology', selection: { kind: 'node', id }, context: { node: id } }))} className="rounded bg-accent/10 px-1.5 text-accent">Asset {id.slice(0, 10)}</button>)}
    </div>
  );
}

function EventContext({ thread }: { thread: ActivityThread }) {
  const latest = thread.latest;
  return (
    <div className="flex h-full min-h-0 items-center justify-center px-6 text-center">
      <div className="max-w-lg">
        {latest.severity === 'success' ? <CheckCircle2 className="mx-auto h-5 w-5 text-success" /> : <Activity className="mx-auto h-5 w-5 text-muted-foreground" />}
        <div className="mt-2 text-xs font-medium text-foreground">{eventContextTitle(latest.kind)}</div>
        <div className="mt-1 text-[10px] leading-4 text-muted-foreground">{latest.summary || 'This timeline event is not linked to an instrumented action, so there is no command output to display.'}</div>
      </div>
    </div>
  );
}

function eventContextTitle(kind: AgentConsoleKind): string {
  if (kind === 'finding') return 'Finding recorded';
  if (kind === 'session' || kind === 'transcript') return 'Session context';
  if (kind === 'approval') return 'Approval decision';
  if (kind === 'thought') return 'Operator reasoning';
  if (kind === 'system') return 'System event';
  return 'Operational event';
}

function severityTone(severity: ActivityThread['severity']): 'success' | 'warning' | 'danger' | 'muted' {
  if (severity === 'success') return 'success';
  if (severity === 'warning') return 'warning';
  if (severity === 'error') return 'danger';
  return 'muted';
}

function DrawerState({ title, detail }: { title: string; detail: string }) {
  return <div className="flex h-full min-h-28 flex-col items-center justify-center px-6 text-center"><div className="text-xs font-medium text-foreground">{title}</div><div className="mt-1 max-w-md text-[10px] leading-4 text-muted-foreground">{detail}</div></div>;
}
