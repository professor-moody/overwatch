import { useEffect, useState, useRef, useMemo, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useEngagementStore } from '../../stores/engagement-store';
import { useToastStore } from '../../stores/toast-store';
import * as api from '../../lib/api';
import { deployTargetsFromRun, recommendArchetypeFor } from '../../lib/agent-archetypes';
import type { ActivityEntry } from '../../lib/types';
import { buildActionRuns, filterRuns, runLabel, type ActionRun, type RunStatus } from '../../lib/action-runs';
import { normalizeActionOutput, formatBytes, matchOutputLines, type ActionOutputView, type OutputStreamView } from '../../lib/action-output';
import { formatRelativeTime, formatTimestamp, cn } from '../../lib/utils';
import { EmptyState } from '../shared';
import { ActionButton, FilterBar, PageHeader, PanelSection, SegmentedControl, StatusPill } from '../shared/primitives';
import { GraphNodeLinks } from '../shared/GraphNodeLinks';
import { useNavigation } from '../../hooks/useNavigation';
import { createDashboardWebSocket } from '../../lib/dashboard-transport';
import { ActionOutputWebSocketEventSchema, buildDashboardWebSocketPath } from '@overwatch/dashboard-contracts';

const MAX_BYTES_INITIAL = 64 * 1024;
const MAX_BYTES_CEIL = 1024 * 1024; // server clamps reads to 1 MiB

const STATUS_OPTIONS: { value: RunStatus | ''; label: string }[] = [
  { value: '', label: 'All' },
  { value: 'running', label: 'Running' },
  { value: 'success', label: 'Success' },
  { value: 'failure', label: 'Failure' },
  { value: 'partial', label: 'Partial' },
];

export function AnalysisPanel() {
  const connected = useEngagementStore((s) => s.connected);
  const initialized = useEngagementStore((s) => s.initialized);
  const [searchParams] = useSearchParams();
  const [entries, setEntries] = useState<ActivityEntry[]>([]);
  const [statusFilter, setStatusFilter] = useState<RunStatus | ''>('');
  const [search, setSearch] = useState('');
  // Deep-link: ?item=<actionId> (e.g. from an Evidence chain's "runs that produced
  // this" link) focuses that run; otherwise the first run is selected below.
  const [selectedId, setSelectedId] = useState<string | null>(searchParams.get('item'));
  const hasLoaded = useRef(false);

  const loadHistory = useCallback(async () => {
    try {
      // Fetch the action lifecycle events ONLY (the sole types buildActionRuns uses),
      // so the limit counts tool runs — not heartbeats/thoughts that would otherwise
      // crowd runs out of the window and hide most of them from this view.
      const data = await api.getHistory({
        limit: 500,
        eventTypes: ['action_started', 'action_completed', 'action_failed'],
      });
      setEntries(data.entries || []);
      hasLoaded.current = true;
    } catch { /* keep current list visible */ }
  }, []);

  useEffect(() => {
    loadHistory();
    const timer = setInterval(() => { if (connected) loadHistory(); }, 5000);
    return () => clearInterval(timer);
  }, [loadHistory, connected]);

  const runs = useMemo(() => buildActionRuns(entries), [entries]);
  const filtered = useMemo(() => filterRuns(runs, { status: statusFilter, search }), [runs, statusFilter, search]);
  // Resolve the selected run. A deep-link (?item=<actionId>) may point at a run that's
  // been filtered out (status/search) OR aged out of the fetched window entirely. In
  // both cases show THAT run — its output still loads by id via getActionOutput — rather
  // than silently swapping to the newest. Only fall back to newest when nothing is pinned.
  const selectedInSet = selectedId ? runs.find(r => r.actionId === selectedId) : undefined;
  const selectedOutOfWindow = !!selectedId && !selectedInSet;
  const selected = selectedInSet
    ?? (selectedOutOfWindow ? outOfWindowStub(selectedId!) : (filtered[0] ?? null));

  // Pin the initial selection so the 5s history poll doesn't yank the
  // assessment view to a newly-arrived run; the user's explicit click sticks.
  useEffect(() => {
    if (!selectedId && filtered.length > 0) setSelectedId(filtered[0].actionId);
  }, [filtered, selectedId]);

  const statusCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const r of runs) counts[r.status] = (counts[r.status] || 0) + 1;
    return counts;
  }, [runs]);

  return (
    <div className="h-[calc(100vh-7rem)] min-h-[680px] flex flex-col gap-4">
      <PageHeader
        title="Analysis"
        meta={`(${filtered.length}/${runs.length})`}
        actions={(
          <FilterBar>
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Filter tool, command, agent, target..."
              className="settings-input w-72"
            />
            <ActionButton onClick={loadHistory} variant="secondary">Refresh</ActionButton>
          </FilterBar>
        )}
      />

      <div className="grid grid-cols-[minmax(340px,1fr)_minmax(440px,2fr)] gap-4 flex-1 min-h-0">
        <PanelSection className="p-0 overflow-hidden min-h-0 flex flex-col">
          <div className="border-b border-border p-2">
            <SegmentedControl
              value={statusFilter}
              onChange={setStatusFilter}
              options={STATUS_OPTIONS.map(opt => ({
                value: opt.value,
                label: opt.label,
                count: opt.value ? statusCounts[opt.value] : undefined,
              }))}
            />
          </div>

          {!initialized && !hasLoaded.current ? (
            <div className="p-4 text-sm text-muted-foreground animate-pulse">Loading runs...</div>
          ) : filtered.length === 0 ? (
            <EmptyState message={runs.length === 0 ? 'No tool runs yet.' : 'No matches.'} className="m-3" />
          ) : (
            <div className="overflow-y-auto p-2 space-y-1">
              {filtered.map(run => (
                <RunRow
                  key={run.actionId}
                  run={run}
                  selected={selected?.actionId === run.actionId}
                  onSelect={() => setSelectedId(run.actionId)}
                />
              ))}
            </div>
          )}
        </PanelSection>

        {/* key on actionId: switching runs remounts, cleanly resetting stream/
            find/maxBytes and issuing a single request (no stale-maxBytes duplicate). */}
        <AssessmentView key={selected?.actionId ?? 'none'} run={selected} outOfWindow={selectedOutOfWindow} />
      </div>
    </div>
  );
}

function RunRow({ run, selected, onSelect }: { run: ActionRun; selected: boolean; onSelect: () => void }) {
  return (
    <button
      onClick={onSelect}
      className={cn(
        'w-full rounded border border-border bg-surface p-2.5 text-left text-xs transition-colors hover:border-accent/40 hover:bg-hover/40 border-l-2',
        statusBorderClass(run.status),
        selected && 'border-accent/60 bg-accent/5',
      )}
    >
      <div className="flex items-center gap-2">
        <StatusPill className={statusPillClass(run.status)}>{run.status}</StatusPill>
        <span className="truncate font-mono text-foreground">{run.tool || 'tool'}</span>
        <span className="ml-auto text-[10px] text-muted-foreground">{formatRelativeTime(run.timestamp)}</span>
      </div>
      <div className="mt-1 truncate font-mono text-muted-foreground">{runLabel(run)}</div>
      <div className="mt-1 flex flex-wrap gap-1">
        {run.agentId && <span className="text-[10px] font-mono text-muted-foreground">agent {run.agentId.slice(0, 14)}</span>}
        {run.targets.slice(0, 2).map(t => <span key={t} className="text-[10px] font-mono text-accent">{t}</span>)}
      </div>
    </button>
  );
}

// A run deep-linked by id that isn't in the fetched window: a minimal stub whose fields
// the getActionOutput fetch fills in. Lets a ?item= link to an aged-out run still open.
function outOfWindowStub(actionId: string): ActionRun {
  return { actionId, tool: null, command: null, status: 'neutral', agentId: null, targets: [], timestamp: '', startedAt: null, description: '' };
}

function AssessmentView({ run, outOfWindow }: { run: ActionRun | null; outOfWindow?: boolean }) {
  const { navigateToFinding, navigateToAgent } = useNavigation();
  const [output, setOutput] = useState<ActionOutputView | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stream, setStream] = useState<'stdout' | 'stderr'>('stdout');
  const [find, setFind] = useState('');
  const [maxBytes, setMaxBytes] = useState(MAX_BYTES_INITIAL);
  // Live stream for a running action (via /ws/actions/:id/output).
  const [live, setLive] = useState<{ stdout: string; stderr: string; done: boolean; dropped: boolean } | null>(null);
  const [reloadNonce, setReloadNonce] = useState(0);

  // Refetch on mount (new run, via key remount), on load-more (maxBytes), and
  // when the selected run transitions (status/timestamp) so a running→done run
  // refreshes in place without a manual reselect.
  useEffect(() => {
    if (!run) { setOutput(null); return; }
    let cancelled = false;
    setLoading(true);
    setError(null);
    api.getActionOutput(run.actionId, maxBytes)
      .then(res => { if (!cancelled) setOutput(normalizeActionOutput(res)); })
      .catch(e => { if (!cancelled) { setError(e instanceof Error ? e.message : String(e)); setOutput(null); } })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [run?.actionId, run?.status, run?.timestamp, maxBytes, reloadNonce]);

  // Live output: while the selected run is in flight, stream its stdout/stderr
  // over a dedicated WS (mirrors the session terminal bridge). On action_done,
  // pull the durable, full-fidelity output via the refetch nonce.
  useEffect(() => {
    if (!run || !output?.isRunning) { setLive(null); return; }
    let so = '';
    let se = '';
    let dropped = false;
    let ws: WebSocket;
    try { ws = createDashboardWebSocket(buildDashboardWebSocketPath('action_output', { action_id: run.actionId })); } catch { return; }
    setLive({ stdout: '', stderr: '', done: false, dropped: false });
    ws.onmessage = (ev) => {
      if (typeof ev.data !== 'string') return;
      try {
        const msg = ActionOutputWebSocketEventSchema.parse(JSON.parse(ev.data));
        if (msg.type === 'output') {
          if (msg.dropped) dropped = true;
          if (msg.stream === 'stderr') se += msg.text; else so += msg.text;
          setLive({ stdout: so, stderr: se, done: false, dropped });
        } else if (msg.type === 'action_done') {
          setLive(l => (l ? { ...l, done: true } : null));
          setReloadNonce(n => n + 1);
        }
      } catch { /* ignore malformed frames */ }
    };
    ws.onerror = () => { /* fall back to durable fetch */ };
    return () => { try { ws.close(); } catch { /* already closed */ } };
  }, [run?.actionId, output?.isRunning]);

  if (!run) {
    return (
      <PanelSection>
        <EmptyState message="Select a tool run to assess its output." />
      </PanelSection>
    );
  }

  const active: OutputStreamView | null = output ? (stream === 'stdout' ? output.stdout : output.stderr) : null;
  // While running we render the live buffer; once done the durable fetch wins.
  // If the buffer reports done with no content (unknown/evicted — e.g. a run
  // not backed by a live tee), drop out of live mode so the operator sees the
  // durable "in progress / no output" state instead of a stuck "Waiting…".
  const liveHasContent = !!live && (live.stdout.length > 0 || live.stderr.length > 0);
  const isLiveMode = !!(output?.isRunning && live && (!live.done || liveHasContent));
  const liveText = live ? (stream === 'stdout' ? live.stdout : live.stderr) : '';
  const bodyText = isLiveMode ? liveText : (active?.text ?? '');
  const match = matchOutputLines(bodyText, find);
  // Deploy-at-findings: route a one-click follow-up at this run's targets.
  const deployPlan = output ? deployTargetsFromRun(output.targetNodeIds, output.targetIps) : { mode: 'none' as const };

  return (
    <PanelSection className="p-0 overflow-hidden min-h-0 flex flex-col">
      {outOfWindow && (
        <div className="border-b border-border bg-accent/10 px-3 py-1.5 text-[11px] text-accent">
          Loaded by link — this run isn't in the recent-runs list (filtered out or older than the window).
        </div>
      )}
      {/* Header: command + status + facts */}
      <div className="border-b border-border p-3 space-y-2">
        <div className="flex items-center gap-2">
          <StatusPill className={statusPillClass(output?.status ?? run.status)}>{output?.status ?? run.status}</StatusPill>
          {isLiveMode && !live?.done && (
            <span className="inline-flex items-center gap-1 text-[10px] text-accent">
              <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" /> live
            </span>
          )}
          <span className="font-mono text-sm text-foreground truncate">{output?.tool ?? run.tool ?? 'tool'}</span>
          <span className="ml-auto text-[10px] text-muted-foreground">{run.timestamp ? formatTimestamp(run.timestamp) : ''}</span>
        </div>
        {(output?.command ?? run.command) && (
          <pre className="overflow-x-auto rounded border border-border bg-background px-2 py-1.5 text-[11px] font-mono text-muted-foreground">
            {output?.command ?? run.command}
          </pre>
        )}
        <div className="flex flex-wrap gap-2 text-[11px]">
          {output?.exitCode != null && <Fact label="exit" value={String(output.exitCode)} />}
          {output?.durationMs != null && <Fact label="duration" value={`${output.durationMs} ms`} />}
          {output?.timedOut && <Fact label="timed out" value="yes" />}
          {(output?.agentId ?? run.agentId) && (
            <button
              onClick={() => navigateToAgent((output?.agentId ?? run.agentId)!)}
              className="rounded border border-border bg-elevated px-2 py-1 hover:border-accent/40 hover:bg-hover"
            >
              <span className="text-muted-foreground">agent </span>
              <span className="font-mono text-foreground">{(output?.agentId ?? run.agentId)!.slice(0, 18)}</span>
            </button>
          )}
        </div>

        {(output ? output.targets.length : run.targets.length) > 0 && (
          <div className="flex flex-wrap items-center gap-1">
            <span className="text-[10px] uppercase tracking-wider text-muted-foreground mr-1">Targets</span>
            {output
              ? (
                <>
                  {output.targetNodeIds.slice(0, 8).map(t => <GraphNodeLinks key={t} nodeId={t} />)}
                  {output.targetIps.slice(0, 8).map(t => (
                    <span key={t} className="rounded border border-border bg-background/45 px-1.5 py-0.5 text-[10px] font-mono text-accent">{t}</span>
                  ))}
                </>
              )
              : run.targets.slice(0, 8).map(t => (
                <span key={t} className="rounded border border-border bg-background/45 px-1.5 py-0.5 text-[10px] font-mono text-accent">{t}</span>
              ))}
          </div>
        )}

        {output && output.findingIds.length > 0 && (
          <div className="flex flex-wrap items-center gap-1">
            <span className="text-[10px] uppercase tracking-wider text-muted-foreground mr-1">Findings</span>
            {output.findingIds.slice(0, 8).map(id => (
              <button
                key={id}
                onClick={() => navigateToFinding(id)}
                className="rounded border border-warning/30 bg-warning/10 px-1.5 py-0.5 text-[10px] font-mono text-warning hover:bg-warning/20"
              >
                {id.slice(0, 12)}
              </button>
            ))}
          </div>
        )}
        {deployPlan.mode !== 'none' && (
          <DeployFromRun
            nodeIds={deployPlan.mode === 'nodes' ? deployPlan.nodeIds : []}
            rawTarget={deployPlan.mode === 'raw' ? deployPlan.target : null}
          />
        )}
        {!isLiveMode && active?.evidenceId && (
          // key per blob: switching stdout/stderr remounts so a stale preview
          // from the other stream can't linger.
          <ReparseControls key={active.evidenceId} actionId={run.actionId} evidenceId={active.evidenceId} defaultTool={output?.tool ?? run.tool} />
        )}
      </div>

      {/* Stream toggle + find-in-output */}
      <div className="border-b border-border p-2 flex items-center gap-2">
        <SegmentedControl
          value={stream}
          onChange={setStream}
          options={[
            { value: 'stdout', label: 'stdout' },
            { value: 'stderr', label: 'stderr' },
          ]}
        />
        <input
          value={find}
          onChange={e => setFind(e.target.value)}
          placeholder="Find in output..."
          className="settings-input flex-1 min-w-0"
        />
        {find && <span className="text-[10px] text-muted-foreground whitespace-nowrap">{match.matchCount} match{match.matchCount === 1 ? '' : 'es'}</span>}
      </div>

      {/* Banners (durable view only — live mode has no truncation/evidence state) */}
      {!isLiveMode && active && <StreamBanners stream={active} onLoadMore={maxBytes < MAX_BYTES_CEIL ? () => setMaxBytes(MAX_BYTES_CEIL) : undefined} />}
      {isLiveMode && live?.dropped && (
        <div className="border-b border-border p-2">
          <div className="flex items-center gap-2 rounded bg-warning/10 px-2 py-1 text-[11px] text-warning">
            Earlier live output scrolled out of the buffer — the full output is available once the run completes.
          </div>
        </div>
      )}

      {/* Output body */}
      <div className="flex-1 min-h-0 overflow-auto bg-background">
        {loading && !output && !live ? (
          <div className="p-4 text-sm text-muted-foreground animate-pulse">Loading output...</div>
        ) : error ? (
          <div className="p-4 text-sm text-destructive">Failed to load output: {error}</div>
        ) : isLiveMode ? (
          bodyText.length === 0 ? (
            <EmptyState message={`Waiting for ${stream}…`} className="m-3" />
          ) : match.filtered && match.matchCount === 0 ? (
            <EmptyState message="No matching lines." className="m-3" />
          ) : (
            <pre className="p-3 text-[11px] leading-relaxed font-mono whitespace-pre-wrap break-words text-muted-foreground">
              {match.lines.join('\n')}
            </pre>
          )
        ) : !active ? (
          <EmptyState message="No output object for this run." className="m-3" />
        ) : active.missing && active.isEmpty ? (
          <EmptyState message={active.captureFailed ? 'Output capture failed — bytes were lost.' : 'Evidence blob is unavailable.'} className="m-3" />
        ) : active.isEmpty ? (
          <EmptyState message={output?.isRunning ? 'Run in progress — no captured output yet.' : `No ${stream} captured for this run.`} className="m-3" />
        ) : match.filtered && match.matchCount === 0 ? (
          <EmptyState message="No matching lines." className="m-3" />
        ) : (
          <pre className="p-3 text-[11px] leading-relaxed font-mono whitespace-pre-wrap break-words text-muted-foreground">
            {match.lines.join('\n')}
          </pre>
        )}
      </div>
    </PanelSection>
  );
}

function StreamBanners({ stream, onLoadMore }: { stream: OutputStreamView; onLoadMore?: () => void }) {
  const banners: { tone: 'warn' | 'error'; text: string; loadMore?: boolean }[] = [];
  if (stream.captureFailed) banners.push({ tone: 'error', text: 'Output capture failed during the run — these bytes are lost.' });
  else if (stream.missing) banners.push({ tone: 'error', text: 'Evidence blob is unavailable on disk.' });
  if (stream.capturedTruncated) banners.push({ tone: 'warn', text: `Inline capture overflowed during the run${stream.droppedBytes > 0 ? ` (~${formatBytes(stream.droppedBytes)} dropped)` : ''}.` });
  if (stream.headTruncated) banners.push({ tone: 'warn', text: `Output is ${formatBytes(stream.totalBytes)} — showing a truncated head.`, loadMore: true });
  if (banners.length === 0) return null;
  return (
    <div className="border-b border-border p-2 space-y-1">
      {banners.map((b, i) => (
        <div key={i} className={cn(
          'flex items-center gap-2 rounded px-2 py-1 text-[11px]',
          b.tone === 'error' ? 'bg-destructive/10 text-destructive' : 'bg-warning/10 text-warning',
        )}>
          <span className="flex-1">{b.text}</span>
          {b.loadMore && onLoadMore && (
            <button onClick={onLoadMore} className="rounded border border-current/30 px-1.5 py-0.5 hover:bg-current/10">Load more</button>
          )}
        </div>
      ))}
    </div>
  );
}

function DeployFromRun({ nodeIds, rawTarget }: { nodeIds: string[]; rawTarget: string | null }) {
  const graphNodes = useEngagementStore(s => s.graph.nodes);
  const addToast = useToastStore(s => s.addToast);
  const [archetypes, setArchetypes] = useState<api.AgentArchetypeSummary[]>([]);
  const [override, setOverride] = useState('');
  const [busy, setBusy] = useState(false);
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    if (!expanded) return;
    let cancelled = false;
    api.getArchetypes().then(d => { if (!cancelled) setArchetypes(d.archetypes || []); }).catch(() => { /* dropdown stays minimal */ });
    return () => { cancelled = true; };
  }, [expanded]);

  const firstNodeType = nodeIds.length ? graphNodes.find(n => n.id === nodeIds[0])?.type : undefined;
  const recommendedId = nodeIds.length ? recommendArchetypeFor({ nodeType: firstNodeType }) : recommendArchetypeFor({ rawTarget: true });
  const effectiveId = override || recommendedId;

  const deploy = async () => {
    setBusy(true);
    try {
      if (nodeIds.length) {
        const res = await api.dispatchAgent({ target_node_ids: nodeIds, archetype: effectiveId });
        if (res.dispatched) {
          addToast({ type: 'success', title: `Deployed ${effectiveId}`, message: api.dispatchedAgentLabel(res.task) });
          setExpanded(false);
        } else {
          addToast({ type: 'warning', title: 'Not deployed', message: res.reason === 'frontier_lease_conflict' ? 'target already being worked' : (res.reason || 'dispatch refused') });
        }
      } else if (rawTarget) {
        const res = await api.quickDeploy({ target: rawTarget, archetype: effectiveId });
        if (res.dispatched) {
          addToast({ type: 'success', title: `Deployed ${res.archetype || effectiveId}`, message: 'scoped + dispatched' });
          setExpanded(false);
        } else {
          addToast({ type: 'warning', title: 'Not deployed', message: res.reason || 'dispatch refused' });
        }
      }
    } catch (e) {
      addToast({ type: 'error', title: 'Deploy failed', message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  const label = nodeIds.length ? `${nodeIds.length} target node${nodeIds.length === 1 ? '' : 's'}` : rawTarget;
  if (!expanded) {
    return <button onClick={() => setExpanded(true)} className="text-[11px] text-accent hover:underline">Deploy agent at {label}…</button>;
  }
  return (
    <div className="rounded border border-border bg-elevated p-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Deploy at {label}</span>
        <select value={override} onChange={e => setOverride(e.target.value)} className="settings-input text-xs py-1">
          <option value="">Recommended: {recommendedId}</option>
          {archetypes.map(a => <option key={a.id} value={a.id}>{a.label} ({a.id})</option>)}
        </select>
        <button onClick={() => void deploy()} disabled={busy} className="rounded border border-success/40 bg-success/10 px-2 py-1 text-[11px] text-success hover:bg-success/20 disabled:opacity-50">
          {busy ? 'Deploying…' : 'Deploy'}
        </button>
        <button onClick={() => setExpanded(false)} className="ml-auto text-[11px] text-muted-foreground hover:text-foreground">Close</button>
      </div>
    </div>
  );
}

function ReparseControls({ actionId, evidenceId, defaultTool }: { actionId: string; evidenceId: string; defaultTool: string | null }) {
  const [parsers, setParsers] = useState<string[]>([]);
  const [tool, setTool] = useState('');
  const [result, setResult] = useState<api.ReparseResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    if (!expanded) return;
    let cancelled = false;
    api.getParsers().then(r => {
      if (cancelled) return;
      const list = r.parsers || [];
      setParsers(list);
      const guess = defaultTool && list.includes(defaultTool) ? defaultTool : (list[0] || '');
      setTool(t => t || guess);
    }).catch(() => { /* dropdown stays empty */ });
    return () => { cancelled = true; };
  }, [expanded, defaultTool]);

  const run = async (ingest: boolean) => {
    if (!tool) return;
    setBusy(true);
    setErr(null);
    try {
      const r = await api.reparseAction(actionId, { tool_name: tool, evidence_id: evidenceId, ingest });
      setResult(r);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  if (!expanded) {
    return <button onClick={() => setExpanded(true)} className="text-[11px] text-accent hover:underline">Re-parse output…</button>;
  }

  const canPromote = !!result
    && (result.parse_outcome === 'ok' || result.parse_outcome === 'partial')
    && !result.ingested
    && (result.nodes_parsed + result.edges_parsed) > 0;
  return (
    <div className="rounded border border-border bg-elevated p-2 space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Re-parse</span>
        <select
          value={tool}
          onChange={e => { setTool(e.target.value); setResult(null); }}
          className="settings-input text-xs py-1"
        >
          {parsers.length === 0 && <option value="">(loading…)</option>}
          {parsers.map(p => <option key={p} value={p}>{p}</option>)}
        </select>
        <button onClick={() => run(false)} disabled={busy || !tool} className="rounded border border-border px-2 py-1 text-[11px] hover:bg-hover disabled:opacity-50">
          Preview
        </button>
        {canPromote && (
          <button onClick={() => run(true)} disabled={busy} className="rounded border border-success/40 bg-success/10 px-2 py-1 text-[11px] text-success hover:bg-success/20 disabled:opacity-50">
            Promote to graph
          </button>
        )}
        <button onClick={() => setExpanded(false)} className="ml-auto text-[11px] text-muted-foreground hover:text-foreground">Close</button>
      </div>
      {err && <div className="text-[11px] text-destructive">{err}</div>}
      {result && <ReparseResult result={result} />}
    </div>
  );
}

function ReparseResult({ result }: { result: api.ReparseResponse }) {
  if (result.parse_outcome === 'partial') {
    const action = result.ingested ? 'Partially parsed and promoted' : 'Partially parsed';
    return <div className="text-[11px] text-warning">{action}: {result.nodes_parsed} nodes, {result.edges_parsed} edges{result.partial_reason ? ` (${result.partial_reason.replaceAll('_', ' ')})` : ''}.</div>;
  }
  if (result.ingested) {
    return <div className="text-[11px] text-success">Promoted: {result.ingested.new_nodes} nodes, {result.ingested.new_edges} edges, {result.ingested.inferred_edges} inferred.</div>;
  }
  switch (result.parse_status) {
    case 'ok':
      return <div className="text-[11px] text-muted-foreground">Parsed {result.nodes_parsed} nodes, {result.edges_parsed} edges — review, then Promote.</div>;
    case 'no_parser':
      return <div className="text-[11px] text-warning">No parser for “{result.tool}”.</div>;
    case 'no_data':
      return <div className="text-[11px] text-warning">No graph data extracted with “{result.tool}”.</div>;
    case 'validation_failed':
      return <div className="text-[11px] text-destructive">Validation failed ({result.validation_errors?.length ?? 0} issue{(result.validation_errors?.length ?? 0) === 1 ? '' : 's'}).</div>;
    case 'parser_exception':
      return <div className="text-[11px] text-destructive">Parser error: {result.error}</div>;
    default:
      return null;
  }
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border border-border bg-elevated px-2 py-1">
      <span className="text-muted-foreground">{label} </span>
      <span className="font-mono text-foreground">{value}</span>
    </div>
  );
}

function statusPillClass(status: RunStatus): string {
  if (status === 'running') return 'bg-accent/10 text-accent';
  if (status === 'success') return 'bg-success/10 text-success';
  if (status === 'failure') return 'bg-destructive/10 text-destructive';
  if (status === 'partial') return 'bg-warning/10 text-warning';
  return 'bg-elevated text-muted-foreground';
}

function statusBorderClass(status: RunStatus): string {
  if (status === 'running') return 'border-l-accent';
  if (status === 'success') return 'border-l-success';
  if (status === 'failure') return 'border-l-destructive';
  if (status === 'partial') return 'border-l-warning';
  return 'border-l-border';
}
