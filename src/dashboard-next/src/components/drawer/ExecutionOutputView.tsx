import { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Check, Copy, ExternalLink, LoaderCircle, RefreshCw, Search } from 'lucide-react';
import { useNavigate } from 'react-router';
import { ActionOutputWebSocketEventSchema, buildDashboardWebSocketPath } from '@overwatch/dashboard-contracts';
import * as api from '../../lib/api';
import {
  formatBytes,
  matchOutputLines,
  normalizeActionOutput,
  type ActionOutputView,
  type OutputStreamView,
} from '../../lib/action-output';
import { createDashboardWebSocket } from '../../lib/dashboard-transport';
import { cn, formatElapsed, formatTimestamp } from '../../lib/utils';
import { useEngagementStore } from '../../stores/engagement-store';
import { ActionButton, StatusPill } from '../shared/primitives';

const INITIAL_BYTES = 64 * 1024;
const PAGE_BYTES = 256 * 1024;

type StreamName = 'stdout' | 'stderr';

interface LoadedStream {
  text: string;
  loadedBytes: number;
  eof: boolean;
}

export function ExecutionOutputView({
  actionId,
  onOpenInRuns,
  showOpenInRuns = true,
}: {
  actionId: string;
  onOpenInRuns?: (actionId: string) => void;
  showOpenInRuns?: boolean;
}) {
  const navigate = useNavigate();
  const connected = useEngagementStore(state => state.connected);
  const [output, setOutput] = useState<ActionOutputView | null>(null);
  const [loaded, setLoaded] = useState<Record<StreamName, LoadedStream>>({
    stdout: { text: '', loadedBytes: 0, eof: true },
    stderr: { text: '', loadedBytes: 0, eof: true },
  });
  const [stream, setStream] = useState<StreamName>('stdout');
  const [find, setFind] = useState('');
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reloadNonce, setReloadNonce] = useState(0);
  const [live, setLive] = useState<{ stdout: string; stderr: string; dropped: boolean; done: boolean } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const normalized = normalizeActionOutput(await api.getActionOutput(actionId, INITIAL_BYTES));
      setOutput(normalized);
      setLoaded({
        stdout: loadedFrom(normalized.stdout),
        stderr: loadedFrom(normalized.stderr),
      });
    } catch (cause) {
      setOutput(null);
      setError(describeActionOutputError(cause));
    } finally {
      setLoading(false);
    }
  }, [actionId]);

  useEffect(() => {
    setOutput(null);
    setLoaded({ stdout: { text: '', loadedBytes: 0, eof: true }, stderr: { text: '', loadedBytes: 0, eof: true } });
    setFind('');
    setStream('stdout');
    setLive(null);
    void load();
  }, [load, reloadNonce]);

  useEffect(() => {
    if (!connected || !output?.isRunning) {
      setLive(null);
      return;
    }
    let socket: WebSocket;
    let stdout = '';
    let stderr = '';
    let dropped = false;
    try {
      socket = createDashboardWebSocket(buildDashboardWebSocketPath('action_output', { action_id: actionId }));
    } catch {
      return;
    }
    setLive({ stdout, stderr, dropped, done: false });
    socket.onmessage = event => {
      if (typeof event.data !== 'string') return;
      try {
        const message = ActionOutputWebSocketEventSchema.parse(JSON.parse(event.data));
        if (message.type === 'output') {
          dropped ||= Boolean(message.dropped);
          if (message.stream === 'stderr') stderr += message.text;
          else stdout += message.text;
          setLive({ stdout, stderr, dropped, done: false });
        } else if (message.type === 'action_done') {
          setLive(current => current ? { ...current, done: true } : null);
          setReloadNonce(value => value + 1);
        }
      } catch {
        // Malformed output frames are ignored; the durable fetch remains canonical.
      }
    };
    return () => {
      try { socket.close(); } catch { /* already closed */ }
    };
  }, [actionId, connected, output?.isRunning]);

  const activeMeta = output?.[stream] ?? null;
  const liveText = live?.[stream] ?? '';
  const liveHasContent = Boolean(live && (live.stdout.length || live.stderr.length));
  const showingLive = Boolean(output?.isRunning && live && (!live.done || liveHasContent));
  const body = showingLive ? liveText : loaded[stream].text;
  const matches = useMemo(() => matchOutputLines(body, find), [body, find]);

  const loadMore = async () => {
    const evidenceId = activeMeta?.evidenceId;
    if (!evidenceId || loaded[stream].eof || loadingMore) return;
    setLoadingMore(true);
    try {
      const page = await api.getEvidenceRaw(evidenceId, {
        offset: loaded[stream].loadedBytes,
        maxBytes: PAGE_BYTES,
      });
      setLoaded(current => ({
        ...current,
        [stream]: {
          text: current[stream].text + page.text,
          loadedBytes: page.offset + page.bytes_read,
          eof: page.eof,
        },
      }));
    } catch (cause) {
      setError(describeActionOutputError(cause));
    } finally {
      setLoadingMore(false);
    }
  };

  if (loading && !output) {
    return <CenteredState icon={<LoaderCircle className="h-4 w-4 animate-spin" />} title="Loading execution" detail="Fetching lifecycle metadata and captured output…" />;
  }

  if (!output) {
    return (
      <CenteredState
        icon={<AlertTriangle className="h-4 w-4 text-warning" />}
        title="Run unavailable"
        detail={error || 'This action is not present in the current runtime or durable evidence index.'}
        action={<ActionButton onClick={() => setReloadNonce(value => value + 1)}><RefreshCw className="h-3 w-3" />Retry</ActionButton>}
      />
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col bg-background/25" data-testid="execution-output-view">
      {!connected && (
        <div className="flex items-center gap-2 border-b border-warning/20 bg-warning/5 px-3 py-1.5 text-[10px] text-warning">
          <AlertTriangle className="h-3 w-3" /> Last captured output remains visible. Live streaming resumes after reconnection.
        </div>
      )}

      <div className="flex-shrink-0 border-b border-border-subtle px-3 py-2">
        <div className="flex min-w-0 items-center gap-2">
          <StatusPill tone={statusTone(output.status)}>{statusCue(output.status)} {output.status}</StatusPill>
          {showingLive && !live?.done && <span className="inline-flex items-center gap-1 text-[10px] text-accent"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />Live</span>}
          <span className="min-w-0 flex-1 truncate text-xs font-medium text-foreground">{output.tool || 'Instrumented action'}</span>
          <button type="button" onClick={() => void copyText(actionId)} className="font-mono text-[9px] text-muted-foreground hover:text-foreground" title={actionId}>{actionId.slice(0, 16)}…</button>
          {showOpenInRuns && onOpenInRuns && (
            <ActionButton size="xs" variant="ghost" onClick={() => onOpenInRuns(actionId)}><ExternalLink className="h-3 w-3" />Open in Runs</ActionButton>
          )}
        </div>

        {output.command && (
          <div className="mt-2 flex min-w-0 items-start gap-2 rounded border border-border-subtle bg-background/75 px-2 py-1.5">
            <code className="min-w-0 flex-1 whitespace-pre-wrap break-all font-mono text-[10px] leading-4 text-foreground">{output.command}</code>
            <CopyButton label="Copy command" value={output.command} />
          </div>
        )}

        <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-muted-foreground">
          {output.technique && <Fact label="Technique" value={output.technique} />}
          {output.invokingTool && <Fact label="Surface" value={output.invokingTool} />}
          {output.agentId && <LinkFact label="Agent" value={output.agentId} onClick={() => navigate(`/operate?view=active&kind=agent&item=${encodeURIComponent(output.agentId!)}`)} />}
          {output.frontierItemId && <Fact label="Frontier" value={output.frontierItemId} />}
          {output.timestamp && <Fact label="Updated" value={formatTimestamp(output.timestamp)} />}
          {output.durationMs != null && <Fact label="Duration" value={formatElapsed(output.durationMs)} />}
          {output.exitCode != null && <Fact label="Exit" value={String(output.exitCode)} />}
          {output.signal && <Fact label="Signal" value={output.signal} />}
          {output.timedOut && <Fact label="Timeout" value="yes" />}
        </div>

        {output.targets.length > 0 && (
          <div className="mt-2 flex min-w-0 flex-wrap items-center gap-1">
            <span className="mr-1 text-[9px] uppercase tracking-[0.14em] text-muted-foreground">Targets</span>
            {output.targetNodeIds.slice(0, 6).map(id => <button key={id} type="button" onClick={() => navigate(`/investigate?lens=topology&entity=node&item=${encodeURIComponent(id)}&node=${encodeURIComponent(id)}`)} className="max-w-36 truncate rounded bg-accent/10 px-1.5 py-0.5 font-mono text-[9px] text-accent">{id}</button>)}
            {output.targetIps.slice(0, 6).map(value => <span key={value} className="rounded bg-elevated px-1.5 py-0.5 font-mono text-[9px] text-muted-foreground">{value}</span>)}
          </div>
        )}

        {output.findingIds.length > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-1">
            <span className="mr-1 text-[9px] uppercase tracking-[0.14em] text-muted-foreground">Findings</span>
            {output.findingIds.map(id => <button key={id} type="button" onClick={() => navigate(`/review?view=readiness&kind=finding&item=${encodeURIComponent(id)}&tab=proof`)} className="max-w-36 truncate rounded bg-warning/10 px-1.5 py-0.5 font-mono text-[9px] text-warning">{id}</button>)}
          </div>
        )}
      </div>

      <div className="flex h-9 flex-shrink-0 items-center gap-2 border-b border-border-subtle px-2">
        <div className="flex items-center gap-1" role="tablist" aria-label="Output stream">
          {(['stdout', 'stderr'] as const).map(name => (
            <button key={name} type="button" role="tab" aria-selected={stream === name} onClick={() => setStream(name)} className={cn('h-7 rounded px-2 font-mono text-[10px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/70', stream === name ? 'bg-elevated text-foreground' : 'text-muted-foreground hover:bg-hover hover:text-foreground')}>{name}</button>
          ))}
        </div>
        <label className="flex h-7 min-w-0 flex-1 items-center gap-1.5 rounded border border-border-subtle bg-background/60 px-2 focus-within:border-accent/50">
          <Search className="h-3 w-3 text-muted-foreground" />
          <input value={find} onChange={event => setFind(event.target.value)} placeholder="Find in loaded output" className="min-w-0 flex-1 bg-transparent text-[10px] outline-none placeholder:text-muted" />
        </label>
        {find && <span className="whitespace-nowrap text-[9px] tabular-nums text-muted-foreground">{matches.matchCount} matches</span>}
        <CopyButton label="Copy loaded output" value={body} disabled={!body} />
      </div>

      {!showingLive && activeMeta && <StreamNotices stream={activeMeta} loaded={loaded[stream]} onLoadMore={() => void loadMore()} loadingMore={loadingMore} />}
      {showingLive && live?.dropped && <Notice tone="warning">Earlier live bytes left the transient buffer. Durable evidence replaces this view when the action completes.</Notice>}
      {error && <Notice tone="danger">{error}</Notice>}

      <div className="min-h-0 flex-1 overflow-auto bg-background" aria-label={`${stream} output`}>
        <OutputBody
          output={output}
          stream={stream}
          meta={activeMeta}
          showingLive={showingLive}
          text={body}
          lines={matches.lines}
          filtered={matches.filtered}
          matchCount={matches.matchCount}
        />
      </div>

      {!showingLive && activeMeta?.evidenceId && (
        <ReparseBar actionId={actionId} evidenceId={activeMeta.evidenceId} defaultTool={output.tool} />
      )}
    </div>
  );
}

function loadedFrom(stream: OutputStreamView): LoadedStream {
  return {
    text: stream.text,
    loadedBytes: new TextEncoder().encode(stream.text).byteLength,
    eof: !stream.headTruncated,
  };
}

function describeActionOutputError(cause: unknown): string {
  const error = cause as { status?: number; message?: string } | undefined;
  if (error?.status === 404) return 'No durable lifecycle or output record was found for this action.';
  return error?.message || 'Action output could not be loaded.';
}

function statusTone(status: ActionOutputView['status']): 'accent' | 'success' | 'warning' | 'danger' | 'muted' {
  if (status === 'running') return 'accent';
  if (status === 'success') return 'success';
  if (status === 'partial') return 'warning';
  if (status === 'failure') return 'danger';
  return 'muted';
}

function statusCue(status: ActionOutputView['status']): string {
  if (status === 'running') return '●';
  if (status === 'success') return '✓';
  if (status === 'partial') return '△';
  if (status === 'failure') return '×';
  return '–';
}

function Fact({ label, value }: { label: string; value: string }) {
  return <span><span className="text-muted">{label}</span> <span className="font-mono text-foreground">{value}</span></span>;
}

function LinkFact({ label, value, onClick }: { label: string; value: string; onClick: () => void }) {
  return <button type="button" onClick={onClick} className="hover:text-accent"><span className="text-muted">{label}</span> <span className="font-mono text-foreground">{value}</span></button>;
}

function CopyButton({ label, value, disabled }: { label: string; value: string; disabled?: boolean }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      disabled={disabled}
      title={label}
      aria-label={label}
      onClick={() => {
        void copyText(value).then(() => {
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1200);
        });
      }}
      className="flex h-6 w-6 flex-shrink-0 items-center justify-center rounded text-muted-foreground hover:bg-hover hover:text-foreground disabled:opacity-30"
    >
      {copied ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
    </button>
  );
}

async function copyText(value: string): Promise<void> {
  if (!value) return;
  await navigator.clipboard?.writeText(value);
}

function StreamNotices({ stream, loaded, onLoadMore, loadingMore }: { stream: OutputStreamView; loaded: LoadedStream; onLoadMore: () => void; loadingMore: boolean }) {
  return (
    <>
      {stream.captureFailed && <Notice tone="danger">Evidence capture failed. Output bytes that were not retained cannot be recovered.</Notice>}
      {!stream.captureFailed && stream.missing && <Notice tone="danger">The evidence record exists, but its blob is unavailable.</Notice>}
      {stream.capturedTruncated && <Notice tone="warning">The execution capture buffer overflowed{stream.droppedBytes ? `; approximately ${formatBytes(stream.droppedBytes)} were dropped` : ''}.</Notice>}
      {!loaded.eof && (
        <Notice tone="warning">
          <span className="flex-1">Showing {formatBytes(loaded.loadedBytes)} of {formatBytes(stream.totalBytes)} captured.</span>
          <button type="button" disabled={loadingMore} onClick={onLoadMore} className="rounded border border-current/30 px-1.5 py-0.5 hover:bg-current/10 disabled:opacity-50">{loadingMore ? 'Loading…' : 'Load more'}</button>
        </Notice>
      )}
    </>
  );
}

function Notice({ tone, children }: { tone: 'warning' | 'danger'; children: React.ReactNode }) {
  return <div className={cn('flex flex-shrink-0 items-center gap-2 border-b px-3 py-1 text-[10px]', tone === 'danger' ? 'border-destructive/20 bg-destructive/5 text-destructive' : 'border-warning/20 bg-warning/5 text-warning')}>{children}</div>;
}

function OutputBody({ output, stream, meta, showingLive, text, lines, filtered, matchCount }: {
  output: ActionOutputView;
  stream: StreamName;
  meta: OutputStreamView | null;
  showingLive: boolean;
  text: string;
  lines: string[];
  filtered: boolean;
  matchCount: number;
}) {
  if (filtered && matchCount === 0) return <CenteredState title="No matching lines" detail="Change the find query to return to the loaded output." />;
  if (text) return <pre className="min-w-0 whitespace-pre-wrap break-words p-3 font-mono text-[10px] leading-[1.55] text-muted-foreground">{lines.join('\n')}</pre>;
  if (showingLive) return <CenteredState title={`Waiting for ${stream}`} detail="The action is live, but this stream has not emitted output yet." />;
  if (!meta) return <CenteredState title="No output record" detail="The action lifecycle exists without a stream capture object." />;
  if (meta.captureFailed) return <CenteredState title="Capture failed" detail="The process produced output, but Overwatch could not persist it." />;
  if (meta.missing) return <CenteredState title="Evidence unavailable" detail="The evidence identifier exists, but its captured bytes are missing." />;
  if (output.isRunning) return <CenteredState title="Run in progress" detail={`No ${stream} has been captured yet.`} />;
  return <CenteredState title={`No ${stream}`} detail="This run completed without producing bytes on this stream." />;
}

function CenteredState({ icon, title, detail, action }: { icon?: React.ReactNode; title: string; detail?: string; action?: React.ReactNode }) {
  return (
    <div className="flex h-full min-h-28 flex-col items-center justify-center px-6 text-center">
      {icon && <div className="mb-2 text-muted-foreground">{icon}</div>}
      <div className="text-xs font-medium text-foreground">{title}</div>
      {detail && <div className="mt-1 max-w-lg text-[10px] leading-4 text-muted-foreground">{detail}</div>}
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
}

function ReparseBar({ actionId, evidenceId, defaultTool }: { actionId: string; evidenceId: string; defaultTool: string | null }) {
  const [expanded, setExpanded] = useState(false);
  const [tool, setTool] = useState(defaultTool || '');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<api.ReparseResponse | null>(null);

  const run = async (ingest: boolean) => {
    if (!tool.trim()) return;
    setBusy(true);
    try {
      setResult(await api.reparseAction(actionId, { tool_name: tool.trim(), evidence_id: evidenceId, ingest }));
    } catch (cause) {
      setResult({
        parsed: false,
        parse_status: 'parser_exception',
        parse_outcome: 'parser_exception',
        isError: true,
        tool: tool.trim(),
        action_id: actionId,
        evidence_id: evidenceId,
        nodes_parsed: 0,
        edges_parsed: 0,
        error: cause instanceof Error ? cause.message : 'Reparse failed',
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex-shrink-0 border-t border-border-subtle bg-surface/80 px-2 py-1.5">
      {!expanded ? (
        <button type="button" onClick={() => setExpanded(true)} className="text-[9px] text-muted-foreground hover:text-foreground">Reparse captured evidence</button>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          <input value={tool} onChange={event => setTool(event.target.value)} placeholder="parser/tool" className="h-6 w-40 rounded border border-border-subtle bg-background px-2 font-mono text-[9px] outline-none focus:border-accent/50" />
          <ActionButton size="xs" disabled={busy || !tool.trim()} onClick={() => void run(false)}>Preview</ActionButton>
          <ActionButton size="xs" variant="primary" disabled={busy || !tool.trim()} onClick={() => void run(true)}>Ingest</ActionButton>
          <button type="button" onClick={() => setExpanded(false)} className="text-[9px] text-muted-foreground hover:text-foreground">Close</button>
          {result && <span className={cn('text-[9px]', result.isError ? 'text-destructive' : 'text-success')}>{result.isError ? (result.error || result.parse_status) : `${result.nodes_parsed} nodes · ${result.edges_parsed} edges`}</span>}
        </div>
      )}
    </div>
  );
}
