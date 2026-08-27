import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, Copy, Edit3, RefreshCw, Search, TerminalSquare } from 'lucide-react';
import { useNavigate } from 'react-router';
import {
  buildDashboardWebSocketPath,
  SessionWebSocketClientEventSchema,
  SessionWebSocketServerEventSchema,
} from '@overwatch/dashboard-contracts';
import * as api from '../../lib/api';
import { createDashboardCommandId, createDashboardWebSocket } from '../../lib/dashboard-transport';
import {
  SESSION_GROUP_LABELS,
  cleanTerminalText,
  extractCommandLikeLines,
  groupSessions,
  searchSession,
  searchSessionBuffer,
  sessionBufferRequestKey,
  sessionCopyFields,
  sessionOperationalLabel,
  sessionSupportsResize,
  sessionTitle,
  sortSessionsForWorkspace,
  type SessionGroup,
} from '../../lib/session-workspace';
import {
  listPendingTerminalMutations,
  pendingTerminalMutationBucket,
  settlePendingTerminalMutation,
} from '../../lib/session-terminal-pending';
import type { SessionBufferResponse, SessionInfo } from '../../lib/types';
import { cn, formatRelativeTime } from '../../lib/utils';
import { useEngagementStore } from '../../stores/engagement-store';
import { ActionButton, StatusPill } from '../shared/primitives';

type SessionView = 'terminal' | 'context' | 'buffer';

interface TerminalEntry {
  connectionId: string;
  generation: number;
  terminal: import('@xterm/xterm').Terminal;
  fitAddon: import('@xterm/addon-fit').FitAddon;
  ws: WebSocket;
  opened: boolean;
  resizeObserver?: ResizeObserver;
}

export function SessionsDrawer({
  selectedItem,
  onSelect,
  onRequestFocus,
}: {
  selectedItem?: string;
  onSelect: (item: string | null) => void;
  onRequestFocus: () => void;
}) {
  const navigate = useNavigate();
  const sessions = useEngagementStore(state => state.sessions);
  const setSessions = useEngagementStore(state => state.setSessions);
  const graph = useEngagementStore(state => state.graph);
  const connected = useEngagementStore(state => state.connected);
  const [query, setQuery] = useState('');
  const [view, setView] = useState<SessionView>('terminal');
  const [attachedIds, setAttachedIds] = useState<string[]>([]);
  const [activeTerminalId, setActiveTerminalId] = useState<string | null>(null);
  const [buffer, setBuffer] = useState<SessionBufferResponse | null>(null);
  const [bufferQuery, setBufferQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [stale, setStale] = useState(false);
  const [attachError, setAttachError] = useState<string | null>(null);
  const [pendingWarning, setPendingWarning] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [draftTitle, setDraftTitle] = useState('');
  const [draftNotes, setDraftNotes] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const terminalEntries = useRef(new Map<string, TerminalEntry>());
  const terminalContainers = useRef(new Map<string, HTMLDivElement>());
  const initializedSelection = useRef(false);
  const mounted = useRef(true);

  const refresh = useCallback(async () => {
    try {
      const response = await api.getSessions();
      setSessions(response.sessions || []);
      setStale(false);
    } catch {
      setStale(true);
    } finally {
      setLoading(false);
    }
  }, [setSessions]);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => { if (connected) void refresh(); }, 5000);
    return () => window.clearInterval(timer);
  }, [connected, refresh]);

  useEffect(() => { if (!connected) setStale(true); }, [connected]);

  const visibleSessions = useMemo(() => sortSessionsForWorkspace(sessions.filter(session => searchSession(session, query.trim()))), [query, sessions]);
  const grouped = useMemo(() => groupSessions(visibleSessions), [visibleSessions]);
  const selected = useMemo(() => selectedItem ? sessions.find(session => session.id === selectedItem) ?? null : null, [selectedItem, sessions]);

  useEffect(() => {
    if (loading || initializedSelection.current) return;
    initializedSelection.current = true;
    if (selectedItem && !sessions.some(session => session.id === selectedItem)) onSelect(null);
    else if (!selectedItem && visibleSessions[0]) onSelect(visibleSessions[0].id);
  }, [loading, onSelect, selectedItem, sessions, visibleSessions]);

  useEffect(() => {
    let reconciling = false;
    const reconcilePending = async () => {
      if (reconciling) return;
      reconciling = true;
      try {
        await Promise.all(listPendingTerminalMutations().map(async pending => {
          const commandId = pending.command.command_id;
          if (!commandId) return;
          try {
            const response = await api.getApplicationCommand(commandId);
            const state = response.command.status;
            if (state === 'succeeded' || state === 'failed' || state === 'interrupted') settlePendingTerminalMutation(pending.generation, commandId, state);
          } catch {
            // Ambiguous mutations intentionally remain visible until a durable receipt exists.
          }
        }));
        const unresolved = listPendingTerminalMutations();
        setPendingWarning(unresolved.length ? `${unresolved.length} terminal command${unresolved.length === 1 ? '' : 's'} still await durable acknowledgement.` : null);
      } finally {
        reconciling = false;
      }
    };
    void reconcilePending();
    const timer = window.setInterval(reconcilePending, 2000);
    return () => window.clearInterval(timer);
  }, []);

  const detach = useCallback((sessionId: string) => {
    const entry = terminalEntries.current.get(sessionId);
    if (entry) {
      entry.resizeObserver?.disconnect();
      entry.ws.onopen = null;
      entry.ws.onmessage = null;
      entry.ws.onclose = null;
      entry.ws.onerror = null;
      try { entry.ws.close(); } catch { /* already closed */ }
      entry.terminal.dispose();
      terminalEntries.current.delete(sessionId);
    }
    terminalContainers.current.delete(sessionId);
    setAttachedIds(current => {
      const next = current.filter(id => id !== sessionId);
      setActiveTerminalId(active => active === sessionId ? (next[next.length - 1] || null) : active);
      return next;
    });
  }, []);

  const attach = useCallback(async (sessionId: string) => {
    if (terminalEntries.current.has(sessionId)) {
      setActiveTerminalId(sessionId);
      setView('terminal');
      onSelect(sessionId);
      onRequestFocus();
      return;
    }
    const session = useEngagementStore.getState().sessions.find(candidate => candidate.id === sessionId);
    if (!session || session.state !== 'connected' || !session.connection_id) throw new Error('This session no longer has an attachable connection generation.');

    const connectionId = session.connection_id;
    const generation = session.connection_generation ?? 0;
    const generationRef = { session_id: sessionId, connection_id: connectionId, connection_generation: generation };
    const pending = pendingTerminalMutationBucket(generationRef);
    const { Terminal } = await import('@xterm/xterm');
    await import('@xterm/xterm/css/xterm.css');
    const { FitAddon } = await import('@xterm/addon-fit');
    if (!mounted.current) return;

    const terminal = new Terminal({
      fontSize: 12,
      fontFamily: 'ui-monospace, "SF Mono", "Cascadia Code", Menlo, monospace',
      theme: {
        background: '#080a0f', foreground: '#dedde6', cursor: '#5b8def', selectionBackground: 'rgba(91,141,239,0.3)',
        black: '#0e1118', brightBlack: '#4e4d58', red: '#ef4444', brightRed: '#f87171', green: '#3ecf8e', brightGreen: '#6ee7b7',
        yellow: '#eab308', brightYellow: '#fde68a', blue: '#5b8def', brightBlue: '#93bbfd', magenta: '#a78bfa', brightMagenta: '#c4b5fd',
        cyan: '#4ecdc4', brightCyan: '#67e8f9', white: '#e2e0ea', brightWhite: '#ffffff',
      },
      cursorBlink: true,
      scrollback: 5000,
      allowTransparency: true,
    });
    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);

    const params = new URLSearchParams({ connection_id: connectionId, connection_generation: String(generation) });
    const ws = createDashboardWebSocket(`${buildDashboardWebSocketPath('session', { session_id: sessionId })}?${params.toString()}`);
    ws.binaryType = 'arraybuffer';
    ws.onopen = () => {
      setAttachError(null);
      terminal.write(`\r\n\x1b[32mAttached to ${sessionId.slice(0, 8)} generation ${generation}\x1b[0m\r\n`);
      for (const message of pending.values()) ws.send(JSON.stringify(message));
    };
    ws.onmessage = event => {
      if (event.data instanceof ArrayBuffer) {
        terminal.write(new Uint8Array(event.data));
        return;
      }
      try {
        const message = SessionWebSocketServerEventSchema.parse(JSON.parse(String(event.data)));
        if (message.type === 'output' && message.text) terminal.write(message.text);
        else if (message.type === 'command_result') settlePendingTerminalMutation(generationRef, message.command_id, message.status);
        else if (message.type === 'error') {
          if (message.command_id && message.status) settlePendingTerminalMutation(generationRef, message.command_id, message.status);
          terminal.write(`\r\n\x1b[31m${message.error}\x1b[0m\r\n`);
        } else if (message.type === 'session_closed') terminal.write('\r\n\x1b[31mSession closed\x1b[0m\r\n');
      } catch {
        terminal.write(String(event.data));
      }
    };
    ws.onclose = () => {
      terminal.write('\r\n\x1b[31mTerminal transport detached\x1b[0m\r\n');
      if (pending.size) setAttachError(`${pending.size} terminal command${pending.size === 1 ? '' : 's'} await durable acknowledgement for generation ${generation}.`);
      void refresh();
    };
    ws.onerror = () => setAttachError(`Terminal transport failed for ${sessionId.slice(0, 8)}.`);

    terminal.onData(data => {
      if (ws.readyState !== WebSocket.OPEN) return;
      const commandId = createDashboardCommandId();
      const message = SessionWebSocketClientEventSchema.parse({ type: 'input', data, command_id: commandId, idempotency_key: `dashboard:ws:input:${commandId}` });
      pending.set(commandId, message);
      ws.send(JSON.stringify(message));
    });
    terminal.onResize(({ cols, rows }) => {
      if (!sessionSupportsResize(session) || ws.readyState !== WebSocket.OPEN) return;
      const commandId = createDashboardCommandId();
      const message = SessionWebSocketClientEventSchema.parse({ type: 'resize', cols, rows, command_id: commandId, idempotency_key: `dashboard:ws:resize:${commandId}` });
      pending.set(commandId, message);
      ws.send(JSON.stringify(message));
    });

    terminalEntries.current.set(sessionId, { connectionId, generation, terminal, fitAddon, ws, opened: false });
    setAttachedIds(current => current.includes(sessionId) ? current : [...current, sessionId]);
    setActiveTerminalId(sessionId);
    setView('terminal');
    onSelect(sessionId);
    onRequestFocus();
  }, [onRequestFocus, onSelect, refresh]);

  const mountTerminal = useCallback((sessionId: string, element: HTMLDivElement | null) => {
    if (!element) {
      terminalContainers.current.delete(sessionId);
      return;
    }
    terminalContainers.current.set(sessionId, element);
    const entry = terminalEntries.current.get(sessionId);
    if (!entry || entry.opened) return;
    entry.terminal.open(element);
    entry.opened = true;
    window.requestAnimationFrame(() => { try { entry.fitAddon.fit(); } catch { /* dimensions not ready */ } });
    entry.resizeObserver = new ResizeObserver(() => { try { entry.fitAddon.fit(); } catch { /* detached */ } });
    entry.resizeObserver.observe(element);
  }, []);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      for (const sessionId of [...terminalEntries.current.keys()]) detach(sessionId);
    };
  }, [detach]);

  useEffect(() => {
    for (const sessionId of attachedIds) {
      const entry = terminalEntries.current.get(sessionId);
      const current = sessions.find(session => session.id === sessionId);
      if (!entry || !current || current.state !== 'connected' || current.connection_id !== entry.connectionId || (current.connection_generation ?? 0) !== entry.generation) detach(sessionId);
    }
  }, [attachedIds, detach, sessions]);

  const bufferKey = selected ? sessionBufferRequestKey(selected) : null;
  const refreshBuffer = useCallback(async () => {
    if (!selected) return;
    try {
      setBuffer(await api.getSessionBuffer(selected.id, { tailBytes: 24_000, connectionId: selected.connection_id, connectionGeneration: selected.connection_generation }));
    } catch {
      setBuffer(null);
    }
  }, [selected]);

  useEffect(() => {
    setBuffer(null);
    void refreshBuffer();
  }, [bufferKey, refreshBuffer]);

  const bufferCommands = useMemo(() => extractCommandLikeLines(buffer), [buffer]);
  const bufferMatches = useMemo(() => searchSessionBuffer(buffer, bufferQuery), [buffer, bufferQuery]);

  const resume = async (sessionId: string) => {
    setBusy(`resume:${sessionId}`);
    setAttachError(null);
    try { await api.resumeSession(sessionId); await refresh(); }
    catch (cause) { setAttachError(cause instanceof Error ? cause.message : 'Listener could not be resumed.'); }
    finally { setBusy(null); }
  };

  const close = async (sessionId: string) => {
    setBusy(`close:${sessionId}`);
    try {
      if (terminalEntries.current.has(sessionId)) detach(sessionId);
      await api.closeSession(sessionId);
      await refresh();
    } catch (cause) {
      setAttachError(cause instanceof Error ? cause.message : 'Session could not be closed.');
    } finally { setBusy(null); }
  };

  const save = async () => {
    if (!selected) return;
    setBusy(`edit:${selected.id}`);
    try {
      await api.updateSession(selected.id, { title: draftTitle, notes: draftNotes });
      setEditing(false);
      await refresh();
    } catch (cause) {
      setAttachError(cause instanceof Error ? cause.message : 'Session context could not be saved.');
    } finally { setBusy(null); }
  };

  const copy = async (label: string, value: string) => {
    try {
      await navigator.clipboard?.writeText(value);
      setCopied(label);
      window.setTimeout(() => setCopied(null), 1200);
    } catch { setCopied(null); }
  };

  return (
    <div className="flex h-full min-h-0 flex-col" data-testid="sessions-drawer">
      <div className="flex min-h-10 flex-shrink-0 items-center gap-2 border-b border-border-subtle px-2">
        <label className="flex h-7 min-w-[180px] flex-1 items-center gap-1.5 rounded border border-border-subtle bg-background/60 px-2 focus-within:border-accent/50 sm:max-w-72">
          <Search className="h-3 w-3 text-muted-foreground" />
          <input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search safe session metadata" className="min-w-0 flex-1 bg-transparent text-[10px] outline-none placeholder:text-muted" />
        </label>
        <span className="text-[9px] tabular-nums text-muted-foreground">{sessions.filter(session => session.state === 'connected').length} live · {attachedIds.length} attached · {sessions.length} total</span>
        <button type="button" onClick={() => void refresh()} className="flex h-7 w-7 items-center justify-center rounded text-muted-foreground hover:bg-hover hover:text-foreground" title="Refresh sessions"><RefreshCw className={cn('h-3 w-3', loading && 'animate-spin')} /></button>
      </div>

      {(stale || attachError || pendingWarning) && (
        <div className={cn('flex flex-shrink-0 items-center gap-2 border-b px-3 py-1 text-[10px]', attachError ? 'border-destructive/20 bg-destructive/5 text-destructive' : 'border-warning/20 bg-warning/5 text-warning')}>
          <AlertTriangle className="h-3 w-3" /><span className="min-w-0 flex-1 truncate">{attachError || pendingWarning || (connected ? 'Session list is stale.' : 'Disconnected — last-good session context remains visible.')}</span>
        </div>
      )}

      <div className="flex min-h-0 flex-1">
        <div className="w-[clamp(300px,31vw,360px)] flex-shrink-0 overflow-y-auto border-r border-border-subtle">
          {loading && sessions.length === 0 ? <DrawerState title="Loading sessions" detail="Reading session lifecycle and generation state…" />
            : sessions.length === 0 ? <DrawerState title="No sessions" detail="Create a listener, shell, or interactive connection to begin." />
              : (['live', 'pending', 'resume_available', 'interrupted', 'error', 'closed'] as SessionGroup[]).map(group => (
                <section key={group}>
                  <div className="sticky top-0 z-10 flex h-6 items-center justify-between border-b border-border-subtle bg-surface/95 px-2.5 text-[8px] font-medium uppercase tracking-[0.14em] text-muted-foreground backdrop-blur"><span>{SESSION_GROUP_LABELS[group]}</span><span>{grouped[group].length}</span></div>
                  {grouped[group].map(session => <SessionRow key={session.id} session={session} selected={selectedItem === session.id} attached={attachedIds.includes(session.id)} onSelect={() => { onSelect(session.id); if (attachedIds.includes(session.id)) setActiveTerminalId(session.id); }} />)}
                  {grouped[group].length === 0 && <div className="border-b border-border-subtle px-3 py-1.5 text-[9px] text-muted">None</div>}
                </section>
              ))}
        </div>

        <div className="flex min-w-0 flex-1 flex-col">
          {selected ? (
            <>
              <div className="flex min-h-10 flex-shrink-0 items-center gap-2 border-b border-border-subtle px-2">
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[10px] font-medium text-foreground">{sessionTitle(selected)}</div>
                  <div className="truncate font-mono text-[8px] text-muted-foreground">{selected.id}</div>
                </div>
                <StatusPill tone={sessionTone(selected.state)}>{sessionStateCue(selected.state)} {sessionOperationalLabel(selected)}</StatusPill>
                <div className="flex items-center gap-1" role="tablist" aria-label="Session detail views">
                  {(['terminal', 'context', 'buffer'] as const).map(option => <button key={option} type="button" role="tab" aria-selected={view === option} onClick={() => setView(option)} className={cn('h-7 rounded px-2 text-[9px] capitalize', view === option ? 'bg-elevated text-foreground' : 'text-muted-foreground hover:bg-hover hover:text-foreground')}>{option}</button>)}
                </div>
                {selected.state === 'connected' && (attachedIds.includes(selected.id)
                  ? <ActionButton size="xs" variant="danger" onClick={() => detach(selected.id)}>Detach</ActionButton>
                  : <ActionButton size="xs" variant="success" onClick={() => void attach(selected.id).catch(cause => setAttachError(cause instanceof Error ? cause.message : 'Attach failed.'))}>Attach</ActionButton>)}
                {selected.state === 'resume_available' && <ActionButton size="xs" variant="success" disabled={busy === `resume:${selected.id}`} onClick={() => void resume(selected.id)}>{busy ? 'Resuming…' : 'Resume'}</ActionButton>}
                {selected.state !== 'closed' && <ActionButton size="xs" variant="danger" disabled={busy === `close:${selected.id}`} onClick={() => void close(selected.id)}>{busy === `close:${selected.id}` ? 'Closing…' : 'Close'}</ActionButton>}
              </div>

              <div className={cn('relative min-h-0 flex-1 bg-background', view !== 'terminal' && 'hidden')}>
                {attachedIds.length === 0 && <DrawerState title="Terminal not attached" detail="Attaching uses the current connection ID and generation, then enters drawer focus mode." action={selected.state === 'connected' ? <ActionButton variant="success" onClick={() => void attach(selected.id).catch(cause => setAttachError(cause instanceof Error ? cause.message : 'Attach failed.'))}><TerminalSquare className="h-3 w-3" />Attach terminal</ActionButton> : undefined} />}
                {attachedIds.length > 1 && <div className="absolute left-2 top-2 z-10 flex max-w-[calc(100%-1rem)] gap-1 overflow-x-auto rounded bg-surface/90 p-1 shadow-lg">{attachedIds.map(id => <button key={id} type="button" onClick={() => { setActiveTerminalId(id); onSelect(id); }} className={cn('rounded px-2 py-1 text-[8px]', activeTerminalId === id ? 'bg-accent/15 text-accent' : 'text-muted-foreground hover:bg-hover')}>{sessionTitle(sessions.find(session => session.id === id) || { id } as SessionInfo)}</button>)}</div>}
                {attachedIds.map(id => <div key={id} ref={element => mountTerminal(id, element)} className={cn('absolute inset-0 min-h-0', activeTerminalId !== id && 'invisible pointer-events-none')} />)}
              </div>

              {view === 'context' && <SessionContext session={selected} graph={graph} editing={editing} draftTitle={draftTitle} draftNotes={draftNotes} busy={busy === `edit:${selected.id}`} copied={copied} onEdit={() => { setDraftTitle(selected.title || ''); setDraftNotes(selected.notes || ''); setEditing(true); }} onCancel={() => setEditing(false)} onDraftTitle={setDraftTitle} onDraftNotes={setDraftNotes} onSave={() => void save()} onCopy={(label, value) => void copy(label, value)} onNavigate={navigate} />}
              {view === 'buffer' && <BufferView buffer={buffer} query={bufferQuery} commands={bufferCommands} matches={bufferMatches} onQuery={setBufferQuery} onRefresh={() => void refreshBuffer()} onCopy={(label, value) => void copy(label, value)} copied={copied} />}
            </>
          ) : <DrawerState title="Select a session" detail="Inspect terminal, generation-safe context, and the authoritative durable buffer." />}
        </div>
      </div>
    </div>
  );
}

function SessionRow({ session, selected, attached, onSelect }: { session: SessionInfo; selected: boolean; attached: boolean; onSelect: () => void }) {
  const owner = session.claimed_by || session.owner || session.agent_id || 'dashboard';
  const target = session.target_node || session.host || session.bind_host || 'No target';
  return (
    <button type="button" onClick={onSelect} className={cn('relative flex w-full min-w-0 items-start gap-2 border-b border-border-subtle px-2.5 py-2 text-left hover:bg-hover/45 focus-visible:z-10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent/70', selected && 'bg-accent/[0.08] before:absolute before:inset-y-2 before:left-0 before:w-0.5 before:bg-accent')}>
      <span className={cn('mt-1 h-2 w-2 flex-shrink-0 rounded-full', sessionDot(session.state))} />
      <div className="min-w-0 flex-1">
        <div className="flex min-w-0 items-center gap-1.5"><span className="min-w-0 flex-1 truncate text-[10px] font-medium text-foreground">{sessionTitle(session)}</span>{attached && <span className="rounded bg-accent/10 px-1 text-[8px] text-accent">attached</span>}<span className="text-[8px] text-muted-foreground">g{session.connection_generation ?? 0}</span></div>
        <div className="mt-0.5 truncate text-[9px] text-muted-foreground">{sessionOperationalLabel(session)} · {session.transport || session.kind} · <span className="font-mono">{target}</span></div>
        <div className="mt-0.5 flex items-center gap-1 text-[8px] text-muted"><span className="min-w-0 flex-1 truncate">{session.user || session.principal_node || 'unknown principal'} · {owner}</span><span className="flex-shrink-0">{formatRelativeTime(session.last_activity_at || session.started_at || session.created_at)}</span></div>
      </div>
    </button>
  );
}

function SessionContext({ session, graph, editing, draftTitle, draftNotes, busy, copied, onEdit, onCancel, onDraftTitle, onDraftNotes, onSave, onCopy, onNavigate }: {
  session: SessionInfo;
  graph: ReturnType<typeof useEngagementStore.getState>['graph'];
  editing: boolean;
  draftTitle: string;
  draftNotes: string;
  busy: boolean;
  copied: string | null;
  onEdit: () => void;
  onCancel: () => void;
  onDraftTitle: (value: string) => void;
  onDraftNotes: (value: string) => void;
  onSave: () => void;
  onCopy: (label: string, value: string) => void;
  onNavigate: ReturnType<typeof useNavigate>;
}) {
  const targetLabel = graph.nodes.find(node => node.id === session.target_node)?.label || session.target_node || session.host || '—';
  return (
    <div className="min-h-0 flex-1 overflow-y-auto px-3 py-2">
      <div className="flex items-start gap-3 border-b border-border-subtle pb-2">
        <div className="min-w-0 flex-1">
          {editing ? <div className="space-y-2"><input value={draftTitle} onChange={event => onDraftTitle(event.target.value)} className="h-7 w-full rounded border border-border-subtle bg-background px-2 text-[10px] outline-none focus:border-accent/50" placeholder="Session title" /><textarea value={draftNotes} onChange={event => onDraftNotes(event.target.value)} className="min-h-16 w-full rounded border border-border-subtle bg-background px-2 py-1.5 text-[10px] outline-none focus:border-accent/50" placeholder="Operator notes" /></div> : <><div className="text-xs font-medium text-foreground">{sessionTitle(session)}</div>{session.notes && <div className="mt-1 text-[10px] leading-4 text-muted-foreground">{session.notes}</div>}</>}
        </div>
        {editing ? <><ActionButton size="xs" variant="primary" disabled={busy} onClick={onSave}>{busy ? 'Saving…' : 'Save'}</ActionButton><ActionButton size="xs" onClick={onCancel}>Cancel</ActionButton></> : <ActionButton size="xs" onClick={onEdit}><Edit3 className="h-3 w-3" />Edit</ActionButton>}
      </div>
      <div className="grid gap-x-6 gap-y-1.5 border-b border-border-subtle py-2 text-[9px] sm:grid-cols-2 xl:grid-cols-3">
        <ContextFact label="Target" value={targetLabel} mono />
        <ContextFact label="Principal" value={session.user || session.principal_node || '—'} mono />
        <ContextFact label="Credential ref" value={session.credential_node || '—'} mono />
        <ContextFact label="Owner" value={session.claimed_by || session.owner || session.agent_id || 'dashboard'} mono />
        <ContextFact label="Validation default" value={session.default_validation?.technique || 'per-command'} mono />
        <ContextFact label="Generation" value={String(session.connection_generation ?? 0)} mono />
        <ContextFact label="Connection ID" value={session.connection_id || session.last_connection_id || '—'} mono />
        <ContextFact label="Transport" value={`${session.kind}${session.transport ? ` · ${session.transport}` : ''}`} />
        <ContextFact label="Last activity" value={formatRelativeTime(session.last_activity_at || session.started_at || session.created_at)} />
      </div>
      {(session.reachability_warnings?.length || session.capabilities?.tty_quality === 'dumb') ? <div className="space-y-1 border-b border-border-subtle py-2">{session.reachability_warnings?.map(warning => <div key={warning} className="text-[9px] leading-4 text-warning">! {warning}</div>)}{session.capabilities?.tty_quality === 'dumb' && <div className="text-[9px] leading-4 text-muted-foreground">Raw socket: resize and signal capabilities are unavailable. The durable buffer remains authoritative.</div>}</div> : null}
      <div className="flex flex-wrap gap-1 py-2">
        {sessionCopyFields(session).map(field => <button key={field.label} type="button" onClick={() => onCopy(field.label, field.value)} className="inline-flex h-6 items-center gap-1 rounded border border-border-subtle bg-elevated px-2 font-mono text-[8px] text-muted-foreground hover:text-foreground"><Copy className="h-2.5 w-2.5" />{copied === field.label ? 'copied' : field.label}</button>)}
        {session.target_node && <button type="button" onClick={() => onNavigate(`/investigate?lens=topology&entity=node&item=${encodeURIComponent(session.target_node!)}&node=${encodeURIComponent(session.target_node!)}`)} className="h-6 rounded bg-accent/10 px-2 text-[8px] text-accent">Show target in topology</button>}
        {session.action_id && <button type="button" onClick={() => onNavigate(`/operate?drawer=run&drawerItem=${encodeURIComponent(session.action_id!)}`)} className="h-6 rounded bg-elevated px-2 font-mono text-[8px] text-foreground">Open producing run</button>}
        {session.frontier_item_id && <button type="button" onClick={() => onNavigate(`/operate?view=ready&kind=frontier&item=${encodeURIComponent(session.frontier_item_id!)}`)} className="h-6 rounded bg-elevated px-2 font-mono text-[8px] text-foreground">Frontier item</button>}
      </div>
    </div>
  );
}

function BufferView({ buffer, query, commands, matches, onQuery, onRefresh, onCopy, copied }: {
  buffer: SessionBufferResponse | null;
  query: string;
  commands: ReturnType<typeof extractCommandLikeLines>;
  matches: ReturnType<typeof searchSessionBuffer>;
  onQuery: (value: string) => void;
  onRefresh: () => void;
  onCopy: (label: string, value: string) => void;
  copied: string | null;
}) {
  const text = buffer ? cleanTerminalText(buffer.text) : '';
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex h-9 flex-shrink-0 items-center gap-2 border-b border-border-subtle px-2">
        <label className="flex h-7 min-w-0 flex-1 items-center gap-1.5 rounded border border-border-subtle bg-background px-2 focus-within:border-accent/50"><Search className="h-3 w-3 text-muted-foreground" /><input value={query} onChange={event => onQuery(event.target.value)} placeholder="Search authoritative session buffer" className="min-w-0 flex-1 bg-transparent text-[9px] outline-none" /></label>
        <span className="text-[8px] tabular-nums text-muted-foreground">{buffer ? `${buffer.start_pos}–${buffer.end_pos}` : 'unavailable'} {buffer?.truncated ? '· truncated' : ''}</span>
        <button type="button" onClick={onRefresh} className="rounded p-1.5 text-muted-foreground hover:bg-hover hover:text-foreground" title="Refresh buffer"><RefreshCw className="h-3 w-3" /></button>
        <button type="button" disabled={!text} onClick={() => onCopy('Buffer', text)} className="rounded p-1.5 text-muted-foreground hover:bg-hover hover:text-foreground disabled:opacity-30" title="Copy buffer"><Copy className="h-3 w-3" /></button>
      </div>
      <div className="grid min-h-0 flex-1 grid-cols-[minmax(0,1fr)_220px]">
        <pre className="min-h-0 overflow-auto whitespace-pre-wrap break-words bg-background p-3 font-mono text-[10px] leading-[1.55] text-muted-foreground">{text || 'No durable session buffer is available.'}</pre>
        <aside className="min-h-0 overflow-y-auto border-l border-border-subtle bg-surface/35 p-2">
          <div className="mb-1 text-[8px] font-medium uppercase tracking-[0.14em] text-muted-foreground">{query ? `${matches.length} matches` : 'Command-like lines (heuristic)'}</div>
          <div className="text-[8px] leading-4 text-muted">The buffer is authoritative. These lines are convenience hints, not reconstructed command/output boundaries.</div>
          <div className="mt-2 space-y-1">{(query ? matches : commands).map(item => <button key={`${item.line}-${item.text}`} type="button" onClick={() => onCopy('Command', item.text)} className="block w-full truncate rounded px-1.5 py-1 text-left font-mono text-[8px] text-muted-foreground hover:bg-hover hover:text-foreground">{item.line}: {item.text}</button>)}</div>
          {copied && <div className="mt-2 text-[8px] text-success">{copied} copied</div>}
        </aside>
      </div>
    </div>
  );
}

function ContextFact({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return <div className="min-w-0"><div className="text-[8px] uppercase tracking-[0.12em] text-muted">{label}</div><div className={cn('truncate text-[9px] text-foreground', mono && 'font-mono')} title={value}>{value}</div></div>;
}

function sessionTone(state: SessionInfo['state']): 'success' | 'warning' | 'danger' | 'accent' | 'muted' {
  if (state === 'connected') return 'success';
  if (state === 'pending' || state === 'interrupted') return 'warning';
  if (state === 'resume_available') return 'accent';
  if (state === 'error') return 'danger';
  return 'muted';
}

function sessionStateCue(state: SessionInfo['state']): string {
  if (state === 'connected') return '●';
  if (state === 'pending') return '◌';
  if (state === 'resume_available') return '↻';
  if (state === 'interrupted') return 'Ⅱ';
  if (state === 'error') return '×';
  return '–';
}

function sessionDot(state: SessionInfo['state']): string {
  if (state === 'connected') return 'bg-success';
  if (state === 'pending') return 'bg-warning animate-pulse';
  if (state === 'resume_available') return 'bg-accent';
  if (state === 'interrupted') return 'bg-warning';
  if (state === 'error') return 'bg-destructive';
  return 'bg-muted';
}

function DrawerState({ title, detail, action }: { title: string; detail: string; action?: React.ReactNode }) {
  return <div className="flex h-full min-h-28 flex-col items-center justify-center px-6 text-center"><div className="text-xs font-medium text-foreground">{title}</div><div className="mt-1 max-w-md text-[10px] leading-4 text-muted-foreground">{detail}</div>{action && <div className="mt-3">{action}</div>}</div>;
}
