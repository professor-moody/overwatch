import { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import type { ReactNode } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import * as api from '../../lib/api';
import { cn, formatRelativeTime } from '../../lib/utils';
import { EmptyState } from '../shared';
import { FilterBar, PageHeader, PanelSection, StatusPill } from '../shared/primitives';
import { useNavigation } from '../../hooks/useNavigation';
import type { SessionInfo } from '../../lib/types';
import { deriveNodeRelationships } from '../../lib/relationships';
import {
  SESSION_GROUP_LABELS,
  addAttachedSession,
  cleanTerminalText,
  extractCommandLikeLines,
  groupSessions,
  removeAttachedSession,
  relatedSessionActions,
  relatedSessionActivity,
  relatedSessionFrontier,
  searchSessionBuffer,
  searchSession,
  sessionCopyFields,
  sessionTitle,
  sortSessionsForWorkspace,
  type SessionGroup,
} from '../../lib/session-workspace';
import type { SessionBufferResponse } from '../../lib/types';

interface TerminalEntry {
  sessionId: string;
  terminal: import('@xterm/xterm').Terminal;
  fitAddon: import('@xterm/addon-fit').FitAddon;
  ws: WebSocket | null;
}

function stateClass(state: SessionInfo['state']): string {
  if (state === 'connected') return 'bg-success/10 text-success';
  if (state === 'pending') return 'bg-warning/10 text-warning';
  if (state === 'error') return 'bg-destructive/10 text-destructive';
  return 'bg-elevated text-muted-foreground';
}

export function SessionsPanel() {
  const sessions = useEngagementStore((s) => s.sessions);
  const setStoreSessions = useEngagementStore((s) => s.setSessions);
  const graph = useEngagementStore((s) => s.graph);
  const pendingActions = useEngagementStore((s) => s.pendingActions);
  const frontier = useEngagementStore((s) => s.frontier);
  const recentActivity = useEngagementStore((s) => s.recentActivity);
  const { navigateToEvidence, navigateToGraph, navigateToPanel } = useNavigation();
  const [query, setQuery] = useState('');
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [attachedIds, setAttachedIds] = useState<string[]>([]);
  const [activeTab, setActiveTab] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [draftTitle, setDraftTitle] = useState('');
  const [draftNotes, setDraftNotes] = useState('');
  const [saving, setSaving] = useState(false);
  const [closingId, setClosingId] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [buffer, setBuffer] = useState<SessionBufferResponse | null>(null);
  const [bufferQuery, setBufferQuery] = useState('');
  const terminalsRef = useRef<Map<string, TerminalEntry>>(new Map());
  const containerRef = useRef<HTMLDivElement>(null);

  const refresh = useCallback(async () => {
    try {
      const data = await api.getSessions();
      setStoreSessions(data.sessions || []);
    } catch { /* silent */ }
  }, [setStoreSessions]);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const data = await api.getSessions();
        if (!cancelled) setStoreSessions(data.sessions || []);
      } catch { /* silent */ }
    };
    load();
    const id = setInterval(load, 5000);
    return () => { cancelled = true; clearInterval(id); };
  }, [setStoreSessions]);

  const visibleSessions = useMemo(() => {
    return sortSessionsForWorkspace(sessions.filter(session => searchSession(session, query.trim())));
  }, [sessions, query]);

  const grouped = useMemo(() => {
    return groupSessions(visibleSessions);
  }, [visibleSessions]);

  const selectedSession = useMemo(() => {
    return sessions.find(s => s.id === selectedSessionId) || sessions.find(s => s.id === activeTab) || sessions[0] || null;
  }, [sessions, selectedSessionId, activeTab]);

  useEffect(() => {
    if (!selectedSessionId && sessions.length > 0) setSelectedSessionId(sessions[0].id);
  }, [sessions, selectedSessionId]);

  const attach = useCallback(async (sessionId: string) => {
    if (terminalsRef.current.has(sessionId)) {
      setActiveTab(sessionId);
      setSelectedSessionId(sessionId);
      return;
    }

    const { Terminal } = await import('@xterm/xterm');
    await import('@xterm/xterm/css/xterm.css');
    const { FitAddon } = await import('@xterm/addon-fit');

    const term = new Terminal({
      fontSize: 13,
      fontFamily: 'ui-monospace, "SF Mono", "Cascadia Code", Menlo, monospace',
      theme: {
        background: '#080a0f',
        foreground: '#e2e0ea',
        cursor: '#5b8def',
        selectionBackground: 'rgba(91,141,239,0.3)',
        black: '#0e1118',
        brightBlack: '#4e4d58',
        red: '#ef4444',
        brightRed: '#f87171',
        green: '#3ecf8e',
        brightGreen: '#6ee7b7',
        yellow: '#eab308',
        brightYellow: '#fde68a',
        blue: '#5b8def',
        brightBlue: '#93bbfd',
        magenta: '#a78bfa',
        brightMagenta: '#c4b5fd',
        cyan: '#4ecdc4',
        brightCyan: '#67e8f9',
        white: '#e2e0ea',
        brightWhite: '#ffffff',
      },
      cursorBlink: true,
      scrollback: 5000,
      allowTransparency: true,
    });

    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);

    const wsProto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const wsUrl = `${wsProto}://${window.location.host}/ws/session/${sessionId}`;
    const ws = new WebSocket(wsUrl);

    ws.binaryType = 'arraybuffer';

    ws.onopen = () => {
      term.write('\r\n\x1b[32mConnected to session ' + sessionId.slice(0, 8) + '\x1b[0m\r\n');
    };

    ws.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(event.data));
      } else {
        try {
          const msg = JSON.parse(event.data as string);
          if (msg.type === 'output' && (msg.text || msg.data)) {
            term.write(msg.text || msg.data);
          } else if (msg.type === 'error' && msg.error) {
            term.write(`\r\n\x1b[31m${msg.error}\x1b[0m\r\n`);
          } else if (msg.type === 'session_closed') {
            term.write('\r\n\x1b[31mSession closed\x1b[0m\r\n');
          }
        } catch {
          term.write(event.data as string);
        }
      }
    };

    ws.onclose = () => {
      term.write('\r\n\x1b[31mSession disconnected\x1b[0m\r\n');
      refresh();
    };

    ws.onerror = () => {
      term.write('\r\n\x1b[31mWebSocket error\x1b[0m\r\n');
    };

    term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'input', data }));
      }
    });

    term.onResize(({ cols, rows }) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', cols, rows }));
      }
    });

    const entry: TerminalEntry = { sessionId, terminal: term, fitAddon, ws };
    terminalsRef.current.set(sessionId, entry);
    setAttachedIds(prev => addAttachedSession(prev, sessionId));
    setActiveTab(sessionId);
    setSelectedSessionId(sessionId);
  }, [refresh]);

  const detach = useCallback((sessionId: string) => {
    const entry = terminalsRef.current.get(sessionId);
    if (entry) {
      entry.ws?.close();
      entry.terminal.dispose();
      terminalsRef.current.delete(sessionId);
    }
    setAttachedIds(prev => {
      const next = removeAttachedSession(prev, sessionId);
      if (activeTab === sessionId) setActiveTab(next.length > 0 ? next[next.length - 1] : null);
      return next;
    });
  }, [activeTab]);

  const handleCloseSession = useCallback(async (sessionId: string) => {
    setClosingId(sessionId);
    try {
      if (terminalsRef.current.has(sessionId)) detach(sessionId);
      await api.closeSession(sessionId);
      await refresh();
    } catch { /* surface stays unchanged; row remains actionable */ }
    finally { setClosingId(null); }
  }, [detach, refresh]);

  const startEdit = useCallback((session: SessionInfo) => {
    setDraftTitle(session.title || '');
    setDraftNotes(session.notes || '');
    setEditing(true);
  }, []);

  const saveEdit = useCallback(async () => {
    if (!selectedSession) return;
    setSaving(true);
    try {
      await api.updateSession(selectedSession.id, { title: draftTitle, notes: draftNotes });
      setEditing(false);
      await refresh();
    } catch { /* silent */ }
    finally { setSaving(false); }
  }, [selectedSession, draftTitle, draftNotes, refresh]);

  const copyText = useCallback(async (label: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(label);
      window.setTimeout(() => setCopied(null), 1200);
    } catch {
      setCopied(null);
    }
  }, []);

  useEffect(() => {
    if (!activeTab || !containerRef.current) return;
    const entry = terminalsRef.current.get(activeTab);
    if (!entry) return;

    containerRef.current.innerHTML = '';
    entry.terminal.open(containerRef.current);
    requestAnimationFrame(() => {
      entry.fitAddon.fit();
    });

    const resizeObs = new ResizeObserver(() => {
      try { entry.fitAddon.fit(); } catch {}
    });
    resizeObs.observe(containerRef.current);
    return () => resizeObs.disconnect();
  }, [activeTab]);

  const active = sessions.filter((s) => s.state === 'connected' || s.state === 'pending');
  const connected = sessions.filter((s) => s.state === 'connected');
  const selectedNodeIds = [selectedSession?.target_node, selectedSession?.principal_node, selectedSession?.credential_node].filter((v): v is string => !!v);
  const selectedRelationships = selectedSession?.target_node
    ? deriveNodeRelationships(selectedSession.target_node, { graph, sessions, pendingActions, frontier })
    : null;
  const selectedTargetLabel = selectedSession?.target_node
    ? graph.nodes.find(n => n.id === selectedSession.target_node)?.label || selectedSession.target_node
    : null;
  const selectedRelatedActions = selectedSession ? relatedSessionActions(selectedSession, pendingActions) : [];
  const selectedRelatedFrontier = selectedSession ? relatedSessionFrontier(selectedSession, frontier) : [];
  const selectedRelatedActivity = selectedSession ? relatedSessionActivity(selectedSession, recentActivity).slice(0, 5) : [];
  const selectedCopyFields = selectedSession ? sessionCopyFields(selectedSession) : [];
  const bufferCommands = useMemo(() => extractCommandLikeLines(buffer), [buffer]);
  const bufferMatches = useMemo(() => searchSessionBuffer(buffer, bufferQuery), [buffer, bufferQuery]);

  useEffect(() => {
    if (!selectedSession) {
      setBuffer(null);
      return;
    }
    let cancelled = false;
    api.getSessionBuffer(selectedSession.id, { tailBytes: 12000 })
      .then(data => { if (!cancelled) setBuffer(data); })
      .catch(() => { if (!cancelled) setBuffer(null); });
    return () => { cancelled = true; };
  }, [selectedSession?.id]);

  return (
    <div className="h-[calc(100vh-7rem)] min-h-[680px] flex flex-col gap-4">
      <PageHeader
        title="Sessions"
        meta={`(${active.length} active · ${attachedIds.length} attached)`}
        actions={(
          <FilterBar>
            <input
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Filter sessions..."
              className="settings-input w-72"
            />
            <button onClick={refresh} className="text-xs px-2 py-1 rounded bg-elevated border border-border text-muted-foreground hover:text-foreground transition-colors">
              Refresh
            </button>
          </FilterBar>
        )}
      />

      {sessions.length === 0 ? (
        <EmptyState message="No sessions. Use open_session to create one." />
      ) : (
        <div className="grid grid-cols-[minmax(320px,380px)_1fr] gap-4 flex-1 min-h-0">
          <PanelSection className="p-0 overflow-hidden min-h-0 flex flex-col">
            <div className="grid grid-cols-3 border-b border-border text-center text-xs">
              <SessionStat label="Live" value={connected.length} tone="success" />
              <SessionStat label="Pending" value={grouped.pending.length} tone="warning" />
              <SessionStat label="Total" value={sessions.length} />
            </div>
            <div className="overflow-y-auto p-2 space-y-3">
              {(['live', 'pending', 'closed'] as SessionGroup[]).map(group => (
                <div key={group} className="space-y-1.5">
                  <div className="flex items-center justify-between px-1 text-[10px] uppercase tracking-wider text-muted-foreground">
                    <span>{SESSION_GROUP_LABELS[group]}</span>
                    <span>{grouped[group].length}</span>
                  </div>
                  {grouped[group].map(session => (
                    <SessionRow
                      key={session.id}
                      session={session}
                      selected={selectedSession?.id === session.id}
                      attached={attachedIds.includes(session.id)}
                      onSelect={() => setSelectedSessionId(session.id)}
                      onAttach={() => attach(session.id)}
                      onDetach={() => detach(session.id)}
                    />
                  ))}
                  {grouped[group].length === 0 && <div className="px-1 pb-1 text-[11px] text-muted">None</div>}
                </div>
              ))}
            </div>
          </PanelSection>

          <div className="min-w-0 min-h-0 flex flex-col gap-3">
            {selectedSession && (
              <PanelSection className="p-3">
                <div className="flex items-start gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <StatusPill className={stateClass(selectedSession.state)}>{selectedSession.state}</StatusPill>
                      {selectedSession.auth_status && <StatusPill className="bg-elevated text-muted-foreground">{selectedSession.auth_status}</StatusPill>}
                      <span className="text-xs text-muted-foreground">{selectedSession.kind}{selectedSession.transport ? ` · ${selectedSession.transport}` : ''}</span>
                    </div>
                    {editing ? (
                      <div className="space-y-2">
                        <input value={draftTitle} onChange={e => setDraftTitle(e.target.value)} className="settings-input w-full" placeholder="Session title" />
                        <textarea value={draftNotes} onChange={e => setDraftNotes(e.target.value)} className="settings-input w-full min-h-16" placeholder="Notes" />
                      </div>
                    ) : (
                      <>
                        <h3 className="text-base font-semibold truncate">{sessionTitle(selectedSession)}</h3>
                        <div className="text-[11px] text-muted-foreground font-mono truncate">{selectedSession.id}</div>
                        {selectedSession.notes && <p className="mt-2 text-xs text-muted-foreground">{selectedSession.notes}</p>}
                      </>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-1 justify-end max-w-sm">
                    {selectedSession.state === 'connected' && (
                      attachedIds.includes(selectedSession.id) ? (
                        <button onClick={() => detach(selectedSession.id)} className="text-xs px-2 py-1 rounded bg-destructive/10 text-destructive border border-destructive/20 hover:bg-destructive/20">Detach</button>
                      ) : (
                        <button onClick={() => attach(selectedSession.id)} className="text-xs px-2 py-1 rounded bg-success/10 text-success border border-success/20 hover:bg-success/20">Attach</button>
                      )
                    )}
                    {selectedSession.target_node && <button onClick={() => navigateToGraph(selectedSession.target_node, 2)} className="text-xs px-2 py-1 rounded bg-accent/10 text-accent hover:bg-accent/20">Graph</button>}
                    {selectedSession.target_node && <button onClick={() => navigateToEvidence(selectedSession.target_node!)} className="text-xs px-2 py-1 rounded bg-elevated text-foreground hover:bg-hover">Evidence</button>}
                    {editing ? (
                      <>
                        <button onClick={saveEdit} disabled={saving} className="text-xs px-2 py-1 rounded bg-accent/10 text-accent hover:bg-accent/20 disabled:opacity-50">{saving ? 'Saving...' : 'Save'}</button>
                        <button onClick={() => setEditing(false)} className="text-xs px-2 py-1 rounded bg-elevated text-muted-foreground hover:text-foreground">Cancel</button>
                      </>
                    ) : (
                      <button onClick={() => startEdit(selectedSession)} className="text-xs px-2 py-1 rounded bg-elevated text-muted-foreground hover:text-foreground">Edit</button>
                    )}
                    {selectedSession.state !== 'closed' && (
                      <button onClick={() => handleCloseSession(selectedSession.id)} disabled={closingId === selectedSession.id} className="text-xs px-2 py-1 rounded bg-destructive/10 text-destructive border border-destructive/20 hover:bg-destructive/20 disabled:opacity-50">
                        {closingId === selectedSession.id ? 'Closing...' : 'Close'}
                      </button>
                    )}
                  </div>
                </div>

                <div className="mt-3 grid grid-cols-2 lg:grid-cols-4 gap-2 text-xs">
                  <DetailFact label="Target" value={selectedTargetLabel || '—'} mono />
                  <DetailFact label="Owner" value={selectedSession.claimed_by || selectedSession.owner || selectedSession.agent_id || 'dashboard'} mono />
                  <DetailFact label="Last Activity" value={selectedSession.last_activity_at ? formatRelativeTime(selectedSession.last_activity_at) : '—'} />
                  <DetailFact label="Buffer" value={selectedSession.buffer_end_pos != null ? String(selectedSession.buffer_end_pos) : '—'} mono />
                </div>

                {selectedNodeIds.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {selectedNodeIds.map(nodeId => (
                      <button key={nodeId} onClick={() => navigateToGraph(nodeId, 2)} className="text-[10px] px-1.5 py-0.5 rounded bg-accent/10 text-accent hover:bg-accent/20 font-mono">
                        {nodeId}
                      </button>
                    ))}
                    {selectedSession.action_id && <span className="text-[10px] px-1.5 py-0.5 rounded bg-elevated text-muted-foreground font-mono">action {selectedSession.action_id.slice(0, 10)}</span>}
                    {selectedSession.frontier_item_id && <span className="text-[10px] px-1.5 py-0.5 rounded bg-elevated text-muted-foreground font-mono">frontier {selectedSession.frontier_item_id.slice(0, 10)}</span>}
                    {selectedRelationships && selectedRelationships.pendingActions.length > 0 && <span className="text-[10px] px-1.5 py-0.5 rounded bg-warning/10 text-warning">{selectedRelationships.pendingActions.length} pending action{selectedRelationships.pendingActions.length === 1 ? '' : 's'}</span>}
                    {selectedRelationships && selectedRelationships.frontier.length > 0 && <span className="text-[10px] px-1.5 py-0.5 rounded bg-accent/10 text-accent">{selectedRelationships.frontier.length} frontier item{selectedRelationships.frontier.length === 1 ? '' : 's'}</span>}
                  </div>
                )}

                <div className="mt-3 grid grid-cols-1 xl:grid-cols-3 gap-2">
                  <SessionContextBlock title="Copy Context">
                    <div className="flex flex-wrap gap-1">
                      {selectedCopyFields.map(field => (
                        <button
                          key={field.label}
                          onClick={() => copyText(field.label, field.value)}
                          className="text-[10px] px-1.5 py-0.5 rounded bg-elevated border border-border text-muted-foreground hover:text-foreground font-mono"
                        >
                          {copied === field.label ? 'copied' : field.label}
                        </button>
                      ))}
                    </div>
                  </SessionContextBlock>
                  <SessionContextBlock title="Terminal Links">
                    <div className="flex flex-wrap gap-1">
                      <button onClick={() => navigateToPanel('actions')} className="text-[10px] px-1.5 py-0.5 rounded bg-warning/10 text-warning">
                        {selectedRelatedActions.length} actions
                      </button>
                      <button onClick={() => navigateToPanel('frontier', selectedSession.target_node || undefined)} className="text-[10px] px-1.5 py-0.5 rounded bg-accent/10 text-accent">
                        {selectedRelatedFrontier.length} frontier
                      </button>
                    </div>
                  </SessionContextBlock>
                  <SessionContextBlock title="Recent Activity">
                    {selectedRelatedActivity.length === 0 ? (
                      <div className="text-[10px] text-muted-foreground">No linked events</div>
                    ) : (
                      <div className="space-y-0.5">
                        {selectedRelatedActivity.map((entry, index) => (
                          <div key={(entry.event_id || entry.id || index)} className="text-[10px] text-muted-foreground truncate">
                            {entry.event_type}
                          </div>
                        ))}
                      </div>
                    )}
                  </SessionContextBlock>
                </div>

                <div className="mt-3 grid grid-cols-1 xl:grid-cols-[1.4fr_1fr] gap-2">
                  <SessionContextBlock title="Buffer Tail">
                    <div className="flex items-center gap-2 mb-2">
                      <input
                        value={bufferQuery}
                        onChange={e => setBufferQuery(e.target.value)}
                        placeholder="Search buffer"
                        className="settings-input h-7 text-xs flex-1"
                      />
                      <button
                        onClick={() => selectedSession && api.getSessionBuffer(selectedSession.id, { tailBytes: 12000 }).then(setBuffer).catch(() => setBuffer(null))}
                        className="text-[10px] px-1.5 py-0.5 rounded bg-elevated border border-border text-muted-foreground hover:text-foreground"
                      >
                        Refresh
                      </button>
                    </div>
                    <pre className="max-h-40 overflow-auto rounded bg-background border border-border p-2 text-[10px] text-muted-foreground whitespace-pre-wrap">
                      {buffer ? cleanTerminalText(buffer.text).slice(-4000) || 'No buffered output.' : 'No buffer available.'}
                    </pre>
                    {buffer && (
                      <div className="mt-1 flex flex-wrap gap-1 text-[10px] text-muted-foreground">
                        <span>{buffer.start_pos}-{buffer.end_pos}</span>
                        {buffer.truncated && <span className="text-warning">truncated</span>}
                        <button onClick={() => copyText('Buffer', cleanTerminalText(buffer.text))} className="text-accent hover:underline">
                          {copied === 'Buffer' ? 'copied' : 'copy buffer'}
                        </button>
                      </div>
                    )}
                  </SessionContextBlock>
                  <SessionContextBlock title="Commands / Matches">
                    {bufferQuery.trim() ? (
                      bufferMatches.length === 0 ? (
                        <div className="text-[10px] text-muted-foreground">No matches</div>
                      ) : (
                        <div className="space-y-1 max-h-40 overflow-auto">
                          {bufferMatches.map(match => (
                            <div key={`${match.line}-${match.text}`} className="text-[10px] text-muted-foreground font-mono truncate">
                              {match.line}: {match.text}
                            </div>
                          ))}
                        </div>
                      )
                    ) : bufferCommands.length === 0 ? (
                      <div className="text-[10px] text-muted-foreground">No command-like lines detected</div>
                    ) : (
                      <div className="space-y-1 max-h-40 overflow-auto">
                        {bufferCommands.map(command => (
                          <button
                            key={`${command.line}-${command.text}`}
                            onClick={() => copyText('Command', command.text)}
                            className="block w-full text-left text-[10px] text-muted-foreground hover:text-foreground font-mono truncate"
                          >
                            {command.text}
                          </button>
                        ))}
                      </div>
                    )}
                  </SessionContextBlock>
                </div>
              </PanelSection>
            )}

            <PanelSection className="p-0 flex-1 min-h-0 overflow-hidden flex flex-col">
              {attachedIds.length > 0 ? (
                <>
                  <div className="flex-shrink-0 flex gap-0.5 border-b border-border px-2 pt-2">
                    {attachedIds.map(id => {
                      const sess = sessions.find(s => s.id === id);
                      return (
                        <button key={id} onClick={() => { setActiveTab(id); setSelectedSessionId(id); }}
                          className={cn('text-[11px] px-2 py-1 rounded-t transition-colors border border-b-0',
                            activeTab === id ? 'bg-background text-foreground border-border' : 'border-transparent text-muted-foreground hover:text-foreground')}>
                          {sess ? sessionTitle(sess) : id.slice(0, 8)}
                          <span onClick={(e) => { e.stopPropagation(); detach(id); }}
                            className="ml-1.5 text-muted-foreground hover:text-destructive">&times;</span>
                        </button>
                      );
                    })}
                  </div>
                  <div ref={containerRef} className="flex-1 min-h-0 bg-background" />
                </>
              ) : (
                <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
                  Attach a connected session to open a terminal.
                </div>
              )}
            </PanelSection>
          </div>
        </div>
      )}
    </div>
  );
}

function SessionStat({ label, value, tone }: { label: string; value: number; tone?: 'success' | 'warning' }) {
  return (
    <div className="py-2 border-r border-border last:border-r-0">
      <div className={cn('text-base font-semibold tabular-nums', tone === 'success' && 'text-success', tone === 'warning' && 'text-warning')}>{value}</div>
      <div className="text-[10px] text-muted-foreground">{label}</div>
    </div>
  );
}

function SessionRow({
  session,
  selected,
  attached,
  onSelect,
  onAttach,
  onDetach,
}: {
  session: SessionInfo;
  selected: boolean;
  attached: boolean;
  onSelect: () => void;
  onAttach: () => void;
  onDetach: () => void;
}) {
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={e => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSelect();
        }
      }}
      className={cn(
        'w-full bg-surface border border-border rounded-lg p-2.5 text-left transition-colors hover:border-accent/40 hover:bg-hover/30 cursor-pointer',
        selected && 'border-accent/50 bg-accent/5',
      )}
    >
      <div className="flex items-start gap-2">
        <span className={cn('mt-1.5 w-2 h-2 rounded-full flex-shrink-0',
          session.state === 'connected' && 'bg-success',
          session.state === 'pending' && 'bg-warning animate-pulse',
          session.state === 'closed' && 'bg-muted',
          session.state === 'error' && 'bg-destructive',
        )} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium truncate">{sessionTitle(session)}</span>
            {attached && <StatusPill className="bg-accent/10 text-accent">attached</StatusPill>}
          </div>
          <div className="text-[10px] text-muted-foreground truncate">
            {session.kind}{session.transport ? ` · ${session.transport}` : ''}{session.host ? ` · ${session.host}` : ''}
          </div>
          <div className="mt-1 flex gap-1 flex-wrap">
            {session.target_node && <span className="text-[10px] font-mono text-accent truncate max-w-32">{session.target_node}</span>}
            {(session.claimed_by || session.agent_id) && <span className="text-[10px] text-muted-foreground truncate max-w-32">{session.claimed_by || session.agent_id}</span>}
          </div>
        </div>
        {session.state === 'connected' && (
          <button
            onClick={e => { e.stopPropagation(); attached ? onDetach() : onAttach(); }}
            className={cn('text-[10px] px-1.5 py-0.5 rounded border transition-colors',
              attached ? 'bg-destructive/10 text-destructive border-destructive/20' : 'bg-success/10 text-success border-success/20')}
          >
            {attached ? 'Detach' : 'Attach'}
          </button>
        )}
      </div>
    </div>
  );
}

function DetailFact({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded border border-border bg-elevated px-2 py-1.5 min-w-0">
      <div className="text-[10px] text-muted-foreground">{label}</div>
      <div className={cn('text-xs text-foreground truncate', mono && 'font-mono')}>{value}</div>
    </div>
  );
}

function SessionContextBlock({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded border border-border bg-background/40 px-2 py-1.5 min-w-0">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">{title}</div>
      {children}
    </div>
  );
}
