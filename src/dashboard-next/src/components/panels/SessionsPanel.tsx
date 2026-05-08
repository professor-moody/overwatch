import { useState, useRef, useEffect, useCallback } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import * as api from '../../lib/api';
import { cn } from '../../lib/utils';
import { EmptyState } from '../shared';

interface TerminalEntry {
  sessionId: string;
  terminal: import('@xterm/xterm').Terminal;
  fitAddon: import('@xterm/addon-fit').FitAddon;
  ws: WebSocket | null;
}

export function SessionsPanel() {
  const sessions = useEngagementStore((s) => s.sessions);
  const setStoreSessions = useEngagementStore((s) => s.setSessions);
  const active = sessions.filter((s) => s.state === 'connected' || s.state === 'pending');
  const [attachedIds, setAttachedIds] = useState<string[]>([]);
  const [activeTab, setActiveTab] = useState<string | null>(null);
  const terminalsRef = useRef<Map<string, TerminalEntry>>(new Map());
  const containerRef = useRef<HTMLDivElement>(null);

  // Safety net: pull fresh session state on mount and on a 5s poll. The
  // store gets sessions via WS full_state / graph_update, but if no WS
  // event has fired yet (or the backend wasn't sending sessions) we'd
  // otherwise render an empty list while live sessions exist.
  useEffect(() => {
    let cancelled = false;
    const refresh = async () => {
      try {
        const data = await api.getSessions();
        if (!cancelled) setStoreSessions(data.sessions || []);
      } catch { /* silent */ }
    };
    refresh();
    const id = setInterval(refresh, 5000);
    return () => { cancelled = true; clearInterval(id); };
  }, [setStoreSessions]);

  const attach = useCallback(async (sessionId: string) => {
    if (terminalsRef.current.has(sessionId)) {
      setActiveTab(sessionId);
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
          if (msg.type === 'output' && msg.data) {
            term.write(msg.data);
          }
        } catch {
          term.write(event.data as string);
        }
      }
    };

    ws.onclose = () => {
      term.write('\r\n\x1b[31mSession disconnected\x1b[0m\r\n');
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
    setAttachedIds(prev => [...prev, sessionId]);
    setActiveTab(sessionId);
  }, []);

  const detach = useCallback((sessionId: string) => {
    const entry = terminalsRef.current.get(sessionId);
    if (entry) {
      entry.ws?.close();
      entry.terminal.dispose();
      terminalsRef.current.delete(sessionId);
    }
    setAttachedIds(prev => {
      const next = prev.filter(id => id !== sessionId);
      if (activeTab === sessionId) {
        setActiveTab(next.length > 0 ? next[next.length - 1] : null);
      }
      return next;
    });
  }, [activeTab]);

  // Mount terminal DOM when active tab changes
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

  return (
    <div className="flex flex-col h-full space-y-4">
      <h2 className="text-lg font-semibold flex-shrink-0">
        Sessions <span className="text-muted-foreground font-normal text-sm">({active.length} active)</span>
      </h2>

      {/* Session list */}
      {sessions.length === 0 ? (
        <EmptyState message="No sessions. Use open_session to create one." />
      ) : (
        <div className="flex-shrink-0 space-y-1.5">
          {sessions.map((s) => {
            const isAttached = attachedIds.includes(s.id);
            return (
              <div key={s.id} className="bg-surface border border-border rounded-lg p-2.5 flex items-center gap-3">
                <span className={cn(
                  'w-2 h-2 rounded-full flex-shrink-0',
                  s.state === 'connected' && 'bg-success',
                  s.state === 'pending' && 'bg-warning animate-pulse',
                  s.state === 'closed' && 'bg-muted',
                  s.state === 'error' && 'bg-destructive',
                )} />
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium truncate">{s.title || s.id.slice(0, 8)}</div>
                  <div className="text-[10px] text-muted-foreground">{s.kind} · {s.state}</div>
                </div>
                {s.state === 'connected' && (
                  isAttached ? (
                    <button onClick={() => detach(s.id)}
                      className="text-[10px] px-2 py-0.5 rounded bg-destructive/10 text-destructive border border-destructive/20 hover:bg-destructive/20">
                      Detach
                    </button>
                  ) : (
                    <button onClick={() => attach(s.id)}
                      className="text-[10px] px-2 py-0.5 rounded bg-success/10 text-success border border-success/20 hover:bg-success/20">
                      Attach
                    </button>
                  )
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Terminal area */}
      {attachedIds.length > 0 && (
        <div className="flex-1 flex flex-col min-h-0">
          {/* Tab bar */}
          <div className="flex-shrink-0 flex gap-0.5 border-b border-border pb-0.5 mb-1">
            {attachedIds.map(id => {
              const sess = sessions.find(s => s.id === id);
              return (
                <button key={id} onClick={() => setActiveTab(id)}
                  className={cn('text-[11px] px-2 py-1 rounded-t transition-colors',
                    activeTab === id ? 'bg-surface text-foreground border border-b-0 border-border' : 'text-muted-foreground hover:text-foreground')}>
                  {sess?.title || id.slice(0, 8)}
                  <span onClick={(e) => { e.stopPropagation(); detach(id); }}
                    className="ml-1.5 text-muted-foreground hover:text-destructive">&times;</span>
                </button>
              );
            })}
          </div>
          {/* Terminal container */}
          <div ref={containerRef} className="flex-1 min-h-0 bg-background rounded" />
        </div>
      )}
    </div>
  );
}
