import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { useEngagementStore } from '../stores/engagement-store';
import { useToastStore } from '../stores/toast-store';
import type { WsMessage, FullStateData, GraphUpdateData, SessionInfo } from '../lib/types';
import * as api from '../lib/api';

interface WsContextValue {
  connected: boolean;
}

const WsContext = createContext<WsContextValue>({ connected: false });

export function useWs() {
  return useContext(WsContext);
}

const RECONNECT_INTERVAL_MS = 3000;
const POLL_INTERVAL_MS = 5000;

export function WsProvider({ children }: { children: ReactNode }) {
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setInterval> | null>(null);
  const pollTimer = useRef<ReturnType<typeof setInterval> | null>(null);
  const hasLoadedState = useRef(false);

  const store = useEngagementStore;

  useEffect(() => {
    function connect() {
      const host = window.location.host;
      const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
      const ws = new WebSocket(`${scheme}://${host}/ws`);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        store.getState().setConnected(true);
        void pollState(true);
        if (reconnectTimer.current) {
          clearInterval(reconnectTimer.current);
          reconnectTimer.current = null;
        }
      };

      ws.onmessage = (event) => {
        try {
          const msg: WsMessage = JSON.parse(event.data);
          handleMessage(msg);
        } catch (err) {
          console.error('[WS] Message parse error:', err);
        }
      };

      ws.onclose = () => {
        setConnected(false);
        store.getState().setConnected(false);
        if (!reconnectTimer.current) {
          reconnectTimer.current = setInterval(connect, RECONNECT_INTERVAL_MS);
        }
      };

      ws.onerror = () => {
        ws.close();
      };
    }

    function handleMessage(msg: WsMessage) {
      const s = store.getState();
      const toast = useToastStore.getState().addToast;
      switch (msg.type) {
        case 'full_state':
          s.loadFullState(msg.data as FullStateData);
          hasLoadedState.current = true;
          break;
        case 'graph_update': {
          const prevAgents = s.agents;
          s.applyGraphUpdate(msg.data as GraphUpdateData);
          // Toast for newly completed agents
          const newAgents = store.getState().agents;
          for (const a of newAgents) {
            const prev = prevAgents.find(p => p.id === a.id);
            if (prev && prev.status === 'running' && a.status === 'completed') {
              toast({
                type: 'success',
                title: `Agent completed`,
                message: `${(a.agent_id || a.id).slice(0, 8)} — ${a.findings_count || 0} findings`,
                linkPanel: 'agents',
                linkItem: a.id,
              });
            }
          }
          break;
        }
        case 'action_pending':
          s.updatePendingAction(msg.type, msg.data);
          toast({
            type: 'warning',
            title: 'Action pending approval',
            message: (msg.data as { description?: string })?.description || undefined,
            linkPanel: 'actions',
          });
          break;
        case 'action_resolved':
          s.updatePendingAction(msg.type, msg.data);
          toast({
            type: (msg.data as { approved?: boolean })?.approved ? 'success' : 'info',
            title: (msg.data as { approved?: boolean })?.approved ? 'Action approved' : 'Action denied',
            linkPanel: 'actions',
          });
          break;
        case 'session_update': {
          const data = msg.data as { type?: string; session?: SessionInfo; sessions?: SessionInfo[] };
          const prev = data.session ? s.sessions.find(session => session.id === data.session?.id) : undefined;
          if (Array.isArray(data.sessions)) {
            s.setSessions(data.sessions);
          } else if (data.session) {
            s.setSessions([...s.sessions.filter(session => session.id !== data.session!.id), data.session]);
          }
          if (prev?.state === 'pending' && data.session?.state === 'connected') {
            toast({
              type: 'success',
              title: 'Session connected',
              message: data.session.title || data.session.id.slice(0, 8),
              linkPanel: 'sessions',
              linkItem: data.session.id,
            });
          }
          break;
        }
        default:
          // agent_update, campaign_update, objective_update
          // These are embedded in graph_update state, but handle standalone if needed
          break;
      }
    }

    async function pollState(force = false) {
      if (!force && wsRef.current?.readyState === WebSocket.OPEN) return;
      try {
        const data = await api.getState();
        const s = store.getState();
        if (!hasLoadedState.current) {
          s.loadFullState(data as FullStateData);
          hasLoadedState.current = true;
        } else {
          // Treat as state refresh
          s.loadFullState(data as FullStateData);
        }
      } catch {
        // Mark initialized even on failure so panels render with empty data
        store.getState().setInitialized();
      }
    }

    // Initial HTTP load
    pollState();

    // WebSocket connection
    connect();

    // Fallback polling
    pollTimer.current = setInterval(pollState, POLL_INTERVAL_MS);

    return () => {
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.close();
      }
      if (reconnectTimer.current) clearInterval(reconnectTimer.current);
      if (pollTimer.current) clearInterval(pollTimer.current);
    };
  }, [store]);

  return (
    <WsContext.Provider value={{ connected }}>
      {children}
    </WsContext.Provider>
  );
}
