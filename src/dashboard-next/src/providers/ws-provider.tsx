import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { useEngagementStore } from '../stores/engagement-store';
import { useToastStore } from '../stores/toast-store';
import type { WsMessage, FullStateData, GraphUpdateData, SessionInfo, AgentConsoleEvent } from '../lib/types';
import * as api from '../lib/api';
import { createDashboardWebSocket } from '../lib/dashboard-transport';
import { FallbackPollCoordinator, GenerationSocketController } from '../lib/generation-socket';
import { buildDashboardWebSocketPath, MainWebSocketEventSchema } from '@overwatch/dashboard-contracts';

interface WsContextValue {
  connected: boolean;
}

const WsContext = createContext<WsContextValue>({ connected: false });

export function useWs() {
  return useContext(WsContext);
}

const POLL_INTERVAL_MS = 5_000;

export function WsProvider({ children }: { children: ReactNode }) {
  const [connected, setConnected] = useState(false);
  const store = useEngagementStore;

  useEffect(() => {
    let active = true;
    const fallbackPoll = new FallbackPollCoordinator();

    const abortFallbackPoll = () => {
      fallbackPoll.invalidate();
    };

    const handleMessage = (raw: unknown, generation: number, controller: GenerationSocketController) => {
      try {
        const msg: WsMessage = MainWebSocketEventSchema.parse(JSON.parse(String(raw)));
        const s = store.getState();
        const toast = useToastStore.getState().addToast;

        if (msg.type === 'full_state') {
          abortFallbackPoll();
          s.loadFullState(msg.data as unknown as FullStateData);
          controller.markSynchronized(generation);
          return;
        }

        // A reconnect is not live until the server has supplied a fresh base.
        if (!controller.isSynchronized()) return;

        switch (msg.type) {
          case 'graph_update': {
            const prevAgents = s.agents;
            s.applyGraphUpdate(msg.data as unknown as GraphUpdateData);
            for (const agent of store.getState().agents) {
              const previous = prevAgents.find(candidate => candidate.id === agent.id);
              if (previous?.status === 'running' && agent.status === 'completed') {
                toast({
                  type: 'success',
                  title: 'Agent completed',
                  message: `${(agent.agent_id || agent.id).slice(0, 8)} — ${agent.findings_count || 0} findings`,
                  linkPanel: 'agents',
                  linkItem: agent.id,
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
          case 'action_resolved': {
            s.updatePendingAction(msg.type, msg.data);
            const status = (msg.data as { status?: string })?.status;
            const outcome =
              status === 'approved' ? { type: 'success' as const, title: 'Action approved' } :
              status === 'timeout' ? { type: 'warning' as const, title: 'Action auto-approved (no operator response)' } :
              status === 'aborted' ? { type: 'info' as const, title: 'Action aborted (client disconnected)' } :
              status === 'denied' ? { type: 'info' as const, title: 'Action denied' } :
              { type: 'info' as const, title: 'Action resolved' };
            toast({ type: outcome.type, title: outcome.title, linkPanel: 'actions' });
            break;
          }
          case 'session_update': {
            const data = msg.data as { type?: string; session?: SessionInfo; sessions?: SessionInfo[] };
            const previous = data.session ? s.sessions.find(session => session.id === data.session?.id) : undefined;
            if (Array.isArray(data.sessions)) {
              s.setSessions(data.sessions);
            } else if (data.session) {
              s.setSessions([...s.sessions.filter(session => session.id !== data.session!.id), data.session]);
            }
            if (previous?.state === 'pending' && data.session?.state === 'connected') {
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
          case 'agent_console_update': {
            const data = msg.data as { events?: AgentConsoleEvent[] };
            window.dispatchEvent(new CustomEvent('overwatch-agent-console-update', { detail: data }));
            break;
          }
          case 'agent_query':
            window.dispatchEvent(new CustomEvent('overwatch-agent-query-update', { detail: msg.data }));
            break;
          default:
            break;
        }
      } catch (error) {
        console.error('[WS] Message parse error:', error);
      }
    };

    let controller: GenerationSocketController;

    const pollState = async () => {
      if (!active || controller.isSynchronized()) return;
      const ticket = fallbackPoll.begin();
      try {
        const data = await api.getState(ticket.controller.signal);
        if (!active || !fallbackPoll.isCurrent(ticket) || controller.isSynchronized()) return;
        store.getState().loadFullState(data as FullStateData);
      } catch (error) {
        if (active && fallbackPoll.isCurrent(ticket)) {
          store.getState().setInitialized();
        }
      } finally {
        fallbackPoll.complete(ticket);
      }
    };

    controller = new GenerationSocketController({
      createSocket: () => createDashboardWebSocket(buildDashboardWebSocketPath('main', {})),
      onMessage: (data, generation) => handleMessage(data, generation, controller),
      onSynchronizedChange: synchronized => {
        if (!active) return;
        setConnected(synchronized);
        store.getState().setConnected(synchronized);
        if (synchronized) abortFallbackPoll();
      },
      onDisconnected: () => { void pollState(); },
    });

    void pollState();
    controller.start();
    const pollTimer = window.setInterval(() => { void pollState(); }, POLL_INTERVAL_MS);

    return () => {
      active = false;
      window.clearInterval(pollTimer);
      abortFallbackPoll();
      controller.stop();
    };
  }, [store]);

  return <WsContext.Provider value={{ connected }}>{children}</WsContext.Provider>;
}
