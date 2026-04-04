import { describe, expect, it, vi } from 'vitest';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerSessionTools } from '../sessions.js';
import type { SessionMetadata } from '../../types.js';
import type { GraphEngine } from '../../services/graph-engine.js';

function makeSession(overrides: Partial<SessionMetadata> = {}): SessionMetadata {
  const now = new Date().toISOString();
  return {
    id: overrides.id ?? 'session-1',
    kind: overrides.kind ?? 'local_pty',
    transport: overrides.transport ?? 'pty',
    state: overrides.state ?? 'connected',
    title: overrides.title ?? 'test-session',
    started_at: overrides.started_at ?? now,
    last_activity_at: overrides.last_activity_at ?? now,
    capabilities: overrides.capabilities ?? {
      has_stdin: true,
      has_stdout: true,
      supports_resize: true,
      supports_signals: true,
      tty_quality: 'full',
    },
    buffer_end_pos: overrides.buffer_end_pos ?? 0,
    ...overrides,
  };
}

function buildHandlers(options: {
  list?: SessionMetadata[];
  session?: SessionMetadata | null;
  createResult?: { metadata: SessionMetadata; initial: { session_id: string; start_pos: number; end_pos: number; text: string; truncated: boolean } };
} = {}) {
  const handlers: Record<string, (args: any) => Promise<any>> = {};
  const fakeServer = {
    registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
      handlers[name] = handler;
    },
  } as unknown as McpServer;

  const create = vi.fn(async () => (
    options.createResult ?? {
      metadata: makeSession(),
      initial: {
        session_id: 'session-1',
        start_pos: 0,
        end_pos: 0,
        text: '',
        truncated: false,
      },
    }
  ));

  const sessionManager = {
    create,
    list: vi.fn(() => options.list ?? []),
    getSession: vi.fn(() => options.session ?? null),
  };

  const engine = {
    getConfig: () => ({
      scope: {
        cidrs: ['10.10.10.0/24'],
        domains: ['test.local'],
        exclusions: ['10.10.10.5'],
      },
    }),
  } as unknown as GraphEngine;

  registerSessionTools(fakeServer, sessionManager as any, engine);
  return { handlers, create };
}

describe('session tools', () => {
  it('rejects out-of-scope remote sessions before creation', async () => {
    const { handlers, create } = buildHandlers();

    const result = await handlers.open_session({
      kind: 'ssh',
      title: 'blocked-ssh',
      host: '10.10.10.5',
      user: 'operator',
    });

    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.scope_reason).toBe('host_out_of_scope');
    expect(payload.host).toBe('10.10.10.5');
    expect(create).not.toHaveBeenCalled();
  });

  it('does not scope-gate socket listeners', async () => {
    const createResult = {
      metadata: makeSession({ id: 'session-listener', kind: 'socket', transport: 'tcp-listen', state: 'pending' }),
      initial: {
        session_id: 'session-listener',
        start_pos: 0,
        end_pos: 0,
        text: '',
        truncated: false,
      },
    };
    const { handlers, create } = buildHandlers({ createResult });

    const result = await handlers.open_session({
      kind: 'socket',
      title: 'listener',
      host: '203.0.113.50',
      mode: 'listen',
      port: 4444,
    });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.session.id).toBe('session-listener');
    expect(create).toHaveBeenCalledOnce();
  });

  it('returns normalized list_sessions counts for connected, pending, and closed sessions', async () => {
    const { handlers } = buildHandlers({
      list: [
        makeSession({ id: 'connected-1', state: 'connected' }),
        makeSession({ id: 'pending-1', state: 'pending' }),
        makeSession({ id: 'closed-1', state: 'closed' }),
      ],
    });

    const result = await handlers.list_sessions({ active_only: false });
    const payload = JSON.parse(result.content[0].text);

    expect(payload.total).toBe(3);
    expect(payload.active).toBe(2);
    expect(payload.sessions).toHaveLength(3);
  });

  it('returns the same list_sessions envelope for single-session lookups', async () => {
    const session = makeSession({ id: 'single-1', state: 'closed', title: 'closed-shell' });
    const { handlers } = buildHandlers({ session });

    const result = await handlers.list_sessions({ session_id: 'single-1' });
    const payload = JSON.parse(result.content[0].text);

    expect(payload.total).toBe(1);
    expect(payload.active).toBe(0);
    expect(payload.sessions).toHaveLength(1);
    expect(payload.sessions[0].id).toBe('single-1');
  });
});
