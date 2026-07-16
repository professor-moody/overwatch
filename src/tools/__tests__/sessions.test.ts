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
  resumeResult?: { metadata: SessionMetadata };
  resumeError?: Error & { code?: string };
  readResult?: {
    session_id: string;
    connection_id?: string;
    connection_generation?: number;
    start_pos: number;
    end_pos: number;
    text: string;
    truncated: boolean;
  };
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
    resume: vi.fn(async () => {
      if (options.resumeError) throw options.resumeError;
      return options.resumeResult ?? { metadata: makeSession({ state: 'pending' }) };
    }),
    list: vi.fn(() => options.list ?? []),
    getSession: vi.fn(() => options.session ?? null),
    update: vi.fn(),
    write: vi.fn(() => ({
      session_id: 'session-1',
      connection_id: 'session-1:g4',
      connection_generation: 4,
      end_pos: 12,
    })),
    read: vi.fn(() => options.readResult ?? ({
      session_id: 'session-1',
      connection_id: 'session-1:g4',
      connection_generation: 4,
      start_pos: 0,
      end_pos: 12,
      text: 'output',
      truncated: false,
    })),
  };
  const addedNodes: Array<Record<string, unknown>> = [];

  const engine = {
    resolveAgentTaskReference: () => ({ status: 'missing' }),
    getConfig: () => ({
      scope: {
        cidrs: ['10.10.10.0/24'],
        domains: ['test.local'],
        exclusions: ['10.10.10.5'],
      },
    }),
    runAtomicGraphCommand: (_description: string, _actionId: string | undefined, mutate: () => unknown) =>
      mutate(),
    getNode: () => null,
    addNode: (node: Record<string, unknown>) => {
      addedNodes.push(node);
      return { id: String(node.id), isNew: true };
    },
    addEdge: () => ({ id: 'edge-1', isNew: true }),
    logActionEvent: () => ({ event_id: 'event-1' }),
  } as unknown as GraphEngine;

  registerSessionTools(fakeServer, sessionManager as any, engine);
  return {
    handlers,
    create,
    resume: sessionManager.resume,
    update: sessionManager.update,
    write: sessionManager.write,
    read: sessionManager.read,
    addedNodes,
  };
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

  it('registers mock infrastructure with the actual ephemeral listener port', async () => {
    const createResult = {
      metadata: makeSession({
        id: 'session-listener',
        kind: 'socket',
        transport: 'tcp-listen',
        state: 'pending',
        port: 61234,
      }),
      initial: {
        session_id: 'session-listener',
        start_pos: 0,
        end_pos: 0,
        text: '',
        truncated: false,
      },
    };
    const { handlers, addedNodes, update } = buildHandlers({ createResult });

    const result = await handlers.open_session({
      kind: 'socket',
      title: 'ephemeral catcher',
      mode: 'listen',
      port: 0,
      mock_service_purpose: 'reverse_shell_catcher',
    });
    const payload = JSON.parse(result.content[0].text);

    expect(result.isError).toBeUndefined();
    expect(addedNodes).toEqual([
      expect.objectContaining({
        bind_port: 61234,
        label: 'reverse_shell_catcher://127.0.0.1:61234',
      }),
    ]);
    expect(update).toHaveBeenCalledWith(
      'session-listener',
      expect.objectContaining({
        capabilities: {
          serves_mock_service_id: payload.mock_service.mock_service_id,
        },
      }),
    );
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

  it('threads connection generation through raw session reads and writes', async () => {
    const { handlers, read, write } = buildHandlers();

    const readResponse = await handlers.read_session({
      session_id: 'session-1',
      from_pos: 7,
      connection_id: 'session-1:g4',
      connection_generation: 4,
    });
    expect(read).toHaveBeenCalledWith(
      'session-1',
      7,
      4096,
      {
        connection_id: 'session-1:g4',
        connection_generation: 4,
      },
    );
    expect(JSON.parse(readResponse.content[0].text)).toMatchObject({
      connection_id: 'session-1:g4',
      connection_generation: 4,
    });

    const writeResponse = await handlers.write_session({
      session_id: 'session-1',
      data: 'id',
      append_newline: true,
      force: false,
      connection_id: 'session-1:g4',
      connection_generation: 4,
    });
    expect(write).toHaveBeenCalledWith(
      'session-1',
      'id\n',
      undefined,
      false,
      {
        connection_id: 'session-1:g4',
        connection_generation: 4,
      },
    );
    expect(JSON.parse(writeResponse.content[0].text)).toMatchObject({
      connection_id: 'session-1:g4',
      connection_generation: 4,
    });
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

  it('resumes a recovered listener explicitly and preserves its session id', async () => {
    const recovered = makeSession({
      id: 'listener-1',
      kind: 'socket',
      transport: 'tcp-listen',
      state: 'pending',
      listener_id: 'listener-1',
      connection_generation: 4,
      resume_policy: 'manual',
      mode: 'listen',
      accept_mode: 'rearm',
    });
    const { handlers, resume } = buildHandlers({
      resumeResult: { metadata: recovered },
    });

    const result = await handlers.resume_session({
      session_id: 'listener-1',
      force: true,
    });
    const payload = JSON.parse(result.content[0].text);

    expect(payload.resumed).toBe(true);
    expect(payload.session).toMatchObject({
      id: 'listener-1',
      state: 'pending',
      connection_generation: 4,
    });
    expect(resume).toHaveBeenCalledWith('listener-1', undefined, true);
  });

  it('returns a classified MCP error when a listener cannot be resumed', async () => {
    const resumeError = Object.assign(
      new Error('Session listener-1 is not an explicitly resumable listener.'),
      { code: 'SESSION_NOT_RESUMABLE' },
    );
    const { handlers } = buildHandlers({ resumeError });

    const result = await handlers.resume_session({
      session_id: 'listener-1',
      force: true,
    });
    const payload = JSON.parse(result.content[0].text);

    expect(result.isError).toBe(true);
    expect(payload).toMatchObject({
      session_id: 'listener-1',
      code: 'SESSION_NOT_RESUMABLE',
      error_type: 'validation_error',
    });
  });
});
