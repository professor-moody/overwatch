// ============================================================
// Overwatch — Session Manager
// Persistent interactive sessions (SSH, PTY, socket) maintained
// server-side across MCP tool calls.
// ============================================================

import { v4 as uuidv4 } from 'uuid';
import type {
  AdapterHandle,
  SessionCapabilities,
  SessionDefaultValidation,
  SessionKind,
  SessionMetadata,
  SessionReadResult,
  SessionState,
} from '../types.js';
import type { GraphEngine } from './graph-engine.js';
import type { ActivityEventType } from './engine-context.js';
import type { PersistedSessionDescriptorV1 } from './persisted-state.js';

// ============================================================
// RingBuffer — fixed-size circular buffer with absolute cursors
// ============================================================

const DEFAULT_BUFFER_SIZE = 128 * 1024; // 128KB
const SOCKET_LISTENER_WAITING_CAPABILITIES: SessionCapabilities = {
  has_stdin: true,
  has_stdout: true,
  supports_resize: false,
  supports_signals: false,
  tty_quality: 'dumb',
};

export class RingBuffer {
  private chunks: Array<{ text: string; absStart: number }> = [];
  private capacity: number;
  private _endPos: number = 0;
  private retainedLength: number = 0;

  constructor(capacity: number = DEFAULT_BUFFER_SIZE, initialPosition: number = 0) {
    this.capacity = capacity;
    this._endPos = initialPosition;
  }

  get endPos(): number {
    return this._endPos;
  }

  get startPos(): number {
    if (this.chunks.length === 0) return this._endPos;
    return this.chunks[0].absStart;
  }

  write(chunk: string): void {
    if (chunk.length === 0) return;

    this.chunks.push({ text: chunk, absStart: this._endPos });
    this._endPos += chunk.length;
    this.retainedLength += chunk.length;

    // Trim oldest chunks when retained data exceeds capacity
    while (this.retainedLength > this.capacity && this.chunks.length > 1) {
      const oldest = this.chunks[0];
      const excess = this.retainedLength - this.capacity;
      if (oldest.text.length <= excess) {
        // Drop entire chunk
        this.chunks.shift();
        this.retainedLength -= oldest.text.length;
      } else {
        // Trim partial front of oldest chunk
        const trimmed = oldest.text.slice(excess);
        oldest.text = trimmed;
        oldest.absStart += excess;
        this.retainedLength -= excess;
        break;
      }
    }

    // If a single chunk exceeds capacity, trim it to capacity
    if (this.retainedLength > this.capacity && this.chunks.length === 1) {
      const c = this.chunks[0];
      const excess = this.retainedLength - this.capacity;
      c.text = c.text.slice(excess);
      c.absStart += excess;
      this.retainedLength = c.text.length;
    }
  }

  read(fromPos: number): { text: string; startPos: number; endPos: number; truncated: boolean } {
    const currentStart = this.startPos;
    const currentEnd = this._endPos;

    if (fromPos >= currentEnd) {
      return { text: '', startPos: currentEnd, endPos: currentEnd, truncated: false };
    }

    let truncated = false;
    let effectiveFrom = fromPos;
    if (effectiveFrom < currentStart) {
      effectiveFrom = currentStart;
      truncated = true;
    }

    const text = this.extractRange(effectiveFrom, currentEnd);
    return { text, startPos: effectiveFrom, endPos: currentEnd, truncated };
  }

  tail(n: number): { text: string; startPos: number; endPos: number; truncated: boolean } {
    const currentEnd = this._endPos;
    const actualN = Math.min(n, this.retainedLength);
    const fromPos = currentEnd - actualN;
    return this.read(fromPos);
  }

  private extractRange(fromAbs: number, toAbs: number): string {
    if (fromAbs >= toAbs || this.chunks.length === 0) return '';

    const parts: string[] = [];
    for (const chunk of this.chunks) {
      const chunkEnd = chunk.absStart + chunk.text.length;
      if (chunkEnd <= fromAbs) continue;
      if (chunk.absStart >= toAbs) break;

      const sliceStart = Math.max(0, fromAbs - chunk.absStart);
      const sliceEnd = Math.min(chunk.text.length, toAbs - chunk.absStart);
      parts.push(chunk.text.slice(sliceStart, sliceEnd));
    }
    return parts.join('');
  }
}

// ============================================================
// Session — wraps an AdapterHandle with metadata + buffer
// ============================================================

export interface Session {
  metadata: SessionMetadata;
  handle: AdapterHandle | null;
  buffer: RingBuffer;
  /** Ephemeral accept identity used to reject stale adapter callbacks. */
  connection_token?: string;
  last_descriptor_activity_persisted_at?: number;
}

function cloneSessionMetadata(metadata: SessionMetadata): SessionMetadata {
  return structuredClone(metadata);
}

// ============================================================
// Adapter factory type
// ============================================================

export interface SessionAdapterFactory {
  kind: SessionKind;
  spawn(options: Record<string, unknown>): Promise<AdapterHandle>;
}

export type SessionEventType = 'session_created' | 'session_updated' | 'session_closed';

export interface SessionEvent {
  type: SessionEventType;
  session: SessionMetadata;
  sessions: SessionMetadata[];
}

export type SessionEventCallback = (event: SessionEvent) => void;

// ============================================================
// SessionManager
// ============================================================

const MAX_CLOSED_SESSIONS = 50;
const DEFAULT_IDLE_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes
const MAX_IDLE_REAPER_INTERVAL_MS = 30_000;
const PERSISTENCE_GATE_POLL_MS = 250;
const SESSION_ACTIVITY_DURABILITY_MS = 1_000;
const IRREVERSIBLE_LIFECYCLE_COMMIT_ATTEMPTS = 3;

export function sessionIdleReaperIntervalMs(idleTimeoutMs: number): number | null {
  if (!Number.isFinite(idleTimeoutMs) || idleTimeoutMs <= 0) return null;
  return Math.max(1, Math.min(
    MAX_IDLE_REAPER_INTERVAL_MS,
    Math.floor(idleTimeoutMs / 2),
  ));
}

export interface SessionCreateOptions {
  kind: SessionKind;
  title: string;
  host?: string;
  user?: string;
  port?: number;
  owner_task_id?: string;
  agent_id?: string;
  target_node?: string;
  principal_node?: string;
  credential_node?: string;
  action_id?: string;
  frontier_item_id?: string;
  cols?: number;
  rows?: number;
  // SSH-specific
  key_path?: string;
  password?: string;
  ssh_options?: string[];
  // local_pty-specific
  shell?: string;
  cwd?: string;
  env?: Record<string, string>;
  // socket-specific
  mode?: 'connect' | 'listen';
  bind_host?: string;
  advertise_host?: string;
  accept_mode?: 'single' | 'rearm';
  reachability_warnings?: string[];
  // instrumentation
  default_validation?: SessionDefaultValidation;
  // internal
  initial_wait_ms?: number;
}

function validateSessionCreateOptions(options: SessionCreateOptions): void {
  const requiredStrings: Array<[string, string | undefined]> = [
    ['title', options.title],
  ];
  const optionalStrings: Array<[string, string | undefined]> = [
    ['host', options.host],
    ['bind_host', options.bind_host],
    ['advertise_host', options.advertise_host],
    ['user', options.user],
    ['owner_task_id', options.owner_task_id],
    ['agent_id', options.agent_id],
    ['target_node', options.target_node],
    ['principal_node', options.principal_node],
    ['credential_node', options.credential_node],
    ['action_id', options.action_id],
    ['frontier_item_id', options.frontier_item_id],
  ];
  for (const [field, value] of [...requiredStrings, ...optionalStrings]) {
    if (value !== undefined && value.length === 0) {
      throw new Error(`Session ${field} must not be empty when provided.`);
    }
  }
  if (
    options.port !== undefined
    && (
      !Number.isSafeInteger(options.port)
      || options.port < 0
      || options.port > 65_535
    )
  ) {
    throw new Error('Session port must be an integer from 0 through 65535.');
  }
  const validation = options.default_validation;
  if (validation) {
    if (validation.technique.length === 0) {
      throw new Error('Session default_validation.technique must not be empty.');
    }
    for (const [field, value] of [
      ['target_ip', validation.target_ip],
      ['target_url', validation.target_url],
      ['target_node', validation.target_node],
      ['agent_id', validation.agent_id],
    ] as const) {
      if (value !== undefined && value.length === 0) {
        throw new Error(`Session default_validation.${field} must not be empty when provided.`);
      }
    }
  }
}

export class SessionManager {
  private sessions: Map<string, Session> = new Map();
  private adapters: Map<SessionKind, SessionAdapterFactory> = new Map();
  private engine: GraphEngine | null;
  private idleTimeoutMs: number;
  private eventListeners: Set<SessionEventCallback> = new Set();
  /**
   * Single durability owner. Unlike ordinary dashboard/event listeners, this
   * callback is allowed to fail the session operation so runtime state can
   * never advance past a descriptor that was not journaled.
   */
  private durableEventListener?: SessionEventCallback;
  private persistenceGateTimer: ReturnType<typeof setInterval> | null = null;
  private idleReaperTimer: ReturnType<typeof setInterval> | null = null;
  private persistenceFrozen = false;
  private shuttingDown = false;
  private resumeInProgress = new Set<string>();
  private persistenceAbortController = new AbortController();

  constructor(engine: GraphEngine | null = null, idleTimeoutMs?: number) {
    this.engine = engine;
    this.idleTimeoutMs = idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS;
    this.startPersistenceGateMonitor();
    this.startIdleReaper();
  }

  registerAdapter(adapter: SessionAdapterFactory): void {
    this.adapters.set(adapter.kind, adapter);
  }

  onEvent(callback: SessionEventCallback): () => void {
    this.eventListeners.add(callback);
    return () => this.eventListeners.delete(callback);
  }

  onDurableEvent(callback: SessionEventCallback): () => void {
    if (this.durableEventListener) {
      throw new Error('SessionManager already has a durable event listener.');
    }
    this.durableEventListener = callback;
    return () => {
      if (this.durableEventListener === callback) {
        this.durableEventListener = undefined;
      }
    };
  }

  /**
   * Hydrate durable, secret-free descriptors after engine recovery. Restored
   * sessions intentionally have no runtime handle or output buffer. A rearmed
   * listener remains inert until the operator explicitly calls resume().
   */
  restorePersistedDescriptors(descriptors: PersistedSessionDescriptorV1[]): void {
    if (this.sessions.size > 0) {
      throw new Error('Cannot restore session descriptors after runtime sessions exist.');
    }
    for (const descriptor of descriptors) {
      const durableLifecycle = descriptor.recovery_lifecycle ?? descriptor.lifecycle;
      const resumableListener = descriptor.kind === 'socket'
        && descriptor.mode === 'listen'
        && descriptor.accept_mode === 'rearm'
        && descriptor.resume_intent.requested;
      const recoveredState: SessionState =
        durableLifecycle === 'pending' || durableLifecycle === 'connected'
          ? (resumableListener ? 'resume_available' : 'interrupted')
          : durableLifecycle;
      const metadata: SessionMetadata = {
        id: descriptor.session_id,
        kind: descriptor.kind,
        adapter: descriptor.adapter ?? descriptor.kind,
        transport: descriptor.transport,
        state: recoveredState,
        listener_id: descriptor.listener_id
          ?? (descriptor.kind === 'socket' && descriptor.mode === 'listen'
            ? descriptor.session_id
            : undefined),
        connection_generation: descriptor.connection_generation
          ?? (durableLifecycle === 'connected' ? 1 : 0),
        connection_id: undefined,
        connection_started_at: undefined,
        last_connection_id: descriptor.last_connection_id
          ?? (durableLifecycle === 'connected'
            ? descriptor.connection_id
              ?? `${descriptor.session_id}:g${Math.max(1, descriptor.connection_generation ?? 1)}`
            : undefined),
        last_connection_state: descriptor.last_connection_state
          ?? (durableLifecycle === 'connected' ? 'interrupted' : undefined),
        last_connection_closed_at: descriptor.last_connection_closed_at,
        resume_policy: resumableListener ? 'manual' : 'none',
        mode: descriptor.mode,
        bind_host: descriptor.bind_host,
        advertise_host: descriptor.advertise_host,
        accept_mode: descriptor.accept_mode,
        reachability_warnings: descriptor.reachability_warnings
          ? [...descriptor.reachability_warnings]
          : undefined,
        auth_status: recoveredState === 'resume_available'
          ? undefined
          : descriptor.auth_status,
        title: descriptor.title,
        host: descriptor.host,
        user: descriptor.user,
        port: descriptor.port,
        target_node: descriptor.target_node,
        principal_node: descriptor.principal_node,
        credential_node: descriptor.credential_node,
        action_id: descriptor.action_id,
        frontier_item_id: descriptor.frontier_item_id,
        claimed_by: descriptor.owner_task_id,
        started_at: descriptor.started_at,
        last_activity_at: descriptor.last_activity_at,
        closed_at: descriptor.closed_at,
        capabilities: recoveredState === 'resume_available'
          && descriptor.kind === 'socket'
          && descriptor.mode === 'listen'
          ? structuredClone(SOCKET_LISTENER_WAITING_CAPABILITIES)
          : structuredClone(descriptor.capabilities),
        buffer_end_pos: 0,
        notes: descriptor.recovery_warning
          ? [descriptor.notes, descriptor.recovery_warning].filter(Boolean).join('\n')
          : descriptor.notes,
        default_validation: descriptor.default_validation
          ? structuredClone(descriptor.default_validation)
          : undefined,
      };
      this.sessions.set(metadata.id, {
        metadata,
        handle: null,
        buffer: new RingBuffer(),
        last_descriptor_activity_persisted_at: 0,
      });
    }
  }

  /** Stop maintenance before any shutdown descriptor snapshot is taken. */
  beginShutdown(): void {
    if (this.shuttingDown) return;
    this.shuttingDown = true;
    this.stopIdleReaper();
    this.persistenceAbortController.abort(new Error('Session manager is shutting down.'));
  }

  async create(options: SessionCreateOptions): Promise<{ metadata: SessionMetadata; initial: SessionReadResult }> {
    if (this.shuttingDown) throw new Error('Session manager is shutting down.');
    this.assertPersistenceWritable();
    this.assertDurableDescriptorOwner();
    validateSessionCreateOptions(options);
    const adapter = this.adapters.get(options.kind);
    if (!adapter) {
      throw new Error(`No adapter registered for session kind: ${options.kind}`);
    }

    const id = uuidv4();
    const now = new Date().toISOString();
    const buffer = new RingBuffer();

    // Determine initial state based on kind
    // Every session begins as a durable reservation. A PTY/SSH descriptor is
    // promoted to connected only after its adapter handle has been created.
    const initialState: SessionState = 'pending';

    // Determine transport label
    let transport = 'pty';
    if (options.kind === 'socket') {
      transport = options.mode === 'listen' ? 'tcp-listen' : 'tcp-connect';
    }

    const metadata: SessionMetadata = {
      id,
      kind: options.kind,
      adapter: options.kind,
      transport,
      state: initialState,
      listener_id: options.kind === 'socket' && options.mode === 'listen'
        ? id
        : undefined,
      connection_generation: 0,
      resume_policy: options.kind === 'socket'
        && options.mode === 'listen'
        && options.accept_mode === 'rearm'
        ? 'manual'
        : 'none',
      mode: options.mode,
      bind_host: options.bind_host,
      advertise_host: options.advertise_host,
      accept_mode: options.accept_mode,
      reachability_warnings: options.reachability_warnings
        ? [...options.reachability_warnings]
        : undefined,
      title: options.title,
      host: options.host,
      user: options.user,
      port: options.port,
      agent_id: options.agent_id,
      target_node: options.target_node,
      principal_node: options.principal_node,
      credential_node: options.credential_node,
      action_id: options.action_id,
      frontier_item_id: options.frontier_item_id,
      claimed_by: options.owner_task_id ?? options.agent_id,
      started_at: now,
      last_activity_at: now,
      capabilities: {
        has_stdin: false,
        has_stdout: false,
        supports_resize: false,
        supports_signals: false,
        tty_quality: 'none',
      },
      buffer_end_pos: 0,
      default_validation: options.default_validation
        ? structuredClone(options.default_validation)
        : undefined,
    };

    const session: Session = {
      metadata,
      handle: null,
      buffer,
      last_descriptor_activity_persisted_at: 0,
    };
    this.sessions.set(id, session);

    try {
      // Reserve the descriptor before DNS, SSH, PTY creation, or listener
      // binding can create a live runtime surface.
      this.emitDurableSessionEvent('session_created', session);
      this.assertPersistenceWritable();
      const handle = await adapter.spawn({
        host: options.host,
        user: options.user,
        port: options.port,
        cols: options.cols || 120,
        rows: options.rows || 30,
        key_path: options.key_path,
        password: options.password,
        ssh_options: options.ssh_options,
        shell: options.shell,
        cwd: options.cwd,
        env: options.env,
        mode: options.mode,
        bind_host: options.bind_host,
        advertise_host: options.advertise_host,
        accept_mode: options.accept_mode,
        sessionId: id,
        onConnect: (info: { connection_token: string }) =>
          this.handleConnect(id, info),
        // Built-in adapters use this to cancel a connect/listen/PTY spawn that
        // is still pending when persistence transitions to read-only.
        abort_signal: this.persistenceAbortController.signal,
      });
      // Take ownership immediately. Persistence may have degraded while the
      // adapter was spawning; if runtime cleanup then fails, this retained
      // handle is the only safe way to retry instead of orphaning the target.
      session.handle = handle;

      // Adapter setup may involve DNS, SSH, or binding a listener. If the gate
      // closed while it was pending, tear the newly-created runtime handle down
      // before it can become an untracked target execution surface.
      if (!this.checkPersistenceGate()) {
        throw this.persistenceReadOnlyError();
      }

      session.metadata.pid = handle.pid;
      if (handle.bound_port !== undefined) {
        session.metadata.port = handle.bound_port;
      }
      session.metadata.capabilities = { ...handle.capabilities };
      this.attachHandleCallbacks(id, session, handle);

      // For PTY-backed sessions, mark connected immediately
      if (options.kind !== 'socket') {
        const connectedAt = new Date().toISOString();
        session.metadata = {
          ...session.metadata,
          state: 'connected',
          connection_generation: 1,
          connection_id: `${id}:g1`,
          connection_started_at: connectedAt,
          last_activity_at: connectedAt,
        };
      }

      this.logSessionEvent(id, 'session_opened',
        `Session "${options.title}" opened (${options.kind}, ${transport})`);
      this.emitSessionEvent('session_created', session);

      // Wait briefly for initial output (e.g. shell prompt, SSH banner)
      const waitMs = options.initial_wait_ms !== undefined ? options.initial_wait_ms : 2000;
      if (waitMs > 0) {
        await this.waitForInitialOutput(session, waitMs);
      }
      if (!this.checkPersistenceGate()) throw this.persistenceReadOnlyError();

      // Session → graph integration: SSH sessions with target_node
      // Deferred until after waitForInitialOutput so we can check for auth failures
      if (this.engine && options.kind === 'ssh' && options.target_node) {
        const authFailed = this.detectSshAuthFailure(session);
        if (authFailed) {
          session.metadata.state = 'error';
          session.metadata.closed_at = new Date().toISOString();
          try { session.handle?.close(); } catch { /* best-effort */ }
          this.logSessionEvent(id, 'session_error',
            `SSH auth failed for "${options.title}": ${authFailed}`);
        }

        // Check for auth prompts (password, MFA, passphrase) — transport connected
        // but auth is NOT complete. The session stays open for operator interaction.
        const authPrompt = !authFailed ? this.detectSshAuthPrompt(session) : null;

        // Check if the process already exited during the initial wait
        const sessionDied = session.metadata.state === 'closed' || session.metadata.state === 'error';

        // Positive confirmation: only if no auth failure, no prompt, and process alive
        let confirmed = false;
        if (!authFailed && !authPrompt && !sessionDied) {
          confirmed = await this.detectSshAuthSuccess(session);
          if (!this.checkPersistenceGate()) throw this.persistenceReadOnlyError();
        }

        // success = authentication was positively established (shell confirmed),
        // or at minimum no failure/prompt detected and the session is alive.
        // Prompt-only and disconnect states are NOT success — they are
        // "transport connected, auth incomplete."
        const success = !authFailed && !authPrompt && !sessionDied;

        // Surface auth state in session metadata so callers can distinguish
        // shell-confirmed sessions from transport-only or auth-failed ones.
        if (authFailed) {
          session.metadata.auth_status = 'auth_failed';
        } else if (authPrompt) {
          session.metadata.auth_status = 'auth_prompt';
        } else if (confirmed) {
          session.metadata.auth_status = 'shell_confirmed';
        } else {
          session.metadata.auth_status = 'connected_unconfirmed';
        }

        this.engine.ingestSessionResult({
          success,
          confirmed,
          target_node: options.target_node,
          principal_node: options.principal_node,
          credential_node: options.credential_node,
          session_id: session.metadata.connection_id ?? id,
          connection_generation: session.metadata.connection_generation,
          agent_id: options.agent_id,
          action_id: options.action_id,
          frontier_item_id: options.frontier_item_id,
        });

        if (authPrompt) {
          this.logSessionEvent(id, 'session_access_unconfirmed',
            `SSH session "${options.title}" reached ${authPrompt} — auth not complete`);
        }
        this.emitSessionEvent('session_updated', session);
      }

      const initial = session.buffer.tail(4096);
      return {
        metadata: cloneSessionMetadata(session.metadata),
        initial: {
          session_id: id,
          connection_id: session.metadata.connection_id,
          connection_generation: session.metadata.connection_generation,
          start_pos: initial.startPos,
          end_pos: initial.endPos,
          text: initial.text,
          truncated: initial.truncated,
        },
      };
    } catch (err) {
      const persistenceDegraded = !this.checkPersistenceGate();
      let cleanupError: unknown;
      if (session.handle) {
        const handle = session.handle;
        try {
          handle.close();
          if (session.handle === handle) session.handle = null;
        } catch (error) {
          // A throwing close is ambiguous: retain ownership so shutdown or an
          // explicit retry can attempt cleanup again.
          session.handle = handle;
          cleanupError = error;
        }
      }
      if (cleanupError !== undefined) {
        session.metadata.state = 'error';
        session.metadata.closed_at = undefined;
        session.metadata.notes = [
          session.metadata.notes,
          `Session-open cleanup could not close runtime: ${
            cleanupError instanceof Error ? cleanupError.message : String(cleanupError)
          }`,
        ].filter(Boolean).join('\n');
      } else {
        session.metadata.state = persistenceDegraded ? 'closed' : 'error';
        session.metadata.closed_at = new Date().toISOString();
      }
      if (!persistenceDegraded) {
        this.logSessionEvent(id, 'session_error',
          `Session "${options.title}" failed to open: ${err instanceof Error ? err.message : String(err)}`);
        this.emitDurableSessionEvent('session_updated', session);
      }

      // Session → graph integration: mark failure on specific frontier item
      if (!persistenceDegraded && this.engine && options.kind === 'ssh' && options.target_node) {
        try {
          this.engine.ingestSessionResult({
            success: false,
            target_node: options.target_node,
            principal_node: options.principal_node,
            credential_node: options.credential_node,
            session_id: session.metadata.connection_id ?? id,
            connection_generation: session.metadata.connection_generation,
            agent_id: options.agent_id,
            action_id: options.action_id,
            frontier_item_id: options.frontier_item_id,
          });
        } catch {
          // Preserve the primary open/cleanup failure. A second graph-ingest
          // error cannot make runtime ownership less important or more precise.
        }
      }

      if (cleanupError !== undefined) {
        throw new AggregateError(
          [err, cleanupError],
          `Session "${options.title}" failed to open and runtime cleanup failed`,
        );
      }
      throw err;
    }
  }

  write(
    sessionId: string,
    data: string,
    claimedBy?: string,
    force?: boolean,
    expected: { connection_id?: string; connection_generation?: number } = {},
  ): {
    session_id: string;
    connection_id?: string;
    connection_generation?: number;
    end_pos: number;
  } {
    this.assertPersistenceWritable();
    const session = this.getSessionOrThrow(sessionId);
    this.assertConnected(session);
    this.assertOwnership(session, claimedBy, force);
    this.assertExpectedConnectionGeneration(session, expected);

    if (!session.handle) {
      throw new Error(`Session ${sessionId} has no active handle`);
    }

    this.assertPersistenceWritable();
    this.commitSessionMetadataUpdate(session, {
      ...session.metadata,
      last_activity_at: new Date().toISOString(),
    });
    session.handle.write(data);
    return {
      session_id: sessionId,
      connection_id: session.metadata.connection_id,
      connection_generation: session.metadata.connection_generation,
      end_pos: session.buffer.endPos,
    };
  }

  read(
    sessionId: string,
    fromPos?: number,
    tailBytes?: number,
    expected: { connection_id?: string; connection_generation?: number } = {},
  ): SessionReadResult {
    this.checkPersistenceGate();
    const session = this.getSessionOrThrow(sessionId);
    this.assertExpectedConnectionGeneration(session, expected);
    const generation = {
      connection_id: session.metadata.connection_id,
      connection_generation: session.metadata.connection_generation,
    };

    if (fromPos !== undefined) {
      const cursorReset = fromPos > session.buffer.endPos;
      const result = session.buffer.read(cursorReset ? session.buffer.startPos : fromPos);
      return {
        session_id: sessionId,
        ...generation,
        start_pos: result.startPos,
        end_pos: result.endPos,
        text: result.text,
        truncated: result.truncated || cursorReset,
        ...(cursorReset ? { cursor_reset: true } : {}),
      };
    }

    const result = session.buffer.tail(tailBytes || 4096);
    return {
      session_id: sessionId,
      ...generation,
      start_pos: result.startPos,
      end_pos: result.endPos,
      text: result.text,
      truncated: result.truncated,
    };
  }

  async sendCommand(
    sessionId: string,
    command: string,
    options: {
      timeout_ms?: number;
      idle_ms?: number;
      wait_for?: string;
      claimedBy?: string;
      force?: boolean;
      connection_id?: string;
      connection_generation?: number;
    } = {},
  ): Promise<SessionReadResult> {
    this.assertPersistenceWritable();
    const session = this.getSessionOrThrow(sessionId);
    this.assertConnected(session);
    this.assertOwnership(session, options.claimedBy, options.force);
    this.assertExpectedConnectionGeneration(session, {
      connection_id: options.connection_id,
      connection_generation: options.connection_generation,
    });
    const connectionId = session.metadata.connection_id;
    const connectionGeneration = session.metadata.connection_generation;

    const timeoutMs = options.timeout_ms || 10000;
    const idleMs = options.idle_ms || 500;
    let waitForRegex: RegExp | null = null;
    if (options.wait_for) {
      if (options.wait_for.length > 1000) {
        throw new Error('wait_for pattern too long (max 1000 chars)');
      }
      // Reject patterns with nested quantifiers that can cause catastrophic backtracking (ReDoS)
      if (/([+*]|\{\d)[^)]*[+*]|\{\d/.test(options.wait_for) || /\([^)]*[+*][^)]*\)[+*?]/.test(options.wait_for)) {
        throw new Error('wait_for pattern rejected: nested quantifiers may cause catastrophic backtracking');
      }
      // Reject overlapping alternation with outer quantifier: (a|a)*, (ab|a)+, etc.
      if (/\([^)]*\|[^)]*\)[+*]/.test(options.wait_for) && /\(([^)|]+)\|.*\1/.test(options.wait_for)) {
        throw new Error('wait_for pattern rejected: overlapping alternation with quantifier may cause catastrophic backtracking');
      }
      // Reject backreference bombs: \1+, \2*, etc.
      if (/\\[1-9][+*{]/.test(options.wait_for)) {
        throw new Error('wait_for pattern rejected: quantified backreference may cause catastrophic backtracking');
      }
      try {
        waitForRegex = new RegExp(options.wait_for);
      } catch (e) {
        throw new Error(`Invalid wait_for regex: ${(e as Error).message}`);
      }
    }

    // Record position before sending
    const generationBuffer = session.buffer;
    const startPos = generationBuffer.endPos;

    // Write command + newline
    if (!session.handle) {
      throw new Error(`Session ${sessionId} has no active handle`);
    }
    this.assertPersistenceWritable();
    this.assertExpectedConnectionGeneration(session, {
      connection_id: connectionId,
      connection_generation: connectionGeneration,
    });
    this.commitSessionMetadataUpdate(session, {
      ...session.metadata,
      last_activity_at: new Date().toISOString(),
    });
    session.handle.write(command + '\n');

    // Wait for output to settle.
    // Phase 1: wait for at least one byte of post-command output (or timeout).
    // Phase 2: once output has started, use idle settling — return when no new
    //          output arrives for idle_ms consecutive milliseconds.
    return new Promise<SessionReadResult>((resolve) => {
      let lastEndPos = generationBuffer.endPos;
      let idleTimer: ReturnType<typeof setTimeout> | null = null;
      let hasReceivedOutput = false;
      let finished = false;

      // R2-3: surface *why* the wait returned so callers can distinguish a
      // settled prompt (`idle` / `wait_for`) from a forced give-up
      // (`timeout`) or a session that disappeared mid-command
      // (`session_closed`). Defaults to `idle` and is overridden at each
      // exit site.
      const finish = (reason: 'wait_for' | 'idle' | 'timeout' | 'session_closed' = 'idle') => {
        if (finished) return;
        finished = true;
        if (idleTimer) clearTimeout(idleTimer);
        if (overallTimer) clearTimeout(overallTimer);
        if (waitInterval) clearInterval(waitInterval);
        const result = generationBuffer.read(startPos);
        resolve({
          session_id: sessionId,
          connection_id: connectionId,
          connection_generation: connectionGeneration,
          start_pos: result.startPos,
          end_pos: result.endPos,
          text: result.text,
          truncated: result.truncated,
          completion_reason: reason,
          timed_out: reason === 'timeout',
        });
      };

      const checkIdle = () => {
        if (finished) return;
        if (!this.checkPersistenceGate()) {
          finish('session_closed');
          return;
        }
        if (
          session.metadata.state !== 'connected'
          || !session.handle
          || session.metadata.connection_id !== connectionId
        ) {
          finish('session_closed');
          return;
        }
        const currentEnd = generationBuffer.endPos;

        if (waitForRegex) {
          const data = generationBuffer.read(startPos);
          if (waitForRegex.test(data.text)) {
            finish('wait_for');
            return;
          }
        }

        if (currentEnd === lastEndPos) {
          finish('idle');
          return;
        }

        lastEndPos = currentEnd;
        idleTimer = setTimeout(checkIdle, idleMs);
      };

      // Phase 1: poll for first output byte before starting idle settling.
      // Check every 50ms. Once output arrives, transition to Phase 2.
      const waitInterval = setInterval(() => {
        if (finished) { clearInterval(waitInterval); return; }
        if (!this.checkPersistenceGate()) {
          finish('session_closed');
          return;
        }
        // Detect session shutdown mid-command so callers don't have to
        // infer it from an empty `idle` return.
        if (
          session.metadata.state !== 'connected'
          || !session.handle
          || session.metadata.connection_id !== connectionId
        ) {
          finish('session_closed');
          return;
        }
        const currentEnd = generationBuffer.endPos;

        // Check wait_for even before any output (covers edge case of
        // output arriving between the write and the first poll)
        if (waitForRegex) {
          const data = generationBuffer.read(startPos);
          if (waitForRegex.test(data.text)) {
            finish('wait_for');
            return;
          }
        }

        if (currentEnd > startPos && !hasReceivedOutput) {
          hasReceivedOutput = true;
          lastEndPos = currentEnd;
          clearInterval(waitInterval);
          // Transition to Phase 2: start idle settling
          idleTimer = setTimeout(checkIdle, idleMs);
        }
      }, 50);

      // Overall timeout — hard deadline regardless of phase
      const overallTimer = setTimeout(() => finish('timeout'), timeoutMs);
    });
  }

  resize(sessionId: string, cols: number, rows: number, claimedBy?: string, force?: boolean): void {
    this.assertPersistenceWritable();
    const session = this.getSessionOrThrow(sessionId);
    this.assertConnected(session);
    this.assertOwnership(session, claimedBy, force);

    if (!session.metadata.capabilities.supports_resize) {
      throw new Error(`Session ${sessionId} does not support resize (tty_quality: ${session.metadata.capabilities.tty_quality})`);
    }

    if (session.handle?.resize) {
      this.assertPersistenceWritable();
      session.handle.resize(cols, rows);
    }
  }

  signal(sessionId: string, sig: string, claimedBy?: string, force?: boolean): void {
    this.assertPersistenceWritable();
    const session = this.getSessionOrThrow(sessionId);
    this.assertConnected(session);
    this.assertOwnership(session, claimedBy, force);

    if (!session.metadata.capabilities.supports_signals) {
      throw new Error(`Session ${sessionId} does not support signals (tty_quality: ${session.metadata.capabilities.tty_quality})`);
    }

    if (session.handle?.kill) {
      this.assertPersistenceWritable();
      session.handle.kill(sig);
      this.logSessionEvent(sessionId, 'session_signaled',
        `Signal ${sig} sent to session "${session.metadata.title}"`);
    }
  }

  update(sessionId: string, updates: {
    capabilities?: Partial<SessionCapabilities>;
    title?: string;
    claimed_by?: string;
    notes?: string;
  }, claimedBy?: string, force?: boolean): SessionMetadata {
    this.assertPersistenceWritable();
    const session = this.getSessionOrThrow(sessionId);
    this.assertOwnership(session, claimedBy, force);
    this.assertPersistenceWritable();

    const metadata: SessionMetadata = {
      ...session.metadata,
      capabilities: updates.capabilities
        ? {
            ...session.metadata.capabilities,
            ...updates.capabilities,
          }
        : session.metadata.capabilities,
      ...(updates.title !== undefined ? { title: updates.title } : {}),
      ...(updates.claimed_by !== undefined ? { claimed_by: updates.claimed_by } : {}),
      ...(updates.notes !== undefined ? { notes: updates.notes } : {}),
      last_activity_at: new Date().toISOString(),
    };
    this.commitSessionMetadataUpdate(session, metadata);

    return cloneSessionMetadata(session.metadata);
  }

  async resume(
    sessionId: string,
    claimedBy?: string,
    force?: boolean,
  ): Promise<{ metadata: SessionMetadata }> {
    if (this.shuttingDown) throw new Error('Session manager is shutting down.');
    this.assertPersistenceWritable();
    this.assertDurableDescriptorOwner();
    const session = this.getSessionOrThrow(sessionId);
    this.assertOwnership(session, claimedBy, force);
    if (
      session.metadata.state !== 'resume_available'
      || session.metadata.kind !== 'socket'
      || session.metadata.mode !== 'listen'
      || session.metadata.accept_mode !== 'rearm'
      || session.metadata.resume_policy !== 'manual'
    ) {
      const error = new Error(
        `Session ${sessionId} is not an explicitly resumable listener (state: ${session.metadata.state}).`,
      );
      (error as Error & { code?: string }).code = 'SESSION_NOT_RESUMABLE';
      throw error;
    }
    if (session.handle) {
      const error = new Error(`Session ${sessionId} already has a runtime listener.`);
      (error as Error & { code?: string }).code = 'SESSION_RESUME_CONFLICT';
      throw error;
    }
    if (this.resumeInProgress.has(sessionId)) {
      const error = new Error(`Session ${sessionId} resume is already in progress.`);
      (error as Error & { code?: string }).code = 'SESSION_RESUME_CONFLICT';
      throw error;
    }
    if (!Number.isSafeInteger(session.metadata.port) || (session.metadata.port ?? -1) < 0) {
      throw new Error(`Session ${sessionId} has no valid persisted listener port.`);
    }
    const adapter = this.adapters.get(session.metadata.adapter ?? session.metadata.kind);
    if (!adapter) {
      throw new Error(`No adapter registered for session kind: ${session.metadata.kind}`);
    }

    const previousMetadata = cloneSessionMetadata(session.metadata);
    this.resumeInProgress.add(sessionId);
    try {
      const handle = await adapter.spawn({
        host: session.metadata.host,
        port: session.metadata.port,
        mode: 'listen',
        bind_host: session.metadata.bind_host,
        advertise_host: session.metadata.advertise_host,
        accept_mode: 'rearm',
        sessionId,
        onConnect: (info: { connection_token: string }) =>
          this.handleConnect(sessionId, info),
        abort_signal: this.persistenceAbortController.signal,
      });
      session.handle = handle;
      if (this.shuttingDown || !this.checkPersistenceGate()) {
        throw this.persistenceReadOnlyError();
      }
      const boundMetadata: SessionMetadata = {
        ...session.metadata,
        state: 'pending',
        pid: handle.pid,
        port: handle.bound_port ?? session.metadata.port,
        capabilities: { ...handle.capabilities },
        buffer_end_pos: session.buffer.endPos,
        closed_at: undefined,
        last_activity_at: new Date().toISOString(),
      };
      this.commitSessionMetadataUpdate(session, boundMetadata);
      this.attachHandleCallbacks(sessionId, session, handle);
      this.resumeInProgress.delete(sessionId);
      return { metadata: cloneSessionMetadata(session.metadata) };
    } catch (error) {
      const handle = session.handle;
      let cleanupError: unknown;
      try {
        handle?.close();
        if (session.handle === handle) session.handle = null;
      } catch (closeError) {
        // Retain the handle for shutdown retry and persist an unresolved
        // ownership state instead of falsely claiming resume is available.
        cleanupError = closeError;
      }
      if (this.persistenceWritable()) {
        const message = error instanceof Error ? error.message : String(error);
        const cleanupMessage = cleanupError instanceof Error
          ? cleanupError.message
          : cleanupError !== undefined
            ? String(cleanupError)
            : undefined;
        const retryableMetadata: SessionMetadata = {
          ...previousMetadata,
          state: cleanupError === undefined ? 'resume_available' : 'error',
          pid: undefined,
          connection_id: undefined,
          connection_started_at: undefined,
          closed_at: undefined,
          last_activity_at: new Date().toISOString(),
          notes: [
            previousMetadata.notes,
            `Listener resume failed: ${message}`,
            cleanupMessage
              ? `Listener resume cleanup could not close runtime: ${cleanupMessage}`
              : undefined,
          ].filter(Boolean).join('\n'),
        };
        this.commitSessionMetadataUpdate(session, retryableMetadata);
      }
      if (cleanupError !== undefined) {
        this.resumeInProgress.delete(sessionId);
        throw new AggregateError(
          [error, cleanupError],
          `Session ${sessionId} resume failed and runtime cleanup was unresolved`,
        );
      }
      this.resumeInProgress.delete(sessionId);
      throw error;
    }
  }

  close(sessionId: string, claimedBy?: string, force?: boolean): { metadata: SessionMetadata; final: SessionReadResult } {
    return this.closeInternal(sessionId, claimedBy, force, false);
  }

  private closeInternal(
    sessionId: string,
    claimedBy: string | undefined,
    force: boolean | undefined,
    preserveDescriptor: boolean,
  ): { metadata: SessionMetadata; final: SessionReadResult } {
    // A degraded manager performs runtime cleanup through freezeForPersistence,
    // which deliberately avoids claiming durable audit/graph updates. Direct
    // service callers must not receive a falsely durable ordinary close.
    this.assertPersistenceWritable();
    const session = this.getSessionOrThrow(sessionId);
    this.assertOwnership(session, claimedBy, force);

    // Capture final output
    const tailResult = session.buffer.tail(8192);
    const final: SessionReadResult = {
      session_id: sessionId,
      connection_id: session.metadata.connection_id,
      connection_generation: session.metadata.connection_generation,
      start_pos: tailResult.startPos,
      end_pos: tailResult.endPos,
      text: tailResult.text,
      truncated: tailResult.truncated,
    };

    const closedAt = new Date().toISOString();
    const connectionId = session.metadata.connection_id;
    const closedMetadata: SessionMetadata = {
      ...session.metadata,
      state: 'closed',
      connection_id: undefined,
      connection_started_at: undefined,
      last_connection_id: connectionId ?? session.metadata.last_connection_id,
      last_connection_state: connectionId ? 'closed' : session.metadata.last_connection_state,
      last_connection_closed_at: connectionId
        ? closedAt
        : session.metadata.last_connection_closed_at,
      closed_at: closedAt,
      claimed_by: undefined,
    };
    const description = `Session "${session.metadata.title}" closed by operator`;
    const previousMetadata = cloneSessionMetadata(session.metadata);
    try {
      this.commitSessionClosure(
        session,
        closedMetadata,
        description,
        preserveDescriptor,
      );
    } catch (error) {
      // A committed transaction that fails its live applier trips the engine's
      // read-only gate synchronously. Freeze immediately so a live target
      // handle cannot survive until the background poll notices.
      this.checkPersistenceGate();
      throw error;
    }

    const handle = session.handle;
    try {
      handle?.close();
      session.handle = null;
    } catch (error) {
      // The durable lifecycle close has committed, but the external runtime
      // may still be alive. Retain ownership for retry and surface an explicit
      // unresolved state instead of returning an ordinary successful close.
      const message = error instanceof Error ? error.message : String(error);
      const unresolvedMetadata: SessionMetadata = {
        ...previousMetadata,
        state: 'error',
        closed_at: undefined,
        last_activity_at: new Date().toISOString(),
        notes: [
          previousMetadata.notes,
          `Runtime close failed: ${message}`,
        ].filter(Boolean).join('\n'),
      };
      if (preserveDescriptor) {
        // Graceful shutdown deliberately retains the previously persisted
        // resumable listener descriptor. Only the retiring in-memory manager
        // needs to remember that runtime cleanup remains unresolved.
        session.metadata = unresolvedMetadata;
      } else {
        try {
          this.commitSessionMetadataUpdate(session, unresolvedMetadata);
        } catch (correctionError) {
          this.checkPersistenceGate();
          throw new AggregateError(
            [error, correctionError],
            `Session ${sessionId} runtime close failed and its unresolved descriptor could not be persisted`,
          );
        }
      }
      throw new Error(`Session ${sessionId} runtime close failed: ${message}`, {
        cause: error,
      });
    }
    this.emitBestEffortSessionEvent('session_closed', session);
    this.pruneClosedSessions();

    return { metadata: cloneSessionMetadata(session.metadata), final };
  }

  list(activeOnly: boolean = false): SessionMetadata[] {
    this.checkPersistenceGate();
    const all = Array.from(this.sessions.values(), session =>
      cloneSessionMetadata(session.metadata));
    if (activeOnly) {
      return all.filter(m => m.state === 'pending' || m.state === 'connected');
    }
    return all;
  }

  /**
   * Runtime ownership that must block state rollback. Lifecycle metadata alone
   * is insufficient: a failed close deliberately leaves state=error with the
   * only retryable adapter handle still attached.
   */
  listUnresolvedRuntimeOwnership(): SessionMetadata[] {
    return Array.from(this.sessions.values())
      .filter(session =>
        session.handle !== null
        || this.resumeInProgress.has(session.metadata.id)
        || session.metadata.state === 'pending'
        || session.metadata.state === 'connected')
      .map(session => cloneSessionMetadata(session.metadata));
  }

  /**
   * Drop runtime-only session metadata after an authoritative state rollback.
   * Live handles must be closed explicitly before rollback; closed entries are
   * safe to discard because the engine has already restored the durable
   * descriptor set selected by the operator.
   */
  reconcileAfterStateRollback(): void {
    const unresolved = this.listUnresolvedRuntimeOwnership();
    if (unresolved.length > 0) {
      throw new Error(
        `Cannot reconcile session runtime after rollback while ${unresolved.length} session(s) retain live or unresolved runtime ownership.`,
      );
    }
    this.sessions.clear();
  }

  getSession(sessionId: string): SessionMetadata | null {
    const session = this.sessions.get(sessionId);
    return session ? cloneSessionMetadata(session.metadata) : null;
  }

  async shutdown(): Promise<void> {
    this.beginShutdown();
    this.stopPersistenceGateMonitor();
    let firstError: unknown;
    try {
      if (!this.persistenceWritable()) {
        this.freezeForPersistence();
        return;
      }
      for (const [id, session] of this.sessions) {
        const active = session.metadata.state === 'connected'
          || session.metadata.state === 'pending';
        if (active || session.handle) {
          try {
            this.interruptRuntimeForShutdown(id, session);
          } catch (error) {
            if (firstError === undefined) firstError = error;
          }
        }
      }
    } finally {
      this.stopIdleReaper();
      this.stopPersistenceGateMonitor();
    }
    if (firstError !== undefined) throw firstError;
  }

  reapIdleSessions(): string[] {
    // Reaping is not a read: it closes a runtime handle, changes durable
    // session metadata, emits an audit event, and downgrades HAS_SESSION.
    // Read surfaces call this method opportunistically, so make the maintenance
    // operation itself fail closed while WAL recovery/persistence is degraded.
    if (!this.checkPersistenceGate()) {
      return [];
    }
    if (this.idleTimeoutMs <= 0) return [];
    const now = Date.now();
    const reaped: string[] = [];
    for (const [id, session] of this.sessions) {
      if (session.metadata.state !== 'connected' && session.metadata.state !== 'pending') continue;
      const lastActivity = new Date(session.metadata.last_activity_at).getTime();
      if (now - lastActivity > this.idleTimeoutMs) {
        const title = session.metadata.title;
        const previousMetadata = cloneSessionMetadata(session.metadata);
        try {
          const closedAt = new Date().toISOString();
          const connectionId = session.metadata.connection_id;
          const closedMetadata: SessionMetadata = {
            ...session.metadata,
            state: 'closed',
            connection_id: undefined,
            connection_started_at: undefined,
            last_connection_id: connectionId ?? session.metadata.last_connection_id,
            last_connection_state: connectionId ? 'closed' : session.metadata.last_connection_state,
            last_connection_closed_at: connectionId
              ? closedAt
              : session.metadata.last_connection_closed_at,
            closed_at: closedAt,
            claimed_by: undefined,
          };
          this.commitSessionClosure(
            session,
            closedMetadata,
            `Session "${title}" auto-closed after idle timeout (${Math.round(this.idleTimeoutMs / 60000)}min)`,
          );
          const handle = session.handle;
          try {
            handle?.close();
            if (session.handle === handle) session.handle = null;
          } catch (error) {
            // The durable close already committed, but runtime ownership is
            // unresolved. Retain the handle and correct the descriptor to an
            // explicit retryable error instead of claiming the session reaped.
            session.handle = handle;
            const message = error instanceof Error ? error.message : String(error);
            const unresolvedMetadata: SessionMetadata = {
              ...previousMetadata,
              state: 'error',
              closed_at: undefined,
              last_activity_at: new Date().toISOString(),
              notes: [
                previousMetadata.notes,
                `Idle reaper runtime close failed: ${message}`,
              ].filter(Boolean).join('\n'),
            };
            try {
              this.commitSessionMetadataUpdate(session, unresolvedMetadata);
            } catch (correctionError) {
              // Keep the live projection truthful even if durability has
              // failed and the persistence gate is about to freeze the manager.
              session.metadata = unresolvedMetadata;
              this.checkPersistenceGate();
              throw new AggregateError(
                [error, correctionError],
                `Session ${id} idle close failed and its unresolved descriptor could not be persisted`,
              );
            }
            continue;
          }
          this.emitBestEffortSessionEvent('session_closed', session);
          reaped.push(id);
        } catch {
          this.checkPersistenceGate();
        }
      }
    }
    this.pruneClosedSessions();
    return reaped;
  }

  // --- Internal helpers ---

  private startPersistenceGateMonitor(): void {
    const persistenceAwareEngine = this.engine as (GraphEngine & {
      isPersistenceWritable?: () => boolean;
    }) | null;
    if (this.persistenceGateTimer || typeof persistenceAwareEngine?.isPersistenceWritable !== 'function') return;
    this.persistenceGateTimer = setInterval(() => this.checkPersistenceGate(), PERSISTENCE_GATE_POLL_MS);
    this.persistenceGateTimer.unref?.();
    this.checkPersistenceGate();
  }

  private startIdleReaper(): void {
    const intervalMs = sessionIdleReaperIntervalMs(this.idleTimeoutMs);
    if (intervalMs === null || this.idleReaperTimer || this.shuttingDown) return;
    this.idleReaperTimer = setInterval(() => {
      if (this.shuttingDown) return;
      try {
        this.reapIdleSessions();
      } catch {
        this.checkPersistenceGate();
      }
    }, intervalMs);
    this.idleReaperTimer.unref?.();
  }

  private stopIdleReaper(): void {
    if (!this.idleReaperTimer) return;
    clearInterval(this.idleReaperTimer);
    this.idleReaperTimer = null;
  }

  private stopPersistenceGateMonitor(): void {
    if (!this.persistenceGateTimer) return;
    clearInterval(this.persistenceGateTimer);
    this.persistenceGateTimer = null;
  }

  private persistenceWritable(): boolean {
    if (this.persistenceFrozen) return false;
    const persistenceAwareEngine = this.engine as (GraphEngine & {
      isPersistenceWritable?: () => boolean;
    }) | null;
    if (typeof persistenceAwareEngine?.isPersistenceWritable !== 'function') return true;
    try {
      return persistenceAwareEngine.isPersistenceWritable();
    } catch {
      // If the persistence owner is disposing or otherwise cannot answer, fail
      // closed rather than allowing a new target-facing operation.
      return false;
    }
  }

  private checkPersistenceGate(): boolean {
    if (this.persistenceWritable()) return true;
    const persistenceAwareEngine = this.engine as (GraphEngine & {
      isStatePersistenceWritable?: () => boolean;
    }) | null;
    if (typeof persistenceAwareEngine?.isStatePersistenceWritable === 'function') {
      try {
        // Config divergence and deferred startup reconciliation temporarily
        // block mutations but do not corrupt the WAL/state owner. Keep the
        // manager inert and retryable so explicit reconciliation can reopen it
        // in the same process.
        if (persistenceAwareEngine.isStatePersistenceWritable()) return false;
      } catch {
        // Fall through to sticky runtime freeze when the durability owner
        // cannot establish that state persistence is healthy.
      }
    }
    this.freezeForPersistence();
    return false;
  }

  /** Close runtime handles without trying to journal lifecycle or graph state.
   * The gate is sticky for this manager instance; recovery requires restart. */
  private freezeForPersistence(): void {
    if (!this.persistenceFrozen) {
      this.persistenceFrozen = true;
      this.stopIdleReaper();
      this.stopPersistenceGateMonitor();
      this.persistenceAbortController.abort(this.persistenceReadOnlyError());
    }
    const closedAt = new Date().toISOString();
    for (const session of this.sessions.values()) {
      if (
        session.metadata.state !== 'connected'
        && session.metadata.state !== 'pending'
        && !session.handle
      ) continue;
      const handle = session.handle;
      try {
        handle?.close();
        session.handle = null;
        const connectionId = session.metadata.connection_id;
        session.metadata.state = 'closed';
        session.metadata.closed_at = closedAt;
        session.metadata.connection_id = undefined;
        session.metadata.connection_started_at = undefined;
        session.metadata.last_connection_id = connectionId
          ?? session.metadata.last_connection_id;
        session.metadata.last_connection_state = connectionId
          ? 'interrupted'
          : session.metadata.last_connection_state;
        session.metadata.last_connection_closed_at = connectionId
          ? closedAt
          : session.metadata.last_connection_closed_at;
        session.metadata.claimed_by = undefined;
        session.connection_token = undefined;
      } catch (error) {
        session.metadata.state = 'error';
        session.metadata.closed_at = undefined;
        session.metadata.notes = [
          session.metadata.notes,
          `Persistence freeze could not close runtime: ${error instanceof Error ? error.message : String(error)}`,
        ].filter(Boolean).join('\n');
      }
      // Session events are an in-memory dashboard projection only. Do not call
      // logSessionEvent/onSessionClosed here: both are durable graph mutations.
      this.emitSessionEvent('session_closed', session);
    }
  }

  private persistenceReadOnlyError(): Error {
    const error = new Error('Session operation refused because durable persistence is read-only');
    (error as Error & { code?: string }).code = 'PERSISTENCE_READ_ONLY';
    return error;
  }

  private assertPersistenceWritable(): void {
    if (this.checkPersistenceGate()) return;
    throw this.persistenceReadOnlyError();
  }

  private assertDurableDescriptorOwner(): void {
    if (
      this.engine
      && typeof this.engine.recordSessionDescriptor === 'function'
      && !this.durableEventListener
    ) {
      throw new Error(
        'Session runtime refused because no durable descriptor owner is registered.',
      );
    }
  }

  private interruptRuntimeForShutdown(sessionId: string, session: Session): void {
    const previousMetadata = cloneSessionMetadata(session.metadata);
    const interruptedAt = new Date().toISOString();
    const connectionId = session.metadata.connection_id;
    const resumableListener = session.metadata.kind === 'socket'
      && session.metadata.mode === 'listen'
      && session.metadata.accept_mode === 'rearm';
    const recoveredMetadata: SessionMetadata = {
      ...session.metadata,
      state: resumableListener ? 'resume_available' : 'interrupted',
      pid: undefined,
      connection_id: undefined,
      connection_started_at: undefined,
      last_connection_id: connectionId ?? session.metadata.last_connection_id,
      last_connection_state: connectionId
        ? 'interrupted'
        : session.metadata.last_connection_state,
      last_connection_closed_at: connectionId
        ? interruptedAt
        : session.metadata.last_connection_closed_at,
      auth_status: resumableListener ? undefined : session.metadata.auth_status,
      capabilities: resumableListener
        ? { ...SOCKET_LISTENER_WAITING_CAPABILITIES }
        : session.metadata.capabilities,
      resume_policy: resumableListener ? 'manual' : 'none',
      closed_at: undefined,
    };
    this.commitSessionClosure(
      session,
      recoveredMetadata,
      resumableListener
        ? `Listener "${session.metadata.title}" stopped; explicit resume is available`
        : `Session "${session.metadata.title}" interrupted by service shutdown`,
      false,
      {
        connection_id: connectionId,
        event_type: 'session_closed',
      },
    );
    const handle = session.handle;
    try {
      handle?.close();
      session.handle = null;
      session.connection_token = undefined;
    } catch (error) {
      session.handle = handle;
      const message = error instanceof Error ? error.message : String(error);
      const unresolvedMetadata: SessionMetadata = {
        ...previousMetadata,
        state: 'error',
        closed_at: undefined,
        last_activity_at: interruptedAt,
        notes: [
          previousMetadata.notes,
          `Shutdown runtime close failed: ${message}`,
        ].filter(Boolean).join('\n'),
      };
      this.commitSessionMetadataUpdate(session, unresolvedMetadata);
      throw new Error(`Session ${sessionId} runtime close failed during shutdown: ${message}`, {
        cause: error,
      });
    }
    this.emitBestEffortSessionEvent('session_updated', session);
  }

  private getSessionOrThrow(sessionId: string): Session {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session not found: ${sessionId}`);
    return session;
  }

  private assertConnected(session: Session): void {
    if (session.metadata.state !== 'connected') {
      throw new Error(`Session ${session.metadata.id} is not connected (state: ${session.metadata.state})`);
    }
  }

  private assertOwnership(session: Session, claimedBy?: string, force?: boolean): void {
    if (force) return;
    if (session.metadata.claimed_by && session.metadata.claimed_by !== claimedBy) {
      throw new Error(
        `Session ${session.metadata.id} is claimed by "${session.metadata.claimed_by}", ` +
        `not "${claimedBy}". Use force=true to override.`
      );
    }
  }

  private assertExpectedConnectionGeneration(
    session: Session,
    expected: { connection_id?: string; connection_generation?: number },
  ): void {
    if (
      (expected.connection_id !== undefined
        && session.metadata.connection_id !== expected.connection_id)
      || (expected.connection_generation !== undefined
        && session.metadata.connection_generation !== expected.connection_generation)
    ) {
      const error = new Error(
        `Session ${session.metadata.id} connection generation changed; refresh session metadata before continuing I/O.`,
      );
      (error as Error & { code?: string }).code = 'SESSION_GENERATION_CHANGED';
      throw error;
    }
  }

  private attachHandleCallbacks(
    sessionId: string,
    session: Session,
    handle: AdapterHandle,
  ): void {
    handle.onData((chunk: string) => {
      if (!this.checkPersistenceGate()) return;
      session.buffer.write(chunk);
      const priorMetadata = session.metadata;
      const observedAt = new Date();
      session.metadata = {
        ...session.metadata,
        buffer_end_pos: session.buffer.endPos,
        last_activity_at: observedAt.toISOString(),
      };
      if (
        observedAt.getTime() - (session.last_descriptor_activity_persisted_at ?? 0)
        >= SESSION_ACTIVITY_DURABILITY_MS
      ) {
        try {
          this.emitSessionEvent('session_updated', session);
          session.last_descriptor_activity_persisted_at = observedAt.getTime();
        } catch {
          session.metadata = priorMetadata;
          this.checkPersistenceGate();
        }
      }
    });

    handle.onExit((info) => {
      if (!this.checkPersistenceGate()) return;
      try {
        if (
          session.metadata.state !== 'closed'
          && session.metadata.state !== 'resume_available'
          && session.metadata.state !== 'interrupted'
        ) {
          const endedAt = new Date().toISOString();
          const connectionId = session.metadata.connection_id;
          const closedMetadata: SessionMetadata = {
            ...session.metadata,
            state: 'closed',
            connection_id: undefined,
            connection_started_at: undefined,
            last_connection_id: connectionId ?? session.metadata.last_connection_id,
            last_connection_state: connectionId ? 'closed' : session.metadata.last_connection_state,
            last_connection_closed_at: connectionId
              ? endedAt
              : session.metadata.last_connection_closed_at,
            closed_at: endedAt,
            claimed_by: undefined,
          };
          this.commitIrreversibleSessionClosure(
            session,
            closedMetadata,
            `Session "${session.metadata.title}" exited (code=${info.exitCode}, signal=${info.signal})`,
          );
          session.connection_token = undefined;
          session.handle = null;
          this.emitBestEffortSessionEvent('session_closed', session);
        }
        this.pruneClosedSessions();
      } catch (error) {
        // Adapter event callbacks must never escape into EventEmitter. If the
        // durable transition cannot be recorded, retire the dead runtime
        // projection locally and let recovery reconcile the durable graph.
        const failedAt = new Date().toISOString();
        const connectionId = session.metadata.connection_id;
        session.handle = null;
        session.connection_token = undefined;
        session.metadata = {
          ...session.metadata,
          state: 'error',
          connection_id: undefined,
          connection_started_at: undefined,
          last_connection_id: connectionId ?? session.metadata.last_connection_id,
          last_connection_state: connectionId
            ? 'interrupted'
            : session.metadata.last_connection_state,
          last_connection_closed_at: connectionId
            ? failedAt
            : session.metadata.last_connection_closed_at,
          closed_at: undefined,
          notes: [
            session.metadata.notes,
            `Session exit could not be durably finalized: ${
              error instanceof Error ? error.message : String(error)
            }`,
          ].filter(Boolean).join('\n'),
        };
        this.emitBestEffortSessionEvent('session_updated', session);
        this.checkPersistenceGate();
      }
    });
    if (handle.onDisconnect) {
      handle.onDisconnect((info) => {
        try { this.handleDisconnect(sessionId, info); } catch { this.checkPersistenceGate(); }
      });
    }
  }

  private handleConnect(
    sessionId: string,
    info?: { connection_token?: string },
  ): void {
    if (!this.checkPersistenceGate()) return;
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session not found: ${sessionId}`);
    if (session.metadata.state !== 'pending') {
      throw new Error(
        `Session ${sessionId} cannot accept a connection while ${session.metadata.state}.`,
      );
    }
    const connectedAt = new Date().toISOString();
    const generation = (session.metadata.connection_generation ?? 0) + 1;
    const connectionId = `${session.metadata.listener_id ?? sessionId}:g${generation}`;
    const previousMetadata = session.metadata;
    const previousBuffer = session.buffer;
    const previousToken = session.connection_token;
    const previousPersistedActivity = session.last_descriptor_activity_persisted_at;
    const nextBufferPosition = previousBuffer.endPos;
    session.buffer = new RingBuffer(DEFAULT_BUFFER_SIZE, nextBufferPosition);
    session.last_descriptor_activity_persisted_at = 0;
    session.connection_token = info?.connection_token
      ?? `${sessionId}:compat:${generation}`;
    const connectedMetadata: SessionMetadata = {
      ...session.metadata,
      state: 'connected',
      connection_generation: generation,
      connection_id: connectionId,
      connection_started_at: connectedAt,
      auth_status: undefined,
      capabilities: session.handle
        ? { ...session.handle.capabilities }
        : session.metadata.capabilities,
      buffer_end_pos: nextBufferPosition,
      last_activity_at: connectedAt,
      closed_at: undefined,
    };
    try {
      this.commitSessionConnection(
        session,
        connectedMetadata,
        `Session "${session.metadata.title}" connected as generation ${generation}`,
      );
    } catch (error) {
      session.metadata = previousMetadata;
      session.buffer = previousBuffer;
      session.connection_token = previousToken;
      session.last_descriptor_activity_persisted_at = previousPersistedActivity;
      throw error;
    }
    this.emitBestEffortSessionEvent('session_updated', session);
  }

  private handleDisconnect(
    sessionId: string,
    info?: { reason?: string; connection_token?: string },
  ): void {
    this.assertPersistenceWritable();
    const session = this.sessions.get(sessionId);
    if (!session) return;
    if (
      session.connection_token
      && info?.connection_token !== session.connection_token
    ) return;
    if (
      session.metadata.kind !== 'socket'
      || session.metadata.mode !== 'listen'
      || session.metadata.accept_mode !== 'rearm'
      || session.metadata.state !== 'connected'
    ) return;
    const disconnectedAt = new Date().toISOString();
    const connectionId = session.metadata.connection_id;
    const waitingMetadata: SessionMetadata = {
      ...session.metadata,
      state: 'pending',
      connection_id: undefined,
      connection_started_at: undefined,
      last_connection_id: connectionId ?? session.metadata.last_connection_id,
      last_connection_state: connectionId
        ? 'disconnected'
        : session.metadata.last_connection_state,
      last_connection_closed_at: connectionId
        ? disconnectedAt
        : session.metadata.last_connection_closed_at,
      auth_status: undefined,
      capabilities: session.handle
        ? { ...session.handle.capabilities }
        : { ...SOCKET_LISTENER_WAITING_CAPABILITIES },
      last_activity_at: disconnectedAt,
    };
    try {
      this.commitIrreversibleSessionClosure(
        session,
        waitingMetadata,
        `Listener "${session.metadata.title}" generation ${session.metadata.connection_generation ?? 0} disconnected and returned to waiting`,
        {
          connection_id: connectionId,
          event_type: 'session_updated',
        },
      );
    } catch (error) {
      try { session.handle?.close(); } catch { /* preserve primary durability error */ }
      session.handle = null;
      session.connection_token = undefined;
      session.metadata = {
        ...session.metadata,
        state: 'error',
        connection_id: undefined,
        connection_started_at: undefined,
        last_connection_id: connectionId ?? session.metadata.last_connection_id,
        last_connection_state: connectionId
          ? 'interrupted'
          : session.metadata.last_connection_state,
        last_connection_closed_at: connectionId
          ? disconnectedAt
          : session.metadata.last_connection_closed_at,
        closed_at: undefined,
        notes: [
          session.metadata.notes,
          `Listener disconnect could not be durably finalized: ${
            error instanceof Error ? error.message : String(error)
          }`,
        ].filter(Boolean).join('\n'),
      };
      this.emitBestEffortSessionEvent('session_updated', session);
      this.checkPersistenceGate();
      throw error;
    }
    session.connection_token = undefined;
    this.emitBestEffortSessionEvent('session_updated', session);
  }

  private emitSessionEvent(type: SessionEventType, session: Session): void {
    const event = this.buildSessionEvent(type, session);
    if (!this.persistenceFrozen) this.emitDurableEvent(event);
    this.emitBestEffortEvent(event);
  }

  private emitBestEffortSessionEvent(type: SessionEventType, session: Session): void {
    this.emitBestEffortEvent(this.buildSessionEvent(type, session));
  }

  private emitBestEffortEvent(event: SessionEvent): void {
    for (const listener of this.eventListeners) {
      try { listener(structuredClone(event)); } catch { /* isolate listener failures */ }
    }
  }

  private emitDurableSessionEvent(type: SessionEventType, session: Session): void {
    if (this.persistenceFrozen) return;
    this.emitDurableEvent(this.buildSessionEvent(type, session));
  }

  private emitDurableEvent(event: SessionEvent): void {
    this.assertDurableDescriptorOwner();
    this.durableEventListener?.(structuredClone(event));
  }

  private buildSessionEvent(type: SessionEventType, session: Session): SessionEvent {
    return {
      type,
      session: cloneSessionMetadata(session.metadata),
      sessions: Array.from(this.sessions.values(), candidate =>
        cloneSessionMetadata(candidate.metadata)),
    };
  }

  private commitSessionClosure(
    session: Session,
    closedMetadata: SessionMetadata,
    description: string,
    preserveDescriptor = false,
    options: {
      connection_id?: string;
      event_type?: ActivityEventType;
    } = {},
  ): void {
    const previous = session.metadata;
    if (
      this.engine
      && typeof this.engine.closeSessionDurably === 'function'
    ) {
      this.engine.closeSessionDurably(closedMetadata, description, {
        preserve_descriptor: preserveDescriptor,
        connection_id: options.connection_id,
        event_type: options.event_type,
      });
      session.metadata = closedMetadata;
      return;
    }

    session.metadata = closedMetadata;
    try {
      this.emitDurableSessionEvent('session_closed', session);
    } catch (error) {
      session.metadata = previous;
      throw error;
    }
  }

  private commitSessionConnection(
    session: Session,
    connectedMetadata: SessionMetadata,
    description: string,
  ): void {
    const previous = session.metadata;
    if (
      this.engine
      && typeof this.engine.connectSessionGenerationDurably === 'function'
    ) {
      this.engine.connectSessionGenerationDurably(connectedMetadata, description);
      session.metadata = connectedMetadata;
      return;
    }
    session.metadata = connectedMetadata;
    try {
      if (
        this.engine
        && connectedMetadata.kind === 'socket'
        && connectedMetadata.target_node
      ) {
        this.engine.ingestSessionResult({
          success: true,
          confirmed: true,
          target_node: connectedMetadata.target_node,
          principal_node: connectedMetadata.principal_node,
          credential_node: connectedMetadata.credential_node,
          session_id: connectedMetadata.connection_id ?? connectedMetadata.id,
          listener_id: connectedMetadata.listener_id,
          connection_generation: connectedMetadata.connection_generation,
          agent_id: connectedMetadata.agent_id,
          action_id: connectedMetadata.action_id,
          frontier_item_id: connectedMetadata.frontier_item_id,
        });
      }
      this.logSessionEvent(
        connectedMetadata.id,
        'session_connected',
        description,
      );
      this.emitDurableSessionEvent('session_updated', session);
    } catch (error) {
      session.metadata = previous;
      throw error;
    }
  }

  private commitIrreversibleSessionClosure(
    session: Session,
    metadata: SessionMetadata,
    description: string,
    options: {
      connection_id?: string;
      event_type?: ActivityEventType;
    } = {},
  ): void {
    let lastError: unknown;
    for (
      let attempt = 0;
      attempt < IRREVERSIBLE_LIFECYCLE_COMMIT_ATTEMPTS;
      attempt++
    ) {
      try {
        this.commitSessionClosure(
          session,
          metadata,
          description,
          false,
          options,
        );
        return;
      } catch (error) {
        lastError = error;
        if (!this.persistenceWritable()) break;
      }
    }
    throw lastError;
  }

  private commitSessionMetadataUpdate(
    session: Session,
    metadata: SessionMetadata,
  ): void {
    const previous = session.metadata;
    session.metadata = metadata;
    try {
      this.emitSessionEvent('session_updated', session);
    } catch (error) {
      session.metadata = previous;
      throw error;
    }
  }

  private logSessionEvent(sessionId: string, eventType: ActivityEventType, description: string): void {
    if (!this.engine || !this.persistenceWritable()) return;
    const session = this.sessions.get(sessionId);
    try {
      this.engine.logActionEvent({
        event_type: eventType,
        description,
        agent_id: session?.metadata.agent_id,
        action_id: session?.metadata.action_id,
        frontier_item_id: session?.metadata.frontier_item_id,
        category: 'system',
        details: {
          session_id: sessionId,
          session_kind: session?.metadata.kind,
          session_state: session?.metadata.state,
        },
      });
    } catch (error) {
      if (!this.checkPersistenceGate()) return;
      throw error;
    }
  }

  private detectSshAuthFailure(session: Session): string | null {
    const output = session.buffer.tail(4096).text;
    const patterns: Array<[RegExp, string]> = [
      [/permission denied/i, 'Permission denied'],
      [/authentication failed/i, 'Authentication failed'],
      [/host key verification failed/i, 'Host key verification failed'],
      [/connection refused/i, 'Connection refused'],
      [/connection reset by peer/i, 'Connection reset by peer'],
      [/no route to host/i, 'No route to host'],
      [/connection timed out/i, 'Connection timed out'],
      [/kex_exchange_identification/i, 'Key exchange failed'],
      [/banner exchange/i, 'Banner exchange error'],
      [/connection closed by .+ port \d+/i, 'Connection closed by remote host'],
      [/closed by remote host/i, 'Closed by remote host'],
      [/no matching (host key|key exchange|cipher|mac)/i, 'Algorithm negotiation failed'],
      [/too many authentication failures/i, 'Too many authentication failures'],
      [/ssh_dispatch_run_fatal/i, 'SSH dispatch fatal error'],
      [/could not resolve hostname/i, 'Could not resolve hostname'],
      [/network is unreachable/i, 'Network unreachable'],
    ];
    for (const [re, label] of patterns) {
      if (re.test(output)) return label;
    }
    return null;
  }

  /**
   * Detect whether SSH output indicates an authentication prompt (password,
   * MFA, passphrase) — meaning transport connected but auth is not complete.
   * Returns the prompt type if detected, null otherwise.
   */
  detectSshAuthPrompt(session: Session): string | null {
    const tail = session.buffer.tail(1024).text;
    const lastLine = tail.split('\n').filter(l => l.trim().length > 0).pop() || '';
    const promptPatterns: Array<[RegExp, string]> = [
      [/password\s*:/i, 'password_prompt'],
      [/password for\s/i, 'password_prompt'],
      [/enter passphrase/i, 'passphrase_prompt'],
      [/verification code\s*:/i, 'mfa_prompt'],
      [/otp\s*:/i, 'mfa_prompt'],
      [/enter.*token/i, 'mfa_prompt'],
      [/are you sure you want to continue connecting/i, 'host_key_prompt'],
    ];
    for (const [re, label] of promptPatterns) {
      if (re.test(lastLine)) return label;
    }
    return null;
  }

  /**
   * Positive confirmation that an SSH session has an interactive shell.
   * Phase 1: Check if output already ends with a common shell prompt.
   * Phase 2: Send an echo probe and check for the expected response.
   * Returns true if confirmed, false if unconfirmed (session may still be live).
   */
  async detectSshAuthSuccess(session: Session): Promise<boolean> {
    // Phase 1: Look for common shell prompt at end of current output
    const tail = session.buffer.tail(1024).text;
    const lastLine = tail.split('\n').filter(l => l.trim().length > 0).pop() || '';
    // Common prompt endings: $, #, >, % (with optional trailing whitespace)
    if (/[$#>%]\s*$/.test(lastLine)) {
      return true;
    }

    // Guard: Do not probe if session appears to be at a non-shell prompt
    // (password, passphrase, host-key, MFA, login/username, or appliance/menu prompt)
    const NON_SHELL_PROMPTS = [
      /password\s*:/i,
      /password for\s/i,
      /enter passphrase/i,
      /are you sure you want to continue connecting/i,
      /verification code\s*:/i,
      /otp\s*:/i,
      /enter.*token/i,
      /enter.*selection/i,
      /press.*to continue/i,
      /choice\s*:/i,
      // Username / login prompts — some appliances and unusual SSH flows
      // present these *after* the SSH transport is up. Treat as non-shell
      // so the echo probe doesn't accept their echo as a confirmed shell.
      /^\s*username\s*:/i,
      /^\s*login\s*:/i,
      /\blogin as\b/i,
    ];
    if (NON_SHELL_PROMPTS.some(re => re.test(lastLine))) {
      return false;
    }

    // Phase 2: Send an echo probe and wait for it
    if (!this.checkPersistenceGate() || !session.handle) return false;
    const marker = `__OW_READY_${session.metadata.id.slice(0, 8)}__`;
    const probeCmd = `echo ${marker}\n`;
    const preProbePos = session.buffer.endPos;

    try {
      session.handle.write(probeCmd);
    } catch {
      return false;
    }

    // Wait up to 3 seconds for the marker to appear *as command output*,
    // not merely as the echoed probe input. We require the marker to appear
    // on a line that does NOT also contain the literal `echo <marker>` we
    // just sent — otherwise terminal echo of the input alone would
    // falsely confirm a shell on appliances at a Username:/login: prompt.
    const deadline = Date.now() + 3000;
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 200));
      if (!this.checkPersistenceGate()) return false;
      const newOutput = session.buffer.read(preProbePos).text;
      if (!newOutput.includes(marker)) continue;
      const lines = newOutput.split(/\r?\n/);
      const outputLine = lines.find(l => l.includes(marker) && !/echo\s+__OW_READY_/.test(l));
      if (outputLine !== undefined) {
        return true;
      }
    }

    return false;
  }

  private waitForInitialOutput(session: Session, maxMs: number): Promise<void> {
    return new Promise((resolve) => {
      const startPos = session.buffer.endPos;
      let timer: ReturnType<typeof setTimeout> | null = null;
      let settled = false;

      const check = () => {
        if (settled) return;
        if (!this.checkPersistenceGate() || session.metadata.state === 'closed' || session.metadata.state === 'error') {
          settled = true;
          clearInterval(interval);
          if (timer) clearTimeout(timer);
          resolve();
          return;
        }
        if (session.buffer.endPos > startPos) {
          settled = true;
          clearInterval(interval);
          if (timer) clearTimeout(timer);
          setTimeout(resolve, 200);
          return;
        }
      };

      // Check every 100ms for output
      const interval = setInterval(check, 100);

      timer = setTimeout(() => {
        clearInterval(interval);
        if (!settled) resolve();
      }, maxMs);

      // Also resolve if already have output
      if (session.buffer.endPos > startPos) {
        settled = true;
        clearInterval(interval);
        if (timer) clearTimeout(timer);
        setTimeout(resolve, 200);
      }
    });
  }

  private pruneClosedSessions(): void {
    const closed = Array.from(this.sessions.entries())
      .filter(([, s]) => s.metadata.state === 'closed' || s.metadata.state === 'error')
      .sort((a, b) => (a[1].metadata.closed_at || '').localeCompare(b[1].metadata.closed_at || ''));

    while (closed.length > MAX_CLOSED_SESSIONS) {
      const [id] = closed.shift()!;
      this.sessions.delete(id);
    }
  }
}
