// ============================================================
// Overwatch — Session Manager
// Persistent interactive sessions (SSH, PTY, socket) maintained
// server-side across MCP tool calls.
// ============================================================

import { v4 as uuidv4 } from 'uuid';
import type {
  AdapterHandle,
  SessionCapabilities,
  SessionKind,
  SessionMetadata,
  SessionReadResult,
  SessionState,
} from '../types.js';
import type { GraphEngine } from './graph-engine.js';
import type { ActivityEventType } from './engine-context.js';

// ============================================================
// RingBuffer — fixed-size circular buffer with absolute cursors
// ============================================================

const DEFAULT_BUFFER_SIZE = 128 * 1024; // 128KB

export class RingBuffer {
  private chunks: Array<{ text: string; absStart: number }> = [];
  private capacity: number;
  private _endPos: number = 0;
  private retainedLength: number = 0;

  constructor(capacity: number = DEFAULT_BUFFER_SIZE) {
    this.capacity = capacity;
  }

  get endPos(): number {
    return this._endPos;
  }

  get startPos(): number {
    if (this.chunks.length === 0) return 0;
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
}

// ============================================================
// Adapter factory type
// ============================================================

export interface SessionAdapterFactory {
  kind: SessionKind;
  spawn(options: Record<string, unknown>): Promise<AdapterHandle>;
}

// ============================================================
// SessionManager
// ============================================================

const MAX_CLOSED_SESSIONS = 50;

export interface SessionCreateOptions {
  kind: SessionKind;
  title: string;
  host?: string;
  user?: string;
  port?: number;
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
  // internal
  initial_wait_ms?: number;
}

export class SessionManager {
  private sessions: Map<string, Session> = new Map();
  private adapters: Map<SessionKind, SessionAdapterFactory> = new Map();
  private engine: GraphEngine | null;

  constructor(engine: GraphEngine | null = null) {
    this.engine = engine;
  }

  registerAdapter(adapter: SessionAdapterFactory): void {
    this.adapters.set(adapter.kind, adapter);
  }

  async create(options: SessionCreateOptions): Promise<{ metadata: SessionMetadata; initial: SessionReadResult }> {
    const adapter = this.adapters.get(options.kind);
    if (!adapter) {
      throw new Error(`No adapter registered for session kind: ${options.kind}`);
    }

    const id = uuidv4();
    const now = new Date().toISOString();
    const buffer = new RingBuffer();

    // Determine initial state based on kind
    const initialState: SessionState = options.kind === 'socket' ? 'pending' : 'connected';

    // Determine transport label
    let transport = 'pty';
    if (options.kind === 'socket') {
      transport = options.mode === 'listen' ? 'tcp-listen' : 'tcp-connect';
    }

    const metadata: SessionMetadata = {
      id,
      kind: options.kind,
      transport,
      state: initialState,
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
      claimed_by: options.agent_id,
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
    };

    const session: Session = { metadata, handle: null, buffer };
    this.sessions.set(id, session);

    try {
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
        sessionId: id,
        onConnect: () => this.handleConnect(id),
      });

      session.handle = handle;
      session.metadata.pid = handle.pid;
      session.metadata.capabilities = { ...handle.capabilities };

      // Wire output to ring buffer
      handle.onData((chunk: string) => {
        session.buffer.write(chunk);
        session.metadata.buffer_end_pos = session.buffer.endPos;
        session.metadata.last_activity_at = new Date().toISOString();
      });

      handle.onExit((info) => {
        if (session.metadata.state !== 'closed') {
          session.metadata.state = 'closed';
          session.metadata.closed_at = new Date().toISOString();
          this.logSessionEvent(id, 'session_closed',
            `Session "${session.metadata.title}" exited (code=${info.exitCode}, signal=${info.signal})`);
        }
        this.pruneClosedSessions();
      });

      // For PTY-backed sessions, mark connected immediately
      if (options.kind !== 'socket') {
        session.metadata.state = 'connected';
      }

      this.logSessionEvent(id, 'session_opened',
        `Session "${options.title}" opened (${options.kind}, ${transport})`);

      // Wait briefly for initial output (e.g. shell prompt, SSH banner)
      const waitMs = options.initial_wait_ms !== undefined ? options.initial_wait_ms : 2000;
      if (waitMs > 0) {
        await this.waitForInitialOutput(session, waitMs);
      }

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

        // Positive confirmation: only if no auth failure detected
        let confirmed = false;
        if (!authFailed) {
          confirmed = await this.detectSshAuthSuccess(session);
        }

        this.engine.ingestSessionResult({
          success: !authFailed,
          confirmed,
          target_node: options.target_node,
          principal_node: options.principal_node,
          credential_node: options.credential_node,
          session_id: id,
          agent_id: options.agent_id,
          action_id: options.action_id,
          frontier_item_id: options.frontier_item_id,
        });
      }

      const initial = session.buffer.tail(4096);
      return {
        metadata: { ...session.metadata },
        initial: {
          session_id: id,
          start_pos: initial.startPos,
          end_pos: initial.endPos,
          text: initial.text,
          truncated: initial.truncated,
        },
      };
    } catch (err) {
      session.metadata.state = 'error';
      session.metadata.closed_at = new Date().toISOString();
      this.logSessionEvent(id, 'session_error',
        `Session "${options.title}" failed to open: ${err instanceof Error ? err.message : String(err)}`);

      // Session → graph integration: mark failure on specific frontier item
      if (this.engine && options.kind === 'ssh' && options.target_node) {
        this.engine.ingestSessionResult({
          success: false,
          target_node: options.target_node,
          principal_node: options.principal_node,
          credential_node: options.credential_node,
          session_id: id,
          agent_id: options.agent_id,
          action_id: options.action_id,
          frontier_item_id: options.frontier_item_id,
        });
      }

      throw err;
    }
  }

  write(sessionId: string, data: string, claimedBy?: string, force?: boolean): { session_id: string; end_pos: number } {
    const session = this.getSessionOrThrow(sessionId);
    this.assertConnected(session);
    this.assertOwnership(session, claimedBy, force);

    if (!session.handle) {
      throw new Error(`Session ${sessionId} has no active handle`);
    }

    session.handle.write(data);
    session.metadata.last_activity_at = new Date().toISOString();
    return { session_id: sessionId, end_pos: session.buffer.endPos };
  }

  read(sessionId: string, fromPos?: number, tailBytes?: number): SessionReadResult {
    const session = this.getSessionOrThrow(sessionId);

    if (fromPos !== undefined) {
      const result = session.buffer.read(fromPos);
      return { session_id: sessionId, start_pos: result.startPos, end_pos: result.endPos, text: result.text, truncated: result.truncated };
    }

    const result = session.buffer.tail(tailBytes || 4096);
    return { session_id: sessionId, start_pos: result.startPos, end_pos: result.endPos, text: result.text, truncated: result.truncated };
  }

  async sendCommand(
    sessionId: string,
    command: string,
    options: { timeout_ms?: number; idle_ms?: number; wait_for?: string; claimedBy?: string; force?: boolean } = {},
  ): Promise<SessionReadResult> {
    const session = this.getSessionOrThrow(sessionId);
    this.assertConnected(session);
    this.assertOwnership(session, options.claimedBy, options.force);

    const timeoutMs = options.timeout_ms || 10000;
    const idleMs = options.idle_ms || 500;
    const waitForRegex = options.wait_for ? new RegExp(options.wait_for) : null;

    // Record position before sending
    const startPos = session.buffer.endPos;

    // Write command + newline
    if (!session.handle) {
      throw new Error(`Session ${sessionId} has no active handle`);
    }
    session.handle.write(command + '\n');
    session.metadata.last_activity_at = new Date().toISOString();

    // Wait for output to settle
    return new Promise<SessionReadResult>((resolve) => {
      let lastEndPos = session.buffer.endPos;
      let idleTimer: ReturnType<typeof setTimeout> | null = null;

      const finish = () => {
        if (idleTimer) clearTimeout(idleTimer);
        if (overallTimer) clearTimeout(overallTimer);
        const result = session.buffer.read(startPos);
        resolve({ session_id: sessionId, start_pos: result.startPos, end_pos: result.endPos, text: result.text, truncated: result.truncated });
      };

      const checkIdle = () => {
        const currentEnd = session.buffer.endPos;

        // Check wait_for regex
        if (waitForRegex) {
          const data = session.buffer.read(startPos);
          if (waitForRegex.test(data.text)) {
            finish();
            return;
          }
        }

        if (currentEnd === lastEndPos) {
          // No new output — idle period elapsed
          finish();
          return;
        }

        lastEndPos = currentEnd;
        idleTimer = setTimeout(checkIdle, idleMs);
      };

      // Start idle checking after a brief initial delay
      idleTimer = setTimeout(checkIdle, idleMs);

      // Overall timeout
      const overallTimer = setTimeout(finish, timeoutMs);
    });
  }

  resize(sessionId: string, cols: number, rows: number, claimedBy?: string, force?: boolean): void {
    const session = this.getSessionOrThrow(sessionId);
    this.assertConnected(session);
    this.assertOwnership(session, claimedBy, force);

    if (!session.metadata.capabilities.supports_resize) {
      throw new Error(`Session ${sessionId} does not support resize (tty_quality: ${session.metadata.capabilities.tty_quality})`);
    }

    if (session.handle?.resize) {
      session.handle.resize(cols, rows);
    }
  }

  signal(sessionId: string, sig: string, claimedBy?: string, force?: boolean): void {
    const session = this.getSessionOrThrow(sessionId);
    this.assertConnected(session);
    this.assertOwnership(session, claimedBy, force);

    if (!session.metadata.capabilities.supports_signals) {
      throw new Error(`Session ${sessionId} does not support signals (tty_quality: ${session.metadata.capabilities.tty_quality})`);
    }

    if (session.handle?.kill) {
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
    const session = this.getSessionOrThrow(sessionId);
    this.assertOwnership(session, claimedBy, force);

    if (updates.capabilities) {
      session.metadata.capabilities = {
        ...session.metadata.capabilities,
        ...updates.capabilities,
      };
    }
    if (updates.title !== undefined) session.metadata.title = updates.title;
    if (updates.claimed_by !== undefined) session.metadata.claimed_by = updates.claimed_by;
    if (updates.notes !== undefined) session.metadata.notes = updates.notes;
    session.metadata.last_activity_at = new Date().toISOString();

    return { ...session.metadata };
  }

  close(sessionId: string, claimedBy?: string, force?: boolean): { metadata: SessionMetadata; final: SessionReadResult } {
    const session = this.getSessionOrThrow(sessionId);
    this.assertOwnership(session, claimedBy, force);

    // Capture final output
    const tailResult = session.buffer.tail(8192);
    const final: SessionReadResult = {
      session_id: sessionId,
      start_pos: tailResult.startPos,
      end_pos: tailResult.endPos,
      text: tailResult.text,
      truncated: tailResult.truncated,
    };

    // Close the handle
    if (session.handle) {
      try { session.handle.close(); } catch { /* best effort */ }
    }

    session.metadata.state = 'closed';
    session.metadata.closed_at = new Date().toISOString();
    session.metadata.claimed_by = undefined;

    this.logSessionEvent(sessionId, 'session_closed',
      `Session "${session.metadata.title}" closed by operator`);
    this.pruneClosedSessions();

    return { metadata: { ...session.metadata }, final };
  }

  list(activeOnly: boolean = false): SessionMetadata[] {
    const all = Array.from(this.sessions.values()).map(s => ({ ...s.metadata }));
    if (activeOnly) {
      return all.filter(m => m.state === 'pending' || m.state === 'connected');
    }
    return all;
  }

  getSession(sessionId: string): SessionMetadata | null {
    const session = this.sessions.get(sessionId);
    return session ? { ...session.metadata } : null;
  }

  async shutdown(): Promise<void> {
    for (const [id, session] of this.sessions) {
      if (session.metadata.state === 'connected' || session.metadata.state === 'pending') {
        try {
          this.close(id, undefined, true);
        } catch { /* best effort on shutdown */ }
      }
    }
  }

  // --- Internal helpers ---

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

  private handleConnect(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    if (session.metadata.state === 'pending') {
      session.metadata.state = 'connected';
      session.metadata.last_activity_at = new Date().toISOString();
      this.logSessionEvent(sessionId, 'session_connected',
        `Session "${session.metadata.title}" transport connected`);
    }
  }

  private logSessionEvent(sessionId: string, eventType: ActivityEventType, description: string): void {
    if (!this.engine) return;
    const session = this.sessions.get(sessionId);
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
  }

  private detectSshAuthFailure(session: Session): string | null {
    const output = session.buffer.tail(4096).text.toLowerCase();
    const patterns: Array<[RegExp, string]> = [
      [/permission denied/i, 'Permission denied'],
      [/authentication failed/i, 'Authentication failed'],
      [/host key verification failed/i, 'Host key verification failed'],
      [/connection refused/i, 'Connection refused'],
      [/connection reset by peer/i, 'Connection reset by peer'],
      [/no route to host/i, 'No route to host'],
      [/connection timed out/i, 'Connection timed out'],
    ];
    for (const [re, label] of patterns) {
      if (re.test(output)) return label;
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
    // (password, passphrase, host-key, MFA, or appliance/menu prompt)
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
    ];
    if (NON_SHELL_PROMPTS.some(re => re.test(lastLine))) {
      return false;
    }

    // Phase 2: Send an echo probe and wait for it
    if (!session.handle) return false;
    const marker = `__OW_READY_${session.metadata.id.slice(0, 8)}__`;
    const probeCmd = `echo ${marker}\n`;
    const preProbePos = session.buffer.endPos;

    try {
      session.handle.write(probeCmd);
    } catch {
      return false;
    }

    // Wait up to 3 seconds for the marker to appear
    const deadline = Date.now() + 3000;
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 200));
      const newOutput = session.buffer.read(preProbePos).text;
      if (newOutput.includes(marker)) {
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
