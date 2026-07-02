// ============================================================
// Overwatch — In-Process Tape Recorder
//
// Captures every JSON-RPC frame the MCP server exchanges with its client
// to a JSONL tape file, *from inside* the server process. Complements the
// standalone `overwatch-mcp-tape` proxy (which lives outside the server
// for blast-radius isolation).
//
// Why both?
// - Proxy: bug-resistant, can be used against any MCP server build, but
//   requires the operator to launch the server under it.
// - In-process: zero-config, integrates with the engagement (auto-registers
//   tape sessions, exposes a dashboard toggle, honors engagement.tape.*),
//   but a bug here can affect the live server.
//
// Off by default. Enable via:
//   - env: OVERWATCH_TAPE=1 [+ OVERWATCH_TAPE_DIR | OVERWATCH_TAPE_FILE]
//   - engagement.tape.enabled = true (with optional dir/file)
//   - dashboard toggle (POST /api/tape/toggle)
//
// Lifecycle:
//   - enable() opens a TapeWriter, emits `tape_session_started` event.
//   - disable() closes the writer, emits `tape_session_stopped` with stats.
//   - wrapTransport(t) returns a Transport that mirrors send/receive into
//     the writer when enabled, transparently passes through when disabled.
//     The wrapper is installed *unconditionally* so toggling at runtime
//     does not require restarting the transport.
// ============================================================

import { randomUUID } from 'crypto';
import { resolve as resolvePath } from 'path';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import type { Transport, TransportSendOptions } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { GraphEngine } from './graph-engine.js';
import { TapeWriter } from './tape-recorder.js';

export type TapeStartSource = 'env' | 'config' | 'dashboard';

export interface InProcessTapeOptions {
  /** Default directory for auto-named tape files. */
  defaultDir?: string;
  /** Explicit tape file path; overrides defaultDir when present. */
  file?: string;
  /** Optional human-readable session id baked into auto-generated names. */
  sessionId?: string;
  /** What caused this tape recording session to start. */
  startedBy?: TapeStartSource;
}

export interface TapeStatus {
  enabled: boolean;
  /** Active tape file path, when enabled. */
  path?: string;
  /** Active session id (random UUID generated at enable() time). */
  session_id?: string;
  /** Frames written since enable(). */
  frame_count: number;
  /** ISO timestamp of last enable(). */
  started_at?: string;
  /** What caused this tape recording session to start. */
  started_by?: TapeStartSource;
  /** Set when the tape writer's stream failed (e.g. ENOSPC) — recording is
   *  silently stopped, so surface it here rather than leaving it invisible. */
  error?: string;
}

function autoTapePath(dir: string, sessionId?: string): string {
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const sid = sessionId ? `${sessionId}-` : '';
  return resolvePath(`${dir}/tape-${sid}${ts}.jsonl`);
}

/**
 * Holds the active TapeWriter (when enabled) and exposes
 * record-incoming/record-outgoing primitives for transport wrappers.
 * One instance per OverwatchApp; shared across stdio + http transports.
 */
export class InProcessTapeController {
  private writer: TapeWriter | null = null;
  private currentPath: string | undefined;
  private currentSessionId: string | undefined;
  private currentStartedBy: TapeStartSource | undefined;
  private startedAt: string | undefined;
  private startEventId: string | undefined;
  private defaults: InProcessTapeOptions;

  constructor(private engine: GraphEngine, defaults: InProcessTapeOptions = {}) {
    this.defaults = defaults;
  }

  isEnabled(): boolean {
    return this.writer !== null;
  }

  getStatus(): TapeStatus {
    return {
      enabled: this.isEnabled(),
      path: this.currentPath,
      session_id: this.currentSessionId,
      frame_count: this.writer?.count ?? 0,
      started_at: this.startedAt,
      started_by: this.currentStartedBy,
      // Surface a writer stream failure so silent tape loss is observable.
      ...(this.writer?.error ? { error: this.writer.error.message } : {}),
    };
  }

  /**
   * Open a fresh tape and start recording. No-op if already enabled (callers
   * must `disable()` first to rotate). Returns the resolved tape path.
   */
  enable(opts: InProcessTapeOptions = {}): TapeStatus {
    if (this.writer) return this.getStatus();
    const sessionId = opts.sessionId ?? this.defaults.sessionId ?? randomUUID();
    const explicit = opts.file ?? this.defaults.file;
    const dir = opts.defaultDir ?? this.defaults.defaultDir ?? './tapes';
    const path = explicit ? resolvePath(explicit) : autoTapePath(dir, sessionId);
    this.writer = new TapeWriter(path);
    this.currentPath = path;
    this.currentSessionId = sessionId;
    this.currentStartedBy = opts.startedBy ?? this.defaults.startedBy;
    this.startedAt = new Date().toISOString();
    // Auto-register with the engagement so retrospectives can locate the
    // tape without needing the operator to call register_tape_session.
    const event = this.engine.logActionEvent({
      description: `In-process tape session started: ${sessionId}`,
      event_type: 'tape_session_started',
      category: 'system',
      provenance: 'system',
      details: {
        session_id: sessionId,
        tape_path: path,
        capture_mode: 'in_process',
        started_at: this.startedAt,
        started_by: this.currentStartedBy,
      },
    });
    this.startEventId = event.event_id;
    return this.getStatus();
  }

  /**
   * Close the active tape. Logs a `tape_session_stopped` event with the
   * frame count + path so the activity log shows both endpoints. No-op if
   * not currently enabled.
   */
  async disable(): Promise<TapeStatus> {
    if (!this.writer) return this.getStatus();
    const path = this.currentPath;
    const sessionId = this.currentSessionId;
    const startedBy = this.currentStartedBy;
    const frames = this.writer.count;
    await this.writer.close();
    this.writer = null;
    this.engine.logActionEvent({
      description: `In-process tape session stopped: ${sessionId} (${frames} frames)`,
      event_type: 'tape_session_stopped',
      category: 'system',
      provenance: 'system',
      details: {
        session_id: sessionId,
        tape_path: path,
        capture_mode: 'in_process',
        frame_count: frames,
        started_event_id: this.startEventId,
        started_by: startedBy,
        stopped_at: new Date().toISOString(),
      },
    });
    this.currentPath = undefined;
    this.currentSessionId = undefined;
    this.currentStartedBy = undefined;
    this.startedAt = undefined;
    this.startEventId = undefined;
    return this.getStatus();
  }

  /**
   * Internal: record one frame. Catches and discards errors so a writer
   * fault never propagates into the live wire path. We log to stderr
   * once, then swallow.
   */
  private record(direction: 'client_to_server' | 'server_to_client', message: JSONRPCMessage, session_id?: string): void {
    if (!this.writer) return;
    try {
      this.writer.write({
        ts: new Date().toISOString(),
        direction,
        ...(session_id ? { session_id } : {}),
        parsed: message as unknown,
      });
    } catch (err) {
      // Best-effort: detach writer to avoid storms; surface once on stderr.
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`[overwatch-tape] write failed, detaching: ${msg}\n`);
      this.writer = null;
      this.currentPath = undefined;
      this.currentSessionId = undefined;
      this.currentStartedBy = undefined;
    }
  }

  /**
   * Wrap an MCP Transport so that, when the controller is enabled, every
   * frame in either direction is mirrored to the active tape. The wrapper
   * is transparent when the controller is disabled — toggling at runtime
   * works without re-wrapping.
   */
  wrapTransport(inner: Transport): Transport {
    return new TapingTransport(inner, this);
  }

  /** Test-only hook: get the current writer's count without exposing it. */
  _frameCountForTest(): number {
    return this.writer?.count ?? 0;
  }
}

/**
 * Transport wrapper that delegates to an inner Transport while tee-ing
 * every frame into the InProcessTapeController. Implements the same
 * Transport interface so the MCP Server can connect to it unchanged.
 */
class TapingTransport implements Transport {
  // The MCP Server assigns these *after* it gets the wrapper. We forward
  // them into the inner transport so its own callbacks fire normally,
  // and we use them to insert our recording hook on the receive path.
  private _onmessage?: Transport['onmessage'];
  private _onclose?: Transport['onclose'];
  private _onerror?: Transport['onerror'];

  constructor(
    private inner: Transport,
    private controller: InProcessTapeController,
  ) {
    // Install our own listeners on the inner transport so we can intercept
    // before forwarding to whatever the MCP Server later assigns.
    this.inner.onmessage = (msg, extra) => {
      // Record incoming (client → server) before dispatching, so a handler
      // exception doesn't prevent the tape entry. Tag with the session id so a
      // multiplexed daemon tape can be demuxed per actor.
      this.controller['record']('client_to_server', msg, this.inner.sessionId);
      try { this._onmessage?.(msg, extra); } catch (err) { this._onerror?.(err as Error); }
    };
    this.inner.onclose = () => { this._onclose?.(); };
    this.inner.onerror = (err) => { this._onerror?.(err); };
  }

  async start(): Promise<void> { await this.inner.start(); }
  async close(): Promise<void> { await this.inner.close(); }

  async send(message: JSONRPCMessage, options?: TransportSendOptions): Promise<void> {
    // Record outgoing first; if the inner send throws we still have the
    // attempted frame in the tape, which matches what the proxy does.
    this.controller['record']('server_to_client', message, this.inner.sessionId);
    await this.inner.send(message, options);
  }

  set onmessage(cb: Transport['onmessage']) { this._onmessage = cb; }
  get onmessage(): Transport['onmessage'] { return this._onmessage; }
  set onclose(cb: Transport['onclose']) { this._onclose = cb; }
  get onclose(): Transport['onclose'] { return this._onclose; }
  set onerror(cb: Transport['onerror']) { this._onerror = cb; }
  get onerror(): Transport['onerror'] { return this._onerror; }

  get sessionId(): string | undefined { return this.inner.sessionId; }
  setProtocolVersion(version: string): void {
    this.inner.setProtocolVersion?.(version);
  }
}
