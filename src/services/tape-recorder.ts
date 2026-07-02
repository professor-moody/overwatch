// ============================================================
// Overwatch — Tape Recorder
// Buffered newline-delimited JSON-RPC frame splitter + writer.
// Used by the overwatch-mcp-tape proxy to capture every frame the
// model and the upstream server exchange.
//
// Design:
// - Pure functions where possible — `splitFrames(buffer, chunk)` returns
//   `{ frames, remainder }` so the proxy can carry the partial-frame
//   tail across chunk boundaries.
// - The writer is a thin class that owns an append-stream and serializes
//   `{ ts, direction, parsed | raw, parse_error? }` records as JSONL.
// - Bad frames are still written (with `parse_error`) and still passed
//   through to the peer. Tape capture must NEVER block or alter the
//   wire stream.
// ============================================================

import { createWriteStream, mkdirSync, type WriteStream } from 'fs';
import { dirname } from 'path';

export type TapeDirection = 'client_to_server' | 'server_to_client';

export interface TapeRecord {
  ts: string;
  direction: TapeDirection;
  /**
   * MCP session id of the connection this frame belongs to. In daemon mode the
   * primary + every headless sub-agent are separate sessions multiplexed into
   * one tape; this is the discriminator that lets the tape be demuxed per actor.
   * Undefined for stdio (single session).
   */
  session_id?: string;
  /**
   * Agent id, when the session can be correlated to an agent. Not always known
   * at the transport layer (the transport sees frames, not agent context), so
   * demux primarily by session_id; agent_id is best-effort enrichment.
   */
  agent_id?: string;
  /** Parsed JSON-RPC frame when the line was valid JSON. */
  parsed?: unknown;
  /** Raw line when parsing failed (kept verbatim, no newline). */
  raw?: string;
  /** Error message from JSON.parse when present. */
  parse_error?: string;
}

export interface SplitResult {
  frames: string[];
  remainder: string;
}

/**
 * Split a buffer + new chunk on newlines. Returns complete frames and the
 * partial remainder to carry forward. Handles `\n` and `\r\n`.
 */
export function splitFrames(buffer: string, chunk: string): SplitResult {
  const combined = buffer + chunk;
  const parts = combined.split('\n');
  const remainder = parts.pop() ?? '';
  const frames = parts.map((line) => (line.endsWith('\r') ? line.slice(0, -1) : line));
  return { frames, remainder };
}

/**
 * Build a tape record from a single frame line. Always succeeds; on parse
 * failure, populates `raw` + `parse_error` so the operator can post-mortem.
 */
export function buildRecord(direction: TapeDirection, frame: string, now: () => Date = () => new Date()): TapeRecord {
  const ts = now().toISOString();
  if (frame.length === 0) {
    return { ts, direction, raw: '', parse_error: 'empty_frame' };
  }
  try {
    const parsed = JSON.parse(frame);
    return { ts, direction, parsed };
  } catch (err) {
    return {
      ts,
      direction,
      raw: frame,
      parse_error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Append-only JSONL writer. Owns one file handle for the lifetime of a
 * tape session.
 */
export class TapeWriter {
  private stream: WriteStream;
  private closed = false;
  private writeCount = 0;
  private streamError?: Error;

  constructor(public readonly path: string) {
    mkdirSync(dirname(path), { recursive: true });
    this.stream = createWriteStream(path, { flags: 'a' });
    // A WriteStream with no 'error' listener throws its 'error' event as an
    // UNCAUGHT exception, crashing the proxy process. Handle it: record the
    // failure and mark the writer closed so further writes become no-ops
    // (tape recording is best-effort — a bad FD must not take down the proxy).
    this.stream.on('error', (err: Error) => {
      this.streamError = err;
      this.closed = true;
    });
  }

  /** The stream error, if the tape writer has failed. */
  get error(): Error | undefined {
    return this.streamError;
  }

  write(record: TapeRecord): void {
    if (this.closed) return;
    this.stream.write(JSON.stringify(record) + '\n');
    this.writeCount++;
  }

  get count(): number {
    return this.writeCount;
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await new Promise<void>((resolve) => this.stream.end(resolve));
  }
}

/**
 * Helper that wires `splitFrames` + `buildRecord` + `TapeWriter` together.
 * Returns the new buffer remainder so the caller can store it.
 */
export function processChunk(
  writer: TapeWriter,
  direction: TapeDirection,
  buffer: string,
  chunk: string,
  now?: () => Date,
): string {
  const { frames, remainder } = splitFrames(buffer, chunk);
  for (const frame of frames) {
    if (frame.length === 0) continue; // skip blank keepalive lines
    writer.write(buildRecord(direction, frame, now));
  }
  return remainder;
}
