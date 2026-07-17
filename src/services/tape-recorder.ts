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

import {
  constants,
  closeSync,
  createWriteStream,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readSync,
  unlinkSync,
  writeSync,
  type WriteStream,
} from 'fs';
import { dirname } from 'path';
import { fsyncDirectory, mkdirDurable } from './durable-fs.js';

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
  private acceptedCount = 0;
  private droppedCount = 0;
  private queuedBytes = 0;
  private streamError?: Error;
  private readonly createdFile: boolean;
  private fileDescriptor: number | undefined;
  private closePromise?: Promise<void>;
  private readonly failureListeners = new Set<(error: Error) => void>();

  private static readonly MAX_QUEUED_BYTES = 8 * 1024 * 1024;

  constructor(public readonly path: string) {
    mkdirDurable(dirname(path));
    let createdFile = false;
    let fd: number;
    try {
      fd = openSync(path, 'ax', 0o600);
      createdFile = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      const existing = lstatSync(path);
      if (existing.isSymbolicLink() || !existing.isFile()) {
        throw new Error(`Tape path must be a regular file: ${path}`);
      }
      fd = openSync(
        path,
        constants.O_APPEND | constants.O_RDWR | (constants.O_NOFOLLOW ?? 0),
        0o600,
      );
    }
    fchmodSync(fd, 0o600);
    const opened = fstatSync(fd);
    const named = lstatSync(path);
    if (
      !opened.isFile()
      || named.isSymbolicLink()
      || !named.isFile()
      || opened.dev !== named.dev
      || opened.ino !== named.ino
    ) {
      closeSync(fd);
      throw new Error(`Tape path changed while it was being opened: ${path}`);
    }
    this.createdFile = createdFile;
    this.fileDescriptor = fd;
    if (createdFile) fsyncDirectory(dirname(path));
    else {
      // Preserve a torn final JSON fragment byte-for-byte, terminate its line,
      // and append a valid recovery marker before accepting new frames.
      const size = opened.size;
      if (size > 0) {
        const tail = Buffer.alloc(1);
        readSync(fd, tail, 0, 1, size - 1);
        if (tail[0] !== 0x0a) {
          writeSync(fd, '\n');
          writeSync(fd, `${JSON.stringify({
            ts: new Date().toISOString(),
            direction: 'server_to_client',
            raw: '',
            parse_error: 'recovered_after_torn_tail',
          } satisfies TapeRecord)}\n`);
          fsyncSync(fd);
        }
      }
    }
    // Supplying the synchronously opened descriptor prevents a failed startup
    // from unlinking the file only for createWriteStream's deferred open to
    // recreate it afterward.
    this.stream = createWriteStream(path, { fd, autoClose: true });
    // A WriteStream with no 'error' listener throws its 'error' event as an
    // UNCAUGHT exception, crashing the proxy process. Handle it: record the
    // failure and mark the writer closed so further writes become no-ops
    // (tape recording is best-effort — a bad FD must not take down the proxy).
    this.stream.on('error', (err: Error) => {
      this.noteFailure(err);
    });
  }

  private noteFailure(error: Error): void {
    if (this.streamError) return;
    this.streamError = error;
    for (const listener of this.failureListeners) {
      try { listener(error); } catch { /* failure observers may not crash the transport */ }
    }
  }

  /** Observe the first asynchronous stream failure immediately. */
  onFailure(listener: (error: Error) => void): () => void {
    this.failureListeners.add(listener);
    if (this.streamError) queueMicrotask(() => listener(this.streamError!));
    return () => { this.failureListeners.delete(listener); };
  }

  /** The stream error, if the tape writer has failed. */
  get error(): Error | undefined {
    return this.streamError;
  }

  write(record: TapeRecord): void {
    if (this.closed || this.streamError) { this.droppedCount++; return; }
    const line = `${JSON.stringify(record)}\n`;
    const bytes = Buffer.byteLength(line);
    if (this.queuedBytes + bytes > TapeWriter.MAX_QUEUED_BYTES) {
      this.droppedCount++;
      return;
    }
    this.acceptedCount++;
    this.queuedBytes += bytes;
    try {
      this.stream.write(line, (error?: Error | null) => {
        this.queuedBytes = Math.max(0, this.queuedBytes - bytes);
        if (error) {
          this.droppedCount++;
          this.noteFailure(error);
        } else {
          this.writeCount++;
        }
      });
    } catch (error) {
      this.queuedBytes = Math.max(0, this.queuedBytes - bytes);
      this.droppedCount++;
      const failure = error instanceof Error ? error : new Error(String(error));
      this.noteFailure(failure);
      throw failure;
    }
  }

  get count(): number {
    return this.writeCount;
  }

  get accepted(): number {
    return this.acceptedCount;
  }

  get dropped(): number {
    return this.droppedCount;
  }

  async close(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.closed = true;
    this.closePromise = new Promise<void>((resolve, reject) => {
      const finish = () => {
        try {
          if (this.fileDescriptor !== undefined) fsyncSync(this.fileDescriptor);
        } catch (error) {
          this.noteFailure(error instanceof Error ? error : new Error(String(error)));
        }
      };
      const closed = () => {
        this.fileDescriptor = undefined;
        try { fsyncDirectory(dirname(this.path)); } catch (error) {
          this.noteFailure(error instanceof Error ? error : new Error(String(error)));
        }
        if (this.streamError) reject(this.streamError); else resolve();
      };
      this.stream.once('finish', finish);
      this.stream.once('close', closed);
      if (this.stream.closed) closed();
      else this.stream.end();
    });
    return this.closePromise;
  }

  /**
   * Abort a startup that failed before the tape session was committed to the
   * activity log. Existing append targets are preserved; a file created solely
   * by this failed attempt is removed once the stream closes.
   */
  abortAndRemoveCreatedFile(): void {
    if (!this.closed) {
      this.closed = true;
      this.stream.destroy();
    }
    if (!this.createdFile) return;
    const remove = (): void => {
      try {
        unlinkSync(this.path);
        fsyncDirectory(dirname(this.path));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
          // Cleanup is best effort; the controller still drops the unusable
          // writer so no frames can land without an audit record.
        }
      }
    };
    remove();
    this.stream.once('close', remove);
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
