// In-memory, bounded, cursor-based live buffer for a running action's
// stdout/stderr. The durable, full-fidelity bytes always go to the evidence
// store (see _process-runner); this buffer exists only to stream a running
// action's output to the dashboard Analysis workspace in real time, mirroring
// the session terminal bridge. Once an action finishes, the entry is retained
// briefly (so a connected client can drain the tail) then evicted — the
// evidence store is the source of truth for completed actions.

const DEFAULT_CAP = 256 * 1024; // chars retained per stream (mirrors the inline cap)
const DEFAULT_EVICT_MS = 30_000;
// Hard ceiling on tracked actions. markDone schedules eviction on the happy
// path, but if a caller throws between open() and markDone() the entry would
// otherwise live forever — this cap bounds memory regardless of caller behavior.
const DEFAULT_MAX_ENTRIES = 256;

interface StreamState {
  /** Retained tail of the stream. */
  text: string;
  /** Chars dropped off the front once the retained window exceeded the cap. */
  dropped: number;
}

interface Entry {
  stdout: StreamState;
  stderr: StreamState;
  done: boolean;
  evictTimer?: ReturnType<typeof setTimeout>;
}

export interface ActionOutputRead {
  text: string;
  /** Absolute end cursor (dropped + retained length) — pass back on the next read. */
  end_pos: number;
  /** The caller's cursor pointed into bytes that have since been evicted from the window. */
  dropped: boolean;
}

export type OutputStream = 'stdout' | 'stderr';

export class ActionOutputBuffer {
  private entries = new Map<string, Entry>();

  constructor(
    private readonly cap: number = DEFAULT_CAP,
    private readonly evictMs: number = DEFAULT_EVICT_MS,
    private readonly maxEntries: number = DEFAULT_MAX_ENTRIES,
  ) {}

  /** Begin buffering a live action. Idempotent for a live entry; a reused id
   *  whose prior run already finished is reset to a fresh entry. */
  open(actionId: string): void {
    const existing = this.entries.get(actionId);
    if (existing) {
      if (!existing.done) return; // already live
      this.evict(actionId);       // id reused within the eviction window — restart
    }
    this.evictOverCap();
    this.entries.set(actionId, {
      stdout: { text: '', dropped: 0 },
      stderr: { text: '', dropped: 0 },
      done: false,
    });
  }

  /** Keep the tracked-action count under the cap, preferring to drop finished
   *  entries (their durable bytes are in the evidence store) before live ones. */
  private evictOverCap(): void {
    while (this.entries.size >= this.maxEntries) {
      let victim: string | undefined;
      for (const [id, e] of this.entries) { if (e.done) { victim = id; break; } }
      if (victim === undefined) victim = this.entries.keys().next().value;
      if (victim === undefined) break;
      this.evict(victim);
    }
  }

  /** Append a chunk. No-op if the action isn't open or is already done. */
  append(actionId: string, stream: OutputStream, chunk: Buffer | string): void {
    const entry = this.entries.get(actionId);
    if (!entry || entry.done) return;
    const s = entry[stream];
    // Each chunk is decoded independently; a multibyte char split across chunks
    // may show a replacement char in the live view. The evidence blob is exact.
    s.text += typeof chunk === 'string' ? chunk : chunk.toString('utf-8');
    if (s.text.length > this.cap) {
      const over = s.text.length - this.cap;
      s.dropped += over;
      s.text = s.text.slice(over);
    }
  }

  /** Read everything after `cursor` for one stream, or null if the action is unknown. */
  read(actionId: string, stream: OutputStream, cursor = 0): ActionOutputRead | null {
    const entry = this.entries.get(actionId);
    if (!entry) return null;
    const s = entry[stream];
    const total = s.dropped + s.text.length;
    const safeCursor = Math.max(0, Math.min(cursor, total));
    const start = Math.max(safeCursor, s.dropped);
    return {
      text: s.text.slice(start - s.dropped),
      end_pos: total,
      dropped: safeCursor < s.dropped,
    };
  }

  has(actionId: string): boolean {
    return this.entries.has(actionId);
  }

  /** True if the action is finished or unknown (evicted) — both mean "no more live output". */
  isDone(actionId: string): boolean {
    return this.entries.get(actionId)?.done ?? true;
  }

  /** Mark the action finished and schedule eviction so connected clients can drain the tail. */
  markDone(actionId: string): void {
    const entry = this.entries.get(actionId);
    if (!entry || entry.done) return;
    entry.done = true;
    entry.evictTimer = setTimeout(() => this.entries.delete(actionId), this.evictMs);
    entry.evictTimer.unref?.();
  }

  /** Drop an entry immediately (tests / shutdown). */
  evict(actionId: string): void {
    const entry = this.entries.get(actionId);
    if (entry?.evictTimer) clearTimeout(entry.evictTimer);
    this.entries.delete(actionId);
  }

  get size(): number {
    return this.entries.size;
  }
}
