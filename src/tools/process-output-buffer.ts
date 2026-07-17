export const STREAM_INLINE_CAP = 256 * 1024;
export const STREAM_HARD_CAP = 16 * 1024 * 1024;
export const STREAM_HEAD_KEEP = 4 * 1024 * 1024;
export const STREAM_TAIL_KEEP = 4 * 1024 * 1024;
export const EVIDENCE_PARSE_MAX_BYTES = 50 * 1024 * 1024;
export const TRUNCATION_MARKER = '\n…[output truncated; full output stored in evidence]…\n';
const HARD_CAP_DROPPED_MARKER = '\n…[output exceeded in-memory cap; middle bytes dropped]…\n';
export const REDACTED_SECRET = '<redacted:reflected-secret>';

/** Scrub caller-supplied secrets from materialized process output, including a
 * value split across one of the bounded-buffer truncation markers. */
export function scrubSecretsFromText(text: string, secrets: string[] | undefined): string {
  if (!secrets || secrets.length === 0 || !text) return text;
  let out = text;
  for (const secret of secrets) {
    if (!secret) continue;
    if (out.includes(secret)) out = out.split(secret).join(REDACTED_SECRET);
    for (const marker of [TRUNCATION_MARKER, HARD_CAP_DROPPED_MARKER]) {
      let from = 0;
      for (;;) {
        const idx = out.indexOf(marker, from);
        if (idx === -1) break;
        const before = out.slice(0, idx);
        const after = out.slice(idx + marker.length);
        const tail = before.slice(Math.max(0, before.length - (secret.length - 1)));
        const head = after.slice(0, secret.length - 1);
        const pos = (tail + head).indexOf(secret);
        if (pos !== -1 && pos < tail.length && pos + secret.length > tail.length) {
          const headFragment = tail.length - pos;
          const tailFragment = secret.length - headFragment;
          const prefix = before.slice(0, before.length - headFragment);
          out = prefix + REDACTED_SECRET + marker + after.slice(tailFragment);
          from = prefix.length + REDACTED_SECRET.length + marker.length;
        } else {
          from = idx + marker.length;
        }
      }
    }
  }
  return out;
}

/** Bounded per-stream byte sink retaining a fixed head and rolling tail after
 * the hard cap is crossed. total_bytes always reflects produced bytes. */
export class BoundedStreamBuffer {
  private head: Buffer[] = [];
  private headBytes = 0;
  private tailChunks: Buffer[] = [];
  private tailBytes = 0;
  private totalBytes = 0;
  private droppedBytes = 0;
  private capExceeded = false;

  push(input: Buffer): void {
    let chunk = input;
    this.totalBytes += chunk.length;
    if (!this.capExceeded && this.headBytes + chunk.length <= STREAM_HARD_CAP) {
      this.head.push(chunk);
      this.headBytes += chunk.length;
      return;
    }
    if (!this.capExceeded) {
      this.capExceeded = true;
      const headRoom = Math.max(0, STREAM_HEAD_KEEP - this.headBytes);
      if (headRoom > 0) {
        const toHead = chunk.subarray(0, headRoom);
        this.head.push(toHead);
        this.headBytes += toHead.length;
        chunk = chunk.subarray(headRoom);
      } else if (this.headBytes > STREAM_HEAD_KEEP) {
        const flat = Buffer.concat(this.head, this.headBytes);
        this.head = [flat.subarray(0, STREAM_HEAD_KEEP)];
        this.headBytes = STREAM_HEAD_KEEP;
        const overflow = flat.subarray(STREAM_HEAD_KEEP);
        if (overflow.length > 0) {
          this.tailChunks.push(overflow);
          this.tailBytes += overflow.length;
        }
      }
    }
    if (chunk.length === 0) return;
    this.tailChunks.push(chunk);
    this.tailBytes += chunk.length;
    while (this.tailBytes > STREAM_TAIL_KEEP && this.tailChunks.length > 0) {
      const first = this.tailChunks[0];
      const overflow = this.tailBytes - STREAM_TAIL_KEEP;
      if (first.length <= overflow) {
        this.tailChunks.shift();
        this.tailBytes -= first.length;
        this.droppedBytes += first.length;
      } else {
        this.tailChunks[0] = first.subarray(overflow);
        this.tailBytes -= overflow;
        this.droppedBytes += overflow;
      }
    }
  }

  get total_bytes(): number { return this.totalBytes; }
  get dropped_bytes(): number { return this.droppedBytes; }
  get cap_exceeded(): boolean { return this.capExceeded; }

  toFullString(): string {
    if (!this.capExceeded) return Buffer.concat(this.head, this.headBytes).toString('utf8');
    const head = Buffer.concat(this.head, this.headBytes).toString('utf8');
    const tail = Buffer.concat(this.tailChunks, this.tailBytes).toString('utf8');
    return head + HARD_CAP_DROPPED_MARKER + tail;
  }
}

export function captureStream(buffer: BoundedStreamBuffer, chunk: Buffer): void {
  buffer.push(chunk);
}

export function joinAndCap(
  buffer: BoundedStreamBuffer,
  cap: number,
): { text: string; truncated: boolean; total: number } {
  const full = buffer.toFullString();
  const total = buffer.total_bytes;
  if (full.length <= cap) return { text: full, truncated: total > full.length, total };
  const head = full.slice(0, Math.floor(cap * 0.75));
  const tail = full.slice(full.length - Math.floor(cap * 0.25));
  return { text: head + TRUNCATION_MARKER + tail, truncated: true, total };
}
