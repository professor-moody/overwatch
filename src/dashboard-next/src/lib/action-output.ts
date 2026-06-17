// View-model normalization for the Analysis workspace's assessment view.
// Pure (no I/O) so it is unit-testable; the panel renders these shapes.

import type { ActionOutputResponse, ActionOutputStream } from './api';

export interface OutputStreamView {
  evidenceId: string | null;
  text: string;
  totalBytes: number;
  /** Capture buffer overflowed while the tool ran — the on-disk blob is fuller. */
  capturedTruncated: boolean;
  /** This payload is only a head slice — more bytes are available via paging. */
  headTruncated: boolean;
  droppedBytes: number;
  /** Evidence id was recorded but the blob is missing/unreadable. */
  missing: boolean;
  /** The tool produced output but capture failed — bytes are lost. */
  captureFailed: boolean;
  isEmpty: boolean;
}

export interface ActionOutputView {
  actionId: string;
  status: ActionOutputResponse['status'];
  isRunning: boolean;
  tool: string | null;
  command: string | null;
  exitCode: number | null;
  durationMs: number | null;
  timedOut: boolean;
  /** Graph node ids (linkable to graph/evidence). */
  targetNodeIds: string[];
  /** Raw IPs / CIDRs (not graph nodes — render as plain pills). */
  targetIps: string[];
  /** Convenience: nodeIds + ips merged. */
  targets: string[];
  agentId: string | null;
  findingIds: string[];
  stdout: OutputStreamView;
  stderr: OutputStreamView;
  hasCaptureError: boolean;
  /** No captured output on either stream. */
  isEmpty: boolean;
}

const EMPTY_STREAM: OutputStreamView = {
  evidenceId: null,
  text: '',
  totalBytes: 0,
  capturedTruncated: false,
  headTruncated: false,
  droppedBytes: 0,
  missing: false,
  captureFailed: false,
  isEmpty: true,
};

function normalizeStream(s: ActionOutputStream | null | undefined): OutputStreamView {
  if (!s) return { ...EMPTY_STREAM };
  const text = typeof s.text === 'string' ? s.text : '';
  return {
    evidenceId: s.evidence_id ?? null,
    text,
    totalBytes: Number.isFinite(s.total_bytes) ? s.total_bytes : 0,
    capturedTruncated: Boolean(s.truncated),
    headTruncated: Boolean(s.head_truncated),
    droppedBytes: Number.isFinite(s.dropped_bytes) ? s.dropped_bytes : 0,
    missing: Boolean(s.missing),
    captureFailed: Boolean(s.capture_failed),
    isEmpty: text.length === 0,
  };
}

export function normalizeActionOutput(raw: ActionOutputResponse): ActionOutputView {
  const targetNodeIds = raw.target_node_ids ?? [];
  const targetIps = [...(raw.target_ips ?? []), ...(raw.target_cidrs ?? [])];
  const targets = [...targetNodeIds, ...targetIps];
  const stdout = normalizeStream(raw.stdout);
  const stderr = normalizeStream(raw.stderr);
  return {
    actionId: raw.action_id,
    status: raw.status ?? 'neutral',
    isRunning: raw.status === 'running',
    tool: raw.tool_name ?? raw.invoking_tool ?? null,
    command: raw.command_repr ?? null,
    exitCode: typeof raw.exit_code === 'number' ? raw.exit_code : null,
    durationMs: typeof raw.duration_ms === 'number' ? raw.duration_ms : null,
    timedOut: Boolean(raw.timed_out),
    targetNodeIds,
    targetIps,
    targets,
    agentId: raw.agent_id ?? null,
    findingIds: raw.linked_finding_ids ?? [],
    stdout,
    stderr,
    hasCaptureError: Boolean(raw.capture_error),
    isEmpty: stdout.isEmpty && stderr.isEmpty,
  };
}

/** Human-readable byte size for the metadata strip. */
export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i === 0 ? v : v.toFixed(1)} ${units[i]}`;
}

/** Whether the viewer should offer to fetch more of a stream (only a head was returned). */
export function streamHasMore(s: OutputStreamView): boolean {
  return s.headTruncated;
}

/**
 * Find-in-output: split text into lines and, when a query is present, keep only
 * matching lines (case-insensitive). Returns the lines to render and the match
 * count so the viewer can show "N matches" and an empty state.
 */
export function matchOutputLines(text: string, query: string): { lines: string[]; matchCount: number; filtered: boolean } {
  // Drop a single trailing newline so a normal "...\n"-terminated blob doesn't
  // render a spurious blank final line.
  const normalized = text.endsWith('\n') ? text.slice(0, -1) : text;
  const allLines = normalized.length === 0 ? [] : normalized.split('\n');
  const q = query.trim().toLowerCase();
  if (!q) return { lines: allLines, matchCount: allLines.length, filtered: false };
  const matched = allLines.filter(l => l.toLowerCase().includes(q));
  return { lines: matched, matchCount: matched.length, filtered: true };
}
