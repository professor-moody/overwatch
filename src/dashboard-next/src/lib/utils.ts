import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Describe an evidence-fetch failure so it can never be mistaken for "there is no
 * evidence". Collapsing a transport/contract error into the empty state is exactly how
 * a server-side 500 on every non-empty evidence chain went undiagnosed in a live
 * engagement. Duck-typed on DashboardApiError's shape to avoid importing generated code.
 */
export function describeEvidenceError(err: unknown): string {
  const e = err as { status?: number; code?: string; message?: string } | undefined;
  if (e && typeof e.status === 'number') {
    if (e.code === 'DASHBOARD_RESPONSE_CONTRACT_FAILED') {
      return `Evidence could not be loaded - the server response failed its API contract (HTTP ${e.status}). `
        + 'This is a server error, not an absence of evidence.';
    }
    return `Evidence could not be loaded - request failed (HTTP ${e.status}${e.code ? ` · ${e.code}` : ''}).`;
  }
  return `Evidence could not be loaded - ${e?.message || 'the request failed'}.`;
}

export function formatElapsed(ms: number | undefined | null): string {
  if (ms === undefined || ms === null || !Number.isFinite(ms) || ms < 0) return 'Time unavailable';
  if (ms === 0) return '0s';
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

/**
 * Elapsed runtime for an agent, derived on the client from `assigned_at` rather than
 * a server-pushed `elapsed_ms`. Deriving here keeps the value live-ticking on re-render
 * and, crucially, stops the server from marking every running agent "changed" on every
 * projection tick (a time field that always differs defeats the bounded/keyed patch).
 * Running → now - assigned; terminal → completed_at - assigned; otherwise undefined.
 */
export function agentElapsedMs(
  agent: { status?: string; assigned_at?: string; completed_at?: string; elapsed_ms?: number },
  now: number = Date.now(),
): number | undefined {
  if (Number.isFinite(agent.elapsed_ms) && agent.elapsed_ms! >= 0) return agent.elapsed_ms;
  const assigned = agent.assigned_at ? new Date(agent.assigned_at).getTime() : NaN;
  if (agent.completed_at && Number.isFinite(assigned)) {
    const completed = new Date(agent.completed_at).getTime();
    return Number.isFinite(completed) && completed >= assigned ? completed - assigned : undefined;
  }
  if (agent.status === 'running' && Number.isFinite(assigned) && now >= assigned) {
    return now - assigned;
  }
  return undefined;
}

export function formatTimestamp(iso: string | undefined): string {
  if (!iso) return '-';
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return iso;
  }
}

export function formatRelativeTime(iso: string | undefined): string {
  if (!iso) return '-';
  try {
    const d = new Date(iso);
    const now = Date.now();
    const diff = now - d.getTime();
    if (!Number.isFinite(diff)) return 'Time unavailable';
    if (diff < -60_000) return 'Time unavailable';
    if (diff < 60_000) return 'just now';
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
    return `${Math.floor(diff / 86_400_000)}d ago`;
  } catch {
    return 'Time unavailable';
  }
}

export function escapeHtml(str: string | undefined | null): string {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 1) + '…';
}
