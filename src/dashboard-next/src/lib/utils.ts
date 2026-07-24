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
      return `Evidence could not be loaded — the server response failed its API contract (HTTP ${e.status}). `
        + 'This is a server error, not an absence of evidence.';
    }
    return `Evidence could not be loaded — request failed (HTTP ${e.status}${e.code ? ` · ${e.code}` : ''}).`;
  }
  return `Evidence could not be loaded — ${e?.message || 'the request failed'}.`;
}

export function formatElapsed(ms: number | undefined | null): string {
  if (!ms || ms < 0) return '—';
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

export function formatTimestamp(iso: string | undefined): string {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return iso;
  }
}

export function formatRelativeTime(iso: string | undefined): string {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    const now = Date.now();
    const diff = now - d.getTime();
    if (diff < 60_000) return 'just now';
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
    return `${Math.floor(diff / 86_400_000)}d ago`;
  } catch {
    return iso;
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
