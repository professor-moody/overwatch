// ============================================================
// TapeToggle — JSON-RPC tape recorder control (toolbar widget)
// Mirrors the in-process tape controller. Polls /api/tape every
// 5s and POSTs to /api/tape/toggle on click. Hides itself when
// the controller is not attached (e.g. dev/test builds).
// ============================================================

import { useCallback, useEffect, useState } from 'react';
import { getTapeStatus, toggleTape, type TapeStatus } from '../../lib/api';
import { cn } from '../../lib/utils';

export function TapeToggle() {
  const [status, setStatus] = useState<TapeStatus | null>(null);
  const [available, setAvailable] = useState(true);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const s = await getTapeStatus();
      setStatus(s);
      setAvailable(true);
    } catch {
      setAvailable(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, [refresh]);

  const onClick = useCallback(async () => {
    setBusy(true);
    try {
      const s = await toggleTape();
      setStatus(s);
    } catch {
      // ignore — next poll will reconcile
    } finally {
      setBusy(false);
    }
  }, []);

  if (!available) return null;

  const enabled = !!status?.enabled;
  const failed = !!status?.error;
  const frames = status?.frame_count ?? 0;
  const dropped = status?.dropped_frame_count ?? 0;
  const source = status?.started_by;
  const sourceLabel = source ? ` via ${source}` : '';
  const dropSummary = dropped > 0 ? `, ${dropped} dropped` : '';
  const title = failed
    ? `Tape recording failed: ${status?.error}${status?.path ? ` (${status.path})` : ''}`
    : enabled
    ? `Recording${sourceLabel} → ${status?.path || '(memory)'} — ${frames} written${dropSummary} — click to stop`
    : `JSON-RPC tape: off${frames > 0 || dropped > 0 ? ` — last session ${frames} written${dropSummary}` : ''} — click to start recording`;

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={busy}
      title={title}
      className={cn(
        'flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full border transition-colors',
        failed
          ? 'bg-warning/10 text-warning border-warning/30 hover:bg-warning/20'
          : enabled
          ? 'bg-destructive/10 text-destructive border-destructive/30 hover:bg-destructive/20'
          : 'bg-surface text-muted-foreground border-border hover:text-foreground hover:border-foreground/40',
        busy && 'opacity-50 cursor-wait',
      )}
    >
      <span
        className={cn(
          'w-1.5 h-1.5 rounded-full',
          failed ? 'bg-warning' : enabled ? 'bg-destructive animate-pulse' : 'bg-muted-foreground/50',
        )}
      />
      <span className="tabular-nums">
        {failed
          ? `Tape error${dropped > 0 ? ` · ${dropped} dropped` : ''}`
          : enabled
            ? `Tape${source ? ` ${source}` : ''} ● ${frames}${dropped > 0 ? ` · ${dropped} dropped` : ''}`
            : dropped > 0 ? `Tape · ${dropped} dropped` : 'Tape'}
      </span>
    </button>
  );
}
