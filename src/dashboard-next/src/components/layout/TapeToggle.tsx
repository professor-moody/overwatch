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
  const frames = status?.frame_count ?? 0;
  const title = enabled
    ? `Recording → ${status?.path || '(memory)'} — click to stop`
    : 'JSON-RPC tape: off — click to start recording';

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={busy}
      title={title}
      className={cn(
        'flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full border transition-colors',
        enabled
          ? 'bg-destructive/10 text-destructive border-destructive/30 hover:bg-destructive/20'
          : 'bg-surface text-muted-foreground border-border hover:text-foreground hover:border-foreground/40',
        busy && 'opacity-50 cursor-wait',
      )}
    >
      <span
        className={cn(
          'w-1.5 h-1.5 rounded-full',
          enabled ? 'bg-destructive animate-pulse' : 'bg-muted-foreground/50',
        )}
      />
      <span className="tabular-nums">
        {enabled ? `Tape ● ${frames}` : 'Tape'}
      </span>
    </button>
  );
}
