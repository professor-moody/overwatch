import { useState, useEffect } from 'react';
import { cn } from '../../lib/utils';

function formatCountdown(ms: number): string {
  if (ms <= 0) return 'auto-approving\u2026';
  const s = Math.ceil(ms / 1000);
  const m = Math.floor(s / 60);
  const sec = s % 60;
  return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
}

export function CountdownTimer({
  targetIso,
  className,
  onExpire,
}: {
  targetIso?: string;
  className?: string;
  onExpire?: () => void;
}) {
  const [remaining, setRemaining] = useState<number>(() => {
    if (!targetIso) return Infinity;
    return new Date(targetIso).getTime() - Date.now();
  });

  useEffect(() => {
    if (!targetIso) return;
    let expired = false;
    let timer: ReturnType<typeof setInterval> | undefined;
    const tick = () => {
      const left = new Date(targetIso).getTime() - Date.now();
      setRemaining(left);
      if (left <= 0 && !expired) {
        expired = true;
        if (timer) clearInterval(timer);
        onExpire?.();
      }
    };
    tick();
    if (!expired) timer = setInterval(tick, 1000);
    return () => {
      expired = true;
      if (timer) clearInterval(timer);
    };
  }, [targetIso, onExpire]);

  if (!targetIso) return null;

  const urgent = remaining > 0 && remaining < 30_000;

  return (
    <span className={cn(
      'text-xs font-mono tabular-nums',
      urgent ? 'text-destructive' : 'text-muted-foreground',
      className,
    )}>
      {formatCountdown(remaining)}
    </span>
  );
}
