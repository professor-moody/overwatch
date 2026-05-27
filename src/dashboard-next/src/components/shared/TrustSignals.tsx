import type { TrustSignal, TrustSignalSeverity } from '../../lib/trust-signals';
import { cn } from '../../lib/utils';
import { StatusPill, type StatusTone } from './primitives';

const SIGNAL_TONE: Record<TrustSignalSeverity, StatusTone> = {
  error: 'danger',
  warning: 'warning',
  info: 'accent',
};

const SIGNAL_BORDER: Record<TrustSignalSeverity, string> = {
  error: 'border-destructive/30 bg-destructive/5',
  warning: 'border-warning/30 bg-warning/5',
  info: 'border-accent/25 bg-accent/5',
};

export function TrustSignalPills({
  signals,
  limit = 3,
  className,
}: {
  signals: TrustSignal[];
  limit?: number;
  className?: string;
}) {
  if (signals.length === 0) return null;
  const visible = signals.slice(0, limit);
  const remaining = signals.length - visible.length;
  return (
    <div className={cn('flex flex-wrap items-center gap-1', className)}>
      {visible.map(signal => (
        <StatusPill key={signal.id} tone={SIGNAL_TONE[signal.severity]} className="border border-current/10" title={signal.detail}>
          {signal.label}
        </StatusPill>
      ))}
      {remaining > 0 && <StatusPill tone="muted">+{remaining}</StatusPill>}
    </div>
  );
}

export function TrustSignalList({ signals, className }: { signals: TrustSignal[]; className?: string }) {
  if (signals.length === 0) return null;
  return (
    <div className={cn('space-y-1.5', className)}>
      {signals.map(signal => (
        <div key={signal.id} className={cn('rounded border px-2 py-1.5 text-xs', SIGNAL_BORDER[signal.severity])}>
          <div className="flex items-center gap-2">
            <StatusPill tone={SIGNAL_TONE[signal.severity]}>{signal.label}</StatusPill>
          </div>
          {signal.detail && <div className="mt-1 text-[11px] text-muted-foreground">{signal.detail}</div>}
          {signal.action && <div className="mt-1 text-[11px] text-foreground">{signal.action}</div>}
        </div>
      ))}
    </div>
  );
}
