import { cn } from '../../lib/utils';

const STATUS_STYLES: Record<string, string> = {
  active: 'bg-success/10 text-success',
  running: 'bg-success/10 text-success',
  connected: 'bg-success/10 text-success',
  completed: 'bg-accent-dim text-accent',
  paused: 'bg-warning/10 text-warning',
  pending: 'bg-warning/10 text-warning',
  aborted: 'bg-destructive/10 text-destructive',
  failed: 'bg-destructive/10 text-destructive',
  error: 'bg-destructive/10 text-destructive',
  draft: 'bg-elevated text-muted-foreground',
  closed: 'bg-elevated text-muted-foreground',
  interrupted: 'bg-warning/10 text-warning',
};

export function StatusBadge({ status, className }: { status: string; className?: string }) {
  return (
    <span className={cn(
      'text-[10px] px-1.5 py-0.5 rounded font-medium uppercase tracking-wide',
      STATUS_STYLES[status] || 'bg-elevated text-muted-foreground',
      className,
    )}>
      {status}
    </span>
  );
}
