import { Link } from 'react-router-dom';
import { recoveryPresentation } from '../../lib/recovery-presentation';
import { useEngagementStore } from '../../stores/engagement-store';
import { cn } from '../../lib/utils';

export function RecoveryBanner({ className }: { className?: string }) {
  const recovery = useEngagementStore(state => state.persistenceRecovery);
  const presentation = recoveryPresentation(recovery);
  if (!presentation) return null;

  const critical = presentation.tone === 'critical';
  return (
    <div
      role={critical ? 'alert' : 'status'}
      aria-live={critical ? 'assertive' : 'polite'}
      className={cn(
        'flex items-start justify-between gap-3 border-b px-4 py-2 text-xs',
        critical
          ? 'border-destructive/30 bg-destructive/10 text-destructive'
          : 'border-warning/30 bg-warning/10 text-warning',
        className,
      )}
    >
      <div className="min-w-0">
        <div className="font-semibold">{presentation.title}</div>
        <div className="mt-0.5 opacity-90">{presentation.message}</div>
      </div>
      <Link
        to="/settings"
        className="shrink-0 rounded border border-current/30 px-2 py-1 font-medium hover:bg-background/20"
      >
        Review recovery
      </Link>
    </div>
  );
}
