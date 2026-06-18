import { cn } from '../../lib/utils';
import type { OpsecBudget } from '../../lib/types';

const APPROACH_BADGE: Record<string, string> = {
  loud: 'bg-success/10 text-success',
  normal: 'bg-warning/10 text-warning',
  quiet: 'bg-destructive/10 text-destructive',
};

/**
 * Noise-budget gauge: spent vs. max, color-graded by remaining headroom, with
 * the recommended approach badge. Shared by the global Overview meter and the
 * per-campaign meter (which passes a campaign-scoped `global_noise_spent` + its
 * own title/caption). `caption` clarifies scope when the numerator and the
 * recommended approach come from different scopes (campaign noise vs. global
 * budget/approach).
 */
export function OpsecGauge({ budget, title = 'OPSEC Budget', caption }: { budget: OpsecBudget; title?: string; caption?: string }) {
  const pct = budget.max_noise > 0
    ? Math.round((budget.global_noise_spent / budget.max_noise) * 100)
    : 0;
  const remainingPct = 100 - pct;

  const barColor = remainingPct > 60 ? 'bg-success' : remainingPct > 30 ? 'bg-warning' : 'bg-destructive';

  return (
    <section className="bg-surface border border-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-medium flex items-center gap-2">
          {title}
          <span className={cn('text-[10px] px-1.5 py-0.5 rounded font-medium', APPROACH_BADGE[budget.recommended_approach] || '')}>
            {budget.recommended_approach}
          </span>
        </h3>
        <span className="text-xs text-muted-foreground font-mono">
          {budget.global_noise_spent.toFixed(2)} / {budget.max_noise}
        </span>
      </div>
      {caption && <div className="-mt-1 mb-2 text-[10px] text-muted-foreground">{caption}</div>}
      <div className="h-2 bg-elevated rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full transition-all', barColor)} style={{ width: `${pct}%` }} />
      </div>
      <div className="flex items-center justify-between mt-1.5 text-[10px] text-muted-foreground">
        <span>{pct}% spent</span>
        {budget.time_window_remaining_hours !== undefined && (
          <span>{budget.time_window_remaining_hours.toFixed(1)}h remaining in window</span>
        )}
      </div>
      {budget.warning && (
        <div className="mt-2 text-xs text-warning bg-warning/5 border border-warning/20 rounded px-2 py-1">
          ⚠ {budget.warning}
        </div>
      )}
      {budget.defensive_signals.length > 0 && (
        <div className="mt-2 text-xs text-destructive">
          {budget.defensive_signals.length} defensive signal{budget.defensive_signals.length > 1 ? 's' : ''} detected
        </div>
      )}
    </section>
  );
}
