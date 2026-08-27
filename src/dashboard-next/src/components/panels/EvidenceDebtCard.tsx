import { useCallback, useEffect, useState } from 'react';
import { getEvidenceDebt, dispatchAgent, type EvidenceDebtItem } from '../../lib/api';
import { useWorkspaceNavigation } from '../../hooks/useWorkspaceNavigation';
import { useToastStore } from '../../stores/toast-store';
import { cn } from '../../lib/utils';

const KIND_META: Record<EvidenceDebtItem['kind'], { label: string; color: string; dot: string }> = {
  contradiction: { label: 'Contradiction', color: 'text-destructive', dot: 'bg-destructive' },
  lapsed_objective: { label: 'Lapsed objective', color: 'text-warning', dot: 'bg-warning' },
  unsupported_critical: { label: 'Unsupported', color: 'text-destructive', dot: 'bg-destructive/70' },
  expiring_validation: { label: 'Expiring', color: 'text-accent', dot: 'bg-accent' },
};

const MAX_SHOWN = 12;

/**
 * The Evidence Debt Queue — a ranked, drill-downable list of the engagement's open quality problems
 * (contradictions, lapsed objectives, unsupported critical findings, expiring validations). Clicking
 * an item jumps to its target so the operator can inspect the evidence or correct the judgment, and a
 * per-item Validate dispatches an agent — turning the scorecard from a readout into an operating loop.
 *
 * `compact` renders the Console intervention-rail variant: a warning-toned strip, fewer rows, and it
 * HIDES itself when there is no debt (so it never clutters the "Needs you" surface). The full Overview
 * card shows the clean/loading states.
 */
export function EvidenceDebtCard({ compact = false }: { compact?: boolean } = {}) {
  const [items, setItems] = useState<EvidenceDebtItem[] | null>(null);
  const [error, setError] = useState(false);
  const [dispatching, setDispatching] = useState<string | null>(null);
  const { navigateToGraph, navigateToFinding, navigateToEvidenceObjective } = useWorkspaceNavigation();
  const addToast = useToastStore(s => s.addToast);

  const refresh = useCallback(async () => {
    try {
      const data = await getEvidenceDebt();
      setItems(data.items ?? []);
      setError(false);
    } catch {
      setError(true);
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 15_000);
    return () => clearInterval(timer);
  }, [refresh]);

  const drillDown = useCallback((item: EvidenceDebtItem) => {
    if (item.finding_id) { navigateToFinding(item.finding_id); return; }
    if (item.objective_id) { navigateToEvidenceObjective(item.objective_id); return; }
    if (item.node_id) { navigateToGraph(item.node_id, 2); return; }
  }, [navigateToFinding, navigateToEvidenceObjective, navigateToGraph]);

  /** Dispatch a validation agent against the debt item's target node to re-establish or re-test it. */
  const validate = useCallback(async (key: string, nodeId: string) => {
    setDispatching(key);
    try {
      const res = await dispatchAgent({ target_node_ids: [nodeId] });
      if (res.dispatched) {
        addToast({ type: 'success', title: 'Validation agent dispatched', message: `Re-validating ${nodeId}` });
      } else {
        addToast({ type: 'error', title: 'Not dispatched', message: res.reason || 'Agent could not be dispatched' });
      }
    } catch (e) {
      addToast({ type: 'error', title: 'Dispatch failed', message: e instanceof Error ? e.message : String(e) });
    } finally {
      setDispatching(null);
    }
  }, [addToast]);

  // Compact (Console rail) hides entirely while loading and when clean, so it never adds noise to the
  // "Needs you" surface. The full Overview card shows the loading / clean states.
  if (!items) {
    if (compact) return null;
    return (
      <section aria-label="Evidence debt">
        <div className="mb-2 text-[10px] font-medium uppercase tracking-[0.14em] text-muted-foreground">Evidence debt</div>
        <div className="text-xs text-muted-foreground">{error ? 'Evidence debt unavailable.' : 'Loading…'}</div>
      </section>
    );
  }
  if (items.length === 0) {
    if (compact) return null;
    return (
      <section aria-label="Evidence debt">
        <div className="mb-2 text-[10px] font-medium uppercase tracking-[0.14em] text-muted-foreground">Evidence debt</div>
        <div className="text-xs text-success">✓ No open evidence debt — every claim is supported and current.</div>
      </section>
    );
  }

  const cap = compact ? 5 : MAX_SHOWN;
  const shown = items.slice(0, cap);
  const rows = (
    <div className="space-y-1">
      {shown.map((item, index) => {
        const meta = KIND_META[item.kind];
        const key = `${item.kind}-${item.node_id ?? item.edge_id ?? item.objective_id ?? item.finding_id ?? index}`;
        return (
          <div key={key} className="group flex items-start gap-1 rounded px-1.5 py-1 -mx-1 hover:bg-hover transition-colors">
            <button
              onClick={() => drillDown(item)}
              className="flex-1 min-w-0 flex items-start gap-2 text-left"
              title="Open its target to inspect or correct it"
            >
              <span className={cn('mt-1 h-1.5 w-1.5 flex-shrink-0 rounded-full', meta.dot)} />
              <span className="flex-1 min-w-0">
                <span className={cn('text-[10px] uppercase tracking-wide font-medium mr-1.5', meta.color)}>{meta.label}</span>
                <span className="text-xs text-foreground break-words">{item.summary}</span>
              </span>
            </button>
            {item.node_id && (
              <button
                onClick={() => validate(key, item.node_id!)}
                disabled={dispatching !== null}
                title="Dispatch a validation agent against this target"
                className={cn(
                  'flex-shrink-0 rounded border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground transition-colors',
                  'hover:border-accent/40 hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40',
                  'opacity-0 group-hover:opacity-100 focus:opacity-100',
                )}
              >
                {dispatching === key ? '…' : 'Validate'}
              </button>
            )}
          </div>
        );
      })}
      {items.length > cap && (
        <div className="text-[11px] text-muted-foreground px-1.5">…and {items.length - cap} more</div>
      )}
    </div>
  );

  if (compact) {
    return (
      <div className="space-y-1.5 rounded-md border border-warning/40 bg-warning/5 p-3">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-warning">⚑ Evidence debt</span>
          <span className="rounded-full bg-warning/20 px-1.5 text-[10px] text-warning">{items.length}</span>
          <span className="text-[10px] text-muted-foreground">quality problems to act on</span>
        </div>
        {rows}
      </div>
    );
  }

  return (
    <section aria-label="Evidence debt">
      <div className="mb-2 flex items-center gap-2 border-b border-border-subtle pb-2">
        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-muted-foreground">Evidence debt</span>
        <span className="font-mono text-[9px] text-warning">{items.length}</span>
      </div>
      {rows}
    </section>
  );
}
