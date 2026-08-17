import { useCallback, useEffect, useState } from 'react';
import { getEvidenceDebt, type EvidenceDebtItem } from '../../lib/api';
import { PanelSection } from '../shared/primitives';
import { useNavigation } from '../../hooks/useNavigation';
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
 * an item jumps to its target so the operator can inspect the evidence or correct the judgment,
 * turning the scorecard from a readout into an operating loop.
 */
export function EvidenceDebtCard() {
  const [items, setItems] = useState<EvidenceDebtItem[] | null>(null);
  const [error, setError] = useState(false);
  const { navigateToGraph, navigateToFinding, navigateToEvidenceObjective } = useNavigation();

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

  if (!items) {
    return (
      <PanelSection title="Evidence Debt">
        <div className="text-xs text-muted-foreground">{error ? 'Evidence debt unavailable.' : 'Loading…'}</div>
      </PanelSection>
    );
  }

  if (items.length === 0) {
    return (
      <PanelSection title="Evidence Debt">
        <div className="text-xs text-success">✓ No open evidence debt — every claim is supported and current.</div>
      </PanelSection>
    );
  }

  const shown = items.slice(0, MAX_SHOWN);

  return (
    <PanelSection title="Evidence Debt" meta={`(${items.length})`}>
      <div className="space-y-1">
        {shown.map((item, index) => {
          const meta = KIND_META[item.kind];
          return (
            <button
              key={`${item.kind}-${item.node_id ?? item.edge_id ?? item.objective_id ?? item.finding_id ?? index}`}
              onClick={() => drillDown(item)}
              className="w-full flex items-start gap-2 text-left rounded px-1.5 py-1 -mx-1 hover:bg-hover transition-colors"
              title="Open its target to inspect or correct it"
            >
              <span className={cn('mt-1 h-1.5 w-1.5 flex-shrink-0 rounded-full', meta.dot)} />
              <span className="flex-1 min-w-0">
                <span className={cn('text-[10px] uppercase tracking-wide font-medium mr-1.5', meta.color)}>{meta.label}</span>
                <span className="text-xs text-foreground break-words">{item.summary}</span>
              </span>
            </button>
          );
        })}
        {items.length > MAX_SHOWN && (
          <div className="text-[11px] text-muted-foreground px-1.5">…and {items.length - MAX_SHOWN} more</div>
        )}
      </div>
    </PanelSection>
  );
}
