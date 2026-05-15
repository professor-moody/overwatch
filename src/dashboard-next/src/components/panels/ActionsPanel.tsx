import { useMemo, useState, useCallback } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import { cn, formatRelativeTime } from '../../lib/utils';
import { CountdownTimer, EmptyState } from '../shared';
import { approveAction, denyAction, getPendingActions } from '../../lib/api';
import type { PendingAction } from '../../lib/types';
import { FilterBar, PageHeader, PanelSection, StatusPill } from '../shared/primitives';
import { useNavigation } from '../../hooks/useNavigation';

type SortMode = 'risk' | 'arrival' | 'noise-desc' | 'timeout-asc';

function actionNoise(action: PendingAction): number {
  return action.opsec_context?.noise_level || action.noise_level || 0;
}

function computeRisk(action: PendingAction) {
  const opsec = action.opsec_context || {};
  const signals = (opsec.defensive_signals || []).length;
  const score = actionNoise(action) * 2 + signals + (action.validation_result === 'warning_only' ? 1 : 0);
  if (score >= 6) return { label: 'HIGH', cls: 'bg-destructive/10 text-destructive', score };
  if (score >= 3) return { label: 'MED', cls: 'bg-warning/10 text-warning', score };
  return { label: 'LOW', cls: 'bg-elevated text-muted-foreground', score };
}

function sortActions(list: PendingAction[], mode: SortMode): PendingAction[] {
  const sorted = [...list];
  if (mode === 'risk') {
    sorted.sort((a, b) => computeRisk(b).score - computeRisk(a).score || actionNoise(b) - actionNoise(a));
  } else if (mode === 'noise-desc') {
    sorted.sort((a, b) => actionNoise(b) - actionNoise(a));
  } else if (mode === 'timeout-asc') {
    sorted.sort((a, b) => {
      const ta = a.timeout_at ? new Date(a.timeout_at).getTime() : Infinity;
      const tb = b.timeout_at ? new Date(b.timeout_at).getTime() : Infinity;
      return ta - tb;
    });
  }
  return sorted;
}

function groupByTechnique(actions: PendingAction[]): Record<string, PendingAction[]> {
  const groups: Record<string, PendingAction[]> = {};
  for (const action of actions) {
    const key = action.technique || 'unknown';
    if (!groups[key]) groups[key] = [];
    groups[key].push(action);
  }
  return groups;
}

function actionNode(action: PendingAction): string | null {
  return action.target_node || action.target || null;
}

export function ActionsPanel() {
  const pendingActions = useEngagementStore((s) => s.pendingActions);
  const { navigateToEvidence, navigateToGraph } = useNavigation();
  const [sortMode, setSortMode] = useState<SortMode>('risk');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [formType, setFormType] = useState<'approve' | 'deny'>('approve');
  const [formInput, setFormInput] = useState('');
  const [busyIds, setBusyIds] = useState<Set<string>>(new Set());

  const sorted = useMemo(() => sortActions(pendingActions, sortMode), [pendingActions, sortMode]);
  const groups = useMemo(() => groupByTechnique(sorted), [sorted]);
  const groupEntries = useMemo(() => {
    return Object.entries(groups).sort(([, a], [, b]) => {
      const risk = Math.max(...b.map(x => computeRisk(x).score)) - Math.max(...a.map(x => computeRisk(x).score));
      if (risk !== 0) return risk;
      return b.length - a.length;
    });
  }, [groups]);

  const refresh = useCallback(async () => {
    try {
      const data = await getPendingActions();
      useEngagementStore.setState({ pendingActions: data.pending || [] });
    } catch { /* silent */ }
  }, []);

  const runAction = useCallback(async (action: PendingAction, type: 'approve' | 'deny', text?: string) => {
    setBusyIds(prev => new Set(prev).add(action.action_id));
    try {
      if (type === 'approve') await approveAction(action.action_id, text ? { notes: text } : {});
      else await denyAction(action.action_id, text || undefined);
      setExpandedId(null);
      setFormInput('');
      await refresh();
    } catch { /* silent */ }
    finally {
      setBusyIds(prev => {
        const next = new Set(prev);
        next.delete(action.action_id);
        return next;
      });
    }
  }, [refresh]);

  const bulkRun = useCallback(async (actions: PendingAction[], type: 'approve' | 'deny') => {
    for (const action of actions) {
      await runAction(action, type, type === 'approve' ? 'bulk approved by technique' : 'bulk denied by technique');
    }
  }, [runAction]);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Actions"
        meta={`(${pendingActions.length} pending)`}
        actions={(
          <FilterBar>
            <select value={sortMode} onChange={e => setSortMode(e.target.value as SortMode)} className="settings-input w-auto text-xs">
              <option value="risk">Risk</option>
              <option value="arrival">Arrival</option>
              <option value="noise-desc">Noise</option>
              <option value="timeout-asc">Timeout</option>
            </select>
          </FilterBar>
        )}
      />

      {sorted.length === 0 ? (
        <EmptyState
          title="No pending actions"
          description="When an agent invokes a noisy or destructive tool under approve-critical mode, the action queues here for the operator to approve or deny."
        />
      ) : (
        <div className="space-y-3">
          {groupEntries.map(([technique, actions]) => {
            const maxRisk = actions.reduce((max, action) => Math.max(max, computeRisk(action).score), 0);
            const canBulk = actions.length >= 2;
            return (
              <PanelSection key={technique} className="p-0 overflow-hidden">
                <div className="px-3 py-2 border-b border-border flex items-center gap-2">
                  <span className="text-sm font-medium text-foreground">{technique}</span>
                  <StatusPill className={maxRisk >= 6 ? 'bg-destructive/10 text-destructive' : maxRisk >= 3 ? 'bg-warning/10 text-warning' : 'bg-elevated text-muted-foreground'}>
                    risk {maxRisk.toFixed(1)}
                  </StatusPill>
                  <span className="text-xs text-muted-foreground">{actions.length} action{actions.length === 1 ? '' : 's'}</span>
                  {canBulk && (
                    <div className="ml-auto flex items-center gap-1">
                      <button onClick={() => bulkRun(actions, 'approve')} className="text-[10px] px-2 py-0.5 rounded bg-success/10 text-success border border-success/20 hover:bg-success/20">
                        Approve group
                      </button>
                      <button onClick={() => bulkRun(actions, 'deny')} className="text-[10px] px-2 py-0.5 rounded bg-destructive/10 text-destructive border border-destructive/20 hover:bg-destructive/20">
                        Deny group
                      </button>
                    </div>
                  )}
                </div>
                <div className="divide-y divide-border">
                  {actions.map(action => (
                    <ActionRow
                      key={action.action_id}
                      action={action}
                      expanded={expandedId === action.action_id}
                      busy={busyIds.has(action.action_id)}
                      formType={formType}
                      formInput={formInput}
                      onFormInput={setFormInput}
                      onToggle={(type) => {
                        setExpandedId(expandedId === action.action_id && formType === type ? null : action.action_id);
                        setFormType(type);
                        setFormInput('');
                      }}
                      onConfirm={() => runAction(action, formType, formInput)}
                      onRefresh={refresh}
                      onGraph={() => { const node = actionNode(action); if (node) navigateToGraph(node, 2); }}
                      onEvidence={() => { const node = actionNode(action); if (node) navigateToEvidence(node); }}
                    />
                  ))}
                </div>
              </PanelSection>
            );
          })}
        </div>
      )}
    </div>
  );
}

function ActionRow({
  action,
  expanded,
  busy,
  formType,
  formInput,
  onFormInput,
  onToggle,
  onConfirm,
  onRefresh,
  onGraph,
  onEvidence,
}: {
  action: PendingAction;
  expanded: boolean;
  busy: boolean;
  formType: 'approve' | 'deny';
  formInput: string;
  onFormInput: (value: string) => void;
  onToggle: (type: 'approve' | 'deny') => void;
  onConfirm: () => void;
  onRefresh: () => void;
  onGraph: () => void;
  onEvidence: () => void;
}) {
  const risk = computeRisk(action);
  const opsec = action.opsec_context || {};
  const budgetPct = opsec.noise_budget_remaining !== undefined ? Math.round(opsec.noise_budget_remaining * 100) + '%' : null;
  const signals = opsec.defensive_signals || [];
  const node = actionNode(action);

  return (
    <div className="px-3 py-2 hover:bg-hover/40 transition-colors">
      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-1">
            <StatusPill className={risk.cls}>{risk.label}</StatusPill>
            {action.validation_result && (
              <StatusPill className={action.validation_result === 'warning_only' ? 'bg-warning/10 text-warning' : 'bg-elevated text-muted-foreground'}>
                {action.validation_result}
              </StatusPill>
            )}
            <span className="text-xs text-muted-foreground">{formatRelativeTime(action.submitted_at)}</span>
            {action.timeout_at && <CountdownTimer targetIso={action.timeout_at} onExpire={onRefresh} className="ml-auto" />}
          </div>
          <p className="text-xs text-foreground mb-1">{action.description}</p>
          <div className="flex items-center gap-3 text-[11px] text-muted-foreground flex-wrap">
            {node && <span>Target <strong className="text-foreground font-mono">{node}</strong></span>}
            {action.target_ip && <span>IP <strong className="text-foreground font-mono">{action.target_ip}</strong></span>}
            <span>Noise <strong>{actionNoise(action).toFixed(2)}</strong></span>
            {budgetPct && <span>Budget <strong>{budgetPct}</strong></span>}
            {opsec.recommended_approach && <span>Approach <strong>{opsec.recommended_approach}</strong></span>}
          </div>
          {signals.length > 0 && (
            <div className="mt-1 flex flex-wrap gap-1">
              {signals.map(signal => (
                <span key={signal} className="text-[10px] px-1.5 py-0.5 rounded bg-warning/10 text-warning">{signal}</span>
              ))}
            </div>
          )}
        </div>
        <div className="flex items-center gap-1 flex-shrink-0">
          {node && <button onClick={onGraph} className="text-[10px] px-1.5 py-0.5 rounded text-accent hover:bg-accent/10">Graph</button>}
          {node && <button onClick={onEvidence} className="text-[10px] px-1.5 py-0.5 rounded text-accent hover:bg-accent/10">Evidence</button>}
          <button onClick={() => onToggle('approve')} disabled={busy} className="text-[10px] px-2 py-0.5 rounded bg-success/10 text-success border border-success/20 hover:bg-success/20 disabled:opacity-50">
            Approve
          </button>
          <button onClick={() => onToggle('deny')} disabled={busy} className="text-[10px] px-2 py-0.5 rounded bg-destructive/10 text-destructive border border-destructive/20 hover:bg-destructive/20 disabled:opacity-50">
            Deny
          </button>
        </div>
      </div>
      {expanded && (
        <div className="mt-2 flex items-center gap-2 pt-2 border-t border-border">
          <input
            value={formInput}
            onChange={e => onFormInput(e.target.value)}
            placeholder={formType === 'approve' ? 'Notes (optional)...' : 'Reason (optional)...'}
            className="settings-input flex-1"
            onKeyDown={e => {
              if (e.key === 'Enter') onConfirm();
            }}
            autoFocus
          />
          <button onClick={onConfirm} disabled={busy} className={cn('text-xs px-3 py-1 rounded border transition-colors disabled:opacity-50',
            formType === 'approve' ? 'bg-success/10 text-success border-success/20' : 'bg-destructive/10 text-destructive border-destructive/20')}>
            {busy ? 'Working...' : `Confirm ${formType}`}
          </button>
        </div>
      )}
    </div>
  );
}
