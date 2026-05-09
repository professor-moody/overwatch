import { useState, useCallback } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import { cn, formatRelativeTime } from '../../lib/utils';
import { CountdownTimer, EmptyState } from '../shared';
import { approveAction, denyAction, getPendingActions } from '../../lib/api';
import type { PendingAction } from '../../lib/types';

type SortMode = 'arrival' | 'noise-desc' | 'timeout-asc';

function computePriority(action: PendingAction) {
  const opsec = action.opsec_context || {};
  const noise = opsec.noise_level || action.noise_level || 0;
  const signals = (opsec.defensive_signals || []).length;
  const score = noise * 2 + signals;
  if (score >= 6) return { label: 'HIGH', cls: 'bg-destructive/10 text-destructive' };
  if (score >= 3) return { label: 'MED', cls: 'bg-warning/10 text-warning' };
  return { label: 'LOW', cls: 'bg-elevated text-muted-foreground' };
}

function sortActions(list: PendingAction[], mode: SortMode): PendingAction[] {
  const sorted = [...list];
  if (mode === 'noise-desc') {
    sorted.sort((a, b) => {
      const na = a.opsec_context?.noise_level || a.noise_level || 0;
      const nb = b.opsec_context?.noise_level || b.noise_level || 0;
      return nb - na;
    });
  } else if (mode === 'timeout-asc') {
    sorted.sort((a, b) => {
      const ta = a.timeout_at ? new Date(a.timeout_at).getTime() : Infinity;
      const tb = b.timeout_at ? new Date(b.timeout_at).getTime() : Infinity;
      return ta - tb;
    });
  }
  return sorted;
}

export function ActionsPanel() {
  const pendingActions = useEngagementStore((s) => s.pendingActions);
  const [sortMode, setSortMode] = useState<SortMode>('arrival');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [formType, setFormType] = useState<'approve' | 'deny'>('approve');
  const [formInput, setFormInput] = useState('');

  const sorted = sortActions(pendingActions, sortMode);

  const refresh = useCallback(async () => {
    try {
      const data = await getPendingActions();
      useEngagementStore.setState({ pendingActions: data.pending || [] });
    } catch { /* silent */ }
  }, []);

  const handleApprove = async (actionId: string) => {
    try {
      await approveAction(actionId, formInput ? { notes: formInput } : {});
      setExpandedId(null); setFormInput('');
      refresh();
    } catch { /* silent */ }
  };

  const handleDeny = async (actionId: string) => {
    try {
      await denyAction(actionId, formInput || undefined);
      setExpandedId(null); setFormInput('');
      refresh();
    } catch { /* silent */ }
  };

  const bulkApprove = async () => {
    const groups = groupByTechnique(pendingActions);
    const bulkGroups = Object.entries(groups).filter(([, g]) => g.length >= 2);
    if (bulkGroups.length === 0) return;
    for (const [, group] of bulkGroups) {
      for (const action of group) {
        try { await approveAction(action.action_id, { notes: 'bulk approved' }); } catch {}
      }
    }
    setExpandedId(null);
    refresh();
  };

  const bulkDeny = async () => {
    const groups = groupByTechnique(pendingActions);
    const bulkGroups = Object.entries(groups).filter(([, g]) => g.length >= 2);
    if (bulkGroups.length === 0) return;
    for (const [, group] of bulkGroups) {
      for (const action of group) {
        try { await denyAction(action.action_id, 'bulk denied'); } catch {}
      }
    }
    setExpandedId(null);
    refresh();
  };

  const hasBulk = Object.values(groupByTechnique(pendingActions)).some(g => g.length >= 2);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">
          Pending Actions <span className="text-muted-foreground font-normal text-sm">({pendingActions.length})</span>
        </h2>
        <div className="flex items-center gap-2">
          {hasBulk && (
            <>
              <button onClick={bulkApprove} className="text-xs px-2 py-1 rounded bg-success/10 text-success border border-success/20 hover:bg-success/20 transition-colors">
                Bulk Approve
              </button>
              <button onClick={bulkDeny} className="text-xs px-2 py-1 rounded bg-destructive/10 text-destructive border border-destructive/20 hover:bg-destructive/20 transition-colors">
                Bulk Deny
              </button>
            </>
          )}
          <select value={sortMode} onChange={e => setSortMode(e.target.value as SortMode)}
            className="settings-input w-auto text-xs">
            <option value="arrival">Arrival</option>
            <option value="noise-desc">Noise (high first)</option>
            <option value="timeout-asc">Timeout (soonest)</option>
          </select>
        </div>
      </div>

      {sorted.length === 0 ? (
        <EmptyState
          title="No pending actions"
          description="When an agent invokes a noisy or destructive tool under approve-critical mode, the action queues here for the operator to approve or deny. Quiet reads under the noise budget auto-approve and never show up here."
        />
      ) : (
        <div className="space-y-2">
          {sorted.map((a) => {
            const prio = computePriority(a);
            const opsec = a.opsec_context || {};
            const budgetPct = opsec.noise_budget_remaining !== undefined
              ? Math.round(opsec.noise_budget_remaining * 100) + '%' : null;
            const signals = (opsec.defensive_signals || []).length;
            const isExpanded = expandedId === a.action_id;

            return (
              <div key={a.action_id} className="bg-surface border border-border rounded-lg p-4">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-sm font-medium">{a.technique}</span>
                  <span className={cn('text-[10px] px-1.5 py-0.5 rounded font-medium', prio.cls)}>{prio.label}</span>
                  {a.validation_result && (
                    <span className={cn('text-[10px] px-1.5 py-0.5 rounded',
                      a.validation_result === 'warning_only' ? 'bg-warning/10 text-warning' : 'bg-elevated text-muted-foreground')}>
                      {a.validation_result}
                    </span>
                  )}
                  <span className="text-xs text-muted-foreground ml-auto">{formatRelativeTime(a.submitted_at)}</span>
                </div>
                <p className="text-xs text-muted-foreground mb-2">{a.description}</p>
                <div className="flex items-center gap-3 text-xs text-muted-foreground mb-2 flex-wrap">
                  {(a.target_node || a.target) && <span>Target: <strong className="text-foreground">{a.target_node || a.target}</strong></span>}
                  {a.target_ip && <span>IP: <strong className="text-foreground">{a.target_ip}</strong></span>}
                  {budgetPct && <span>Budget: <strong>{budgetPct}</strong></span>}
                  {opsec.recommended_approach && (
                    <span>Approach: <strong className={cn(
                      opsec.recommended_approach === 'proceed' ? 'text-success' :
                      opsec.recommended_approach === 'caution' ? 'text-warning' : 'text-destructive'
                    )}>{opsec.recommended_approach}</strong></span>
                  )}
                  {signals > 0 && <span className="text-warning">Signals: <strong>{signals}</strong></span>}
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={() => { setExpandedId(isExpanded ? null : a.action_id); setFormType('approve'); setFormInput(''); }}
                    className="text-xs px-2 py-1 rounded bg-success/10 text-success border border-success/20 hover:bg-success/20 transition-colors">
                    Approve
                  </button>
                  <button onClick={() => { setExpandedId(isExpanded ? null : a.action_id); setFormType('deny'); setFormInput(''); }}
                    className="text-xs px-2 py-1 rounded bg-destructive/10 text-destructive border border-destructive/20 hover:bg-destructive/20 transition-colors">
                    Deny
                  </button>
                  <CountdownTimer targetIso={a.timeout_at} onExpire={refresh} className="ml-auto" />
                </div>
                {isExpanded && (
                  <div className="mt-3 flex items-center gap-2 pt-2 border-t border-border">
                    <input value={formInput} onChange={e => setFormInput(e.target.value)}
                      placeholder={formType === 'approve' ? 'Notes (optional)\u2026' : 'Reason (optional)\u2026'}
                      className="settings-input flex-1"
                      onKeyDown={e => {
                        if (e.key === 'Enter') formType === 'approve' ? handleApprove(a.action_id) : handleDeny(a.action_id);
                        if (e.key === 'Escape') setExpandedId(null);
                      }}
                      autoFocus />
                    <button onClick={() => formType === 'approve' ? handleApprove(a.action_id) : handleDeny(a.action_id)}
                      className={cn('text-xs px-3 py-1 rounded border transition-colors',
                        formType === 'approve' ? 'bg-success/10 text-success border-success/20' : 'bg-destructive/10 text-destructive border-destructive/20')}>
                      Confirm {formType === 'approve' ? 'Approve' : 'Deny'}
                    </button>
                    <button onClick={() => setExpandedId(null)} className="text-xs text-muted-foreground hover:text-foreground">Cancel</button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function groupByTechnique(actions: PendingAction[]): Record<string, PendingAction[]> {
  const groups: Record<string, PendingAction[]> = {};
  for (const a of actions) {
    const key = a.technique || 'unknown';
    if (!groups[key]) groups[key] = [];
    groups[key].push(a);
  }
  return groups;
}
