import { useMemo, useState, useCallback } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import { cn, formatRelativeTime } from '../../lib/utils';
import { CountdownTimer, EmptyState } from '../shared';
import { approveAction, denyAction, getPendingActions } from '../../lib/api';
import type { PendingAction } from '../../lib/types';
import { FilterBar, PageHeader, PanelSection, StatusPill } from '../shared/primitives';
import { GraphNodeLinks } from '../shared/GraphNodeLinks';
import {
  actionNodeId,
  actionNoise,
  computeActionRisk,
  groupActionsByTechnique,
  sortActionsForQueue,
  sortTechniqueGroups,
  type ActionSortMode,
} from '../../lib/action-queue';

type BulkProgress = {
  technique: string;
  type: 'approve' | 'deny';
  total: number;
  done: number;
  currentId: string | null;
} | null;

export function ActionsPanel() {
  const pendingActions = useEngagementStore((s) => s.pendingActions);
  const [sortMode, setSortMode] = useState<ActionSortMode>('risk');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [formType, setFormType] = useState<'approve' | 'deny'>('approve');
  const [formInput, setFormInput] = useState('');
  const [busyIds, setBusyIds] = useState<Set<string>>(new Set());
  const [rowErrors, setRowErrors] = useState<Record<string, string>>({});
  const [bulkProgress, setBulkProgress] = useState<BulkProgress>(null);

  const sorted = useMemo(() => sortActionsForQueue(pendingActions, sortMode), [pendingActions, sortMode]);
  const groups = useMemo(() => groupActionsByTechnique(sorted), [sorted]);
  const groupEntries = useMemo(() => sortTechniqueGroups(groups), [groups]);

  const refresh = useCallback(async () => {
    try {
      const data = await getPendingActions();
      useEngagementStore.setState({ pendingActions: data.pending || [] });
    } catch { /* silent */ }
  }, []);

  const runAction = useCallback(async (action: PendingAction, type: 'approve' | 'deny', text?: string) => {
    setBusyIds(prev => new Set(prev).add(action.action_id));
    setRowErrors(prev => {
      const next = { ...prev };
      delete next[action.action_id];
      return next;
    });
    try {
      if (type === 'approve') await approveAction(action.action_id, text ? { notes: text } : {});
      else await denyAction(action.action_id, text || undefined);
      setExpandedId(null);
      setFormInput('');
      await refresh();
      return true;
    } catch (err) {
      setRowErrors(prev => ({ ...prev, [action.action_id]: err instanceof Error ? err.message : String(err) }));
      return false;
    }
    finally {
      setBusyIds(prev => {
        const next = new Set(prev);
        next.delete(action.action_id);
        return next;
      });
    }
  }, [refresh]);

  const bulkRun = useCallback(async (technique: string, actions: PendingAction[], type: 'approve' | 'deny') => {
    setBulkProgress({ technique, type, total: actions.length, done: 0, currentId: null });
    try {
      for (const [index, action] of actions.entries()) {
        setBulkProgress({ technique, type, total: actions.length, done: index, currentId: action.action_id });
        await runAction(action, type, type === 'approve' ? 'bulk approved by technique' : 'bulk denied by technique');
        setBulkProgress({ technique, type, total: actions.length, done: index + 1, currentId: null });
      }
    } finally {
      setBulkProgress(null);
    }
  }, [runAction]);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Actions"
        meta={`(${pendingActions.length} pending)`}
        actions={(
          <FilterBar>
            <select value={sortMode} onChange={e => setSortMode(e.target.value as ActionSortMode)} className="settings-input w-auto text-xs">
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
            const maxRisk = actions.reduce((max, action) => Math.max(max, computeActionRisk(action).score), 0);
            const canBulk = actions.length >= 2;
            const bulkActive = bulkProgress?.technique === technique;
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
                      {bulkActive && (
                        <span className="text-[10px] text-muted-foreground font-mono">
                          {bulkProgress.type} {bulkProgress.done}/{bulkProgress.total}{bulkProgress.currentId ? ` · ${bulkProgress.currentId.slice(0, 8)}` : ''}
                        </span>
                      )}
                      <button disabled={!!bulkProgress} onClick={() => bulkRun(technique, actions, 'approve')} className="text-[10px] px-2 py-0.5 rounded bg-success/10 text-success border border-success/20 hover:bg-success/20 disabled:opacity-50">
                        Approve group
                      </button>
                      <button disabled={!!bulkProgress} onClick={() => bulkRun(technique, actions, 'deny')} className="text-[10px] px-2 py-0.5 rounded bg-destructive/10 text-destructive border border-destructive/20 hover:bg-destructive/20 disabled:opacity-50">
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
                      error={rowErrors[action.action_id]}
                      onConfirm={() => runAction(action, formType, formInput)}
                      onRefresh={refresh}
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
  error,
  onConfirm,
  onRefresh,
}: {
  action: PendingAction;
  expanded: boolean;
  busy: boolean;
  formType: 'approve' | 'deny';
  formInput: string;
  onFormInput: (value: string) => void;
  onToggle: (type: 'approve' | 'deny') => void;
  error?: string;
  onConfirm: () => void;
  onRefresh: () => void;
}) {
  const risk = computeActionRisk(action);
  const opsec = action.opsec_context || {};
  const budgetPct = opsec.noise_budget_remaining !== undefined ? Math.round(opsec.noise_budget_remaining * 100) + '%' : null;
  const signals = opsec.defensive_signals || [];
  const node = actionNodeId(action);

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
          <div className="grid grid-cols-2 lg:grid-cols-5 gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
            {node && <span className="lg:col-span-2">Target <strong className="text-foreground font-mono">{node}</strong></span>}
            {action.target_ip && <span>IP <strong className="text-foreground font-mono">{action.target_ip}</strong></span>}
            <span>Noise <strong>{actionNoise(action).toFixed(2)}</strong></span>
            {budgetPct && <span>Budget <strong>{budgetPct}</strong></span>}
            {opsec.recommended_approach && <span>Approach <strong>{opsec.recommended_approach}</strong></span>}
          </div>
          {node && <GraphNodeLinks nodeId={node} className="mt-1" />}
          {signals.length > 0 && (
            <div className="mt-1 flex flex-wrap gap-1">
              {signals.map(signal => (
                <span key={signal} className="text-[10px] px-1.5 py-0.5 rounded bg-warning/10 text-warning">{signal}</span>
              ))}
            </div>
          )}
        </div>
        <div className="flex items-center gap-1 flex-shrink-0">
          <button onClick={() => onToggle('approve')} disabled={busy} className="text-[10px] px-2 py-0.5 rounded bg-success/10 text-success border border-success/20 hover:bg-success/20 disabled:opacity-50">
            Approve
          </button>
          <button onClick={() => onToggle('deny')} disabled={busy} className="text-[10px] px-2 py-0.5 rounded bg-destructive/10 text-destructive border border-destructive/20 hover:bg-destructive/20 disabled:opacity-50">
            Deny
          </button>
        </div>
      </div>
      {error && (
        <div className="mt-2 rounded border border-destructive/20 bg-destructive/10 px-2 py-1 text-[11px] text-destructive">
          {error}
        </div>
      )}
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
