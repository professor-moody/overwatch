import { useEffect, useMemo, useState, useCallback } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import { useToastStore } from '../../stores/toast-store';
import { cn, formatRelativeTime } from '../../lib/utils';
import { CountdownTimer, EmptyState } from '../shared';
import { approveAction, approveBatch, denyAction, denyBatch, explainAction, getPendingActions } from '../../lib/api';
import { isDenyReasonValid } from '../../lib/console-approvals';
import type { ActionExplanation, ActionQueueDiagnostics, PendingAction } from '../../lib/types';
import { ActionButton, EmptyPanelState, FilterBar, PageHeader, PanelSection, StatusPill } from '../shared/primitives';
import { GraphNodeLinks } from '../shared/GraphNodeLinks';
import {
  actionNodeId,
  actionNoise,
  classifyActionLifecycle,
  computeActionRisk,
  groupActionsByTechnique,
  recommendedDecision,
  sortActionsForQueue,
  sortTechniqueGroups,
  terminalApprovalCommand,
  terminalApprovalSummary,
  type ActionLifecycle,
  type ActionSortMode,
} from '../../lib/action-queue';
import { deriveNodeRelationships } from '../../lib/relationships';
import { useNavigation } from '../../hooks/useNavigation';

export function ActionsPanel() {
  const pendingActions = useEngagementStore((s) => s.pendingActions);
  const graph = useEngagementStore((s) => s.graph);
  const sessions = useEngagementStore((s) => s.sessions);
  const frontier = useEngagementStore((s) => s.frontier);
  const connected = useEngagementStore((s) => s.connected);
  const [sortMode, setSortMode] = useState<ActionSortMode>('risk');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [copied, setCopied] = useState<string | null>(null);
  const [recentResolved, setRecentResolved] = useState<PendingAction[]>([]);
  const [diagnostics, setDiagnostics] = useState<ActionQueueDiagnostics | null>(null);
  const [batchMode, setBatchMode] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkDenyIds, setBulkDenyIds] = useState<string[] | null>(null);
  const [bulkReason, setBulkReason] = useState('');
  const { navigateToPanel } = useNavigation();
  const addToast = useToastStore(s => s.addToast);

  const sorted = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = q
      ? pendingActions.filter(action => [
        action.action_id,
        action.technique,
        action.target,
        action.target_node,
        action.target_ip,
        action.target_cidr,
        action.description,
      ].some(value => typeof value === 'string' && value.toLowerCase().includes(q)))
      : pendingActions;
    return sortActionsForQueue(list, sortMode);
  }, [pendingActions, query, sortMode]);

  const groups = useMemo(() => groupActionsByTechnique(sorted), [sorted]);
  const groupEntries = useMemo(() => sortTechniqueGroups(groups), [groups]);
  const selectedAction = sorted.find(action => action.action_id === selectedId) || sorted[0] || null;

  const refresh = useCallback(async () => {
    try {
      const data = await getPendingActions();
      useEngagementStore.setState({ pendingActions: data.pending || [] });
      setRecentResolved(data.recent || []);
      setDiagnostics(data.diagnostics || null);
    } catch { /* keep current queue visible */ }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const copyText = useCallback(async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      window.setTimeout(() => setCopied(null), 1500);
    } catch {
      setCopied(null);
    }
  }, []);

  const toggleSelect = useCallback((id: string) => {
    setSelectedIds(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  }, []);

  // Bulk resolve — every id routes through the same canonical approve/deny path as
  // the single action (the batch endpoint loops queue.approve/deny), so audit + OPSEC
  // accounting stay identical. Denials always carry a reason.
  const runBulk = useCallback(async (ids: string[], verb: 'approve' | 'deny', reason?: string) => {
    const uniq = [...new Set(ids)];
    if (uniq.length === 0 || bulkBusy) return;
    setBulkBusy(true);
    try {
      const res = verb === 'approve' ? await approveBatch(uniq) : await denyBatch(uniq, reason!);
      addToast({
        type: res.resolved > 0 ? (verb === 'approve' ? 'success' : 'info') : 'warning',
        title: verb === 'approve' ? 'Approved' : 'Denied',
        message: `${res.resolved}/${res.total} ${verb === 'approve' ? 'approved' : 'denied'}`,
      });
      setSelectedIds(new Set());
      setBulkDenyIds(null);
      setBulkReason('');
      await refresh();
    } catch (err) {
      addToast({ type: 'error', title: `Bulk ${verb} failed`, message: err instanceof Error ? err.message : String(err) });
    } finally {
      setBulkBusy(false);
    }
  }, [bulkBusy, addToast, refresh]);

  // Keyboard single-approve of the FOCUSED row — routes through the single-action
  // path (never the batch endpoint), so it can't touch the multi-select. Reuses
  // bulkBusy to serialize against the bulk bar. One deliberate keypress = one action.
  const approveFocused = useCallback(async (id: string) => {
    if (bulkBusy) return;
    setBulkBusy(true);
    try {
      await approveAction(id, { notes: 'approved from dashboard (keyboard)' });
      addToast({ type: 'success', title: 'Approved', message: id });
      await refresh();
    } catch (err) {
      addToast({ type: 'error', title: 'Approve failed', message: err instanceof Error ? err.message : String(err) });
    } finally {
      setBulkBusy(false);
    }
  }, [bulkBusy, addToast, refresh]);

  // Keyboard triage — approve / navigate / select the focused action. Deny stays
  // click-driven because a reason is always required (no reason-less keystroke deny).
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // Ignore OS key auto-repeat: a held key must NOT walk down and approve the
      // whole queue. Only deliberate, distinct presses decide actions.
      if (e.repeat) return;
      const t = e.target as HTMLElement | null;
      if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)) return;
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (sorted.length === 0) return;
      const idx = Math.max(0, sorted.findIndex(a => a.action_id === selectedAction?.action_id));
      if (e.key === 'j') { const n = sorted[Math.min(idx + 1, sorted.length - 1)]; if (n) { setSelectedId(n.action_id); e.preventDefault(); } }
      else if (e.key === 'k') { const n = sorted[Math.max(idx - 1, 0)]; if (n) { setSelectedId(n.action_id); e.preventDefault(); } }
      else if (e.key === 'a' && selectedAction) {
        e.preventDefault();
        // While assembling a batch (Select mode with a selection), 'a' is a no-op —
        // the operator is using the visible bulk bar; a stray 'a' must neither
        // bypass the selection nor wipe it. Otherwise approve just the focused row
        // and advance focus to the next queued action (like 'j'), so repeated
        // presses triage down the list instead of resetting focus to the top.
        if (batchMode && selectedIds.size > 0) return;
        const next = sorted[idx + 1] || sorted[idx - 1] || null;
        void approveFocused(selectedAction.action_id);
        if (next) setSelectedId(next.action_id);
      }
      else if (e.key === 'x' && selectedAction) { toggleSelect(selectedAction.action_id); e.preventDefault(); }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [sorted, selectedAction, approveFocused, toggleSelect, batchMode, selectedIds]);

  const selectedList = [...selectedIds];

  return (
    <div className="h-[calc(100vh-7rem)] min-h-[680px] flex flex-col gap-4">
      <PageHeader
        title="Approvals"
        meta={`(${pendingActions.length} pending) · a/j/k to triage · Select for bulk`}
        actions={(
          <FilterBar>
            <input
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Filter actions..."
              className="settings-input w-56"
            />
            <select value={sortMode} onChange={e => setSortMode(e.target.value as ActionSortMode)} className="settings-input w-auto text-xs">
              <option value="risk">Risk</option>
              <option value="arrival">Arrival</option>
              <option value="noise-desc">Noise</option>
              <option value="timeout-asc">Timeout</option>
            </select>
            {pendingActions.length > 0 && (
              <ActionButton onClick={() => { setBatchMode(v => !v); setSelectedIds(new Set()); }} variant={batchMode ? 'primary' : 'secondary'}>
                {batchMode ? 'Done' : 'Select'}
              </ActionButton>
            )}
            <ActionButton onClick={refresh} variant="secondary">
              Refresh
            </ActionButton>
          </FilterBar>
        )}
      />

      {/* Bulk action bar (batch mode + a selection) — or the shared deny-reason bar. */}
      {batchMode && selectedList.length > 0 && bulkDenyIds === null && (
        <div className="flex items-center gap-2 rounded-md border border-accent/30 bg-accent/5 px-3 py-2 text-xs">
          <span className="font-medium text-foreground">{selectedList.length} selected</span>
          <ActionButton variant="success" size="xs" disabled={bulkBusy} onClick={() => void runBulk(selectedList, 'approve')}>Approve selected</ActionButton>
          <ActionButton variant="danger" size="xs" disabled={bulkBusy} onClick={() => { setBulkDenyIds(selectedList); setBulkReason(''); }}>Deny selected…</ActionButton>
          <ActionButton variant="ghost" size="xs" disabled={bulkBusy} onClick={() => setSelectedIds(new Set())}>Deselect</ActionButton>
        </div>
      )}
      {bulkDenyIds !== null && (
        <div className="flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs">
          <span className="flex-shrink-0 text-muted-foreground">Deny {bulkDenyIds.length} —</span>
          <input
            autoFocus
            value={bulkReason}
            onChange={e => setBulkReason(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && isDenyReasonValid(bulkReason)) void runBulk(bulkDenyIds, 'deny', bulkReason.trim());
              if (e.key === 'Escape') setBulkDenyIds(null);
            }}
            placeholder="Reason for denial (required)…"
            className="flex-1 rounded border border-border bg-surface px-2 py-1 text-xs outline-none focus:border-accent"
            disabled={bulkBusy}
          />
          <ActionButton variant="danger" size="xs" disabled={bulkBusy || !isDenyReasonValid(bulkReason)} onClick={() => void runBulk(bulkDenyIds, 'deny', bulkReason.trim())}>Confirm deny</ActionButton>
          <ActionButton variant="ghost" size="xs" disabled={bulkBusy} onClick={() => setBulkDenyIds(null)}>Cancel</ActionButton>
        </div>
      )}

      {pendingActions.length === 0 ? (
        <ActionEmptyState
          diagnostics={diagnostics}
          connected={connected}
          recentResolvedCount={recentResolved.length}
          onRefresh={refresh}
        />
      ) : (
        <div className="grid grid-cols-[minmax(360px,460px)_1fr] gap-4 flex-1 min-h-0">
          <PanelSection className="p-0 overflow-hidden min-h-0 flex flex-col">
            <div className="grid grid-cols-3 border-b border-border text-center text-xs">
              <ActionStat label="High" value={pendingActions.filter(a => computeActionRisk(a).label === 'HIGH').length} tone="destructive" />
              <ActionStat label="Warnings" value={pendingActions.filter(a => a.validation_result === 'warning_only').length} tone="warning" />
              <ActionStat label="Terminal" value={pendingActions.length} tone="accent" />
            </div>
            <div className="overflow-y-auto p-2 space-y-3">
              {groupEntries.map(([technique, actions]) => (
                <div key={technique} className="space-y-1.5">
                  <div className="flex items-center justify-between px-1 text-[10px] uppercase tracking-wider text-muted-foreground">
                    <span>{technique} · {actions.length}</span>
                    <button
                      onClick={() => void runBulk(actions.map(a => a.action_id), 'approve')}
                      disabled={bulkBusy}
                      className="rounded px-1.5 py-0.5 normal-case text-muted-foreground hover:text-success disabled:opacity-50"
                      title={`Approve all ${actions.length} ${technique} action(s)`}
                    >
                      Approve all ({actions.length})
                    </button>
                  </div>
                  {actions.map(action => (
                    <ActionQueueRow
                      key={action.action_id}
                      action={action}
                      selected={selectedAction?.action_id === action.action_id}
                      batchMode={batchMode}
                      checked={selectedIds.has(action.action_id)}
                      onToggleSelect={() => toggleSelect(action.action_id)}
                      onSelect={() => setSelectedId(action.action_id)}
                    />
                  ))}
                </div>
              ))}
              {sorted.length === 0 && <EmptyPanelState message="No actions match the filter." className="m-2" />}
            </div>
          </PanelSection>

          {selectedAction ? (
            <ActionDetail
              action={selectedAction}
              graph={graph}
              sessions={sessions}
              frontier={frontier}
              copied={copied}
              onCopy={copyText}
              onOpenSessions={() => navigateToPanel('sessions')}
              onOpenFrontier={(nodeId) => navigateToPanel('frontier', nodeId)}
            />
          ) : (
            <PanelSection>
              <EmptyState message="Select an action to inspect terminal approval context." />
            </PanelSection>
          )}
        </div>
      )}
    </div>
  );
}

function ActionEmptyState({
  diagnostics,
  connected,
  recentResolvedCount,
  onRefresh,
}: {
  diagnostics: ActionQueueDiagnostics | null;
  connected: boolean;
  recentResolvedCount: number;
  onRefresh: () => void;
}) {
  const approvalMode = diagnostics?.approval_mode || 'auto-approve';
  const reason = !connected
    ? 'Dashboard websocket is disconnected. Polling can still recover persisted approvals, but live updates may be delayed.'
    : approvalMode === 'auto-approve'
      ? 'Current policy auto-approves actions, so the terminal approval queue is expected to stay empty.'
      : diagnostics?.latest_action_at && !diagnostics.latest_approval_at
        // approve-all / approve-critical DO gate actions — so don't claim they "did not require approval".
        ? `Nothing is waiting for approval right now under the current OPSEC policy (${approvalMode}).`
        : 'When an action waits for terminal review, it will appear here with copyable approval commands.';

  return (
    <PanelSection className="min-h-80">
      <div className="flex h-full min-h-72 flex-col justify-center">
        <div className="max-w-3xl">
          <div className="flex items-center gap-2">
            <h3 className="text-base font-semibold text-foreground">No pending terminal approvals</h3>
            <StatusPill tone={connected ? 'success' : 'danger'}>{connected ? 'live' : 'disconnected'}</StatusPill>
          </div>
          <p className="mt-2 text-sm text-muted-foreground">{reason}</p>
          <div className="mt-4 grid grid-cols-2 gap-2 text-xs md:grid-cols-5">
            <DetailFact label="Approval mode" value={approvalMode} />
            <DetailFact label="OPSEC" value={diagnostics?.opsec_enabled ? 'enabled' : 'not enforced'} />
            <DetailFact label="Last action" value={diagnostics?.latest_action_at ? formatRelativeTime(diagnostics.latest_action_at) : '—'} />
            <DetailFact label="Last approval" value={diagnostics?.latest_approval_at ? formatRelativeTime(diagnostics.latest_approval_at) : '—'} />
            <DetailFact label="Resolved recent" value={recentResolvedCount} />
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            <ActionButton onClick={onRefresh} variant="secondary">Refresh</ActionButton>
            {diagnostics?.latest_action_type && (
              <span className="rounded border border-border bg-background/40 px-2 py-1 text-xs text-muted-foreground">
                latest: {diagnostics.latest_action_type}
              </span>
            )}
            {diagnostics?.latest_approval_status && (
              <span className="rounded border border-border bg-background/40 px-2 py-1 text-xs text-muted-foreground">
                approval: {diagnostics.latest_approval_status}
              </span>
            )}
          </div>
        </div>
      </div>
    </PanelSection>
  );
}

function ActionQueueRow({ action, selected, batchMode, checked, onToggleSelect, onSelect }: {
  action: PendingAction; selected: boolean; batchMode: boolean; checked: boolean; onToggleSelect: () => void; onSelect: () => void;
}) {
  const risk = computeActionRisk(action);
  const lifecycle = classifyActionLifecycle(action);
  const node = actionNodeId(action);
  const cue = recommendedDecision(action); // visual-only triage cue

  return (
    <div className="flex items-start gap-2">
      {batchMode && (
        <input
          type="checkbox"
          checked={checked}
          onChange={onToggleSelect}
          className="mt-2.5 flex-shrink-0 accent-accent"
          aria-label="Select action for bulk resolve"
        />
      )}
      <button
        onClick={onSelect}
        className={cn(
          'min-w-0 flex-1 rounded border border-border bg-surface px-2.5 py-2 text-left transition-colors hover:border-accent/40 hover:bg-hover/40',
          selected && 'border-accent/50 bg-accent/5',
          // Subtle recommend cue — a left edge tint. Visual only; never auto-acts.
          cue === 'approve' && 'border-l-2 border-l-success/50',
          cue === 'deny' && 'border-l-2 border-l-destructive/50',
        )}
      >
        <div className="flex items-center gap-2">
          <StatusPill className={risk.cls}>{risk.label}</StatusPill>
          <StatusPill className={lifecycleClass(lifecycle)}>{lifecycleLabel(lifecycle)}</StatusPill>
          <span className="ml-auto text-[10px] text-muted-foreground">{formatRelativeTime(action.submitted_at)}</span>
        </div>
        <div className="mt-1 text-xs font-medium text-foreground line-clamp-2">{action.description}</div>
        <div className="mt-1 flex items-center gap-2 text-[10px] text-muted-foreground">
          <span className="font-mono truncate">{action.action_id.slice(0, 12)}</span>
          {node && <span className="font-mono truncate">{node}</span>}
          <span>noise {actionNoise(action).toFixed(2)}</span>
        </div>
      </button>
    </div>
  );
}

function ActionDetail({
  action,
  graph,
  sessions,
  frontier,
  copied,
  onCopy,
  onOpenSessions,
  onOpenFrontier,
}: {
  action: PendingAction;
  graph: ReturnType<typeof useEngagementStore.getState>['graph'];
  sessions: ReturnType<typeof useEngagementStore.getState>['sessions'];
  frontier: ReturnType<typeof useEngagementStore.getState>['frontier'];
  copied: string | null;
  onCopy: (key: string, text: string) => void;
  onOpenSessions: () => void;
  onOpenFrontier: (nodeId?: string) => void;
}) {
  const risk = computeActionRisk(action);
  const node = actionNodeId(action);
  const related = node ? deriveNodeRelationships(node, { graph, sessions, pendingActions: [action], frontier }) : null;
  const budgetPct = action.opsec_context?.noise_budget_remaining !== undefined ? Math.round(action.opsec_context.noise_budget_remaining * 100) : null;
  const approveCommand = terminalApprovalCommand(action, 'approve');
  const denyCommand = terminalApprovalCommand(action, 'deny');
  const summary = terminalApprovalSummary(action);
  const signals = action.opsec_context?.defensive_signals || [];
  const [explanation, setExplanation] = useState<ActionExplanation | null>(null);

  useEffect(() => {
    let cancelled = false;
    explainAction(action.action_id)
      .then(data => { if (!cancelled) setExplanation(data); })
      .catch(() => { if (!cancelled) setExplanation(null); });
    return () => { cancelled = true; };
  }, [action.action_id]);

  return (
    <div className="min-w-0 min-h-0 flex flex-col gap-3 overflow-y-auto">
      <PanelSection title="Terminal Approval Context">
        <div className="flex items-start gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 mb-2">
              <StatusPill className={risk.cls}>{risk.label}</StatusPill>
              <StatusPill className={lifecycleClass(classifyActionLifecycle(action))}>{lifecycleLabel(classifyActionLifecycle(action))}</StatusPill>
              {action.timeout_at && <CountdownTimer targetIso={action.timeout_at} className="ml-auto" />}
            </div>
            <h3 className="text-base font-semibold text-foreground">{action.technique}</h3>
            <p className="mt-1 text-sm text-muted-foreground">{action.description}</p>
          </div>
        </div>

        <div className="mt-3 grid grid-cols-2 lg:grid-cols-4 gap-2 text-xs">
          <DetailFact label="Action" value={action.action_id} mono />
          <DetailFact label="Noise" value={actionNoise(action).toFixed(2)} />
          <DetailFact label="Budget" value={budgetPct !== null ? `${budgetPct}%` : '—'} />
          <DetailFact label="Approach" value={action.opsec_context?.recommended_approach || 'terminal'} />
        </div>

        <div className="mt-3 rounded border border-accent/20 bg-accent/5 p-3">
          <div className="text-xs font-medium text-accent mb-1">Terminal-forward review</div>
          <div className="text-xs text-muted-foreground mb-2">
            Use the terminal as the approval surface for this slice. The dashboard is preparing context, not taking over execution.
          </div>
          <CommandCopy label="Context" value={summary} copied={copied === 'summary'} onCopy={() => onCopy('summary', summary)} />
          <CommandCopy label="Approve" value={approveCommand} copied={copied === 'approve'} onCopy={() => onCopy('approve', approveCommand)} />
          <CommandCopy label="Deny" value={denyCommand} copied={copied === 'deny'} onCopy={() => onCopy('deny', denyCommand)} />
        </div>
      </PanelSection>

      <PanelSection title="Related Workspace">
        <div className="space-y-2">
          {node && <GraphNodeLinks nodeId={node} />}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-2 text-xs">
            <RelationshipButton label="Sessions" count={related?.sessions.length || 0} onClick={onOpenSessions} />
            <RelationshipButton label="Frontier" count={related?.frontier.length || 0} onClick={() => onOpenFrontier(node || undefined)} />
            <RelationshipButton label="Target IP" count={action.target_ip ? 1 : 0} value={action.target_ip || '—'} />
            <RelationshipButton label="Validation" count={action.validation_result ? 1 : 0} value={action.validation_result || '—'} />
          </div>
          {signals.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {signals.map(signal => (
                <span key={signal} className="text-[10px] px-1.5 py-0.5 rounded bg-warning/10 text-warning">{signal}</span>
              ))}
            </div>
          )}
        </div>
      </PanelSection>

      {explanation?.found && (
        <PanelSection title="Read-Only Introspection">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-2 text-xs mb-3">
            <DetailFact label="Decision Agent" value={explanation.agent_id || '—'} mono />
            <DetailFact label="Frontier" value={explanation.frontier_item_id || '—'} mono />
            <DetailFact label="Validation" value={explanation.validation?.validation_result || '—'} />
            <DetailFact label="Outcome" value={explanation.outcome?.classification || 'open'} />
          </div>
          <div className="rounded border border-border bg-background/40 p-2 text-xs text-muted-foreground">
            {explanation.log_thought_chain[0]?.description || explanation.outcome?.description || 'No log_thought chain has been recorded for this action yet.'}
          </div>
        </PanelSection>
      )}

      <PanelSection title="Resolve">
        <div className="text-xs text-muted-foreground mb-2">
          Approve or deny here, or copy the commands above to act from the terminal — both route through the same
          approval record, so the audit trail and OPSEC accounting stay consistent.
        </div>
        <ActionResolveControls action={action} />
      </PanelSection>
    </div>
  );
}

// In-dashboard approve/deny for the deep triage view, mirroring the console
// "Needs you" lane. Routes through POST /api/actions/:id/{approve,deny} →
// resolveApprovalRequest (canonical). The store drops the action on the
// `action_resolved` WS push, so the selected action advances on its own; we
// don't mutate optimistically. Denials require a reason (audit semantics).
function ActionResolveControls({ action }: { action: PendingAction }) {
  const addToast = useToastStore(s => s.addToast);
  const [busy, setBusy] = useState(false);
  const [denying, setDenying] = useState(false);
  const [reason, setReason] = useState('');
  const cue = recommendedDecision(action); // visual-only: soft-ring the suggested button

  // Reset the inline deny form when the operator selects a different action.
  useEffect(() => { setDenying(false); setReason(''); setBusy(false); }, [action.action_id]);

  const approve = async () => {
    setBusy(true);
    try {
      await approveAction(action.action_id, { notes: 'approved from dashboard' });
      addToast({ type: 'success', title: 'Action approved', message: action.technique || action.action_id });
    } catch (err) {
      addToast({ type: 'error', title: 'Approve failed', message: err instanceof Error ? err.message : String(err) });
      setBusy(false);
    }
  };

  const deny = async () => {
    if (!isDenyReasonValid(reason)) return;
    setBusy(true);
    try {
      await denyAction(action.action_id, reason.trim());
      addToast({ type: 'info', title: 'Action denied', message: action.technique || action.action_id });
    } catch (err) {
      addToast({ type: 'error', title: 'Deny failed', message: err instanceof Error ? err.message : String(err) });
      setBusy(false);
    }
  };

  return (
    <div className="rounded border border-border bg-background/40 p-3">
      {!denying ? (
        <div className="flex items-center gap-2">
          <ActionButton variant="success" disabled={busy} onClick={approve} className={cn(cue === 'approve' && 'ring-1 ring-success/60')}>Approve</ActionButton>
          <ActionButton variant="danger" disabled={busy} onClick={() => setDenying(true)} className={cn(cue === 'deny' && 'ring-1 ring-destructive/60')}>Deny</ActionButton>
          {cue && <span className="text-[10px] text-muted-foreground">suggested: {cue}</span>}
        </div>
      ) : (
        <div className="flex items-center gap-2">
          <input
            autoFocus
            className="flex-1 rounded border border-border bg-surface px-2 py-1 text-xs outline-none focus:border-accent"
            placeholder="Reason for denial (required)…"
            value={reason}
            onChange={e => setReason(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter') void deny();
              if (e.key === 'Escape') { setDenying(false); setReason(''); }
            }}
            disabled={busy}
          />
          <ActionButton variant="danger" disabled={busy || !isDenyReasonValid(reason)} onClick={deny}>Confirm deny</ActionButton>
          <ActionButton variant="ghost" disabled={busy} onClick={() => { setDenying(false); setReason(''); }}>Cancel</ActionButton>
        </div>
      )}
    </div>
  );
}

function ActionStat({ label, value, tone }: { label: string; value: number; tone?: 'destructive' | 'warning' | 'accent' }) {
  return (
    <div className="py-2 border-r border-border last:border-r-0">
      <div className={cn(
        'text-base font-semibold tabular-nums',
        tone === 'destructive' && 'text-destructive',
        tone === 'warning' && 'text-warning',
        tone === 'accent' && 'text-accent',
      )}>{value}</div>
      <div className="text-[10px] text-muted-foreground">{label}</div>
    </div>
  );
}

function DetailFact({ label, value, mono }: { label: string; value: string | number; mono?: boolean }) {
  return (
    <div className="rounded border border-border bg-elevated px-2 py-1.5 min-w-0">
      <div className="text-[10px] text-muted-foreground">{label}</div>
      <div className={cn('text-xs text-foreground truncate', mono && 'font-mono')}>{value}</div>
    </div>
  );
}

function RelationshipButton({ label, count, value, onClick }: { label: string; count: number; value?: string; onClick?: () => void }) {
  const Comp = onClick ? 'button' : 'div';
  return (
    <Comp onClick={onClick} className={cn('rounded border border-border bg-elevated px-2 py-1.5 text-left', onClick && 'hover:border-accent/40 hover:bg-hover')}>
      <div className="text-[10px] text-muted-foreground">{label}</div>
      <div className="text-xs text-foreground truncate">{value ?? count}</div>
    </Comp>
  );
}

function CommandCopy({ label, value, copied, onCopy }: { label: string; value: string; copied: boolean; onCopy: () => void }) {
  return (
    <div className="mt-1 flex items-center gap-2">
      <span className="w-14 text-[10px] uppercase text-muted-foreground">{label}</span>
      <code className="flex-1 rounded bg-background px-2 py-1 text-[11px] text-foreground overflow-x-auto">{value}</code>
      <ActionButton onClick={onCopy} variant="secondary" size="xs">
        {copied ? 'Copied' : 'Copy'}
      </ActionButton>
    </div>
  );
}

function lifecycleLabel(lifecycle: ActionLifecycle): string {
  if (lifecycle === 'timeout_soon') return 'timeout soon';
  if (lifecycle === 'blocked_warning') return 'warning';
  if (lifecycle === 'high_risk') return 'high risk';
  return 'terminal approval';
}

function lifecycleClass(lifecycle: ActionLifecycle): string {
  if (lifecycle === 'timeout_soon') return 'bg-destructive/10 text-destructive';
  if (lifecycle === 'blocked_warning') return 'bg-warning/10 text-warning';
  if (lifecycle === 'high_risk') return 'bg-destructive/10 text-destructive';
  return 'bg-accent/10 text-accent';
}
