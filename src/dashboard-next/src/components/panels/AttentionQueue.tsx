import { useState, useMemo } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import { useToastStore } from '../../stores/toast-store';
import * as api from '../../lib/api';
import { isDenyReasonValid } from '../../lib/console-approvals';
import { buildAttentionQueue, type AttentionItem } from '../../lib/attention-queue';
import { recommendedDecision } from '../../lib/action-queue';
import { cn } from '../../lib/utils';
import { ActionButton, StatusPill } from '../shared/primitives';

// Phase 5 (Mission Control) - the single "Needs you" surface, merging pending
// approvals, agent questions, and failed agents into one prioritized queue with
// exactly one item expanded. Replaces the separate approvals lane + questions
// inbox. View-model + ordering are in lib/attention-queue.ts (tested); approve/
// deny route through the canonical resolveApprovalRequest path and clear off the
// action_resolved WS push (the store drops them). Hidden when nothing waits.

const DISPLAY_CAP = 6;

export function AttentionQueue({
  agentQueries,
  proposedPlans,
  onAnswered,
  onPlanResolved,
  onSelectAgent,
  onForceRemove,
  onTriageAll,
  proofGap,
  onReviewProof,
  onSelectItem,
  full = false,
}: {
  agentQueries: api.AgentQuery[];
  proposedPlans: api.ProposedPlan[];
  onAnswered: () => void;
  onPlanResolved: () => void;
  onSelectAgent: (taskId: string) => void;
  onForceRemove: (taskId: string) => Promise<void> | void;
  onTriageAll: () => void;
  proofGap?: { draft: number; needs_validation: number };
  onReviewProof?: () => void;
  onSelectItem?: (item: AttentionItem) => void;
  /** Main Operate attention view renders the complete queue; the compact console
   *  embedding retains the historical one-row summary behavior. */
  full?: boolean;
}) {
  const pendingActions = useEngagementStore(s => s.pendingActions);
  const agents = useEngagementStore(s => s.agents);
  const view = useMemo(
    () => buildAttentionQueue({ pendingActions, agentQueries, proposedPlans, agents, proofGap }),
    [pendingActions, agentQueries, proposedPlans, agents, proofGap],
  );
  const [expandedId, setExpandedId] = useState<string | null>(null);
  // Compact by default: show only the summary line + the single top-priority item
  // (still actionable inline). The operator opens the rest on demand so a queue of
  // 4–6 expanded rows can't own the viewport and bury the fleet below.
  const [open, setOpen] = useState(full);
  const addToast = useToastStore(s => s.addToast);
  const [bulkBusy, setBulkBusy] = useState(false);

  if (view.total === 0) return null;

  // Collapsed → just the top item; open → the visible slice (one expanded at a
  // time). Default the expanded item to the top if the prior selection is gone.
  const visible = full ? view.items : open ? view.items.slice(0, DISPLAY_CAP) : view.items.slice(0, 1);
  const activeId = visible.some(i => i.id === expandedId) ? expandedId : visible[0]?.id ?? null;
  const overflow = view.total - visible.length;
  // Items the toggle reveals INLINE when opened (capped at DISPLAY_CAP). Anything
  // beyond that stays behind the "+N more → Triage all" link, so the toggle must
  // not promise "all" - it shows up to this many more rows in place.
  const inlineMore = Math.min(view.total, DISPLAY_CAP) - 1;

  // Compact bulk-clear over ALL pending approvals (not just the visible slice), so
  // the operator can drain the routine queue from the console without opening the
  // full Approvals panel. Deny stays single (per-item judgement + a reason).
  const approvalIds = pendingActions.map(a => a.action_id);
  const safeIds = pendingActions.filter(a => recommendedDecision(a) === 'approve').map(a => a.action_id);
  const bulkApprove = async (ids: string[], label: string) => {
    if (ids.length === 0 || bulkBusy) return;
    setBulkBusy(true);
    try {
      const res = await api.approveBatch(ids);
      addToast({ type: res.resolved > 0 ? 'success' : 'warning', title: label, message: `${res.resolved}/${res.total} approved` });
    } catch (err) {
      addToast({ type: 'error', title: `${label} failed`, message: err instanceof Error ? err.message : String(err) });
    } finally {
      setBulkBusy(false);
    }
  };

  return (
    <div className={cn(full ? 'border-y border-border-subtle bg-transparent' : 'space-y-2 rounded-md border border-warning/40 bg-warning/5 p-3')}>
      <div className={cn('flex items-center gap-2', full && 'min-h-10 border-b border-border-subtle px-3 py-2')}>
        <span className="text-xs font-medium text-warning">⚠ Needs you</span>
        <span className="rounded-full bg-warning/20 px-1.5 text-[10px] text-warning">{view.total}</span>
        {view.counts.approval > 0 && <span className="text-[10px] text-muted-foreground">{view.counts.approval} approval{view.counts.approval !== 1 ? 's' : ''}</span>}
        {view.counts.question > 0 && <span className="text-[10px] text-muted-foreground">{view.counts.question} question{view.counts.question !== 1 ? 's' : ''}</span>}
        {view.counts.plan > 0 && <span className="text-[10px] text-muted-foreground">{view.counts.plan} plan{view.counts.plan !== 1 ? 's' : ''}</span>}
        {view.counts.stuck > 0 && <span className="text-[10px] text-muted-foreground">{view.counts.stuck} stuck</span>}
        {view.counts.failed > 0 && <span className="text-[10px] text-muted-foreground">{view.counts.failed} failed</span>}
        {view.counts.proof_gap > 0 && <span className="text-[10px] text-muted-foreground">proof gap</span>}
        <div className="ml-auto flex items-center gap-3">
          {!full && view.total > 1 && (
            <button onClick={() => setOpen(o => !o)} className="text-[10px] text-muted-foreground hover:text-foreground">
              {open ? '▾ hide' : `▸ show ${inlineMore} more`}
            </button>
          )}
          {pendingActions.length > 0 && (
            <>
              <button onClick={() => void bulkApprove(approvalIds, 'Approve all')} disabled={bulkBusy} className="text-[10px] text-success hover:underline disabled:opacity-50" title="Approve every pending action">Approve all ({approvalIds.length})</button>
              {safeIds.length > 0 && safeIds.length < approvalIds.length && (
                <button onClick={() => void bulkApprove(safeIds, 'Approve safe')} disabled={bulkBusy} className="text-[10px] text-success/80 hover:underline disabled:opacity-50" title="Approve only the low-risk (recommended) actions">Approve safe ({safeIds.length})</button>
              )}
              <button onClick={onTriageAll} className="text-[10px] text-accent hover:underline">Triage all →</button>
            </>
          )}
        </div>
      </div>

      <div className={cn('space-y-1.5', open && 'max-h-[40vh] overflow-y-auto pr-1')}>
        {visible.map(item => (
          <AttentionRow
            key={item.id}
            item={item}
            expanded={item.id === activeId}
            // Expansion-only: clicking a row focuses it. There's intentionally no
            // collapse-to-zero - the queue always keeps one item expanded, and a
            // sentinel collapse wouldn't survive the store/poll re-render anyway.
            onToggle={() => { setExpandedId(item.id); onSelectItem?.(item); }}
            onAnswered={onAnswered}
            onPlanResolved={onPlanResolved}
            onSelectAgent={onSelectAgent}
            onForceRemove={onForceRemove}
            onReviewProof={onReviewProof}
            full={full}
          />
        ))}
        {!full && open && overflow > 0 && (
          <button onClick={onTriageAll} className="text-[10px] text-muted-foreground hover:text-accent">
            +{overflow} more →
          </button>
        )}
      </div>
    </div>
  );
}

/** Reused by the URL-backed attention inspector so its decision controls stay
 * identical to the inline queue actions. */
export function AttentionDecisionActions({
  item,
  onAnswered,
  onPlanResolved,
  onReviewProof,
}: {
  item: AttentionItem;
  onAnswered: () => void;
  onPlanResolved: () => void;
  onReviewProof?: () => void;
}) {
  if (item.kind === 'approval' && item.actionId) return <ApprovalActions actionId={item.actionId} title={item.title} />;
  if (item.kind === 'question' && item.queryIds?.length) return <AnswerActions queryIds={item.queryIds} options={item.options} onAnswered={onAnswered} />;
  if (item.kind === 'plan' && item.planId) return <PlanActions planId={item.planId} onResolved={onPlanResolved} />;
  if (item.kind === 'proof_gap' && onReviewProof) return <ActionButton size="xs" variant="purple" onClick={onReviewProof}>Review proof gaps →</ActionButton>;
  return null;
}

function AttentionRow({
  item,
  expanded,
  onToggle,
  onAnswered,
  onPlanResolved,
  onSelectAgent,
  onForceRemove,
  onReviewProof,
  full,
}: {
  item: AttentionItem;
  expanded: boolean;
  onToggle: () => void;
  onAnswered: () => void;
  onPlanResolved: () => void;
  onSelectAgent: (taskId: string) => void;
  onForceRemove: (taskId: string) => Promise<void> | void;
  onReviewProof?: () => void;
  full: boolean;
}) {
  // Force-remove is an escape hatch for a wedged/failed agent: kill + clear in one
  // click without leaving the "needs you" surface. The parent owns canonicalization
  // + refresh + error toast (forceRemoveAgent); we only track the in-flight state.
  const [removing, setRemoving] = useState(false);
  const forceRemove = async () => {
    if (!item.taskId || removing) return;
    setRemoving(true);
    try { await onForceRemove(item.taskId); }
    finally { setRemoving(false); }   // success unmounts the row; modern React no-ops the stale set
  };
  const kindTone = item.kind === 'question' ? 'text-warning' : item.kind === 'failed' ? 'text-destructive' : item.kind === 'stuck' ? 'text-warning' : item.kind === 'proof_gap' ? 'text-purple' : item.kind === 'plan' ? 'text-accent' : 'text-accent';
  return (
    <div className={cn(full ? 'border-b border-border-subtle bg-transparent' : 'rounded border bg-surface', !full && (expanded ? 'border-accent/40' : 'border-border'), full && expanded && 'bg-accent/[0.035]')}>
      <button onClick={onToggle} className={cn('flex w-full items-center gap-2 text-left text-xs', full ? 'min-h-10 px-3 py-2' : 'px-2 py-1.5')}>
        <span className={cn('text-[10px] uppercase tracking-wide', kindTone)}>{item.kind === 'proof_gap' ? 'proof gap' : item.kind}</span>
        {item.risk && <StatusPill className={item.risk.cls}>{item.risk.label}</StatusPill>}
        <span className="min-w-0 flex-1 truncate text-foreground">{item.title}</span>
        {item.agentLabel && <span className="flex-shrink-0 font-mono text-[10px] text-muted-foreground">{item.agentLabel}</span>}
      </button>
      {expanded && (
        <div className={cn('border-t', full ? 'border-border-subtle px-3 py-3 pl-[5.25rem]' : 'border-border px-2 py-2')}>
          <div className="mb-2 whitespace-pre-wrap break-words text-[11px] text-muted-foreground">{item.detail}</div>
          {item.kind === 'question' && item.queryIds && item.queryIds.length > 1 && (
            <div className="mb-2 text-[10px] text-warning">
              Answering fans out to {item.queryIds.length} agents{item.clusterAgentLabels && item.clusterAgentLabels.length > 0 ? `: ${item.clusterAgentLabels.join(', ')}` : ''}.
            </div>
          )}
          {item.kind === 'approval' && item.actionId && <ApprovalActions actionId={item.actionId} title={item.title} />}
          {item.kind === 'question' && item.queryIds && item.queryIds.length > 0 && <AnswerActions queryIds={item.queryIds} options={item.options} onAnswered={onAnswered} />}
          {item.kind === 'plan' && item.planId && <PlanActions planId={item.planId} onResolved={onPlanResolved} />}
          {(item.kind === 'failed' || item.kind === 'stuck') && item.taskId && (
            <div className="flex flex-wrap gap-1.5">
              <ActionButton size="xs" variant="secondary" onClick={() => onSelectAgent(item.taskId!)}>View agent →</ActionButton>
              <ActionButton
                size="xs"
                variant="danger"
                disabled={removing}
                title="Force stop & remove - kills the process and clears the agent even if Cancel won't"
                onClick={forceRemove}
              >
                {removing ? 'Removing…' : 'Force remove'}
              </ActionButton>
            </div>
          )}
          {item.kind === 'proof_gap' && onReviewProof && (
            <ActionButton size="xs" variant="purple" onClick={onReviewProof}>Review proof gaps →</ActionButton>
          )}
        </div>
      )}
    </div>
  );
}

function ApprovalActions({ actionId, title }: { actionId: string; title: string }) {
  const addToast = useToastStore(s => s.addToast);
  const [busy, setBusy] = useState(false);
  const [denying, setDenying] = useState(false);
  const [reason, setReason] = useState('');

  const approve = async () => {
    setBusy(true);
    try {
      await api.approveAction(actionId, { notes: 'approved from console' });
      addToast({ type: 'success', title: 'Action approved', message: title });
    } catch (err) {
      addToast({ type: 'error', title: 'Approve failed', message: err instanceof Error ? err.message : String(err) });
      setBusy(false);
    }
  };
  const deny = async () => {
    if (!isDenyReasonValid(reason)) return;
    setBusy(true);
    try {
      await api.denyAction(actionId, reason.trim());
      addToast({ type: 'info', title: 'Action denied', message: title });
    } catch (err) {
      addToast({ type: 'error', title: 'Deny failed', message: err instanceof Error ? err.message : String(err) });
      setBusy(false);
    }
  };

  if (denying) {
    return (
      <div className="flex items-center gap-1.5">
        <input
          autoFocus
          className="flex-1 rounded border border-border bg-background px-2 py-1 text-[11px] outline-none focus:border-accent"
          placeholder="Reason for denial (required)…"
          value={reason}
          onChange={e => setReason(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') void deny(); if (e.key === 'Escape') { setDenying(false); setReason(''); } }}
          disabled={busy}
        />
        <ActionButton size="xs" variant="danger" disabled={busy || !isDenyReasonValid(reason)} onClick={deny}>Confirm deny</ActionButton>
        <ActionButton size="xs" variant="ghost" disabled={busy} onClick={() => { setDenying(false); setReason(''); }}>Cancel</ActionButton>
      </div>
    );
  }
  return (
    <div className="flex gap-1.5">
      <ActionButton size="xs" variant="success" disabled={busy} onClick={approve}>Approve</ActionButton>
      <ActionButton size="xs" variant="danger" disabled={busy} onClick={() => setDenying(true)}>Deny</ActionButton>
    </div>
  );
}

function PlanActions({ planId, onResolved }: { planId: string; onResolved: () => void }) {
  const addToast = useToastStore(s => s.addToast);
  const [busy, setBusy] = useState(false);

  const confirm = async () => {
    setBusy(true);
    try {
      await api.confirmCommand(planId);
      addToast({ type: 'success', title: 'Plan confirmed', message: 'Directive applied.' });
      onResolved();
    } catch (err) {
      addToast({ type: 'error', title: 'Confirm failed', message: err instanceof Error ? err.message : String(err) });
      setBusy(false);
    }
  };
  const dismiss = async () => {
    setBusy(true);
    try {
      await api.denyCommandPlan(planId);
      addToast({ type: 'info', title: 'Plan dismissed', message: 'Nothing was applied.' });
      onResolved();
    } catch (err) {
      addToast({ type: 'error', title: 'Dismiss failed', message: err instanceof Error ? err.message : String(err) });
      setBusy(false);
    }
  };

  return (
    <div className="flex gap-1.5">
      <ActionButton size="xs" variant="success" disabled={busy} onClick={confirm}>Confirm &amp; run</ActionButton>
      <ActionButton size="xs" variant="ghost" disabled={busy} onClick={dismiss}>Dismiss</ActionButton>
    </div>
  );
}

function AnswerActions({ queryIds, options, onAnswered }: { queryIds: string[]; options?: string[]; onAnswered: () => void }) {
  const [answer, setAnswer] = useState('');
  const [busy, setBusy] = useState(false);
  const send = async (value: string) => {
    const text = value.trim();
    if (!text || busy) return;
    setBusy(true);
    try {
      // Fan out to the whole cluster when >1; the single route keeps its
      // specific agent-gone messaging for the common one-question case.
      if (queryIds.length > 1) await api.answerAgentQueryBatch(queryIds, text);
      else await api.answerAgentQuery(queryIds[0], text);
      onAnswered();
    } catch {
      setBusy(false); // keep the card so the operator can retry
    }
  };
  return (
    <div className="space-y-1.5">
      {options && options.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {options.map((opt, i) => (
            <ActionButton key={i} size="xs" variant="secondary" disabled={busy} onClick={() => void send(opt)}>{opt}</ActionButton>
          ))}
        </div>
      )}
      <div className="flex items-center gap-1.5">
        <input
          className="flex-1 rounded border border-border bg-background px-2 py-1 text-[11px] outline-none focus:border-accent"
          placeholder="Answer…"
          value={answer}
          onChange={e => setAnswer(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') void send(answer); }}
          disabled={busy}
        />
        <ActionButton size="xs" variant="success" disabled={busy || !answer.trim()} onClick={() => void send(answer)}>Answer</ActionButton>
      </div>
    </div>
  );
}
