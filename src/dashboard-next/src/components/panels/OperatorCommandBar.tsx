import { useState, useEffect, useCallback, useRef } from 'react';
import * as api from '../../lib/api';
import { cn } from '../../lib/utils';
import { POLL } from '../../lib/polling';
import { projectPlannerCommand } from '../../lib/planner-command-state';
import { ActionButton } from '../shared/primitives';

// Phase 3A NL operator cockpit: type a plain-English command → it becomes a
// confirmable plan (grammar fast-path) or is handed to a headless planner that
// proposes one → operator confirms → executes through the validated engine path.
// The executed command + proposed plans also stream into the console below.

type Phase =
  | { kind: 'idle' }
  | { kind: 'previewing' }
  | { kind: 'preview'; planId: string; summary: string; ops: api.OperatorOp[] }
  | {
      kind: 'planning';
      commandId: string;
      plannerTaskId?: string;
      phase: 'planning_queued' | 'planning_running';
      cancelError?: string;
    }
  | { kind: 'proposed'; plan: api.ProposedPlan }
  | { kind: 'executing' }
  | { kind: 'result'; ok: boolean; text: string }
  | { kind: 'answer'; answer: api.QueryAnswer }
  | { kind: 'error'; text: string };

const ACTIVE_PLANNER_COMMAND_KEY = 'overwatch.dashboard.activePlannerCommand';

function describeOp(op: api.OperatorOp): string {
  switch (op.op) {
    case 'directive': return `${String(op.kind)} → ${String(op.agent_label ?? op.task_id)}`;
    case 'scope': return `scope +${[...(op.add_cidrs as string[] ?? []), ...(op.add_domains as string[] ?? [])].join(', ')}`;
    case 'approve': return `approve ${String(op.action_id)}`;
    case 'deny': return `deny ${String(op.action_id)}`;
    case 'dispatch': return `deploy ${String(op.archetype ?? 'agent')} → ${(op.target_node_ids as string[] ?? []).length} node(s)`;
    default: return JSON.stringify(op);
  }
}

export function OperatorCommandBar() {
  const [command, setCommand] = useState('');
  const [phase, setPhase] = useState<Phase>({ kind: 'idle' });
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pollGenerationRef = useRef(0);
  const pollAbortRef = useRef<AbortController | null>(null);
  const operatorIntentGenerationRef = useRef(0);

  const clearPoll = useCallback(() => {
    pollGenerationRef.current += 1;
    if (pollRef.current) {
      clearTimeout(pollRef.current);
      pollRef.current = null;
    }
    pollAbortRef.current?.abort();
    pollAbortRef.current = null;
  }, []);
  useEffect(() => () => clearPoll(), [clearPoll]);

  const clearStoredPlanner = useCallback(() => {
    try { sessionStorage.removeItem(ACTIVE_PLANNER_COMMAND_KEY); } catch { /* storage can be unavailable */ }
  }, []);

  const startPolling = useCallback((commandId: string, plannerTaskId?: string) => {
    clearPoll();
    const generation = pollGenerationRef.current;
    const controller = new AbortController();
    pollAbortRef.current = controller;
    try {
      sessionStorage.setItem(
        ACTIVE_PLANNER_COMMAND_KEY,
        JSON.stringify({ commandId, plannerTaskId }),
      );
    } catch { /* the durable server record remains authoritative */ }
    const schedule = () => {
      if (pollGenerationRef.current !== generation) return;
      pollRef.current = setTimeout(() => {
        void reconcile();
      }, POLL.PLAN_POLL_MS);
    };
    const reconcile = async () => {
      const requestController = new AbortController();
      const abortRequest = () => requestController.abort();
      controller.signal.addEventListener('abort', abortRequest, { once: true });
      const requestTimeout = setTimeout(() => requestController.abort(), 10_000);
      try {
        const { command: commandRecord } = await api.getApplicationCommand(
          commandId,
          requestController.signal,
        );
        if (pollGenerationRef.current !== generation) return;
        const projected = projectPlannerCommand(commandRecord, plannerTaskId);
        if (projected.kind === 'planning') {
          setPhase(previous => ({
            kind: 'planning',
            commandId,
            plannerTaskId: projected.plannerTaskId,
            phase: projected.phase,
            ...(previous.kind === 'planning'
              && previous.commandId === commandId
              && previous.cancelError
              ? { cancelError: previous.cancelError }
              : {}),
          }));
          schedule();
          return;
        }
        if (projected.kind === 'proposed') {
          clearPoll();
          clearStoredPlanner();
          setPhase({ kind: 'proposed', plan: projected.plan });
          return;
        }
        clearPoll();
        clearStoredPlanner();
        setPhase(projected);
      } catch (error) {
        if (pollGenerationRef.current !== generation || controller.signal.aborted) return;
        if (error instanceof api.DashboardApiError && error.status === 404) {
          clearPoll();
          clearStoredPlanner();
          setPhase({
            kind: 'error',
            text: 'The saved planner command no longer exists. Send the command again.',
          });
          return;
        }
        if (
          error instanceof api.DashboardApiError
          && (error.status === 401 || error.status === 403)
        ) {
          clearPoll();
          clearStoredPlanner();
          setPhase({
            kind: 'error',
            text: 'Planner status authorization failed. Reopen the dashboard with a valid token.',
          });
          return;
        }
        schedule();
      } finally {
        clearTimeout(requestTimeout);
        controller.signal.removeEventListener('abort', abortRequest);
      }
    };
    void reconcile();
  }, [clearPoll, clearStoredPlanner]);

  useEffect(() => {
    const intentGeneration = operatorIntentGenerationRef.current;
    let restoredFromBrowser = false;
    try {
      const raw = sessionStorage.getItem(ACTIVE_PLANNER_COMMAND_KEY);
      if (raw) {
        const restored = JSON.parse(raw) as { commandId?: unknown; plannerTaskId?: unknown };
        if (typeof restored.commandId === 'string') {
          restoredFromBrowser = true;
          startPolling(
            restored.commandId,
            typeof restored.plannerTaskId === 'string' ? restored.plannerTaskId : undefined,
          );
        }
      }
    } catch { /* ignore malformed/unavailable transient browser storage */ }
    if (restoredFromBrowser) return;

    // sessionStorage is only a fast pointer. Durable server state remains the
    // source of truth, so a new tab or privacy-restricted browser can still
    // rediscover the newest queued/running planner after navigation or reload.
    const controller = new AbortController();
    void api.getActiveApplicationCommands(controller.signal)
      .then(({ commands }) => {
        const activeCommand = commands[0];
        if (
          !activeCommand
          || controller.signal.aborted
          || operatorIntentGenerationRef.current !== intentGeneration
        ) return;
        const projected = projectPlannerCommand(activeCommand);
        if (projected.kind !== 'planning') return;
        startPolling(activeCommand.command_id, projected.plannerTaskId);
      })
      .catch(() => { /* transient discovery failure; a submitted command still polls directly */ });
    return () => controller.abort();
  }, [startPolling]);

  const submit = useCallback(async () => {
    const text = command.trim();
    if (!text) return;
    // A mount-time discovery request must not replace this newer command if
    // the old response arrives after the operator has already submitted it.
    operatorIntentGenerationRef.current += 1;
    setPhase({ kind: 'previewing' });
    try {
      const res = await api.previewCommand(text);
      if (res.query_answer) {
        // Read-only query: answer is already computed server-side — render it
        // inline, no confirm gate (nothing mutated).
        setPhase({ kind: 'answer', answer: res.query_answer });
        setCommand('');
      } else if (res.plan_id && res.ops.length > 0) {
        setPhase({ kind: 'preview', planId: res.plan_id, summary: res.summary, ops: res.ops });
      } else if (res.needs_planner && res.planner_plan) {
        clearStoredPlanner();
        setPhase({ kind: 'proposed', plan: res.planner_plan });
      } else if (res.needs_planner && res.command_id) {
        // The durable command distinguishes queued, launched, plan-ready, and
        // terminal failure. It survives navigation/restart and has no false
        // wall-clock timeout while the planner is waiting for a runtime slot.
        setPhase({
          kind: 'planning',
          commandId: res.command_id,
          plannerTaskId: res.planner_task_id,
          phase: res.planner_status === 'running' ? 'planning_running' : 'planning_queued',
        });
        startPolling(res.command_id, res.planner_task_id);
      } else if (res.needs_planner) {
        setPhase({ kind: 'error', text: 'Natural-language planning needs the headless runtime (daemon mode). Use a direct command, e.g. "pause <agent>" or "scan 10.0.0.0/24".' });
      } else {
        setPhase({ kind: 'error', text: res.unresolved?.[0]?.reason || 'Command not understood.' });
      }
    } catch (err) {
      setPhase({ kind: 'error', text: err instanceof Error ? err.message : String(err) });
    }
  }, [clearStoredPlanner, command, startPolling]);

  const confirm = useCallback(async (planId: string) => {
    setPhase({ kind: 'executing' });
    try {
      const res = await api.confirmCommand(planId);
      const ok = res.results.every(r => r.ok);
      const text = ok
        ? `Executed ${res.results.length} op(s).`
        : res.results.filter(r => !r.ok).map(r => r.error || 'failed').join('; ');
      setPhase({ kind: 'result', ok, text });
      setCommand('');
    } catch (err) {
      setPhase({ kind: 'error', text: err instanceof Error ? err.message : String(err) });
    }
  }, []);

  const deny = useCallback(async (planId: string) => {
    try { await api.denyCommandPlan(planId); } catch { /* best-effort */ }
    setPhase({ kind: 'idle' });
  }, []);

  const cancelPlanning = useCallback(async (
    commandId: string,
    plannerTaskId: string | undefined,
  ) => {
    if (!plannerTaskId) {
      setPhase(previous => previous.kind === 'planning'
        && previous.commandId === commandId
        ? {
            ...previous,
            cancelError: 'The planner task identity is not available yet; status tracking will continue.',
          }
        : previous);
      return;
    }
    try {
      await api.cancelAgent(plannerTaskId);
      clearPoll();
      clearStoredPlanner();
      setPhase({ kind: 'idle' });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setPhase(previous => previous.kind === 'planning'
        && previous.commandId === commandId
        ? {
            ...previous,
            cancelError: `Cancel failed: ${message}. Planner status tracking is still active.`,
          }
        : previous);
    }
  }, [clearPoll, clearStoredPlanner]);

  // Reconcile the transient "Confirm & run" card against server state: if this
  // plan was confirmed/dismissed elsewhere (e.g. from the persistent "Needs you"
  // queue) or aged out its 10-min TTL, drop the stale card so it can't offer
  // Confirm on a plan that no longer exists. Only runs while the card is showing.
  useEffect(() => {
    if (phase.kind !== 'proposed') return;
    const planId = phase.plan.plan_id;
    const timer = setInterval(() => {
      api.getProposedPlans().then(({ plans }) => {
        if (plans.some(p => p.plan_id === planId)) return;
        // Functional update: only drop the card if we're STILL showing this exact
        // proposed plan — so a confirm()/deny() that already moved phase off
        // 'proposed' isn't clobbered by a late-firing reconcile.
        setPhase(prev => (prev.kind === 'proposed' && prev.plan.plan_id === planId)
          ? { kind: 'result', ok: false, text: 'This proposed plan is no longer available — it was resolved elsewhere or expired.' }
          : prev);
      }).catch(() => { /* transient — keep the card */ });
    }, POLL.AGENTS_MS); // gentle reconcile cadence — no need for the fast planner-detection poll
    return () => clearInterval(timer);
  }, [phase]);

  const reset = useCallback(() => {
    clearPoll();
    clearStoredPlanner();
    setPhase({ kind: 'idle' });
  }, [clearPoll, clearStoredPlanner]);

  const busy = phase.kind === 'previewing' || phase.kind === 'executing';

  const active = phase.kind !== 'idle';

  return (
    <div className={cn(
      'space-y-2 rounded-md border px-3 py-2 transition-colors',
      active ? 'border-accent/30 bg-accent-dim/40' : 'border-border bg-surface',
    )}>
      <div className="flex items-center gap-2">
        <span className="text-xs font-medium text-accent">⌘</span>
        <input
          className="flex-1 bg-transparent px-1 py-0.5 text-xs outline-none placeholder:text-muted-foreground"
          placeholder='Command or ask — "pause the apache agent", "scan 10.50.0.0/16", "what changed in the last hour", "list hosts"'
          value={command}
          onChange={e => setCommand(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && !busy) void submit(); }}
          disabled={busy || phase.kind === 'planning'}
        />
        <ActionButton onClick={() => void submit()} variant="purple" size="xs" disabled={busy || phase.kind === 'planning' || !command.trim()}>
          {phase.kind === 'previewing' ? '…' : 'Send'}
        </ActionButton>
      </div>

      {phase.kind === 'preview' && (
        <div className="rounded border border-border bg-surface p-2 text-xs space-y-2">
          <div className="text-muted-foreground">Proposed plan: <span className="text-foreground">{phase.summary}</span></div>
          <ul className="space-y-0.5">
            {phase.ops.map((op, i) => <li key={i} className="font-mono text-[11px] text-foreground">• {describeOp(op)}</li>)}
          </ul>
          <div className="flex gap-2">
            <ActionButton onClick={() => void confirm(phase.planId)} variant="success" size="xs">Confirm &amp; run</ActionButton>
            <ActionButton onClick={reset} variant="ghost" size="xs">Cancel</ActionButton>
          </div>
        </div>
      )}

      {phase.kind === 'planning' && (
        <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
          <span>
            {phase.phase === 'planning_queued'
              ? 'Planner is queued and will start when an agent slot is available…'
              : 'Planner is reasoning over the graph… a proposed plan will appear here.'}
          </span>
          <ActionButton
            onClick={() => void cancelPlanning(phase.commandId, phase.plannerTaskId)}
            variant="ghost"
            size="xs"
          >
            Cancel
          </ActionButton>
          {phase.cancelError && (
            <span className="text-[11px] text-destructive">{phase.cancelError}</span>
          )}
        </div>
      )}

      {phase.kind === 'proposed' && (
        <div className="rounded border border-purple/40 bg-surface p-2 text-xs space-y-2">
          <div className="text-muted-foreground">Planner proposed: <span className="text-foreground">{phase.plan.summary}</span></div>
          {phase.plan.rationale && <div className="text-[11px] text-muted-foreground italic">{phase.plan.rationale}</div>}
          <ul className="space-y-0.5">
            {phase.plan.ops.map((op, i) => <li key={i} className="font-mono text-[11px] text-foreground">• {describeOp(op)}</li>)}
          </ul>
          <div className="flex gap-2">
            <ActionButton onClick={() => void confirm(phase.plan.plan_id)} variant="success" size="xs">Confirm &amp; run</ActionButton>
            <ActionButton onClick={() => void deny(phase.plan.plan_id)} variant="ghost" size="xs">Dismiss</ActionButton>
          </div>
        </div>
      )}

      {phase.kind === 'answer' && (
        <div className="rounded border border-border bg-surface p-2 text-xs space-y-1.5">
          <div className="text-foreground">{phase.answer.summary}</div>
          {phase.answer.rows && phase.answer.rows.length > 0 && (
            <ul className="space-y-0.5">
              {phase.answer.rows.map((r, i) => <li key={i} className="font-mono text-[11px] text-muted-foreground">• {r}</li>)}
            </ul>
          )}
          {phase.answer.note && <div className="text-[11px] italic text-muted-foreground">{phase.answer.note}</div>}
          <div className="flex justify-end">
            <ActionButton onClick={reset} variant="ghost" size="xs">Dismiss</ActionButton>
          </div>
        </div>
      )}

      {phase.kind === 'result' && (
        <div className={cn('flex items-center justify-between text-xs', phase.ok ? 'text-success' : 'text-destructive')}>
          <span>{phase.ok ? '✓ ' : '✗ '}{phase.text}</span>
          <ActionButton onClick={reset} variant="ghost" size="xs">Dismiss</ActionButton>
        </div>
      )}

      {phase.kind === 'error' && (
        <div className="flex items-center justify-between text-xs text-destructive">
          <span>{phase.text}</span>
          <ActionButton onClick={reset} variant="ghost" size="xs">Dismiss</ActionButton>
        </div>
      )}
    </div>
  );
}
