import { useState, useEffect, useCallback, useRef } from 'react';
import * as api from '../../lib/api';
import { cn } from '../../lib/utils';
import { POLL } from '../../lib/polling';
import { ActionButton } from '../shared/primitives';

// Phase 3A NL operator cockpit: type a plain-English command → it becomes a
// confirmable plan (grammar fast-path) or is handed to a headless planner that
// proposes one → operator confirms → executes through the validated engine path.
// The executed command + proposed plans also stream into the console below.

type Phase =
  | { kind: 'idle' }
  | { kind: 'previewing' }
  | { kind: 'preview'; planId: string; summary: string; ops: api.OperatorOp[] }
  | { kind: 'planning' }
  | { kind: 'proposed'; plan: api.ProposedPlan }
  | { kind: 'executing' }
  | { kind: 'result'; ok: boolean; text: string }
  | { kind: 'error'; text: string };

const POLL_MAX_TRIES = 45; // ~90s for a planner to return

function describeOp(op: api.OperatorOp): string {
  switch (op.op) {
    case 'directive': return `${String(op.kind)} → ${String(op.agent_label ?? op.task_id)}`;
    case 'scope': return `scope +${[...(op.add_cidrs as string[] ?? []), ...(op.add_domains as string[] ?? [])].join(', ')}`;
    case 'approve': return `approve ${String(op.action_id)}`;
    case 'deny': return `deny ${String(op.action_id)}`;
    default: return JSON.stringify(op);
  }
}

export function OperatorCommandBar() {
  const [command, setCommand] = useState('');
  const [phase, setPhase] = useState<Phase>({ kind: 'idle' });
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const clearPoll = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);
  useEffect(() => () => clearPoll(), [clearPoll]);

  const startPolling = useCallback((plannerTaskId: string) => {
    clearPoll();
    let tries = 0;
    pollRef.current = setInterval(() => {
      tries += 1;
      api.getProposedPlans().then(({ plans }) => {
        // Correlate by the dispatched planner's task id: /api/plans returns ALL
        // open plans (newest-first, 10-min TTL), so plans[0] could be a stale or
        // another command's plan. Only latch the plan OUR planner produced.
        const match = plans.find(p => p.source_task_id === plannerTaskId);
        if (match) {
          clearPoll();
          setPhase({ kind: 'proposed', plan: match });
        } else if (tries >= POLL_MAX_TRIES) {
          clearPoll();
          setPhase({ kind: 'error', text: 'The planner did not return a plan in time.' });
        }
      }).catch(() => { /* transient — keep polling */ });
    }, POLL.PLAN_POLL_MS);
  }, [clearPoll]);

  const submit = useCallback(async () => {
    const text = command.trim();
    if (!text) return;
    setPhase({ kind: 'previewing' });
    try {
      const res = await api.previewCommand(text);
      if (res.plan_id && res.ops.length > 0) {
        setPhase({ kind: 'preview', planId: res.plan_id, summary: res.summary, ops: res.ops });
      } else if (res.needs_planner && res.planner_task_id) {
        // A planner was dispatched (planner_task_id is only set when the headless
        // runtime is available) — poll for the plan it produces.
        setPhase({ kind: 'planning' });
        startPolling(res.planner_task_id);
      } else if (res.needs_planner) {
        setPhase({ kind: 'error', text: 'Natural-language planning needs the headless runtime (daemon mode). Use a direct command, e.g. "pause <agent>" or "scan 10.0.0.0/24".' });
      } else {
        setPhase({ kind: 'error', text: res.unresolved?.[0]?.reason || 'Command not understood.' });
      }
    } catch (err) {
      setPhase({ kind: 'error', text: err instanceof Error ? err.message : String(err) });
    }
  }, [command, startPolling]);

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

  const reset = useCallback(() => { clearPoll(); setPhase({ kind: 'idle' }); }, [clearPoll]);

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
          placeholder='Command the engagement — "pause the apache agent", "scan 10.50.0.0/16", "focus everyone on credentials"'
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
        <div className="text-xs text-muted-foreground">Planner is reasoning over the graph… a proposed plan will appear here.</div>
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
