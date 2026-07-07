import { useState, useEffect } from 'react';
import * as api from '../../lib/api';
import type { AgentInfo } from '../../lib/types';
import { useToastStore } from '../../stores/toast-store';
import {
  defaultScopeFor,
  canScopeToAgent,
  routeCommand,
  scopePlaceholder,
  ENGAGEMENT_SCOPE,
  ALL_AGENTS_SCOPE,
  type CommandScope,
} from '../../lib/command-scope';
import { cn } from '../../lib/utils';
import { ActionButton } from '../shared/primitives';
import { OperatorCommandBar } from './OperatorCommandBar';

// Phase 5 (Mission Control) — one command input with a scope pill, replacing the
// separate global command bar and per-agent "Tell" box. The pill decides where
// the text goes:
//   • Plan (engagement) → the NL command bar (preview → confirm via /api/commands,
//     which spawns the headless planner). This is the DELIBERATE planner path —
//     it is not a silent default.
//   • <agent> → a free-text `instruct` directive to the focused agent. Shown for
//     any commandable (running OR pending) agent; a terminal agent shows a
//     disabled pill explaining why, instead of silently falling back to Plan.
//   • All agents → broadcast the instruct to every running agent (/api/fleet/directive).
// Routing decisions live in lib/command-scope.ts (tested).

export function ContextualCommandBar({
  focusedAgent,
  agents,
  onAgentCommandSent,
}: {
  focusedAgent: AgentInfo | null;
  /** The full fleet, used to decide whether an "All agents" broadcast is available. */
  agents?: AgentInfo[];
  /** Called after an agent-scoped instruction lands, so the console can refresh
   *  the focused agent's thread immediately (the per-agent WS push doesn't carry
   *  dashboard-sourced events, so without this the command echo waits for the poll). */
  onAgentCommandSent?: () => void;
}) {
  const [scope, setScope] = useState<CommandScope>(() => defaultScopeFor(focusedAgent));
  const commandable = canScopeToAgent(focusedAgent);
  const terminalFocused = !!focusedAgent && !commandable;
  const hasRunning = (agents ?? []).some(a => a.status === 'running');
  const primary = (agents ?? []).find(a => a.role === 'orchestrator' && a.status === 'running');

  // Follow focus: when the focused AGENT changes, default the scope to it (or
  // Plan). Keyed on id ONLY — a status heartbeat on the same agent must not clobber
  // a deliberate Plan / All-agents / Primary choice the operator made.
  useEffect(() => {
    setScope(defaultScopeFor(focusedAgent));
  }, [focusedAgent?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  // Guard a stranded scope: if the scope's target stops being valid — the focused
  // agent went terminal, the fleet emptied under an "All agents" broadcast, or the
  // orchestrator stopped under "Primary" — fall back to Plan so the box never
  // routes into the void.
  useEffect(() => {
    if (scope.kind === 'agent' && !commandable) setScope(ENGAGEMENT_SCOPE);
    else if (scope.kind === 'all_agents' && !hasRunning) setScope(ENGAGEMENT_SCOPE);
    else if (scope.kind === 'primary' && !primary) setScope(ENGAGEMENT_SCOPE);
  }, [scope.kind, commandable, hasRunning, primary?.id]);

  const route = routeCommand(scope);

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-1.5 text-[10px]">
        <span className="uppercase tracking-wider text-muted-foreground">Command</span>
        <ScopePill label="Plan" active={scope.kind === 'engagement'} onClick={() => setScope(ENGAGEMENT_SCOPE)} />
        {primary && (
          <ScopePill
            label="Primary"
            active={scope.kind === 'primary'}
            onClick={() => setScope({ kind: 'primary' })}
            title="Steer the persistent primary orchestrator"
          />
        )}
        {focusedAgent && commandable && (
          <ScopePill
            label={focusedAgent.agent_id || focusedAgent.id}
            active={scope.kind === 'agent'}
            onClick={() => setScope({ kind: 'agent', taskId: focusedAgent.id, label: focusedAgent.agent_id || focusedAgent.id })}
          />
        )}
        {focusedAgent && terminalFocused && (
          <ScopePill
            label={`${focusedAgent.agent_id || focusedAgent.id} · ${focusedAgent.status}`}
            active={false}
            disabled
            title="This agent has finished — you can't command it. Dismiss it, or select a running/pending agent."
          />
        )}
        {hasRunning && (
          <ScopePill label="All agents" active={scope.kind === 'all_agents'} onClick={() => setScope(ALL_AGENTS_SCOPE)} />
        )}
      </div>
      {route.via === 'command' && <OperatorCommandBar />}
      {route.via === 'instruct' && (
        <InstructBar
          taskId={route.taskId}
          placeholder={scopePlaceholder(scope)}
          pendingNote={scope.kind === 'agent' && focusedAgent?.status === 'pending'}
          onSent={onAgentCommandSent}
        />
      )}
      {route.via === 'instruct_primary' && primary && (
        // Resolve the orchestrator id LIVE at render, not at click — so a crash +
        // respawn (a new task id) re-points steering to the healthy orchestrator
        // instead of 409'ing against the dead one.
        <InstructBar taskId={primary.id} placeholder={scopePlaceholder(scope)} onSent={onAgentCommandSent} />
      )}
      {route.via === 'instruct_all' && (
        <InstructAllBar placeholder={scopePlaceholder(scope)} onSent={onAgentCommandSent} />
      )}
    </div>
  );
}

function ScopePill({ label, active, onClick, disabled, title }: { label: string; active: boolean; onClick?: () => void; disabled?: boolean; title?: string }) {
  return (
    <button
      onClick={disabled ? undefined : onClick}
      disabled={disabled}
      title={title}
      className={cn(
        'max-w-[12rem] truncate rounded px-1.5 py-0.5 font-mono transition-colors',
        disabled
          ? 'cursor-default bg-elevated/50 text-muted-foreground/60'
          : active ? 'bg-accent/15 text-accent' : 'bg-elevated text-muted-foreground hover:text-foreground',
      )}
    >
      {label}
    </button>
  );
}

function InstructBar({ taskId, placeholder, pendingNote, onSent }: { taskId: string; placeholder: string; pendingNote?: boolean; onSent?: () => void }) {
  const addToast = useToastStore(s => s.addToast);
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);

  const send = async () => {
    const note = text.trim();
    if (!note || busy) return;
    setBusy(true);
    try {
      const res = await api.issueDirective(taskId, 'instruct', { note });
      addToast({
        type: res.ok ? 'success' : 'warning',
        title: 'Instruction sent',
        message: res.ok ? (pendingNote ? 'queued — applies when the agent runs' : 'agent honors it on its next heartbeat') : 'not applied',
      });
      if (res.ok) { setText(''); onSent?.(); }
    } catch (err) {
      addToast({ type: 'error', title: 'Instruction failed', message: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2 rounded-md border border-border bg-surface px-3 py-2">
        <span className="text-xs font-medium text-accent">⌘</span>
        <input
          className="flex-1 bg-transparent px-1 py-0.5 text-xs outline-none placeholder:text-muted-foreground"
          placeholder={placeholder}
          value={text}
          onChange={e => setText(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && !busy) void send(); }}
          disabled={busy}
        />
        <ActionButton onClick={() => void send()} variant="purple" size="xs" disabled={busy || !text.trim()}>
          {busy ? '…' : 'Send'}
        </ActionButton>
      </div>
      {pendingNote && <p className="pl-1 text-[10px] text-muted-foreground">Agent hasn't started yet — the instruction is queued and delivered on its first heartbeat.</p>}
    </div>
  );
}

function InstructAllBar({ placeholder, onSent }: { placeholder: string; onSent?: () => void }) {
  const addToast = useToastStore(s => s.addToast);
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);

  const send = async () => {
    const note = text.trim();
    if (!note || busy) return;
    setBusy(true);
    try {
      const res = await api.fleetInstruct(note);
      const clean = res.total > 0 && res.applied === res.total;
      addToast({
        type: res.total === 0 ? 'warning' : clean ? 'success' : 'warning',
        title: 'Broadcast to fleet',
        message: res.total === 0 ? 'no running agents' : `sent to ${res.applied}/${res.total} running agent(s)`,
      });
      if (res.total > 0) { setText(''); onSent?.(); }
    } catch (err) {
      addToast({ type: 'error', title: 'Broadcast failed', message: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex items-center gap-2 rounded-md border border-border bg-surface px-3 py-2">
      <span className="text-xs font-medium text-accent">⌘⌘</span>
      <input
        className="flex-1 bg-transparent px-1 py-0.5 text-xs outline-none placeholder:text-muted-foreground"
        placeholder={placeholder}
        value={text}
        onChange={e => setText(e.target.value)}
        onKeyDown={e => { if (e.key === 'Enter' && !busy) void send(); }}
        disabled={busy}
      />
      <ActionButton onClick={() => void send()} variant="purple" size="xs" disabled={busy || !text.trim()}>
        {busy ? '…' : 'Send all'}
      </ActionButton>
    </div>
  );
}
