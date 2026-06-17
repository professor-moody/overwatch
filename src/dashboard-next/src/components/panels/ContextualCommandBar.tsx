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
  type CommandScope,
} from '../../lib/command-scope';
import { cn } from '../../lib/utils';
import { ActionButton } from '../shared/primitives';
import { OperatorCommandBar } from './OperatorCommandBar';

// Phase 5 (Mission Control) — one command input with a scope pill, replacing the
// separate global command bar and per-agent "Tell" box. Engagement scope renders
// the full NL command bar (preview → confirm via /api/commands); Agent scope
// sends a free-text `instruct` directive to the focused agent. The pill follows
// focus but the operator can flip to Engagement without deselecting. Routing
// decisions live in lib/command-scope.ts (tested).

export function ContextualCommandBar({
  focusedAgent,
  onAgentCommandSent,
}: {
  focusedAgent: AgentInfo | null;
  /** Called after an agent-scoped instruction lands, so the console can refresh
   *  the focused agent's thread immediately (the per-agent WS push doesn't carry
   *  dashboard-sourced events, so without this the command echo waits for the poll). */
  onAgentCommandSent?: () => void;
}) {
  const [scope, setScope] = useState<CommandScope>(() => defaultScopeFor(focusedAgent));
  const agentAvailable = canScopeToAgent(focusedAgent);

  // Follow focus: when the focused agent changes (or stops being commandable),
  // re-default the scope. The operator can still flip back to Engagement.
  useEffect(() => {
    setScope(defaultScopeFor(focusedAgent));
  }, [focusedAgent?.id, focusedAgent?.status]);

  const route = routeCommand(scope);

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-1.5 text-[10px]">
        <span className="uppercase tracking-wider text-muted-foreground">Command</span>
        <ScopePill label="Engagement" active={scope.kind === 'engagement'} onClick={() => setScope(ENGAGEMENT_SCOPE)} />
        {agentAvailable && focusedAgent && (
          <ScopePill
            label={focusedAgent.agent_id || focusedAgent.id}
            active={scope.kind === 'agent'}
            onClick={() => setScope({ kind: 'agent', taskId: focusedAgent.id, label: focusedAgent.agent_id || focusedAgent.id })}
          />
        )}
      </div>
      {route.via === 'command'
        ? <OperatorCommandBar />
        : <InstructBar taskId={route.taskId} placeholder={scopePlaceholder(scope)} onSent={onAgentCommandSent} />}
    </div>
  );
}

function ScopePill({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'max-w-[12rem] truncate rounded px-1.5 py-0.5 font-mono transition-colors',
        active ? 'bg-accent/15 text-accent' : 'bg-elevated text-muted-foreground hover:text-foreground',
      )}
    >
      {label}
    </button>
  );
}

function InstructBar({ taskId, placeholder, onSent }: { taskId: string; placeholder: string; onSent?: () => void }) {
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
        message: res.ok ? 'agent honors it on its next heartbeat' : 'not applied',
      });
      if (res.ok) { setText(''); onSent?.(); }
    } catch (err) {
      addToast({ type: 'error', title: 'Instruction failed', message: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
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
  );
}
