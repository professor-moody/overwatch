import type { AgentInfo } from './types';

// Phase 5 (Mission Control) — one contextual command box replaces the separate
// global command bar and per-agent "Tell" box. A scope pill selects where the
// command goes; this module is the pure routing decision (the component owns the
// input + the two-phase preview/confirm UI it already has).
//
// Phase 1 scopes: Engagement (the NL command bar — handles fleet verbs like
// "pause all" + planner fallback through /api/commands) and Agent (free text →
// an `instruct` directive to the focused agent, via /api/agents/:id/directive).
// A Campaign scope arrives with swimlanes in Phase 4 (no per-campaign free-text
// command endpoint exists yet), so it is deliberately not offered here.

export type CommandScope =
  | { kind: 'engagement' }
  | { kind: 'agent'; taskId: string; label: string };

export type CommandRoute =
  | { via: 'command' }                       // POST /api/commands — NL preview → confirm
  | { via: 'instruct'; taskId: string };     // issueDirective(taskId, 'instruct', { note })

export const ENGAGEMENT_SCOPE: CommandScope = { kind: 'engagement' };

/** The scope to default to given the focused agent (follows focus). */
export function defaultScopeFor(agent: AgentInfo | null | undefined): CommandScope {
  if (agent && agent.status === 'running') {
    return { kind: 'agent', taskId: agent.id, label: agent.agent_id || agent.id };
  }
  return ENGAGEMENT_SCOPE;
}

/** Whether an agent can be the target of a contextual instruction (must be live). */
export function canScopeToAgent(agent: AgentInfo | null | undefined): boolean {
  return !!agent && agent.status === 'running';
}

export function routeCommand(scope: CommandScope): CommandRoute {
  return scope.kind === 'agent'
    ? { via: 'instruct', taskId: scope.taskId }
    : { via: 'command' };
}

export function scopeLabel(scope: CommandScope): string {
  return scope.kind === 'agent' ? scope.label : 'Engagement';
}

export function scopePlaceholder(scope: CommandScope): string {
  return scope.kind === 'agent'
    ? `Command ${scope.label}… e.g. "focus on SMB"`
    : 'Command the engagement… e.g. "pause the apache agent", "scan 10.50.0.0/16"';
}
