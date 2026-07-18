import type { AgentInfo } from './types';
import { agentDisplayLabel, canonicalAgentTaskId } from './agent-reference';

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
  | { kind: 'all_agents' }
  | { kind: 'primary' }                       // steer the current orchestrator (id resolved live)
  | { kind: 'agent'; taskId: string; label: string };

export type CommandRoute =
  | { via: 'command' }                       // POST /api/commands — NL preview → confirm (the planner)
  | { via: 'instruct'; taskId: string }      // issueDirective(taskId, 'instruct', { note })
  | { via: 'instruct_primary' }              // instruct the live orchestrator (id resolved at render)
  | { via: 'instruct_all' };                 // fleetInstruct(note) → every running agent

export const ENGAGEMENT_SCOPE: CommandScope = { kind: 'engagement' };
export const ALL_AGENTS_SCOPE: CommandScope = { kind: 'all_agents' };

/**
 * Whether an agent can be the target of a contextual instruction. Commandable
 * while `running` (acts live) or `pending` (the instruct is queued and delivered
 * on the agent's first heartbeat once it launches). Terminal agents can't act.
 */
export function canScopeToAgent(agent: AgentInfo | null | undefined): boolean {
  return !!agent && (agent.status === 'running' || agent.status === 'pending');
}

/** The scope to default to given the focused agent (follows focus). A focused,
 *  commandable agent scopes to it; otherwise fall back to the planner. */
export function defaultScopeFor(agent: AgentInfo | null | undefined): CommandScope {
  if (agent && canScopeToAgent(agent)) {
    return {
      kind: 'agent',
      taskId: canonicalAgentTaskId(agent),
      label: agentDisplayLabel(agent),
    };
  }
  return ENGAGEMENT_SCOPE;
}

export function routeCommand(scope: CommandScope): CommandRoute {
  if (scope.kind === 'agent') return { via: 'instruct', taskId: scope.taskId };
  if (scope.kind === 'primary') return { via: 'instruct_primary' };
  if (scope.kind === 'all_agents') return { via: 'instruct_all' };
  return { via: 'command' };
}

export function scopeLabel(scope: CommandScope): string {
  if (scope.kind === 'agent') return scope.label;
  if (scope.kind === 'primary') return 'Primary';
  if (scope.kind === 'all_agents') return 'All agents';
  return 'Plan';
}

export function scopePlaceholder(scope: CommandScope): string {
  if (scope.kind === 'agent') return `Command ${scope.label}… e.g. "focus on SMB"`;
  if (scope.kind === 'primary') return 'Steer the primary orchestrator… e.g. "prioritize the DC", "pause dispatching"';
  if (scope.kind === 'all_agents') return 'Instruct all running agents… e.g. "stop and report what you have"';
  return 'Plan the engagement… e.g. "what should we do next", "scan 10.50.0.0/16"';
}
