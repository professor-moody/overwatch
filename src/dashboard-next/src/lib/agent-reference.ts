/** The stable and rolling-release aliases carried by agent DTOs. */
export interface AgentReference {
  task_id?: string;
  agent_label?: string;
  id?: string;
  agent_id?: string;
}

/** Return the durable task identity used by every agent route and action. */
export function canonicalAgentTaskId(agent: AgentReference): string {
  return agent.task_id || agent.id || '';
}

/** Human-readable label with a stable, never-undefined task fallback. */
export function agentDisplayLabel(agent: AgentReference): string {
  return agent.agent_label
    || agent.agent_id
    || canonicalAgentTaskId(agent)
    || 'Agent';
}

/**
 * Resolve an operator/deep-link reference without guessing between duplicate
 * legacy labels. Canonical task IDs always win, followed by a unique legacy ID
 * alias and finally a unique label alias.
 */
export function resolveAgentReference<T extends AgentReference>(
  agents: readonly T[],
  reference: string,
): T | null {
  const taskMatch = agents.find(agent => agent.task_id === reference);
  if (taskMatch) return taskMatch;

  const idMatches = agents.filter(agent => agent.id === reference);
  if (idMatches.length === 1) return idMatches[0];

  const labelMatches = agents.filter(agent =>
    agent.agent_label === reference || agent.agent_id === reference);
  return labelMatches.length === 1 ? labelMatches[0] : null;
}
