import type { AgentInfo, Campaign, PlaybookRun } from './types';

export type LiveWorkState = 'running' | 'queued' | 'waiting';

export function isTerminalAgent(agent: AgentInfo): boolean {
  return agent.status === 'completed' || agent.status === 'failed' || agent.status === 'interrupted';
}

export function agentLiveWorkState(agent: AgentInfo): LiveWorkState | null {
  if (agent.status === 'running') return 'running';
  if (agent.status === 'pending') return 'queued';
  return null;
}

export function isActiveCampaign(campaign: Campaign): boolean {
  return campaign.status === 'active';
}

export function playbookLiveWorkState(run: PlaybookRun): LiveWorkState | null {
  if (run.status === 'running') return 'running';
  if (run.status === 'pending') return 'queued';
  if (run.status === 'blocked' || run.status === 'awaiting_approval') return 'waiting';
  return null;
}

export function displayWorkState(state: LiveWorkState): string {
  return state === 'running' ? 'Running' : state === 'queued' ? 'Queued' : 'Waiting';
}

export interface ActiveWorkSelection {
  agents: AgentInfo[];
  campaigns: Campaign[];
  playbooks: PlaybookRun[];
  total: number;
}

/**
 * Canonical presentation selector for the Operate Active view. Keeping the
 * rendered collections and badge total in one result prevents the count from
 * drifting from the rows the operator can actually see.
 */
export function selectActiveWork(input: {
  agents: readonly AgentInfo[];
  campaigns: readonly Campaign[];
  playbooks: readonly PlaybookRun[];
}): ActiveWorkSelection {
  const agents = input.agents.filter(agent => agentLiveWorkState(agent) !== null);
  const campaigns = input.campaigns.filter(isActiveCampaign);
  const playbooks = input.playbooks.filter(run => playbookLiveWorkState(run) !== null);

  return {
    agents,
    campaigns,
    playbooks,
    total: agents.length + campaigns.length + playbooks.length,
  };
}
