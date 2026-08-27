import { describe, expect, it } from 'vitest';
import type { AgentInfo, Campaign, PlaybookRun } from '../types';
import {
  agentLiveWorkState,
  displayWorkState,
  isActiveCampaign,
  isTerminalAgent,
  playbookLiveWorkState,
  selectActiveWork,
} from '../work-state';

describe('workspace work-state presentation', () => {
  it('separates running, queued, and terminal agents', () => {
    expect(agentLiveWorkState({ status: 'running' } as AgentInfo)).toBe('running');
    expect(agentLiveWorkState({ status: 'pending' } as AgentInfo)).toBe('queued');
    expect(agentLiveWorkState({ status: 'completed' } as AgentInfo)).toBeNull();
    expect(isTerminalAgent({ status: 'failed' } as AgentInfo)).toBe(true);
  });

  it('counts only canonical active campaigns as active work', () => {
    expect(isActiveCampaign({ status: 'active' } as Campaign)).toBe(true);
    expect(isActiveCampaign({ status: 'draft' } as Campaign)).toBe(false);
    expect(isActiveCampaign({ status: 'paused' } as Campaign)).toBe(false);
  });

  it('groups nonterminal playbooks without treating terminal runs as live', () => {
    expect(playbookLiveWorkState({ status: 'running' } as PlaybookRun)).toBe('running');
    expect(playbookLiveWorkState({ status: 'pending' } as PlaybookRun)).toBe('queued');
    expect(playbookLiveWorkState({ status: 'awaiting_approval' } as PlaybookRun)).toBe('waiting');
    expect(playbookLiveWorkState({ status: 'succeeded' } as PlaybookRun)).toBeNull();
    expect(displayWorkState('queued')).toBe('Queued');
  });

  it('derives the Active count from the same rows it returns', () => {
    const active = selectActiveWork({
      agents: [
        { id: 'running', status: 'running' },
        { id: 'queued', status: 'pending' },
        { id: 'done', status: 'completed' },
      ] as AgentInfo[],
      campaigns: [
        { id: 'active', status: 'active' },
        { id: 'draft', status: 'draft' },
        { id: 'paused', status: 'paused' },
      ] as Campaign[],
      playbooks: [
        { run_id: 'running', status: 'running' },
        { run_id: 'waiting', status: 'blocked' },
        { run_id: 'done', status: 'succeeded' },
      ] as PlaybookRun[],
    });

    expect(active.agents.map(agent => agent.id)).toEqual(['running', 'queued']);
    expect(active.campaigns.map(campaign => campaign.id)).toEqual(['active']);
    expect(active.playbooks.map(run => run.run_id)).toEqual(['running', 'waiting']);
    expect(active.total).toBe(active.agents.length + active.campaigns.length + active.playbooks.length);
  });
});
