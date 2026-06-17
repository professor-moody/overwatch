import { describe, it, expect } from 'vitest';
import {
  defaultScopeFor,
  canScopeToAgent,
  routeCommand,
  scopeLabel,
  scopePlaceholder,
  ENGAGEMENT_SCOPE,
} from '../command-scope';
import type { AgentInfo } from '../types';

function agent(o: Partial<AgentInfo> = {}): AgentInfo {
  return { id: 't1', agent_id: 'recon-1', status: 'running', task: 'recon', ...o };
}

describe('command-scope', () => {
  it('defaults to the focused running agent, else engagement', () => {
    expect(defaultScopeFor(agent())).toEqual({ kind: 'agent', taskId: 't1', label: 'recon-1' });
    expect(defaultScopeFor(null)).toBe(ENGAGEMENT_SCOPE);
    // a non-running focused agent cannot receive an instruction → engagement
    expect(defaultScopeFor(agent({ status: 'completed' }))).toBe(ENGAGEMENT_SCOPE);
  });

  it('canScopeToAgent only for a live agent', () => {
    expect(canScopeToAgent(agent())).toBe(true);
    expect(canScopeToAgent(agent({ status: 'failed' }))).toBe(false);
    expect(canScopeToAgent(null)).toBe(false);
  });

  it('routes engagement scope to the NL command endpoint', () => {
    expect(routeCommand(ENGAGEMENT_SCOPE)).toEqual({ via: 'command' });
  });

  it('routes agent scope to an instruct directive for that task', () => {
    expect(routeCommand({ kind: 'agent', taskId: 't1', label: 'recon-1' })).toEqual({ via: 'instruct', taskId: 't1' });
  });

  it('labels and placeholders reflect the scope', () => {
    expect(scopeLabel(ENGAGEMENT_SCOPE)).toBe('Engagement');
    expect(scopeLabel({ kind: 'agent', taskId: 't1', label: 'recon-1' })).toBe('recon-1');
    expect(scopePlaceholder(ENGAGEMENT_SCOPE)).toMatch(/engagement/i);
    expect(scopePlaceholder({ kind: 'agent', taskId: 't1', label: 'recon-1' })).toMatch(/recon-1/);
  });
});
