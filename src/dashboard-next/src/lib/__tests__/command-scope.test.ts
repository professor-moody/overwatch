import { describe, it, expect } from 'vitest';
import {
  defaultScopeFor,
  canScopeToAgent,
  routeCommand,
  scopeLabel,
  scopePlaceholder,
  ENGAGEMENT_SCOPE,
  ALL_AGENTS_SCOPE,
} from '../command-scope';
import type { AgentInfo } from '../types';

function agent(o: Partial<AgentInfo> = {}): AgentInfo {
  return { id: 't1', agent_id: 'recon-1', status: 'running', task: 'recon', ...o };
}

describe('command-scope', () => {
  it('defaults to a commandable (running or pending) focused agent, else Plan', () => {
    expect(defaultScopeFor(agent())).toEqual({ kind: 'agent', taskId: 't1', label: 'recon-1' });
    expect(defaultScopeFor(agent({ status: 'pending' }))).toEqual({ kind: 'agent', taskId: 't1', label: 'recon-1' });
    expect(defaultScopeFor(null)).toBe(ENGAGEMENT_SCOPE);
    // a terminal focused agent cannot receive an instruction → Plan (engagement)
    expect(defaultScopeFor(agent({ status: 'completed' }))).toBe(ENGAGEMENT_SCOPE);
  });

  it('canScopeToAgent for a running OR pending agent (not terminal)', () => {
    expect(canScopeToAgent(agent())).toBe(true);
    expect(canScopeToAgent(agent({ status: 'pending' }))).toBe(true);
    expect(canScopeToAgent(agent({ status: 'failed' }))).toBe(false);
    expect(canScopeToAgent(agent({ status: 'completed' }))).toBe(false);
    expect(canScopeToAgent(agent({ status: 'interrupted' }))).toBe(false);
    expect(canScopeToAgent(null)).toBe(false);
  });

  it('routes engagement scope to the NL command endpoint (the planner)', () => {
    expect(routeCommand(ENGAGEMENT_SCOPE)).toEqual({ via: 'command' });
  });

  it('routes agent scope to an instruct directive for that task', () => {
    expect(routeCommand({ kind: 'agent', taskId: 't1', label: 'recon-1' })).toEqual({ via: 'instruct', taskId: 't1' });
  });

  it('routes all-agents scope to a broadcast instruct', () => {
    expect(routeCommand(ALL_AGENTS_SCOPE)).toEqual({ via: 'instruct_all' });
  });

  it('routes primary scope to the live-orchestrator instruct (id resolved at render, not pinned)', () => {
    expect(routeCommand({ kind: 'primary' })).toEqual({ via: 'instruct_primary' });
  });

  it('labels and placeholders reflect the scope', () => {
    expect(scopeLabel(ENGAGEMENT_SCOPE)).toBe('Plan');
    expect(scopeLabel(ALL_AGENTS_SCOPE)).toBe('All agents');
    expect(scopeLabel({ kind: 'primary' })).toBe('Primary');
    expect(scopeLabel({ kind: 'agent', taskId: 't1', label: 'recon-1' })).toBe('recon-1');
    expect(scopePlaceholder(ENGAGEMENT_SCOPE)).toMatch(/plan/i);
    expect(scopePlaceholder(ALL_AGENTS_SCOPE)).toMatch(/all/i);
    expect(scopePlaceholder({ kind: 'primary' })).toMatch(/primary/i);
    expect(scopePlaceholder({ kind: 'agent', taskId: 't1', label: 'recon-1' })).toMatch(/recon-1/);
  });
});
