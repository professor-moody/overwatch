import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import { GraphEngine } from '../graph-engine.js';
import type { EngagementConfig, AgentTask } from '../../types.js';

const TEST_STATE_FILE = './state-test-agent-directives.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-directives',
    name: 'directives test',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function cleanup(): void {
  try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch { /* ignore */ }
}

function registerTask(engine: GraphEngine, id: string): AgentTask {
  const task: AgentTask = {
    id, agent_id: `agent-${id}`, assigned_at: new Date().toISOString(),
    status: 'running', subgraph_node_ids: [],
  };
  engine.registerAgent(task);
  return task;
}

describe('Agent directives (engine)', () => {
  let engine: GraphEngine;

  beforeEach(() => { cleanup(); engine = new GraphEngine(makeConfig(), TEST_STATE_FILE); });
  afterEach(() => { cleanup(); });

  it('issues a pending directive that getPendingAgentDirective returns', () => {
    registerTask(engine, 't1');
    const d = engine.issueAgentDirective({ task_id: 't1', kind: 'narrow_scope', node_ids: ['host-1', 'host-2'] });
    expect(d.status).toBe('pending');
    expect(d.kind).toBe('narrow_scope');
    expect(d.node_ids).toEqual(['host-1', 'host-2']);
    expect(d.issued_by).toBe('primary');

    const pending = engine.getPendingAgentDirective('t1');
    expect(pending?.id).toBe(d.id);
  });

  it('supersedes a prior pending directive (only the latest stays pending)', () => {
    registerTask(engine, 't2');
    const first = engine.issueAgentDirective({ task_id: 't2', kind: 'pause' });
    const second = engine.issueAgentDirective({ task_id: 't2', kind: 'skip_types', frontier_types: ['network_discovery'] });

    const history = engine.getAgentDirectives('t2');
    expect(history.map(h => h.status)).toEqual(['superseded', 'pending']);
    expect(history.find(h => h.id === first.id)?.status).toBe('superseded');
    expect(engine.getPendingAgentDirective('t2')?.id).toBe(second.id);
  });

  it('acknowledge flips status and clears the pending slot', () => {
    registerTask(engine, 't3');
    const d = engine.issueAgentDirective({ task_id: 't3', kind: 'pause' });
    const acked = engine.acknowledgeAgentDirective('t3', d.id);
    expect(acked?.status).toBe('acknowledged');
    expect(acked?.acknowledged_at).toBeDefined();
    expect(engine.getPendingAgentDirective('t3')).toBeNull();
  });

  it('logs directive_issued and directive_acknowledged events linked to the task', () => {
    const task = registerTask(engine, 't4');
    const before = engine.getFullHistory().length;
    const d = engine.issueAgentDirective({ task_id: 't4', kind: 'stop' });
    engine.acknowledgeAgentDirective('t4', d.id);
    const after = engine.getFullHistory().slice(before);
    const issued = after.find(e => (e.details as any)?.reason === 'directive_issued');
    const acked = after.find(e => (e.details as any)?.reason === 'directive_acknowledged');
    expect(issued?.linked_agent_task_id).toBe('t4');
    expect(issued?.agent_id).toBe(task.agent_id);
    expect(acked?.linked_agent_task_id).toBe('t4');
  });

  it('engine alone records but never executes — issuing stop does not change task status', () => {
    registerTask(engine, 't5');
    engine.issueAgentDirective({ task_id: 't5', kind: 'stop' });
    // No TaskExecutionService here: the engine records the decision only.
    expect(engine.getTask('t5')?.status).toBe('running');
    expect(engine.getPendingAgentDirective('t5')?.kind).toBe('stop');
  });

  it('persists directives across a state reload', () => {
    registerTask(engine, 't6');
    const d = engine.issueAgentDirective({ task_id: 't6', kind: 'prioritize', frontier_types: ['credential_test'], note: 'creds first' });
    engine.flushNow();

    const reloaded = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const history = reloaded.getAgentDirectives('t6');
    expect(history).toHaveLength(1);
    expect(history[0].id).toBe(d.id);
    expect(history[0].kind).toBe('prioritize');
    expect(history[0].frontier_types).toEqual(['credential_test']);
    expect(history[0].note).toBe('creds first');
  });
});
