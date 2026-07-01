import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import { GraphEngine } from '../graph-engine.js';
import { interpretCommand, executeOps, buildPlannerObjective, type InterpreterState } from '../command-interpreter.js';
import type { EngagementConfig, AgentTask } from '../../types.js';

const TEST_STATE_FILE = './state-test-command-interpreter.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-cmd', name: 'cmd test', created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [], opsec: { name: 'pentest', max_noise: 0.7 },
  };
}
function cleanup() { try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch { /* ignore */ } }

const state = (tasks: InterpreterState['tasks'], pending: string[] = []): InterpreterState => ({ tasks, pendingActionIds: pending });
const t = (id: string, agent_id: string, status = 'running', skill?: string) => ({ id, agent_id, status, skill });

describe('interpretCommand (grammar)', () => {
  it('"pause all" → a directive op per running agent', () => {
    const r = interpretCommand('pause all', state([t('1', 'a1'), t('2', 'a2'), t('3', 'a3', 'completed')]));
    expect(r.ops).toHaveLength(2); // only the 2 running
    expect(r.ops.every(o => o.op === 'directive' && o.kind === 'pause')).toBe(true);
  });

  it('"stop <agent_id>" → one stop directive for that agent', () => {
    const r = interpretCommand('stop a2', state([t('1', 'a1'), t('2', 'a2')]));
    expect(r.ops).toHaveLength(1);
    expect(r.ops[0]).toMatchObject({ op: 'directive', task_id: '2', kind: 'stop' });
  });

  it('"halt" maps to stop', () => {
    const r = interpretCommand('halt a1', state([t('1', 'a1')]));
    expect(r.ops[0]).toMatchObject({ kind: 'stop' });
  });

  it('unknown agent → unresolved, no ops', () => {
    const r = interpretCommand('pause nonesuch', state([t('1', 'a1')]));
    expect(r.ops).toHaveLength(0);
    expect(r.unresolved[0].reason).toMatch(/no running agent/);
  });

  it('ambiguous ref → unresolved', () => {
    const r = interpretCommand('pause research', state([t('1', 'cve-research-1', 'running', 'cve-research'), t('2', 'cve-research-2', 'running', 'cve-research')]));
    expect(r.ops).toHaveLength(0);
    expect(r.unresolved[0].reason).toMatch(/matches 2 agents/);
  });

  it('"tell <agent> <text>" → an instruct directive carrying the free text', () => {
    const r = interpretCommand('tell a1 focus on SMB shares', state([t('1', 'a1')]));
    expect(r.ops).toHaveLength(1);
    expect(r.ops[0]).toMatchObject({ op: 'directive', task_id: '1', kind: 'instruct', note: 'focus on SMB shares' });
  });

  it('"instruct <agent> to <text>" strips the leading "to"', () => {
    const r = interpretCommand('instruct a1 to try password spray', state([t('1', 'a1')]));
    expect(r.ops[0]).toMatchObject({ op: 'directive', kind: 'instruct', note: 'try password spray' });
  });

  it('tell with an unknown agent → unresolved', () => {
    const r = interpretCommand('tell ghost do something', state([t('1', 'a1')]));
    expect(r.ops).toHaveLength(0);
    expect(r.unresolved[0].reason).toMatch(/no running agent/);
  });

  it('"scan <cidr> <ip> <domain>" → scope op with correct classification', () => {
    const r = interpretCommand('scan 10.50.0.0/16 192.168.1.5 corp.example.com', state([]));
    expect(r.ops).toHaveLength(1);
    expect(r.ops[0]).toMatchObject({ op: 'scope', add_cidrs: ['10.50.0.0/16', '192.168.1.5/32'], add_domains: ['corp.example.com'] });
  });

  it('scan with a junk token → token unresolved, valid ones still added', () => {
    const r = interpretCommand('scan 10.0.0.0/8 notanaddress', state([]));
    expect(r.ops[0]).toMatchObject({ op: 'scope', add_cidrs: ['10.0.0.0/8'] });
    expect(r.unresolved.some(u => u.text === 'notanaddress')).toBe(true);
  });

  it('"add scope X except Y" routes Y to add_exclusions, not add_cidrs (scope-broadening fix)', () => {
    const r = interpretCommand('add scope 10.0.0.0/24 except 10.0.0.5', state([]));
    expect(r.ops[0]).toMatchObject({ op: 'scope', add_cidrs: ['10.0.0.0/24'], add_exclusions: ['10.0.0.5'] });
    expect((r.ops[0] as { add_cidrs?: string[] }).add_cidrs).not.toContain('10.0.0.5/32');
  });

  it('"scan X but not Y" honors the exclusion qualifier', () => {
    const r = interpretCommand('scan 10.50.0.0/16 but not 10.50.0.9', state([]));
    expect(r.ops[0]).toMatchObject({ op: 'scope', add_cidrs: ['10.50.0.0/16'], add_exclusions: ['10.50.0.9'] });
  });

  it('"exclude Y Z" (dedicated verb) produces an exclusion-only scope op', () => {
    const r = interpretCommand('exclude 10.10.10.9 10.10.20.0/24', state([]));
    expect(r.ops[0]).toMatchObject({ op: 'scope', add_exclusions: ['10.10.10.9', '10.10.20.0/24'] });
    expect((r.ops[0] as { add_cidrs?: string[] }).add_cidrs).toBeUndefined();
  });

  it('"add scope except Y" (keyword LEADS, no add part) still excludes — not adds', () => {
    const r = interpretCommand('add scope except 10.0.0.5', state([]));
    expect(r.ops[0]).toMatchObject({ op: 'scope', add_exclusions: ['10.0.0.5'] });
    expect((r.ops[0] as { add_cidrs?: string[] }).add_cidrs).toBeUndefined();
    // "except" must not surface as a spurious unresolved token.
    expect(r.unresolved.some(u => /except/i.test(u.text))).toBe(false);
  });

  it('"target not Y" (leading keyword) routes Y to exclusions', () => {
    const r = interpretCommand('target not 10.0.0.9', state([]));
    expect(r.ops[0]).toMatchObject({ op: 'scope', add_exclusions: ['10.0.0.9'] });
    expect((r.ops[0] as { add_cidrs?: string[] }).add_cidrs).toBeUndefined();
  });

  it('"exclude Y except Z" (exclude verb + embedded keyword) excludes both, no bogus unresolved', () => {
    const r = interpretCommand('exclude 10.0.0.5 except 10.0.0.6', state([]));
    expect(r.ops[0]).toMatchObject({ op: 'scope', add_exclusions: ['10.0.0.5', '10.0.0.6'] });
    expect(r.unresolved.some(u => /except/i.test(u.text))).toBe(false);
  });

  it('"approve <action>" resolves a pending action id (incl. unique prefix)', () => {
    const r = interpretCommand('approve act-123 looks good', state([], ['act-123-full']));
    expect(r.ops[0]).toMatchObject({ op: 'approve', action_id: 'act-123-full', notes: 'looks good' });
  });

  it('approve of unknown action → unresolved', () => {
    const r = interpretCommand('deny act-999', state([], ['act-123']));
    expect(r.ops).toHaveLength(0);
    expect(r.unresolved[0].reason).toMatch(/no pending action/);
  });

  it('gibberish → unresolved, no ops (planner fallback territory)', () => {
    const r = interpretCommand('go find me something cool', state([t('1', 'a1')]));
    expect(r.ops).toHaveLength(0);
    expect(r.unresolved[0].reason).toMatch(/not recognized/);
  });
});

describe('executeOps (engine effects)', () => {
  let engine: GraphEngine;
  beforeEach(() => { cleanup(); engine = new GraphEngine(makeConfig(), TEST_STATE_FILE); });
  afterEach(() => { cleanup(); });

  it('directive op issues a pending directive on the task', () => {
    engine.registerAgent({ id: 'task-1', agent_id: 'a1', assigned_at: new Date().toISOString(), status: 'running', subgraph_node_ids: [] } as AgentTask);
    const results = executeOps(engine, [{ op: 'directive', task_id: 'task-1', agent_label: 'a1', kind: 'pause' }]);
    expect(results[0].ok).toBe(true);
    expect(engine.getPendingAgentDirective('task-1')?.kind).toBe('pause');
  });

  it('scope op adds CIDRs/domains through the validated engine path', () => {
    const results = executeOps(engine, [{ op: 'scope', add_cidrs: ['10.99.0.0/24'], add_domains: ['new.example.com'] }]);
    expect(results[0].ok).toBe(true);
    expect(engine.getConfig().scope.cidrs).toContain('10.99.0.0/24');
    expect(engine.getConfig().scope.domains).toContain('new.example.com');
  });

  it('approve of a non-existent action returns ok:false (no throw)', () => {
    const results = executeOps(engine, [{ op: 'approve', action_id: 'nope' }]);
    expect(results[0].ok).toBe(false);
    expect(results[0].error).toMatch(/not found/);
  });
});

describe('buildPlannerObjective (3A.2 — handed to the headless planner)', () => {
  it('embeds the command + the EXACT running task ids the planner may reference', () => {
    const obj = buildPlannerObjective('go pause the noisy scanner', state(
      [t('task-aaa', 'scanner-1'), t('task-bbb', 'idp-1', 'completed')], ['act-1'],
    ));
    expect(obj).toContain('go pause the noisy scanner');
    expect(obj).toContain('task_id="task-aaa"'); // running → listed
    expect(obj).not.toContain('task-bbb'); // completed → not steerable
    expect(obj).toContain('action_id="act-1"');
    // documents the op vocabulary so the planner emits OperatorOp-shaped ops
    expect(obj).toContain('"op":"directive"');
    expect(obj).toContain('"op":"scope"');
  });

  it('handles no running agents / no pending actions gracefully', () => {
    const obj = buildPlannerObjective('do something', state([]));
    expect(obj).toContain('(none running)');
    expect(obj).toContain('(none pending)');
  });
});
