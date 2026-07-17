import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { existsSync, mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { PlaybookCommandService } from '../../services/playbook-command-service.js';
import { PlaybookRunService } from '../../services/playbook-run-service.js';
import { registerRunBashTool } from '../run-bash.js';
import { startAgentKeepalive } from '../_process-runner.js';
import type { EngagementConfig } from '../../types.js';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-run-bash',
    name: 'run_bash test engagement',
    created_at: new Date().toISOString(),
    scope: {
      cidrs: ['10.10.10.0/30'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function parseTextResult(result: any): any {
  return JSON.parse(result.content[0].text);
}

describe('run_bash tool', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;
  let toolConfigs: Record<string, any>;
  let testDir: string;
  const engines = new Set<GraphEngine>();

  function createEngine(config = makeConfig(), filename = 'state.json'): GraphEngine {
    const created = new GraphEngine(config, join(testDir, filename));
    engines.add(created);
    return created;
  }

  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'overwatch-run-bash-'));
    engine = createEngine();
    handlers = {};
    toolConfigs = {};
    const fakeServer = {
      registerTool(name: string, config: unknown, handler: (args: any) => Promise<any>) {
        handlers[name] = handler;
        toolConfigs[name] = config;
      },
    } as unknown as McpServer;
    registerRunBashTool(fakeServer, engine);
  });

  afterEach(() => {
    for (const created of engines) created.dispose();
    engines.clear();
    rmSync(testDir, { recursive: true, force: true });
  });

  it('executes a simple command and logs the full lifecycle', async () => {
    const result = await handlers.run_bash({
      command: 'echo hello-from-bash',
      validate: false,
    });
    const payload = parseTextResult(result);

    expect(result.isError).toBeFalsy();
    expect(payload.executed).toBe(true);
    expect(payload.exit_code).toBe(0);
    expect(payload.stdout).toContain('hello-from-bash');
    expect(payload.action_id).toBeTruthy();
    expect(payload.stdout_evidence_id).toBeTruthy();

    const events = engine.getFullHistory().filter(e => e.action_id === payload.action_id);
    const types = events.map(e => e.event_type);
    expect(types).toContain('action_started');
    expect(types).toContain('action_completed');
    expect(types).not.toContain('action_failed');

    // Evidence store has the stdout
    const stored = engine.getEvidenceStore().getRawOutput(payload.stdout_evidence_id);
    expect(stored).toContain('hello-from-bash');
  });

  it('executes a linked playbook claim exactly once and retains only durable references', async () => {
    const commands = new PlaybookCommandService(engine);
    const runs = new PlaybookRunService(engine);
    const opened = commands.open({
      definition: {
        definition_id: 'runner-contract',
        definition_version: 1,
        provider: 'aws',
        title: 'Runner contract',
      },
      credential_id: 'cred-runner',
      normalized_inputs: {},
      steps: [{
        step_id: 'execute',
        description: 'Execute through run_bash',
        runner: 'run_bash',
        command: 'printf playbook-output-%s $$',
        validate: false,
        ready: true,
        status: 'ready',
      }],
    });
    const claim = commands.start(opened.run.run_id, 'execute');

    const first = await handlers.run_bash(claim.execution);
    const replay = await handlers.run_bash(claim.execution);
    const firstPayload = parseTextResult(first);
    expect(parseTextResult(replay)).toEqual(firstPayload);

    const completed = runs.getDurable(opened.run.run_id);
    expect(completed.steps[0].attempts).toHaveLength(1);
    expect(completed.steps[0].attempts[0]).toMatchObject({
      status: 'succeeded',
      action_id: claim.attempt.execution_action_id,
      evidence_ids: [expect.any(String)],
      plan_revision: 1,
      execution_template_hash: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(firstPayload.stdout).toMatch(/^playbook-output-\d+$/);
    expect(JSON.stringify(completed)).not.toContain(firstPayload.stdout);
    expect(engine.getRuntimeRuns()).toHaveLength(1);
    expect(engine.getFullHistory().filter(event =>
      event.action_id === claim.attempt.execution_action_id && event.event_type === 'action_started')).toHaveLength(1);
  });

  it('rejects added or changed claimed execution controls before creating durable work', async () => {
    const commands = new PlaybookCommandService(engine);
    const opened = commands.open({
      definition: {
        definition_id: 'sealed-runner', definition_version: 1,
        provider: 'aws', title: 'Sealed runner',
      },
      credential_id: 'cred-sealed',
      normalized_inputs: {},
      steps: [{
        step_id: 'execute', description: 'Execute the sealed command',
        runner: 'run_bash', command: 'printf sealed', technique: 'local_analysis',
        ready: true, status: 'ready',
      }],
    });
    const claim = commands.start(opened.run.run_id, 'execute');
    const mutations: Array<Record<string, unknown>> = [
      { validate: false },
      { allow_unverified_scope: true },
      { operator_infra: true },
      { target_ip: '8.8.8.8' },
      { target_url: 'https://example.invalid/' },
      { timeout_ms: 250 },
      { cwd: '/tmp' },
      { parse_with: 'nmap' },
      { noise_estimate: 0 },
      { tool_name: 'different-tool' },
      { description: 'Misleading approval text' },
    ];
    for (const mutation of mutations) {
      const result = await handlers.run_bash({ ...claim.execution, ...mutation });
      expect(result.isError, JSON.stringify(mutation)).toBe(true);
      expect(parseTextResult(result).error).toMatch(/immutable|unclaimed execution field/);
    }
    expect(engine.getRuntimeRuns()).toHaveLength(0);
    expect(engine.getApplicationCommandById(claim.attempt.execution_command_id)).toBeUndefined();
    expect(engine.getFullHistory().filter(event =>
      event.action_id === claim.attempt.execution_action_id)).toHaveLength(0);

    // Exercise the public schema path: it strips declarative plan fields and
    // materializes validate=true, which is semantically identical to omission.
    const publicInput = z.object(toolConfigs.run_bash.inputSchema).parse(claim.execution);
    expect(publicInput).toMatchObject({ validate: true });
    const accepted = await handlers.run_bash(publicInput);
    expect(parseTextResult(accepted)).toMatchObject({ executed: true, stdout: 'sealed' });
  });

  it('cannot close a linked claim with missing durable runner identity', async () => {
    const commands = new PlaybookCommandService(engine);
    const runs = new PlaybookRunService(engine);
    const opened = commands.open({
      definition: {
        definition_id: 'runner-identity', definition_version: 1,
        provider: 'aws', title: 'Runner identity',
      },
      credential_id: 'cred-runner-identity',
      normalized_inputs: {},
      steps: [{
        step_id: 'execute', description: 'Authenticated runner', runner: 'run_bash',
        command: 'false', validate: false, ready: true, status: 'ready',
      }],
    });
    const claim = commands.start(opened.run.run_id, 'execute');
    const invalid = { ...claim.execution };
    delete invalid.command_id;

    const result = await handlers.run_bash(invalid);
    expect(result.isError).toBe(true);
    expect(parseTextResult(result).error).toContain('command_id/idempotency_key');
    expect(runs.getDurable(opened.run.run_id).steps[0].attempts[0].status).toBe('claimed');
    expect(engine.getRuntimeRuns()).toHaveLength(0);
  });

  it('reports awaiting approval before a linked playbook process starts', async () => {
    const approvalEngine = createEngine({
      ...makeConfig(),
      opsec: { ...makeConfig().opsec, approval_mode: 'approve-all', approval_timeout_ms: 5_000 },
    }, 'playbook-approval.json');
    const approvalHandlers: Record<string, (args: any) => Promise<any>> = {};
    registerRunBashTool({
      registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
        approvalHandlers[name] = handler;
      },
    } as unknown as McpServer, approvalEngine);
    const commands = new PlaybookCommandService(approvalEngine);
    const runs = new PlaybookRunService(approvalEngine);
    const opened = commands.open({
      definition: {
        definition_id: 'approval-contract', definition_version: 1,
        provider: 'aws', title: 'Approval contract',
      },
      credential_id: 'cred-approval',
      normalized_inputs: {},
      steps: [{
        step_id: 'approve', description: 'Wait for approval', runner: 'run_bash',
        command: 'printf approved', validate: true, technique: 'local_analysis',
        ready: true, status: 'ready',
      }],
    });
    const claim = commands.start(opened.run.run_id, 'approve');
    const pendingResult = approvalHandlers.run_bash(claim.execution);
    for (let attempt = 0; attempt < 100 && approvalEngine.getPendingActionQueue().getPending().length === 0; attempt += 1) {
      await new Promise(resolve => setTimeout(resolve, 2));
    }
    expect(runs.getDurable(opened.run.run_id)).toMatchObject({
      status: 'awaiting_approval',
      steps: [{ status: 'awaiting_approval', attempts: [{ status: 'awaiting_approval' }] }],
    });
    expect(approvalEngine.getPendingActionQueue().approve(claim.attempt.execution_action_id)).not.toBeNull();
    const result = await pendingResult;
    expect(parseTextResult(result)).toMatchObject({ executed: true, stdout: 'approved' });
    expect(runs.getDurable(opened.run.run_id)).toMatchObject({
      status: 'succeeded',
      steps: [{ status: 'succeeded', attempts: [{ status: 'succeeded' }] }],
    });
  });

  it('interrupts and exactly replays a linked command cancelled while awaiting approval', async () => {
    const approvalEngine = createEngine({
      ...makeConfig(),
      opsec: { ...makeConfig().opsec, approval_mode: 'approve-all', approval_timeout_ms: 5_000 },
    }, 'playbook-approval-abort.json');
    const approvalHandlers: Record<string, (args: any, extra?: any) => Promise<any>> = {};
    registerRunBashTool({
      registerTool(name: string, _config: unknown, handler: (args: any, extra?: any) => Promise<any>) {
        approvalHandlers[name] = handler;
      },
    } as unknown as McpServer, approvalEngine);
    const commands = new PlaybookCommandService(approvalEngine);
    const runs = new PlaybookRunService(approvalEngine);
    const opened = commands.open({
      definition: {
        definition_id: 'approval-abort', definition_version: 1,
        provider: 'aws', title: 'Approval abort',
      },
      credential_id: 'cred-approval-abort', normalized_inputs: {},
      steps: [{
        step_id: 'approve', description: 'Wait for approval then execute',
        runner: 'run_bash', command: 'printf should-not-run', validate: true,
        technique: 'local_analysis', ready: true, status: 'ready',
      }],
    });
    const claim = commands.start(opened.run.run_id, 'approve');
    const controller = new AbortController();
    const pending = approvalHandlers.run_bash(claim.execution, { signal: controller.signal });
    for (let attempt = 0; attempt < 100 && approvalEngine.getPendingActionQueue().getPending().length === 0; attempt += 1) {
      await new Promise(resolve => setTimeout(resolve, 2));
    }
    controller.abort(new Error('client disconnected'));
    const first = await pending;
    const payload = parseTextResult(first);
    expect(payload).toMatchObject({
      action_id: claim.attempt.execution_action_id,
      executed: false,
      approval_status: 'aborted',
      interrupted: true,
      code: 'COMMAND_INTERRUPTED',
    });
    expect(approvalEngine.getPendingActionQueue().getPending()).toHaveLength(0);
    expect(approvalEngine.getRuntimeRuns()).toHaveLength(0);
    expect(runs.getDurable(opened.run.run_id).steps[0].attempts[0]).toMatchObject({
      status: 'interrupted', execution_outcome: 'interrupted',
      action_id: claim.attempt.execution_action_id,
    });
    expect(approvalEngine.getApplicationCommandById(claim.attempt.execution_command_id)).toMatchObject({
      status: 'succeeded',
      result: { interrupted: true, approval_status: 'aborted' },
    });
    expect(approvalEngine.getFullHistory().filter(event =>
      event.action_id === claim.attempt.execution_action_id && event.event_type === 'action_started')).toHaveLength(0);

    const replay = await approvalHandlers.run_bash(claim.execution);
    expect(parseTextResult(replay)).toEqual(payload);
    expect(approvalEngine.getPendingActionQueue().getPending()).toHaveLength(0);
    expect(approvalEngine.getRuntimeRuns()).toHaveLength(0);
  });

  it.skipIf(process.platform === 'win32')(
    'interrupts a running linked process and replays it without another spawn',
    async () => {
      const commands = new PlaybookCommandService(engine);
      const runs = new PlaybookRunService(engine);
      const opened = commands.open({
        definition: {
          definition_id: 'running-abort', definition_version: 1,
          provider: 'aws', title: 'Running abort',
        },
        credential_id: 'cred-running-abort', normalized_inputs: {},
        steps: [{
          step_id: 'run', description: 'Run until cancelled', runner: 'run_bash',
          command: 'printf started; sleep 10', validate: false, timeout_ms: 15_000,
          ready: true, status: 'ready',
        }],
      });
      const claim = commands.start(opened.run.run_id, 'run');
      const controller = new AbortController();
      const pending = (handlers.run_bash as any)(claim.execution, { signal: controller.signal });
      for (let attempt = 0; attempt < 200 && !engine.getRuntimeRuns().some(run =>
        run.action_id === claim.attempt.execution_action_id); attempt += 1) {
        await new Promise(resolve => setTimeout(resolve, 5));
      }
      controller.abort(new Error('operator cancelled'));
      const first = await pending;
      const payload = parseTextResult(first);
      expect(payload).toMatchObject({
        action_id: claim.attempt.execution_action_id,
        executed: true,
        interrupted: true,
      });
      expect(engine.getRuntimeRuns().filter(run =>
        run.action_id === claim.attempt.execution_action_id)).toEqual([
        expect.objectContaining({ lifecycle: 'interrupted' }),
      ]);
      expect(engine.getApplicationCommandById(claim.attempt.execution_command_id)).toMatchObject({
        status: 'succeeded', result: { interrupted: true },
      });
      expect(runs.getDurable(opened.run.run_id).steps[0].attempts[0]).toMatchObject({
        status: 'interrupted', execution_outcome: 'interrupted',
        action_id: claim.attempt.execution_action_id,
      });
      const firstEvents = engine.getFullHistory().filter(event =>
        event.action_id === claim.attempt.execution_action_id);
      expect(firstEvents.filter(event => event.event_type === 'action_started')).toHaveLength(1);
      expect(firstEvents.filter(event => event.event_type === 'action_failed')).toHaveLength(1);

      const replay = await handlers.run_bash(claim.execution);
      expect(parseTextResult(replay)).toEqual(payload);
      expect(engine.getRuntimeRuns().filter(run =>
        run.action_id === claim.attempt.execution_action_id)).toHaveLength(1);
      expect(engine.getFullHistory().filter(event =>
        event.action_id === claim.attempt.execution_action_id)).toHaveLength(firstEvents.length);
      expect(runs.getDurable(opened.run.run_id).steps[0].attempts).toHaveLength(1);
    },
    10_000,
  );

  it('refreshes the calling agent heartbeat while its tool runs (no reap mid-scan)', async () => {
    // A running agent whose last beat is well past its TTL: without the keepalive
    // it would be reaped as stale the moment it blocks on a long scan.
    const stale = new Date(Date.now() - 10 * 60_000).toISOString();
    engine.registerAgent({
      id: 'task-hb', agent_id: 'agent-hb', assigned_at: stale,
      status: 'running', subgraph_node_ids: [], heartbeat_at: stale, heartbeat_ttl_seconds: 120,
    });
    const before = engine.getTask('task-hb')?.heartbeat_at;

    await handlers.run_bash({ command: 'echo scanning', agent_id: 'agent-hb', validate: false });

    const after = engine.getTask('task-hb')?.heartbeat_at;
    expect(after).toBeTruthy();
    expect(Date.parse(after!)).toBeGreaterThan(Date.parse(before!));
    // The keepalive must not create a duplicate task for the same agent_id.
    expect(engine.getAgentTasks().filter(t => t.agent_id === 'agent-hb').length).toBe(1);
  });

  it('startAgentKeepalive bumps on an interval, stops on dispose, and self-caps at maxMs', () => {
    const stale = new Date(Date.now() - 10 * 60_000).toISOString();
    engine.registerAgent({
      id: 'task-k', agent_id: 'agent-k', assigned_at: stale,
      status: 'running', subgraph_node_ids: [], heartbeat_at: stale,
    });
    const spy = vi.spyOn(engine, 'agentHeartbeat');
    vi.useFakeTimers();
    try {
      // Interval + dispose.
      const stop = startAgentKeepalive(engine, 'agent-k', { intervalMs: 1000, maxMs: 60_000 });
      expect(spy).toHaveBeenCalledTimes(1);           // immediate bump
      vi.advanceTimersByTime(3000);
      expect(spy).toHaveBeenCalledTimes(4);           // + 3 interval bumps
      stop();
      vi.advanceTimersByTime(5000);
      expect(spy).toHaveBeenCalledTimes(4);           // no bumps after dispose

      // Self-cap: past maxMs the keepalive stops on its own.
      spy.mockClear();
      startAgentKeepalive(engine, 'agent-k', { intervalMs: 1000, maxMs: 2500 });
      expect(spy).toHaveBeenCalledTimes(1);           // immediate (t=0)
      vi.advanceTimersByTime(10_000);
      // bumps at t=1000, t=2000 (both < 2500); t=3000 sees elapsed>maxMs → stop, no bump.
      expect(spy).toHaveBeenCalledTimes(3);
    } finally {
      vi.useRealTimers();
      spy.mockRestore();
    }
  });

  it('logs action_failed on non-zero exit', async () => {
    const result = await handlers.run_bash({
      command: 'exit 7',
      validate: false,
    });
    const payload = parseTextResult(result);

    expect(result.isError).toBe(true);
    expect(payload.exit_code).toBe(7);
    const events = engine.getFullHistory().filter(e => e.action_id === payload.action_id);
    const terminal = events.find(e => e.event_type === 'action_failed' || e.event_type === 'action_completed');
    expect(terminal?.event_type).toBe('action_failed');
    expect((terminal?.details as any).reason).toBe('nonzero_exit');
  });

  it('times out long-running commands and reports timeout', async () => {
    const result = await handlers.run_bash({
      command: 'sleep 5',
      timeout_ms: 200,
      validate: false,
    });
    const payload = parseTextResult(result);

    expect(payload.timed_out).toBe(true);
    expect(result.isError).toBe(true);
    const events = engine.getFullHistory().filter(e => e.action_id === payload.action_id);
    const failed = events.find(e => e.event_type === 'action_failed');
    expect(failed).toBeTruthy();
    expect((failed!.details as any).reason).toBe('timeout');
  }, 10_000);

  it.skipIf(process.platform === 'win32')(
    'rejects shell backgrounding before it can leave an unowned scan',
    async () => {
      const marker = join(testDir, 'background-ran');
      const result = await handlers.run_bash({
        command: `sleep 10 & echo ran > ${JSON.stringify(marker)}`,
        timeout_ms: 5_000,
        validate: false,
      });
      const payload = parseTextResult(result);

      expect(result.isError).toBe(true);
      expect(payload.timed_out).toBe(false);
      expect(payload.spawn_error).toContain('background operator');
      expect(payload.stdout).toBe('');
      expect(existsSync(marker)).toBe(false);
      expect(engine.getRuntimeRuns()).toContainEqual(expect.objectContaining({
        action_id: payload.action_id,
        lifecycle: 'failed',
      }));
    },
    10_000,
  );

  it('does not confuse a quoted ampersand with shell backgrounding', async () => {
    const result = await handlers.run_bash({
      command: 'printf "%s" "rock & roll"',
      validate: false,
    });
    const payload = parseTextResult(result);

    expect(result.isError).toBeFalsy();
    expect(payload.stdout).toBe('rock & roll');
  });

  it('blocks execution when target_ip is out of scope', async () => {
    const result = await handlers.run_bash({
      command: 'echo would-not-run',
      target_ip: '8.8.8.8',
      technique: 'portscan',
    });
    const payload = parseTextResult(result);

    expect(result.isError).toBe(true);
    expect(payload.executed).toBe(false);
    expect(payload.validation_result).toBe('invalid');
    expect(payload.errors.join(' ')).toContain('out of scope');

    const events = engine.getFullHistory().filter(e => e.action_id === payload.action_id);
    expect(events.find(e => e.event_type === 'action_started')).toBeUndefined();
    expect(events.find(e => e.event_type === 'action_failed')).toBeTruthy();
  });

  it('blocks when any target_ips entry is out of scope (no singular target_ip)', async () => {
    // Regression: previously target_ips was logged but never validated, so a
    // multi-target invocation could ride out-of-scope IPs through.
    const result = await handlers.run_bash({
      command: 'echo would-not-run',
      target_ips: ['8.8.8.8'],
      technique: 'portscan',
    });
    const payload = parseTextResult(result);

    expect(result.isError).toBe(true);
    expect(payload.executed).toBe(false);
    expect(payload.validation_result).toBe('invalid');
    expect(payload.errors.join(' ')).toContain('8.8.8.8');
    expect(payload.errors.join(' ')).toContain('out of scope');
  });

  it('blocks when one of multiple target_ips is out of scope', async () => {
    const result = await handlers.run_bash({
      command: 'echo would-not-run',
      target_ips: ['10.10.10.1', '8.8.8.8'],
      technique: 'portscan',
    });
    const payload = parseTextResult(result);

    expect(result.isError).toBe(true);
    expect(payload.executed).toBe(false);
    expect(payload.errors.join(' ')).toContain('8.8.8.8');
  });

  it('extracts implicit targets from a known target-facing binary even without technique (regression: scope-bypass P0)', async () => {
    // Caller omits both target_ip(s) and technique. Previously this slipped
    // through scope because implicit-target extraction was gated on
    // TARGET_FACING_TECHNIQUES. Now extraction also fires when the binary is
    // a known scanner (nmap), so the out-of-scope IP is rejected.
    const result = await handlers.run_bash({
      command: 'nmap 8.8.8.8',
    });
    const payload = parseTextResult(result);

    expect(result.isError).toBe(true);
    expect(payload.executed).toBe(false);
    expect(payload.validation_result).toBe('invalid');
    expect(payload.errors.join(' ')).toContain('8.8.8.8');
    expect(payload.errors.join(' ')).toContain('out of scope');
  });

  it('does not over-extract on non-target-facing commands that mention out-of-scope hosts', async () => {
    // A non-scanner command that happens to mention an out-of-scope IP/URL
    // must still run — neither the binary (echo) nor the technique are
    // target-facing, so we deliberately don't sniff argv. This guards against
    // the fix for the P0 scope-bypass over-rejecting innocuous commands.
    const result = await handlers.run_bash({
      command: 'echo connecting-to-https://example.com/and/8.8.8.8-mention',
    });
    const payload = parseTextResult(result);
    expect(payload.executed).toBe(true);
  });

  it('rejects direct actions whose noise_estimate exceeds the OPSEC ceiling (P1 max_noise)', async () => {
    // Build a fresh engine with OPSEC enforcement enabled and a tight ceiling.
    const tightEngine = createEngine({
      ...makeConfig(),
      opsec: { name: 'tight', max_noise: 0.2, enabled: true } as any,
    }, 'tight.json');
    const tightHandlers: Record<string, (a: any) => Promise<any>> = {};
    const fakeServer = {
      registerTool(name: string, _config: unknown, handler: (a: any) => Promise<any>) {
        tightHandlers[name] = handler;
      },
    } as unknown as McpServer;
    registerRunBashTool(fakeServer, tightEngine);

    const result = await tightHandlers.run_bash({
      command: 'echo would-be-noisy',
      target_ip: '10.10.10.1',
      technique: 'portscan',
      noise_estimate: 0.9, // way over headroom
    });
    const payload = parseTextResult(result);

    expect(result.isError).toBe(true);
    expect(payload.executed).toBe(false);
    expect(payload.validation_result).toBe('invalid');
    expect(payload.errors.join(' ')).toContain('OPSEC noise ceiling');
  });

  it('OPSEC stays inert with opsec.enabled=false — no noise recorded, no defaults substituted', async () => {
    // OPSEC is opt-in. With enforcement disabled, missing noise_estimate must
    // NOT be silently filled in by the runner (neither the old buggy
    // cumulative-spend substitution nor the new per-technique defaults), and
    // no noise should be recorded against the OpsecTracker. The whole
    // pipeline stays out of the way unless the operator turns it on.
    const r1 = await handlers.run_bash({
      command: 'echo first',
      target_ip: '10.10.10.1',
      technique: 'enum_smb',
    });
    const payload = parseTextResult(r1);
    expect(payload.executed).toBe(true);
    const events = engine.getFullHistory().filter(e => e.action_id === payload.action_id);
    const started = events.find(e => e.event_type === 'action_started');
    expect(started?.noise_estimate).toBeUndefined();
    // OpsecTracker should still report zero global noise.
    expect(engine.getOpsecContext().global_noise_spent).toBe(0);
  });

  it('respects an explicit noise_estimate even when OPSEC is disabled (records, does not enforce)', async () => {
    // If the caller explicitly passes noise_estimate, we honor it (record it
    // on the event and the tracker) but do NOT enforce a ceiling — that
    // requires opsec.enabled.
    const r1 = await handlers.run_bash({
      command: 'echo explicit',
      target_ip: '10.10.10.1',
      technique: 'enum_smb',
      noise_estimate: 0.5,
    });
    const payload = parseTextResult(r1);
    expect(payload.executed).toBe(true);
    const events = engine.getFullHistory().filter(e => e.action_id === payload.action_id);
    const started = events.find(e => e.event_type === 'action_started');
    expect(started?.noise_estimate).toBe(0.5);
    expect(engine.getOpsecContext().global_noise_spent).toBe(0.5);
  });

  it('substitutes per-technique noise default only when OPSEC is enabled (no double-count)', async () => {
    // Regression: previously, when noise_estimate was undefined, the runner
    // substituted v.opsec_context.global_noise_spent, recording cumulative
    // spend back onto each subsequent action. With OPSEC enabled, the runner
    // now uses a per-technique default (enum_smb → 0.15), not the accumulated
    // total. With OPSEC disabled this whole branch is skipped (covered above).
    const opsecEngine = createEngine({
      ...makeConfig(),
      opsec: { name: 'pentest', max_noise: 1.0, enabled: true } as any,
    }, 'opsec.json');
    const opsecHandlers: Record<string, (a: any) => Promise<any>> = {};
    const fakeServer = {
      registerTool(name: string, _config: unknown, handler: (a: any) => Promise<any>) {
        opsecHandlers[name] = handler;
      },
    } as unknown as McpServer;
    registerRunBashTool(fakeServer, opsecEngine);

    await opsecHandlers.run_bash({ command: 'echo first', target_ip: '10.10.10.1', technique: 'enum_smb' });
    const r2 = await opsecHandlers.run_bash({ command: 'echo second', target_ip: '10.10.10.1', technique: 'enum_smb' });
    const payload2 = parseTextResult(r2);
    expect(payload2.executed).toBe(true);
    const events = opsecEngine.getFullHistory().filter(e => e.action_id === payload2.action_id);
    const started = events.find(e => e.event_type === 'action_started');
    // Per-action default for enum_smb is 0.15, not the cumulative sum (~0.3).
    expect(started?.noise_estimate).toBe(0.15);
  });

  it('approval gate sees the worst per-target OPSEC context, not the last (regression)', async () => {
    // Two in-scope targets; only the first carries a defensive signal. The
    // logged opsec_context for the action must reflect that signal — earlier
    // versions overwrote opsec_context with the last validated target.
    const now = new Date().toISOString();
    engine.addNode({ id: 'host-1', type: 'host', label: '10.10.10.1', discovered_at: now, confidence: 1 });
    engine.addNode({ id: 'host-2', type: 'host', label: '10.10.10.2', discovered_at: now, confidence: 1 });
    engine.recordDefensiveSignal({
      type: 'rate_limit',
      host_id: 'host-1',
      detected_at: now,
      description: 'WAF rate limited /admin',
    });

    const result = await handlers.run_bash({
      command: 'echo multi',
      target_node_ids: ['host-1', 'host-2'],
      technique: 'portscan',
    });
    const payload = parseTextResult(result);
    expect(payload.executed).toBe(true);

    const validated = engine.getFullHistory().find(
      e => e.action_id === payload.action_id && e.event_type === 'action_validated',
    );
    const opsec = (validated?.details as any)?.opsec_context;
    expect(opsec).toBeTruthy();
    const signals = opsec.defensive_signals as Array<{ host_id?: string }>;
    expect(signals.some(s => s.host_id === 'host-1')).toBe(true);
  });

  it('threads frontier_item_id through events', async () => {
    const result = await handlers.run_bash({
      command: 'true',
      validate: false,
      frontier_item_id: 'fake-frontier-1',
    });
    const payload = parseTextResult(result);
    const events = engine.getFullHistory().filter(e => e.action_id === payload.action_id);
    for (const e of events) {
      expect(e.frontier_item_id).toBe('fake-frontier-1');
    }
  });

  it('returns a parse error if parse_with names an unknown parser', async () => {
    const result = await handlers.run_bash({
      command: 'echo x',
      validate: false,
      parse_with: 'definitely-not-a-real-parser',
    });
    const payload = parseTextResult(result);
    expect(result.isError).toBe(true);
    expect(payload.parse_summary).toBeTruthy();
    expect(String(payload.parse_summary.error)).toContain('No parser found');
    expect(payload.parse_summary).toMatchObject({
      parse_status: 'no_parser', parse_outcome: 'validation_failed', isError: true,
    });
  });

  // -----------------------------------------------------------------
  // Phase I: parse output even on non-zero exit; tag the parse partial
  // -----------------------------------------------------------------
  it('parses output on non-zero exit without permanently tagging graph nodes partial', async () => {
    // emit a single line that the nuclei text parser will accept, then exit 7
    const cmd = `echo '[CVE-2099-9999] [http] [high] http://10.10.10.1/x'; exit 7`;
    const result = await handlers.run_bash({
      command: cmd,
      validate: false,
      parse_with: 'nuclei',
    });
    const payload = parseTextResult(result);
    expect(payload.parse_summary).toBeTruthy();
    expect(payload.parse_summary.parsed).toBe(true);
    expect(payload.parse_summary.partial).toBe(true);
    expect(payload.parse_summary.exit_code).toBe(7);

    const findingId = payload.parse_summary.finding_id as string;
    const vuln = engine.getNodesByType('vulnerability').find(
      v => (v as Record<string, unknown>).cve === 'CVE-2099-9999',
    );
    expect(vuln).toBeTruthy();
    expect((vuln as Record<string, unknown>).partial).toBeUndefined();
    expect(engine.getFullHistory().some(entry => entry.event_type === 'parse_output'
      && entry.details?.partial === true && entry.details?.exit_code === 7)).toBe(true);
    expect(findingId).toBeTruthy();
  });

  it('treats an acceptable_exit_code with zero yield as an explicit parse failure', async () => {
    // nuclei exits 1 when no template matched. Output is empty so the
    // parser will produce no nodes — but partial must NOT be true because
    // exit 1 is whitelisted for nuclei.
    const result = await handlers.run_bash({
      command: 'exit 1',
      validate: false,
      parse_with: 'nuclei',
    });
    const payload = parseTextResult(result);
    expect(result.isError).toBe(true);
    expect(payload.executed).toBe(true);
    expect(payload.exit_code).toBe(1);
    expect(payload.parse_summary).toMatchObject({
      parsed: false, parse_status: 'no_data', parse_outcome: 'no_data',
      nodes_parsed: 0, edges_parsed: 0, isError: true,
    });
    const actionEvents = engine.getFullHistory().filter(event =>
      event.action_id === payload.action_id);
    expect(actionEvents.map(event => event.event_type)).toEqual(
      expect.arrayContaining(['parse_output', 'action_failed']),
    );
    expect(actionEvents.findIndex(event => event.event_type === 'parse_output'))
      .toBeLessThan(actionEvents.findIndex(event => event.event_type === 'action_failed'));
    expect(actionEvents.some(event => event.event_type === 'action_completed')).toBe(false);
    expect(actionEvents.find(event => event.event_type === 'action_failed')?.details)
      .toMatchObject({ reason: 'parse_failed', parse_outcome: 'no_data' });
  });

  it('preserves Entra tenant context through inline run_bash parsing', async () => {
    const output = JSON.stringify({ value: [{
      id: 'user-object-1', displayName: 'Alice', userPrincipalName: 'alice@acme.onmicrosoft.com',
    }] });
    const result = await handlers.run_bash({
      command: `printf '%s' '${output}'`,
      validate: false,
      parse_with: 'msgraph-users',
      parser_context: { tenant_id: 'acme.onmicrosoft.com', provider_extension: { retained: true } },
    });
    const payload = parseTextResult(result);
    expect(result.isError).toBeFalsy();
    expect(payload.parse_summary.parse_outcome).toBe('ok');
    expect(engine.getNodesByType('idp_principal')[0]).toMatchObject({ tenant_id: 'acme.onmicrosoft.com' });
  });
});
