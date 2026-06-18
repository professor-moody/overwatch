import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'events';
import { existsSync, rmSync, mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { GraphEngine } from '../graph-engine.js';
import { ProcessTracker } from '../process-tracker.js';
import { TaskExecutionService } from '../task-execution-service.js';
import { allowedToolsFor } from '../headless-mcp-runner.js';
import type { EngagementConfig, AgentTask } from '../../types.js';

const TEST_STATE_FILE = './state-test-headless-runner.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-headless',
    name: 'headless test',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

// Minimal stand-in for a spawned ChildProcess.
class FakeChild extends EventEmitter {
  pid: number;
  stdout = new EventEmitter();
  stderr = new EventEmitter();
  signals: string[] = [];
  constructor(pid: number) { super(); this.pid = pid; }
  kill(sig: NodeJS.Signals = 'SIGTERM'): boolean { this.signals.push(sig); return true; }
  simulateExit(code: number | null, signal: NodeJS.Signals | null = null): void {
    this.emit('exit', code, signal);
  }
}

function headlessTask(overrides: Partial<AgentTask> = {}): AgentTask {
  return {
    id: overrides.id ?? `task-${Math.random().toString(36).slice(2, 10)}`,
    agent_id: overrides.agent_id ?? 'sub-agent',
    assigned_at: new Date().toISOString(),
    status: 'running',
    subgraph_node_ids: [],
    backend: 'headless_mcp',
    frontier_item_id: overrides.frontier_item_id,
  };
}

const settle = () => new Promise(r => setTimeout(r, 5));

describe('Headless runner mechanics (injected spawn)', () => {
  let engine: GraphEngine;
  let svc: TaskExecutionService;
  let spawned: FakeChild[];
  let spawnedArgs: string[][];
  let logDir: string;
  let nextPid: number;

  function makeService(opts: { maxConcurrentHeadless?: number; engineOverride?: GraphEngine } = {}) {
    return new TaskExecutionService(opts.engineOverride ?? engine, new ProcessTracker(), {
      maxConcurrentHeadless: opts.maxConcurrentHeadless,
      headless: {
        logDir,
        spawnFn: (_cmd: string, args: string[]) => {
          spawnedArgs.push(args);
          const child = new FakeChild(4_000_000_000 + (nextPid++));
          spawned.push(child);
          return child as any;
        },
      },
    });
  }

  beforeEach(() => {
    try { if (existsSync(TEST_STATE_FILE)) rmSync(TEST_STATE_FILE); } catch { /* ignore */ }
    logDir = mkdtempSync(join(tmpdir(), 'ow-headless-log-'));
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    spawned = [];
    spawnedArgs = [];
    nextPid = 1;
  });

  afterEach(() => {
    svc?.stop();
    try { if (existsSync(TEST_STATE_FILE)) rmSync(TEST_STATE_FILE); } catch { /* ignore */ }
    try { rmSync(logDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('does NOT launch headless tasks until an HTTP endpoint is set', async () => {
    svc = makeService();
    svc.start();
    engine.registerAgent(headlessTask({ id: 'h-noendpoint' }));
    await settle();
    expect(svc.activeHeadlessCount()).toBe(0);
    expect(engine.getTask('h-noendpoint')?.status).toBe('running'); // deferred
  });

  it('launches a headless process once an endpoint is available', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-launch' }));
    await settle();
    expect(svc.activeHeadlessCount()).toBe(1);
    expect(spawned).toHaveLength(1);
  });

  it('routes an UNSET-backend open-ended task to headless (not scripted no-op) when endpoint available', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    // A network_discovery frontier item is generated from the scope CIDR. A
    // dispatched task pointing at it with NO explicit backend must become a real
    // headless agent — previously it defaulted to scripted and was auto-"completed".
    const disco = engine.computeFrontier().find(f => f.type === 'network_discovery');
    expect(disco).toBeDefined();
    engine.registerAgent({ id: 'open-1', agent_id: 'a-open', assigned_at: new Date().toISOString(), status: 'running', subgraph_node_ids: [], frontier_item_id: disco!.id } as AgentTask);
    await settle();
    expect(svc.activeHeadlessCount()).toBe(1);
    expect(engine.getTask('open-1')?.status).toBe('running'); // launched, NOT auto-completed
  });

  it('fails an open-ended task loudly when no headless endpoint exists (no false "completed")', async () => {
    // With no endpoint, an open-ended (network_discovery) task falls to scripted,
    // which has no handler for it. It must fail LOUDLY with a reason — never a
    // silent "completed" (the prior behavior masked a real recon task as done).
    svc = makeService();
    svc.start(); // no endpoint
    const disco = engine.computeFrontier().find(f => f.type === 'network_discovery');
    engine.registerAgent({ id: 'open-noep', agent_id: 'a', assigned_at: new Date().toISOString(), status: 'running', subgraph_node_ids: [], frontier_item_id: disco!.id } as AgentTask);
    await settle();
    expect(svc.activeHeadlessCount()).toBe(0); // no endpoint → no headless
    const t = engine.getTask('open-noep');
    expect(t?.status).toBe('failed');
    expect(t?.result_summary ?? '').toContain('no_scripted_handler');
  });

  it('reconciles to interrupted when the child exits without closing the task', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-exit' }));
    await settle();
    expect(svc.activeHeadlessCount()).toBe(1);

    spawned[0].simulateExit(0);
    await settle();
    // Process gone, and the still-running task is marked interrupted (lease released).
    expect(svc.activeHeadlessCount()).toBe(0);
    expect(engine.getTask('h-exit')?.status).toBe('interrupted');
  });

  it('cancelHeadless kills the process (SIGTERM) and marks the task interrupted', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-cancel' }));
    await settle();

    // The per-task temp mcp-config (bearer token) exists while running.
    const cfgPath = join(tmpdir(), 'overwatch-mcp-h-cancel.json');
    expect(existsSync(cfgPath)).toBe(true);

    const killed = svc.cancelHeadless('h-cancel', 'operator cancel');
    expect(killed).toBe(true);
    expect(spawned[0].signals).toContain('SIGTERM');
    expect(engine.getTask('h-cancel')?.status).toBe('interrupted');
    // Killing cleans up the temp config even though the fake child never emits
    // 'exit' (regression: configs used to leak when a child was killed).
    expect(existsSync(cfgPath)).toBe(false);
  });

  it('watchdog reconcile kills an orphaned process AND aborts its pending approval after a reap', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-orphan', agent_id: 'sub-orphan' }));
    await settle();
    expect(svc.activeHeadlessCount()).toBe(1);

    // The agent is blocked on an approval gate (submitted directly; we're testing
    // the abort path, not the needsApproval gate).
    const queue = engine.getPendingActionQueue();
    const pendingApproval = {
      action_id: 'orphan-act',
      description: 'risky thing',
      opsec_context: { global_noise_spent: 0.1, noise_budget_remaining: 0.9, recommended_approach: 'normal' as const, defensive_signals: [] },
      validation_result: 'valid' as const,
      agent_id: 'sub-orphan',
    };
    engine.recordApprovalRequest(pendingApproval);
    const approvalPromise = queue.submit(pendingApproval);
    expect(queue.getPendingCount()).toBe(1);

    // Simulate a heartbeat-reap: the task flips terminal, but reaping does NOT
    // fire onUpdate, kill the process, or settle the approval (the P1 bug). The
    // process is still tracked and the approval still pending.
    engine.updateAgentStatus('h-orphan', 'interrupted', 'heartbeat timeout');
    await settle();
    expect(spawned[0].signals).not.toContain('SIGTERM'); // gap: not yet reconciled
    expect(queue.getPendingCount()).toBe(1);

    // The watchdog tick must reconcile: kill the orphan + abort its approval.
    svc.tickWatchdog();
    await settle();

    expect(spawned[0].signals).toContain('SIGTERM');     // orphaned process killed
    const resolution = await approvalPromise;
    expect(resolution.status).toBe('aborted');           // NOT auto-fired/executed
    expect(queue.getPendingCount()).toBe(0);
    // Durable record resolved too — dashboard/state stop showing a stuck 'pending'.
    const rec = engine.getApprovalRequests({ includeResolved: true }).find(r => r.action_id === 'orphan-act');
    expect(rec?.status).toBe('aborted');
  });

  it('enforces the max-concurrent-headless cap and launches the next when a slot frees', async () => {
    svc = makeService({ maxConcurrentHeadless: 1 });
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });

    engine.registerAgent(headlessTask({ id: 'h-cap-1' }));
    engine.registerAgent(headlessTask({ id: 'h-cap-2' }));
    await settle();

    // Only one launched (cap = 1).
    expect(svc.activeHeadlessCount()).toBe(1);
    expect(spawned).toHaveLength(1);

    // First finishes → its exit cascades a drain that launches the second.
    spawned[0].simulateExit(0);
    await settle();
    expect(svc.activeHeadlessCount()).toBe(1);
    expect(spawned).toHaveLength(2);
  });

  it('marks the task failed when spawn throws', async () => {
    svc = new TaskExecutionService(engine, new ProcessTracker(), {
      headless: {
        logDir,
        spawnFn: () => { throw new Error('ENOENT: claude not found'); },
      },
    });
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-spawnfail' }));
    await settle();
    expect(svc.activeHeadlessCount()).toBe(0);
    expect(engine.getTask('h-spawnfail')?.status).toBe('failed');
  });

  it('executes a stop directive: engine records, service kills the live process + interrupts', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-stopdir' }));
    await settle();
    expect(svc.activeHeadlessCount()).toBe(1);

    // Operator issues a stop directive through the engine. The engine only
    // records it; the service observes the pending stop and performs the kill.
    engine.issueAgentDirective({ task_id: 'h-stopdir', kind: 'stop', issued_by: 'operator' });
    await settle();

    expect(spawned[0].signals).toContain('SIGTERM');
    expect(engine.getTask('h-stopdir')?.status).toBe('interrupted');
    // The stop directive was acknowledged (executed), not left pending.
    expect(engine.getPendingAgentDirective('h-stopdir')).toBeNull();
  });

  it('does NOT act on pause/resume/steering directives — those are agent-observed', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-pausedir' }));
    await settle();

    engine.issueAgentDirective({ task_id: 'h-pausedir', kind: 'pause' });
    await settle();
    // Process stays alive; the agent honors pause itself via heartbeat.
    expect(spawned[0].signals).not.toContain('SIGTERM');
    expect(svc.activeHeadlessCount()).toBe(1);
    expect(engine.getPendingAgentDirective('h-pausedir')?.kind).toBe('pause');
  });

  function seedVersionedService(eng: GraphEngine, id: string) {
    eng.ingestFinding({
      id: `seed-${id}`, agent_id: 't', timestamp: new Date().toISOString(),
      nodes: [{ id, type: 'service', label: `http/${id}`, service_name: 'apache', version: '2.4.49' }],
      edges: [],
    } as any);
  }

  it('auto-dispatches a versioned service to a headless RESEARCH agent (web tools, no target execution)', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    seedVersionedService(engine, 'svc-cve');
    await settle();

    expect(svc.activeHeadlessCount()).toBe(1);
    const task = engine.getAgentTasks().find(t => t.role === 'research');
    expect(task?.backend).toBe('headless_mcp');
    // launched with web research tools, NOT target execution. Assert on the
    // --allowedTools VALUE (the prompt itself legitimately names run_bash to
    // tell the agent not to use it, so don't scan the whole arg vector).
    const argv = spawnedArgs[0];
    const allowed = argv[argv.indexOf('--allowedTools') + 1];
    expect(allowed).toContain('WebSearch');
    expect(allowed).toContain('mcp__overwatch__research_cve');
    expect(allowed).not.toContain('run_bash');
    expect(allowed).not.toContain('run_tool');
  });

  it('launches a PLANNER agent read-only (propose_plan, no target/web tools) carrying its objective', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent({
      id: 'h-planner', agent_id: 'planner-x', assigned_at: new Date().toISOString(), status: 'running',
      subgraph_node_ids: [], backend: 'headless_mcp', role: 'planner',
      objective: 'OPERATOR COMMAND (free-form): "pause everything"',
    } as AgentTask);
    await settle();
    expect(svc.activeHeadlessCount()).toBe(1);
    const argv = spawnedArgs[0];
    const allowed = argv[argv.indexOf('--allowedTools') + 1];
    expect(allowed).toContain('mcp__overwatch__propose_plan');
    expect(allowed).toContain('ToolSearch');
    // read-only: no target execution, no web, and NOT the whole-server prefix
    expect(allowed).not.toContain('run_bash');
    expect(allowed).not.toContain('run_tool');
    expect(allowed).not.toContain('WebSearch');
    expect(allowed.split(/\s+/)).not.toContain('mcp__overwatch');
    // the operator command is embedded in the -p bootstrap prompt
    const prompt = argv[argv.indexOf('-p') + 1];
    expect(prompt).toContain('pause everything');
  });

  it('isHeadlessAvailable reflects whether an endpoint is set', () => {
    svc = makeService();
    expect(svc.isHeadlessAvailable()).toBe(false);
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    expect(svc.isHeadlessAvailable()).toBe(true);
  });

  it('does NOT auto-dispatch cve_research when cve_research.enabled is false (air-gapped)', async () => {
    const offlineStateFile = './state-test-headless-runner-offline.json';
    try { if (existsSync(offlineStateFile)) rmSync(offlineStateFile); } catch { /* ignore */ }
    const offlineEngine = new GraphEngine({ ...makeConfig(), cve_research: { enabled: false } }, offlineStateFile);
    const offlineSvc = makeService({ engineOverride: offlineEngine });
    try {
      offlineSvc.start();
      offlineSvc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
      seedVersionedService(offlineEngine, 'svc-off');
      await settle();
      expect(offlineSvc.activeHeadlessCount()).toBe(0);
    } finally {
      offlineSvc.stop();
      try { if (existsSync(offlineStateFile)) rmSync(offlineStateFile); } catch { /* ignore */ }
    }
  });

  it('killAll on stop() terminates live headless children', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-shutdown' }));
    await settle();
    const child = spawned[0];
    svc.stop();
    expect(child.signals).toContain('SIGTERM');
  });
});

describe('allowedToolsFor (role tool profiles)', () => {
  it('default = whole Overwatch MCP surface + ToolSearch', () => {
    expect(allowedToolsFor('default')).toBe('mcp__overwatch ToolSearch');
  });

  it('research = web tools + per-tool research allowlist, no target execution', () => {
    const a = allowedToolsFor('research');
    expect(a).toContain('WebSearch');
    expect(a).toContain('mcp__overwatch__research_cve');
    expect(a).not.toContain('run_bash');
    expect(a.split(/\s+/)).not.toContain('mcp__overwatch'); // not the whole-server prefix
  });

  it('planner = read-only graph + propose_plan, no target/web tools, never the whole server', () => {
    const a = allowedToolsFor('planner');
    expect(a).toContain('mcp__overwatch__propose_plan');
    expect(a).toContain('mcp__overwatch__query_graph');
    expect(a).toContain('ToolSearch');
    expect(a).not.toContain('run_bash');
    expect(a).not.toContain('run_tool');
    expect(a).not.toContain('WebSearch');
    expect(a).not.toContain('research_cve');
    expect(a).not.toContain('report_finding');
    expect(a.split(/\s+/)).not.toContain('mcp__overwatch');
  });
});
