import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { EventEmitter } from 'events';
import { chmodSync, existsSync, rmSync, mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { GraphEngine } from '../graph-engine.js';
import { ProcessTracker } from '../process-tracker.js';
import { TaskExecutionService } from '../task-execution-service.js';
import { HeadlessMcpRunner, allowedToolsFor } from '../headless-mcp-runner.js';
import { HeadlessProcessRegistry } from '../headless-process-registry.js';
import { ApplicationCommandService } from '../application-command-service.js';
import { z } from 'zod';
import type { EngagementConfig, AgentTask } from '../../types.js';

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
  // 'close' fires after the process exits AND stdout/stderr have drained — the
  // runner salvages a cut-off agent's captured output here.
  simulateClose(code: number | null = null, signal: NodeJS.Signals | null = null): void {
    this.emit('close', code, signal);
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
    ...overrides,
  };
}

const settle = () => new Promise(r => setTimeout(r, 5));

describe('Headless runner mechanics (injected spawn)', () => {
  let engine: GraphEngine;
  let svc: TaskExecutionService;
  let spawned: FakeChild[];
  let spawnedArgs: string[][];
  let spawnedCmds: string[];
  let testDir: string;
  let logDir: string;
  let nextPid: number;
  const engines = new Set<GraphEngine>();

  function createEngine(config = makeConfig(), filename = 'state.json'): GraphEngine {
    const created = new GraphEngine(config, join(testDir, filename));
    engines.add(created);
    return created;
  }

  // Public task getters intentionally return detached read models. Tests that
  // simulate stale persisted runtime state must shape the owned fixture map.
  function liveTask(id: string): AgentTask {
    return (engine as any).ctx.agents.get(id) as AgentTask;
  }

  function makeService(opts: { maxConcurrentHeadless?: number; engineOverride?: GraphEngine; orchestratorHealthyMs?: number; orchestratorWedgedCeilingMs?: number; persistenceGatePollMs?: number } = {}) {
    return new TaskExecutionService(opts.engineOverride ?? engine, new ProcessTracker(), {
      maxConcurrentHeadless: opts.maxConcurrentHeadless,
      orchestratorHealthyMs: opts.orchestratorHealthyMs,
      orchestratorWedgedCeilingMs: opts.orchestratorWedgedCeilingMs,
      persistenceGatePollMs: opts.persistenceGatePollMs,
      headless: {
        logDir,
        spawnFn: (cmd: string, args: string[]) => {
          spawnedCmds.push(cmd);
          spawnedArgs.push(args);
          const child = new FakeChild(4_000_000_000 + (nextPid++));
          spawned.push(child);
          return child as any;
        },
      },
    });
  }

  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'overwatch-headless-runner-'));
    logDir = mkdtempSync(join(testDir, 'logs-'));
    engine = createEngine();
    spawned = [];
    spawnedArgs = [];
    spawnedCmds = [];
    nextPid = 1;
  });

  afterEach(() => {
    svc?.stop();
    for (const created of engines) created.dispose();
    engines.clear();
    rmSync(testDir, { recursive: true, force: true });
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

  it('freezes owned execution when persistence becomes read-only after launch', async () => {
    svc = makeService({ persistenceGatePollMs: 5 });
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-persistence-freeze' }));
    await settle();
    expect(spawned).toHaveLength(1);
    expect(svc.activeHeadlessCount()).toBe(1);

    let writable = true;
    const gate = vi.spyOn(engine, 'isPersistenceWritable').mockImplementation(() => writable);
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => {});
    const historyCount = engine.getFullHistory().length;
    writable = false;

    try {
      await new Promise(resolve => setTimeout(resolve, 20));
      expect(spawned[0].signals).toContain('SIGTERM');
      expect(() => svc.tickWatchdog()).not.toThrow();
      expect(svc.tickWatchdog()).toBe(0);

      // Late process callbacks only clean runtime resources. They must not stamp
      // task/process lifecycle state that cannot be persisted.
      spawned[0].simulateExit(null, 'SIGTERM');
      spawned[0].simulateClose(null, 'SIGTERM');
      await settle();
      expect(svc.activeHeadlessCount()).toBe(0);
      expect(engine.getTask('h-persistence-freeze')?.status).toBe('running');
      expect(engine.getFullHistory()).toHaveLength(historyCount);
      expect(stderr).toHaveBeenCalledWith(expect.stringContaining('task execution frozen'));
    } finally {
      stderr.mockRestore();
      gate.mockRestore();
    }
  });

  it('passes --model <id> to the spawn when the task specifies a model', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-model', model: 'claude-opus-4-8' }));
    await settle();
    const args = spawnedArgs[0];
    expect(args[args.indexOf('--model') + 1]).toBe('claude-opus-4-8');
  });

  it('omits --model when the task has no model', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-nomodel' }));
    await settle();
    expect(spawnedArgs[0]).not.toContain('--model');
  });

  // ---- Phase 3.1: re-offer (alert) of stranded frontier work ----

  const reofferCount = () =>
    engine.getFullHistory().filter(e => (e.details as { reason?: string })?.reason === 'work_reoffered').length;

  // Launch a headless agent on a real frontier item, then kill its process so the
  // runner marks it interrupted AND clears the registry (the sweep only alerts
  // once the old process is confirmed gone).
  async function launchThenDie(id: string, agentId: string, extra: Partial<AgentTask> = {}) {
    const disco = engine.computeFrontier().find(f => f.type === 'network_discovery');
    expect(disco).toBeDefined();
    const before = spawned.length;
    engine.registerAgent(headlessTask({ id, agent_id: agentId, frontier_item_id: disco!.id, ...extra }));
    await settle();
    expect(spawned.length).toBe(before + 1);
    spawned[spawned.length - 1].simulateExit(1, null);   // process died → interrupted + registry cleared
    spawned[spawned.length - 1].simulateClose(1, null);
    await settle();
    expect(engine.getTask(id)?.status).toBe('interrupted');
    return disco!.id;
  }

  it('alerts (loudly, once) when a dead headless agent leaves unfinished frontier work', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    await launchThenDie('dead-1', 'a-dead');
    const before = spawned.length;
    svc.tickWatchdog();
    await settle();
    expect(reofferCount()).toBe(1);                                       // loud alert
    expect(engine.getAgentTasks().some(t => t.agent_id.startsWith('retry-'))).toBe(false); // no autonomous re-spawn
    expect(spawned.length).toBe(before);
    expect(engine.getTask('dead-1')?.reoffered).toBe(true);
  });

  it('does NOT alert for an operator-stopped (no_retry) agent', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    await launchThenDie('stopped-1', 'a-stop', { no_retry: true });
    svc.tickWatchdog();
    await settle();
    expect(reofferCount()).toBe(0);
    expect(engine.getTask('stopped-1')?.reoffered).toBeFalsy();
  });

  it('alerts once — a second tick does not re-alert (durable dedup)', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    await launchThenDie('dedup-1', 'a-dd');
    svc.tickWatchdog();
    await settle();
    expect(reofferCount()).toBe(1);
    svc.tickWatchdog();                              // second tick
    await settle();
    expect(reofferCount()).toBe(1);                 // still once
  });

  it('does NOT alert while the old process is still live (no premature strand)', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    const disco = engine.computeFrontier().find(f => f.type === 'network_discovery');
    engine.registerAgent(headlessTask({ id: 'live-1', agent_id: 'a-live', frontier_item_id: disco!.id }));
    await settle();
    // Heartbeat-reap marks it interrupted but the OS process has NOT exited yet
    // (still in the registry). The sweep must defer until it's confirmed gone.
    engine.updateAgentStatus('live-1', 'interrupted', 'heartbeat timeout');
    svc.tickWatchdog();
    await settle();
    expect(reofferCount()).toBe(0);
    expect(engine.getTask('live-1')?.reoffered).toBeFalsy(); // not evaluated until the process is gone
  });

  it('does not permanently suppress the alert if the frontier compute throws (transient)', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    await launchThenDie('throwy-1', 'a-throw');
    const orig = engine.getFrontierItem.bind(engine);
    // First tick: computeFrontier throws → no alert, and the durable dedup flag
    // must NOT be committed (else the strand would be suppressed forever).
    engine.getFrontierItem = (() => { throw new Error('frontier compute error'); }) as typeof engine.getFrontierItem;
    svc.tickWatchdog();
    await settle();
    expect(reofferCount()).toBe(0);
    expect(engine.getTask('throwy-1')?.reoffered).toBeFalsy();
    // Recovery: the next clean tick finally surfaces the strand.
    engine.getFrontierItem = orig;
    svc.tickWatchdog();
    await settle();
    expect(reofferCount()).toBe(1);
    expect(engine.getTask('throwy-1')?.reoffered).toBe(true);
  });

  // ---- Phase 3.2: persistent orchestrator lifecycle ----

  const runningOrchestrators = () =>
    engine.getAgentTasks().filter(t => t.role === 'orchestrator' && (t.status === 'running' || t.status === 'pending'));

  it('does NOT start a persistent orchestrator unless opted in', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    await settle();
    expect(runningOrchestrators().length).toBe(0);
  });

  it('starts exactly one orchestrator when enabled + headless available (idempotent)', async () => {
    svc = makeService();
    svc.start();
    engine.updateConfig({ orchestrator: { enabled: true } });
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' }); // headless available → reconcileOrchestrator
    await settle();
    const orchs = runningOrchestrators();
    expect(orchs.length).toBe(1);
    expect(orchs[0].orchestrator).toBe(true);              // primary bootstrap + full tools
    expect(spawned.length).toBe(1);
    svc.tickWatchdog(); await settle();
    svc.tickWatchdog(); await settle();
    expect(runningOrchestrators().length).toBe(1);         // still exactly one
    expect(spawned.length).toBe(1);
  });

  it('backs off (no hot-loop) when the orchestrator dies fast', async () => {
    svc = makeService(); // default 5-min healthy threshold
    svc.start();
    engine.updateConfig({ orchestrator: { enabled: true } });
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    await settle();
    expect(spawned.length).toBe(1);
    spawned[0].simulateExit(1, null); spawned[0].simulateClose(1, null); // dies immediately (fast)
    await settle();
    svc.tickWatchdog(); await settle();
    expect(runningOrchestrators().length).toBe(0);         // backing off — NOT respawned
    expect(spawned.length).toBe(1);
    expect(engine.getFullHistory().some(e => (e.details as { reason?: string })?.reason === 'orchestrator_restart_backoff')).toBe(true);
  });

  it('restarts the orchestrator after a healthy run ends', async () => {
    svc = makeService({ orchestratorHealthyMs: 0 }); // every run counts as healthy → no backoff
    svc.start();
    engine.updateConfig({ orchestrator: { enabled: true } });
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    await settle();
    expect(spawned.length).toBe(1);
    const first = runningOrchestrators()[0];
    spawned[0].simulateExit(0, null); spawned[0].simulateClose(0, null);
    await settle();
    svc.tickWatchdog(); await settle();
    const orchs = runningOrchestrators();
    expect(orchs.length).toBe(1);                          // a fresh one
    expect(orchs[0].id).not.toBe(first.id);
    expect(spawned.length).toBe(2);                        // relaunched
  });

  it('supervisor liveness: a LIVE orchestrator is not reaped even when its beat goes stale past the TTL', async () => {
    svc = makeService({ orchestratorHealthyMs: 0 }); // healthy → a real reap would respawn (we assert it does NOT)
    svc.start();
    engine.updateConfig({ orchestrator: { enabled: true } });
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    await settle();
    const orch = runningOrchestrators()[0];
    expect(orch).toBeDefined();
    expect(spawned.length).toBe(1);
    // Simulate a busy-but-quiet orchestrator: its process is still alive (never
    // exited → still in the registry), but the model hasn't called agent_heartbeat,
    // so its beat is now 700s old against the 600s TTL — a reap without the fix.
    liveTask(orch.id).heartbeat_at = new Date(Date.now() - 700_000).toISOString();
    svc.tickWatchdog();               // beforeTick refresh must land before the reap
    await settle();
    // Not reaped, not churned: same task, same single process.
    expect(engine.getTask(orch.id)?.status).toBe('running');
    expect(runningOrchestrators().map(o => o.id)).toEqual([orch.id]);
    expect(spawned.length).toBe(1);
    // The supervisor refreshed the beat — it's now recent, not the stale value.
    expect(Date.now() - Date.parse(engine.getTask(orch.id)!.heartbeat_at!)).toBeLessThan(30_000);
  });

  it('supervisor liveness stops once the process exits — a dead orchestrator still reaps + respawns', async () => {
    svc = makeService({ orchestratorHealthyMs: 0 });
    svc.start();
    engine.updateConfig({ orchestrator: { enabled: true } });
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    await settle();
    const first = runningOrchestrators()[0];
    // Process dies → exit handler clears the registry + marks it interrupted. The
    // liveness refresh must NOT resurrect it (registry no longer has it).
    spawned[0].simulateExit(0, null); spawned[0].simulateClose(0, null);
    await settle();
    svc.tickWatchdog();
    await settle();
    const orchs = runningOrchestrators();
    expect(orchs.length).toBe(1);
    expect(orchs[0].id).not.toBe(first.id);   // a fresh one, not the dead task kept alive
    expect(spawned.length).toBe(2);
  });

  it('runs the orchestrator OUTSIDE the concurrency cap (no sub-agent starvation)', async () => {
    svc = makeService({ maxConcurrentHeadless: 1 });      // one sub-agent slot
    svc.start();
    engine.updateConfig({ orchestrator: { enabled: true } });
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    await settle();
    expect(runningOrchestrators().length).toBe(1);
    expect(spawned.length).toBe(1);                        // orchestrator launched
    // A sub-agent dispatched alongside it still launches — the orchestrator does
    // not consume the single sub-agent slot (would deadlock before the fix).
    const disco = engine.computeFrontier().find(f => f.type === 'network_discovery');
    engine.registerAgent(headlessTask({ id: 'sub-1', agent_id: 'a-sub', frontier_item_id: disco!.id }));
    await settle();
    expect(spawned.length).toBe(2);                        // sub-agent launched too
  });

  it('runs an orchestrator task with the full tool surface + a primary bootstrap, and honors a per-task binary override', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent({
      id: 'h-primary', agent_id: 'a-primary', assigned_at: new Date().toISOString(),
      status: 'running', subgraph_node_ids: [], backend: 'headless_mcp',
      orchestrator: true, claudeBinary: '/fake/real-claude',
    } as AgentTask);
    await settle();
    expect(spawned).toHaveLength(1);
    // Per-task binary override is used (not the runner default).
    expect(spawnedCmds[0]).toBe('/fake/real-claude');
    const args = spawnedArgs[0];
    // Full surface, like 'default' (not a scoped sub-agent allowlist).
    expect(args).toContain(allowedToolsFor('default'));
    // Primary orchestration bootstrap, not the sub-agent brief.
    const prompt = args[args.indexOf('-p') + 1];
    expect(prompt).toContain('PRIMARY orchestrator');
    expect(prompt).toContain('get_system_prompt(role="primary")');
    expect(prompt).toContain('dispatch_agents');
    expect(prompt).not.toContain('role="sub_agent"');
  });

  it('a normal (non-orchestrator) task uses the runner default binary', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-default-bin' }));
    await settle();
    expect(spawnedCmds[0]).toBe(process.env.OVERWATCH_CLAUDE_BINARY ?? 'claude');
  });

  it('grants a launched headless agent a generous cold-start heartbeat TTL', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-ttl' }));
    await settle();
    expect(svc.activeHeadlessCount()).toBe(1);
    // The default 120s TTL would let cold-start (spawn + MCP bootstrap + first
    // tool call) trip the watchdog and reap a healthy agent before its first beat.
    expect(engine.getTask('h-ttl')?.heartbeat_ttl_seconds).toBe(300);
  });

  it('keeps a headless task queued behind the concurrency cap alive (heartbeat + lease) so it is not reaped before it launches', async () => {
    svc = makeService({ maxConcurrentHeadless: 1 });
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'q-A' }));   // fills the single slot → launches
    engine.registerAgent(headlessTask({ id: 'q-B' }));   // at capacity → queued, NOT launched
    await settle();
    expect(spawned.length).toBe(1);
    expect(engine.getTask('q-B')?.status).toBe('running');
    // Simulate the queued task waiting past its 120s TTL: age its beat beyond the
    // TTL. Before the fix the watchdog reaped it (heartbeat_timeout) before it ever
    // ran; now the supervisor refreshes it (before the reap) while it waits.
    liveTask('q-B').heartbeat_at = new Date(Date.now() - 130_000).toISOString();
    svc.tickWatchdog();
    await settle();
    expect(engine.getTask('q-B')?.status).toBe('running');                 // not reaped
    expect(Date.now() - Date.parse(engine.getTask('q-B')!.heartbeat_at!)).toBeLessThan(30_000); // refreshed
    // When the running slot frees, the queued task launches and beats for itself.
    spawned[0].simulateExit(0, null); spawned[0].simulateClose(0, null);
    await settle();
    svc.tickWatchdog(); await settle();
    expect(spawned.length).toBe(2);
  });

  it('keeps a LAUNCHED sub-agent alive while its process is live (busy in a long tool child), not reaped mid-scan', async () => {
    // A launched sub-agent must self-beat, but while it's blocked inside one long tool
    // child (a big nmap/subfinder/crawl) the model isn't looping, so no agent_heartbeat
    // fires. Its process is still alive → the supervisor keeps the beat fresh (same
    // process-liveness signal the orchestrator uses) instead of reaping a healthy scanner.
    // Small ceiling + an OLD assigned_at so the assigned_at fallback alone would reap it;
    // the only thing that keeps it alive is fresh process OUTPUT (last_output_at). This
    // pins the test to the output-liveness path, not the fallback — and is the exact
    // mirror of the wedged test below, which is identical but emits no output.
    svc = makeService({ orchestratorWedgedCeilingMs: 1000 });
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'busy-scanner', agent_id: 'network-recon' }));
    await settle();
    expect(spawned.length).toBe(1);                                          // launched, process alive
    const busy = engine.getTask('busy-scanner')!;
    busy.assigned_at = new Date(Date.now() - 5000).toISOString();            // past the 1s ceiling → fallback would reap
    busy.heartbeat_at = new Date(Date.now() - 310_000).toISOString();        // beat aged past the 300s cold-start TTL
    spawned[0].stdout.emit('data', Buffer.from('{"type":"assistant"}\n'));   // nmap just returned → last_output_at now, within ceiling
    svc.tickWatchdog();
    await settle();
    expect(engine.getTask('busy-scanner')?.status).toBe('running');          // NOT reaped — output proves it's live
    expect(Date.now() - Date.parse(engine.getTask('busy-scanner')!.heartbeat_at!)).toBeLessThan(30_000); // refreshed
  });

  it('does NOT prop up a launched sub-agent that is genuinely WEDGED (process alive but silent past the ceiling)', async () => {
    // Alive process, but no output for longer than the wedged ceiling AND a stale beat →
    // the supervisor stops refreshing it and the reaper takes it (the 30-min wall-clock
    // timeout is the other backstop). Distinguishes "busy" (recent output) from "hung".
    svc = makeService({ orchestratorWedgedCeilingMs: 1000 });
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'wedged-sub', agent_id: 'osint' }));
    await settle();
    expect(spawned.length).toBe(1);
    // Deliberately shape persisted internals to simulate a process that has not
    // emitted output or heartbeats; public getters return detached read models.
    const t = (engine as any).ctx.agents.get('wedged-sub')!;
    t.assigned_at = new Date(Date.now() - 5000).toISOString();               // no output ever → falls back to assigned_at, past the 1s ceiling
    t.heartbeat_at = new Date(Date.now() - 310_000).toISOString();           // beat also stale past the 300s TTL
    svc.tickWatchdog();
    await settle();
    expect(engine.getTask('wedged-sub')?.status).toBe('interrupted');        // reaped, not propped up
  });

  it('restarts a WEDGED orchestrator (alive but no genuine heartbeat) instead of propping it up forever', async () => {
    svc = makeService({ orchestratorHealthyMs: 0, orchestratorWedgedCeilingMs: 1000 });
    svc.start();
    engine.updateConfig({ orchestrator: { enabled: true } });
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    await settle();
    const first = runningOrchestrators()[0];
    expect(first).toBeDefined();
    expect(spawned.length).toBe(1);
    // Wedged: process still alive, but has produced NO output for longer than the
    // ceiling (no last_output_at → liveness falls back to assigned_at).
    liveTask(first.id).assigned_at = new Date(Date.now() - 5000).toISOString();
    svc.tickWatchdog();
    await settle();
    expect(engine.getFullHistory().some(e => (e.details as { reason?: string })?.reason === 'orchestrator_wedged')).toBe(true);
    const orchs = runningOrchestrators();
    expect(orchs.length).toBe(1);
    expect(orchs[0].id).not.toBe(first.id);                // a fresh primary
    expect(spawned.length).toBe(2);
  });

  it('does NOT treat a genuinely-active orchestrator as wedged (recent process output resets the ceiling)', async () => {
    svc = makeService({ orchestratorHealthyMs: 0, orchestratorWedgedCeilingMs: 1000 });
    svc.start();
    engine.updateConfig({ orchestrator: { enabled: true } });
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    await settle();
    const orch = runningOrchestrators()[0];
    // Old start, but the process is streaming output NOW → healthy, not wedged.
    liveTask(orch.id).assigned_at = new Date(Date.now() - 5000).toISOString();
    spawned[0].stdout.emit('data', Buffer.from('{"type":"assistant"}\n')); // process alive + producing
    svc.tickWatchdog();
    await settle();
    expect(engine.getTask(orch.id)?.status).toBe('running');
    expect(runningOrchestrators().map(o => o.id)).toEqual([orch.id]); // same primary, not restarted
  });

  it('gives an orchestrator-flagged task with NO configured TTL the cold-start grace (not the tight 120s default)', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    // Eval-style: orchestrator:true + headless_mcp, but NO role/heartbeat_ttl_seconds.
    engine.registerAgent({
      id: 'h-eval-orch', agent_id: 'a-eval', assigned_at: new Date().toISOString(),
      status: 'running', subgraph_node_ids: [], backend: 'headless_mcp', orchestrator: true,
    } as never);
    await settle();
    expect(spawned.length).toBe(1);
    expect(engine.getTask('h-eval-orch')?.heartbeat_ttl_seconds).toBe(300);
  });

  it('does NOT clobber the orchestrator\'s configured 600s TTL with the sub-agent cold-start grace', async () => {
    svc = makeService();
    svc.start();
    engine.updateConfig({ orchestrator: { enabled: true } });
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    await settle();
    const orch = runningOrchestrators()[0];
    expect(orch).toBeDefined();
    // Registered with 600s; the launch path must leave it there (not 300).
    expect(orch.heartbeat_ttl_seconds).toBe(600);
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

  it('reconciles a CLEAN exit (code 0) without a transcript to interrupted, with a non-crash reason, and salvages its output', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-clean', agent_id: 'a-clean' }));
    await settle();
    expect(svc.activeHeadlessCount()).toBe(1);

    // The agent produced output but exited 0 without ever calling submit_agent_transcript
    // (ended its turn / hit its budget). That's incomplete work → interrupted so the
    // frontier item is re-offered, but the reason says so instead of reading like a crash.
    spawned[0].stdout.emit('data', Buffer.from('{"type":"assistant","text":"enumerated 3 hosts"}\n'));
    spawned[0].simulateExit(0, null);
    spawned[0].simulateClose(0, null);
    await settle();

    expect(svc.activeHeadlessCount()).toBe(0);
    const task = engine.getTask('h-clean');
    expect(task?.status).toBe('interrupted');                              // re-offerable, not counted as campaign success
    expect(task?.result_summary ?? '').toContain('clean exit');           // distinguished from a crash
    expect(task?.result_summary ?? '').toContain('returned to the frontier');
    // Its work is still salvaged even though it never self-submitted.
    const salvage = engine.getFullHistory().find(e =>
      (e.details as { salvaged?: boolean } | undefined)?.salvaged === true &&
      e.linked_agent_task_id === 'h-clean');
    expect(salvage).toBeDefined();
    const evidenceId = (salvage!.details as { evidence_id?: string }).evidence_id;
    expect(engine.getEvidenceStore().getContent(evidenceId ?? '') ?? '').toContain('enumerated 3 hosts');
  });

  it('reconciles a non-clean exit (non-zero code / killed) without a transcript to interrupted, tagging the code/signal', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-crash' }));
    await settle();
    expect(svc.activeHeadlessCount()).toBe(1);

    spawned[0].simulateExit(1, null); // crashed (non-zero) → genuine interruption, lease released
    await settle();
    expect(svc.activeHeadlessCount()).toBe(0);
    const task = engine.getTask('h-crash');
    expect(task?.status).toBe('interrupted');
    expect(task?.result_summary ?? '').toContain('code=1');               // crash detail preserved for triage
  });

  it('salvages a cut-off agent\'s run log to evidence on exit', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-salvage', agent_id: 'a-salvage' }));
    await settle();
    expect(spawned).toHaveLength(1);

    // The agent emits stream-json output, then is killed mid-flight (exits while
    // still running) BEFORE it ever called submit_agent_transcript.
    const trace = '{"type":"assistant","text":"found cred on host-1"}\n{"type":"tool_use","name":"run_bash"}\n';
    spawned[0].stdout.emit('data', Buffer.from(trace));
    spawned[0].simulateExit(null, 'SIGTERM'); // marks interrupted (lease release)
    spawned[0].simulateClose(null, 'SIGTERM'); // stdio drained → salvage runs
    await settle();

    expect(engine.getTask('h-salvage')?.status).toBe('interrupted');
    const salvage = engine.getFullHistory().find(e =>
      e.event_type === 'agent_transcript_submitted' &&
      (e.details as { salvaged?: boolean } | undefined)?.salvaged === true &&
      e.linked_agent_task_id === 'h-salvage');
    expect(salvage).toBeDefined();
    const evidenceId = (salvage!.details as { evidence_id?: string }).evidence_id;
    expect(evidenceId).toBeTruthy();
    expect(engine.getEvidenceStore().getContent(evidenceId!) ?? '').toContain('found cred on host-1');
  });

  it('does NOT salvage when the agent completed normally (it reported its own work)', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-done', agent_id: 'a-done' }));
    await settle();
    spawned[0].stdout.emit('data', Buffer.from('{"type":"assistant"}\n'));
    // Agent finished deliberately before its process exited.
    engine.updateAgentStatus('h-done', 'completed', 'all done');
    spawned[0].simulateExit(0);
    spawned[0].simulateClose(0);
    await settle();

    expect(engine.getTask('h-done')?.status).toBe('completed');
    const salvage = engine.getFullHistory().find(e =>
      (e.details as { salvaged?: boolean } | undefined)?.salvaged === true &&
      e.linked_agent_task_id === 'h-done');
    expect(salvage).toBeUndefined();
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

  it('cancels a queued command-owned planner without leaving its command accepted forever', async () => {
    svc = makeService({ maxConcurrentHeadless: 1 });
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-capacity-blocker' }));
    await settle();
    new ApplicationCommandService(engine).reserveSync({
      command_kind: 'operator.plan',
      input: { command: 'inspect the queued target' },
      schema: z.object({ command: z.string() }).strict(),
      metadata: {
        command_id: 'queued-planner-command',
        idempotency_key: 'queued-planner-command',
      },
      reserve: () => ({
        status: 'accepted',
        result: {
          phase: 'planning_queued',
          planner_task_id: 'h-queued-planner',
        },
      }),
    });
    engine.registerAgent(headlessTask({
      id: 'h-queued-planner',
      role: 'planner',
      application_command_id: 'queued-planner-command',
    }));
    await settle();
    expect(spawned).toHaveLength(1);

    expect(svc.cancelHeadless('h-queued-planner', 'operator cancelled queued planner'))
      .toBe(false);
    expect(engine.getTask('h-queued-planner')?.status).toBe('interrupted');
    expect(engine.getApplicationCommandById('queued-planner-command')).toMatchObject({
      status: 'interrupted',
      error: {
        code: 'PLANNER_INTERRUPTED',
        message: 'operator cancelled queued planner',
      },
    });
  });

  it('terminalizes a launched planner command even if the child never emits exit', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    new ApplicationCommandService(engine).reserveSync({
      command_kind: 'operator.plan',
      input: { command: 'inspect the live target' },
      schema: z.object({ command: z.string() }).strict(),
      metadata: {
        command_id: 'live-planner-command',
        idempotency_key: 'live-planner-command',
      },
      reserve: () => ({
        status: 'accepted',
        result: {
          phase: 'planning_queued',
          planner_task_id: 'h-live-planner',
        },
      }),
    });
    engine.registerAgent(headlessTask({
      id: 'h-live-planner',
      role: 'planner',
      application_command_id: 'live-planner-command',
    }));
    await settle();
    expect(engine.getApplicationCommandById('live-planner-command')?.status)
      .toBe('running');

    expect(svc.cancelHeadless('h-live-planner', 'operator cancelled live planner'))
      .toBe(true);
    expect(engine.getApplicationCommandById('live-planner-command')).toMatchObject({
      status: 'interrupted',
      error: { code: 'PLANNER_INTERRUPTED' },
    });
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
      task_id: 'h-orphan',
      agent_label: 'sub-orphan',
      agent_id: 'sub-orphan',
    };
    engine.recordApprovalRequest(pendingApproval);
    const approvalPromise = queue.submit(pendingApproval);
    expect(queue.getPendingCount()).toBe(1);

    // The canonical lifecycle transition immediately settles task-owned
    // coordination state, but process ownership remains the supervisor's job.
    engine.updateAgentStatus('h-orphan', 'interrupted', 'heartbeat timeout');
    await settle();
    expect(spawned[0].signals).not.toContain('SIGTERM');
    expect(queue.getPendingCount()).toBe(0);
    await expect(approvalPromise).resolves.toMatchObject({ status: 'aborted' });

    // The watchdog tick reconciles the remaining runtime handle.
    svc.tickWatchdog();
    await settle();

    expect(spawned[0].signals).toContain('SIGTERM');     // orphaned process killed
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

  it('marks the task failed when spawn returns a child with no pid (no zombie task)', async () => {
    svc = new TaskExecutionService(engine, new ProcessTracker(), {
      headless: {
        logDir,
        spawnFn: () => new FakeChild(0) as any, // pid 0 → falsy: a pidless child
      },
    });
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-nopid' }));
    await settle();
    // A pidless child can't be killed or heartbeated — it must NOT be registered
    // as a running task (which would leave a zombie holding a lease until TTL).
    expect(svc.activeHeadlessCount()).toBe(0);
    expect(engine.getTask('h-nopid')?.status).toBe('failed');
  });

  it('a pidless child emitting an async error does NOT crash (error handler attached before bail-out)', async () => {
    const children: FakeChild[] = [];
    svc = new TaskExecutionService(engine, new ProcessTracker(), {
      headless: { logDir, spawnFn: () => { const c = new FakeChild(0); children.push(c); return c as any; } },
    });
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    engine.registerAgent(headlessTask({ id: 'h-nopid-err' }));
    await settle();
    expect(engine.getTask('h-nopid-err')?.status).toBe('failed');
    // ENOENT surfaces a pidless child that fires 'error' asynchronously. With no
    // listener, EventEmitter re-throws it → ERR_UNHANDLED_ERROR crashes the daemon.
    // The fix attaches the handler BEFORE the pidless bail-out, so this is handled.
    expect(() => children[0].emit('error', new Error('spawn claude ENOENT'))).not.toThrow();
  });

  it.each([
    'spawned',
    'ttl_registered',
    'process_registered',
  ] as const)(
    'fails closed and leaves restart truth clean when ownership setup fails after %s',
    (failureStage) => {
      const taskId = `h-unwind-${failureStage}`;
      const commandId = `planner-command-${failureStage}`;
      new ApplicationCommandService(engine).reserveSync({
        command_kind: 'operator.plan',
        input: { command: `plan after ${failureStage}` },
        schema: z.object({ command: z.string() }).strict(),
        metadata: {
          command_id: commandId,
          idempotency_key: commandId,
          transport: 'dashboard',
        },
        reserve: () => ({
          status: 'accepted',
          result: { phase: 'planning_queued', planner_task_id: taskId },
        }),
      });
      expect(engine.registerAgent(headlessTask({
        id: taskId,
        role: 'planner',
        application_command_id: commandId,
      })).ok).toBe(true);

      const registry = new HeadlessProcessRegistry();
      const tracker = new ProcessTracker();
      tracker.setMutationGuard(() => engine.assertPersistenceWritable());
      const unsubscribe = tracker.onChange(() => {
        engine.setTrackedProcesses(tracker.serialize());
      });
      const child = new FakeChild(4_100_000_000 + nextPid++);
      const groupSignals: NodeJS.Signals[] = [];
      const processKill = process.platform === 'win32'
        ? undefined
        : vi.spyOn(process, 'kill').mockImplementation((pid, signal = 0) => {
            if (pid === -child.pid && typeof signal === 'string') {
              groupSignals.push(signal as NodeJS.Signals);
            }
            return true;
          });
      let configPath = '';
      const runner = new HeadlessMcpRunner(engine, registry, tracker, {
        logDir,
        spawnFn: (_command, args) => {
          configPath = args[args.indexOf('--mcp-config') + 1];
          return child as any;
        },
        onLaunchCheckpoint: stage => {
          if (stage === failureStage) throw new Error(`injected ${stage} failure`);
        },
      });

      try {
        const launched = runner.launch(
          engine.getTask(taskId)!,
          { url: 'http://127.0.0.1:9/mcp', token: 'test-secret' },
        );

        expect(launched).toBeNull();
        if (process.platform === 'win32') {
          expect(child.signals).toContain('SIGTERM');
          expect(child.signals).toContain('SIGKILL');
        } else {
          expect(groupSignals).toContain('SIGTERM');
          expect(groupSignals).toContain('SIGKILL');
        }
        expect(registry.has(taskId)).toBe(false);
        expect(tracker.get(`headless-${taskId}`)).toBeNull();
        expect(engine.getTrackedProcesses()).not.toContainEqual(
          expect.objectContaining({ id: `headless-${taskId}` }),
        );
        expect(engine.getRuntimeRuns()).toContainEqual(expect.objectContaining({
          run_id: `headless-${taskId}`,
          kind: 'headless_agent',
          task_id: taskId,
          lifecycle: 'failed',
          finalization_status: 'failed',
          recovery_warning: expect.stringContaining(`injected ${failureStage} failure`),
        }));
        expect(engine.getTask(taskId)?.status).toBe('failed');
        expect(engine.getApplicationCommandById(commandId)).toMatchObject({
          status: 'failed',
          error: {
            code: 'PLANNER_OWNERSHIP_SETUP_FAILED',
            message: expect.stringContaining(`injected ${failureStage} failure`),
          },
        });
        expect(
          engine.getTask(taskId)?.heartbeat_ttl_seconds
          ?? 120,
        ).toBe(120);
        expect(configPath).not.toBe('');
        expect(existsSync(configPath)).toBe(false);

        const reasons = () => engine.getFullHistory()
          .map(entry => (entry.details as { reason?: string } | undefined)?.reason);
        expect(reasons()).not.toContain('headless_launched');
        expect(reasons()).not.toContain('headless_exited');
        const historyLength = engine.getFullHistory().length;

        // Late callbacks from the killed, never-owned child are ephemeral-only:
        // no false process completion, exit action, or task transition.
        child.simulateExit(null, 'SIGKILL');
        child.simulateClose(null, 'SIGKILL');
        expect(engine.getFullHistory()).toHaveLength(historyLength);

        engine.flushNow();
        unsubscribe();
        const previous = engine;
        previous.dispose();
        engines.delete(previous);
        engine = createEngine(makeConfig());

        expect(engine.getTask(taskId)?.status).toBe('failed');
        expect(engine.getApplicationCommandById(commandId)).toMatchObject({
          status: 'failed',
          error: { code: 'PLANNER_OWNERSHIP_SETUP_FAILED' },
        });
        expect(engine.getTrackedProcesses()).not.toContainEqual(
          expect.objectContaining({ id: `headless-${taskId}` }),
        );
        expect(engine.getRuntimeRuns()).toContainEqual(expect.objectContaining({
          run_id: `headless-${taskId}`,
          lifecycle: 'failed',
          finalization_status: 'failed',
          recovery_warning: expect.stringContaining(`injected ${failureStage} failure`),
        }));
        expect(
          engine.getTask(taskId)?.heartbeat_ttl_seconds
          ?? 120,
        ).toBe(120);
      } finally {
        processKill?.mockRestore();
        unsubscribe();
      }
    },
  );

  it('uses the managed supervisor handshake in the production headless path', async () => {
    const fakeClaude = join(testDir, 'fake-claude.mjs');
    writeFileSync(fakeClaude, [
      '#!/usr/bin/env node',
      'process.stdout.write(JSON.stringify({type:"result",result:"done"}) + "\\n");',
    ].join('\n'));
    chmodSync(fakeClaude, 0o755);
    const taskId = 'h-managed-production';
    expect(engine.registerAgent(headlessTask({ id: taskId })).ok).toBe(true);
    const tracker = new ProcessTracker();
    tracker.setMutationGuard(() => engine.assertPersistenceWritable());
    const unsubscribe = tracker.onChange(() => engine.setTrackedProcesses(tracker.serialize()));
    const runner = new HeadlessMcpRunner(
      engine,
      new HeadlessProcessRegistry(),
      tracker,
      { claudeBinary: fakeClaude, logDir },
    );

    try {
      const child = runner.launch(
        engine.getTask(taskId)!,
        { url: 'http://127.0.0.1:9/mcp' },
      );
      expect(child).not.toBeNull();
      await new Promise<void>(resolve => child!.once('close', () => resolve()));
      await settle();

      expect(engine.getRuntimeRuns()).toContainEqual(expect.objectContaining({
        run_id: `headless-${taskId}`,
        kind: 'headless_agent',
        task_id: taskId,
        pid: expect.any(Number),
        process_group_id: expect.any(Number),
        process_start_identity: expect.any(String),
        ownership_token: expect.stringMatching(/^[0-9a-f-]{36}$/),
        target_pid: expect.any(Number),
        lifecycle: 'interrupted',
        finalization_status: 'interrupted',
      }));
      expect(engine.getTask(taskId)?.status).toBe('interrupted');
    } finally {
      unsubscribe();
    }
  });

  it.skipIf(process.platform === 'win32')(
    'records the target signal rather than the supervisor wrapper exit',
    async () => {
      const fakeClaude = join(testDir, 'fake-claude-signal.mjs');
      writeFileSync(fakeClaude, [
        '#!/usr/bin/env node',
        'process.kill(process.pid, "SIGTERM");',
      ].join('\n'));
      chmodSync(fakeClaude, 0o755);
      const taskId = 'h-managed-signal';
      expect(engine.registerAgent(headlessTask({ id: taskId })).ok).toBe(true);
      const tracker = new ProcessTracker();
      tracker.setMutationGuard(() => engine.assertPersistenceWritable());
      const unsubscribe = tracker.onChange(() => engine.setTrackedProcesses(tracker.serialize()));
      const runner = new HeadlessMcpRunner(
        engine,
        new HeadlessProcessRegistry(),
        tracker,
        { claudeBinary: fakeClaude, logDir },
      );

      try {
        const child = runner.launch(
          engine.getTask(taskId)!,
          { url: 'http://127.0.0.1:9/mcp' },
        );
        expect(child).not.toBeNull();
        await new Promise<void>(resolve => child!.once('close', () => resolve()));
        await settle();

        expect(engine.getRuntimeRuns()).toContainEqual(expect.objectContaining({
          run_id: `headless-${taskId}`,
          lifecycle: 'interrupted',
          exit_code: null,
          exit_signal: 'SIGTERM',
        }));
      } finally {
        unsubscribe();
      }
    },
  );

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
    const offlineEngine = createEngine({ ...makeConfig(), cve_research: { enabled: false } }, 'offline.json');
    const offlineSvc = makeService({ engineOverride: offlineEngine });
    try {
      offlineSvc.start();
      offlineSvc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
      seedVersionedService(offlineEngine, 'svc-off');
      await settle();
      expect(offlineSvc.activeHeadlessCount()).toBe(0);
    } finally {
      offlineSvc.stop();
    }
  });

  it('writable stop interrupts an active planner command instead of reporting PLANNER_NO_PLAN', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    new ApplicationCommandService(engine).reserveSync({
      command_kind: 'operator.plan',
      input: { command: 'finish during shutdown' },
      schema: z.object({ command: z.string() }).strict(),
      metadata: {
        command_id: 'shutdown-planner-command',
        idempotency_key: 'shutdown-planner-command',
      },
      reserve: () => ({
        status: 'accepted',
        result: {
          phase: 'planning_queued',
          planner_task_id: 'h-shutdown',
        },
      }),
    });
    engine.registerAgent(headlessTask({
      id: 'h-shutdown',
      role: 'planner',
      application_command_id: 'shutdown-planner-command',
    }));
    await settle();
    const child = spawned[0];
    svc.stop();
    expect(child.signals).toContain('SIGTERM');
    child.simulateExit(1, 'SIGTERM');
    child.simulateClose(1, 'SIGTERM');
    await settle();
    expect(engine.getTask('h-shutdown')?.status).toBe('interrupted');
    expect(engine.getApplicationCommandById('shutdown-planner-command')).toMatchObject({
      status: 'interrupted',
      error: {
        code: 'PLANNER_INTERRUPTED',
        message: 'task execution service stopped',
      },
    });
    expect(engine.getFullHistory().some(event =>
      event.linked_agent_task_id === 'h-shutdown'
      && (event.details as { reason?: string })?.reason === 'headless_exited'
    )).toBe(true);
  });

  it('CVE auto-dispatch budget counts non-CVE headless agents (cap honored, no over-registration)', async () => {
    svc = makeService({ maxConcurrentHeadless: 1 });
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    // An open-ended dispatched agent with NO persisted backend resolves to headless
    // and takes the only slot. Pre-fix the CVE budget counted backend==='headless_mcp'
    // only, missed this agent, and over-registered a CVE task past the cap (which
    // then got reaped → CVE research abandoned). The fix counts it via resolveBackend.
    const disco = engine.computeFrontier().find(f => f.type === 'network_discovery');
    engine.registerAgent({ id: 'open-busy', agent_id: 'a-open', assigned_at: new Date().toISOString(), status: 'running', subgraph_node_ids: [], frontier_item_id: disco!.id } as AgentTask);
    await settle();
    expect(svc.activeHeadlessCount()).toBe(1);

    seedVersionedService(engine, 'svc-busy');
    await settle();
    // Budget is full → no CVE research task registered, no extra launch.
    expect(engine.getAgentTasks().filter(t => t.role === 'research')).toHaveLength(0);
    expect(spawned).toHaveLength(1);
  });

  it('CVE auto-dispatch is once-per-session (no re-dispatch on later drains)', async () => {
    svc = makeService({ maxConcurrentHeadless: 3 });
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });
    seedVersionedService(engine, 'svc-once');
    await settle();
    expect(engine.getAgentTasks().filter(t => t.role === 'research')).toHaveLength(1);

    // A later, unrelated finding fires another onUpdate → drainCveResearch runs
    // again. The item is in cveAttempted, so it is NOT re-dispatched.
    engine.ingestFinding({ id: 'tick', agent_id: 't', timestamp: new Date().toISOString(), nodes: [{ id: 'h-tick', type: 'host', label: '10.0.0.9', ip: '10.0.0.9', alive: true }], edges: [] } as any);
    await settle();
    expect(engine.getAgentTasks().filter(t => t.role === 'research')).toHaveLength(1);
  });

  it('retries a lease-conflicted cve_research item on a later drain (does not abandon it)', async () => {
    svc = makeService({ maxConcurrentHeadless: 3 });
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });

    // Another task already holds the lease on the CVE item's deterministic
    // frontier id (`frontier-cve-<serviceId>`), so the auto-dispatch register
    // will lease-conflict. Manual backend → never executed, never counted
    // against the headless budget, and it keeps the lease until we release it.
    const leaseHolder = {
      id: 'lease-holder', agent_id: 'op', assigned_at: new Date().toISOString(),
      status: 'running', subgraph_node_ids: [], backend: 'manual',
      frontier_item_id: 'frontier-cve-svc-lease',
    } as AgentTask;
    expect(engine.registerAgent(leaseHolder).ok).toBe(true);

    // Seed the versioned service → its cve_research item is in the frontier but
    // held by the lease, so drainCveResearch SKIPS it before registering: no
    // research agent, nothing spawned.
    seedVersionedService(engine, 'svc-lease');
    await settle();
    expect(engine.getAgentTasks().filter(t => t.role === 'research')).toHaveLength(0);
    expect(spawned).toHaveLength(0);
    // And it must skip QUIETLY: a held lease must not be re-registered+refused on
    // every drain. Un-marking on refusal without the pre-check would log a
    // frontier_lease_conflict warning (and persist) per onUpdate for the whole
    // lease lifetime — assert zero such warnings while the lease is held.
    expect(engine.getFullHistory().filter(e => (e.details as any)?.reason === 'frontier_lease_conflict')).toHaveLength(0);

    // Release the lease; a later drain MUST dispatch the item now that it's free.
    // Skipping-without-marking (not marking attempted) is what preserves this:
    // the item never entered cveAttempted, so it's eligible on the next drain.
    engine.updateAgentStatus('lease-holder', 'completed');
    engine.ingestFinding({ id: 'tick2', agent_id: 't', timestamp: new Date().toISOString(), nodes: [{ id: 'h-tick2', type: 'host', label: '10.0.0.8', ip: '10.0.0.8', alive: true }], edges: [] } as any);
    await settle();
    expect(engine.getAgentTasks().filter(t => t.role === 'research')).toHaveLength(1);
    expect(spawned).toHaveLength(1);
  });

  it('launches a specialized archetype with its restricted --allowedTools (recon_scanner, web_tester)', async () => {
    svc = makeService();
    svc.start();
    svc.setHttpEndpoint({ url: 'http://127.0.0.1:9/mcp' });

    engine.registerAgent({ id: 'h-recon', agent_id: 'a-recon', assigned_at: new Date().toISOString(), status: 'running', subgraph_node_ids: [], backend: 'headless_mcp', archetype: 'recon_scanner' } as AgentTask);
    await settle();
    const reconArgv = spawnedArgs[spawnedArgs.length - 1];
    const reconAllowed = reconArgv[reconArgv.indexOf('--allowedTools') + 1];
    expect(reconAllowed).toBe(allowedToolsFor('recon_scanner'));
    // recon_scanner has NO interactive sessions or credential tools in its surface.
    expect(reconAllowed).not.toContain('mcp__overwatch__open_session');

    engine.registerAgent({ id: 'h-web', agent_id: 'a-web', assigned_at: new Date().toISOString(), status: 'running', subgraph_node_ids: [], backend: 'headless_mcp', archetype: 'web_tester' } as AgentTask);
    await settle();
    const webArgv = spawnedArgs[spawnedArgs.length - 1];
    const webAllowed = webArgv[webArgv.indexOf('--allowedTools') + 1];
    expect(webAllowed).toBe(allowedToolsFor('web_tester'));
    // Neither archetype gets the whole-server prefix.
    expect(webAllowed.split(/\s+/)).not.toContain('mcp__overwatch');
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
