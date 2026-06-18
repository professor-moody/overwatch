// ============================================================
// Overwatch — Headless MCP Runner
//
// Launches a headless `claude -p` process for a `headless_mcp` agent task. The
// child connects back to THIS daemon's /mcp endpoint as an MCP client (shared
// engine, validated by Phase 0) and drives itself through the real Overwatch
// tools. We do NOT use the subagent-ipc child-module path.
//
// Responsibilities here: spawn + per-task temp mcp-config (with bearer token,
// 0600, deleted on exit) + stream-json log + exit reconciliation. Process
// lifecycle (kill on cancel/timeout/shutdown) lives in HeadlessProcessRegistry,
// driven by TaskExecutionService.
//
// The child's tool surface is restricted to the Overwatch MCP server + ToolSearch
// (NO native Bash/Write/Edit) so all target-facing work flows through the
// instrumented, OPSEC-gated mcp__overwatch__run_bash/run_tool — never a raw
// shell outside the Overwatch lifecycle.
// ============================================================

import { spawn, type ChildProcess, type SpawnOptions } from 'child_process';
import { mkdirSync, writeFileSync, createWriteStream, unlinkSync, type WriteStream } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { GraphEngine } from './graph-engine.js';
import type { ProcessTracker } from './process-tracker.js';
import type { AgentTask } from '../types.js';
import { HeadlessProcessRegistry } from './headless-process-registry.js';

export interface HeadlessEndpoint {
  /** Full MCP URL, e.g. http://127.0.0.1:3000/mcp */
  url: string;
  /** Bearer token the child must present (required when /mcp auth is enforced). */
  token?: string;
}

type SpawnFn = (command: string, args: string[], options: SpawnOptions) => ChildProcess;

export interface HeadlessMcpRunnerOptions {
  /** Path/name of the Claude Code CLI. Default 'claude'. Tests inject a fake. */
  claudeBinary?: string;
  /** Directory for per-agent stream-json logs. Default 'logs/agents'. */
  logDir?: string;
  /** Permission mode passed to the child (default omitted; allowedTools whitelist governs). */
  permissionMode?: string;
  /** Hard cap on agentic turns (maps to --max-turns). */
  maxTurns?: number;
  /** Extra CLI args appended verbatim (escape hatch / tuning). */
  extraArgs?: string[];
  /** Injectable spawn for tests. Defaults to child_process.spawn. */
  spawnFn?: SpawnFn;
  /** Injectable clock for deterministic timestamps in tests. */
  now?: () => string;
}

/**
 * Tool profile per agent role:
 *  - default : full Overwatch MCP surface + ToolSearch. No native shell/editor
 *    tools — all target work flows through instrumented mcp__overwatch__run_*.
 *  - research: adds Claude Code's WebSearch + WebFetch so the agent can research
 *    CVEs/POCs the way an operator would, but STILL no run_bash/run_tool/sessions
 *    (research reads the public web and writes findings; it never executes
 *    against targets). Target-facing tools are part of the mcp__overwatch surface
 *    and the agent is told (prompt) not to use them in this role.
 */
// Tool surfaces are now data-driven in agent-archetypes.ts — each archetype
// (recon_scanner, web_tester, credential_operator, …, plus the legacy
// default/research/planner roles) carries a real `--allowedTools` allowlist
// boundary. Imported + re-exported here so existing callers/tests keep importing
// it from the runner; the legacy role strings are byte-identical (regression-locked).
import { allowedToolsFor, getArchetype, bootstrapMission } from './agent-archetypes.js';
export { allowedToolsFor };

/** Heartbeat TTL (seconds) granted to a freshly-launched headless agent so its
 *  cold start (spawn + MCP bootstrap + first tool call) can't trip the watchdog
 *  before its first heartbeat. Its own periodic heartbeats keep it fresh after. */
const HEADLESS_STARTUP_TTL_SECONDS = 300;

export class HeadlessMcpRunner {
  private engine: GraphEngine;
  private registry: HeadlessProcessRegistry;
  private processTracker: ProcessTracker;
  private opts: Required<Pick<HeadlessMcpRunnerOptions, 'claudeBinary' | 'logDir'>> & HeadlessMcpRunnerOptions;
  private spawnFn: SpawnFn;
  private now: () => string;

  constructor(
    engine: GraphEngine,
    registry: HeadlessProcessRegistry,
    processTracker: ProcessTracker,
    options: HeadlessMcpRunnerOptions = {},
  ) {
    this.engine = engine;
    this.registry = registry;
    this.processTracker = processTracker;
    this.spawnFn = options.spawnFn ?? (spawn as SpawnFn);
    this.now = options.now ?? (() => new Date().toISOString());
    this.opts = {
      claudeBinary: options.claudeBinary ?? process.env.OVERWATCH_CLAUDE_BINARY ?? 'claude',
      logDir: options.logDir ?? 'logs/agents',
      permissionMode: options.permissionMode,
      maxTurns: options.maxTurns,
      extraArgs: options.extraArgs,
      spawnFn: options.spawnFn,
      now: options.now,
    };
  }

  /**
   * Launch a headless sub-agent for `task`. Returns the child process, or null
   * if spawning failed (task is marked failed in that case).
   */
  launch(task: AgentTask, endpoint: HeadlessEndpoint): ChildProcess | null {
    const configPath = this.writeMcpConfig(task.id, endpoint);
    const args = this.buildArgs(task, configPath);

    let child: ChildProcess;
    try {
      child = this.spawnFn(this.opts.claudeBinary, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        // Own process group so killTree can reap grandchildren (POSIX).
        detached: process.platform !== 'win32',
        env: { ...process.env, OVERWATCH_TASK_ID: task.id },
      });
    } catch (err) {
      this.cleanupConfig(configPath);
      this.engine.updateAgentStatus(task.id, 'failed', `headless spawn failed: ${err instanceof Error ? err.message : String(err)}`);
      return null;
    }

    if (!child.pid) {
      // spawn reported no pid (e.g. ENOENT surfaced via 'error' below); guard anyway.
      this.cleanupConfig(configPath);
    }

    this.registry.register(task.id, child, configPath, this.now());
    // Cold-start grace: spawning claude + MCP bootstrap + the first tool call can
    // take longer than the default 120s heartbeat TTL, which would let the watchdog
    // reap a perfectly healthy agent before its first heartbeat lands. Give headless
    // agents a generous startup TTL; their own periodic heartbeats keep it fresh,
    // and the 30-min wall-clock timeout remains the backstop for a truly wedged one.
    this.engine.setAgentHeartbeatTtl(task.id, HEADLESS_STARTUP_TTL_SECONDS);
    if (child.pid) {
      this.processTracker.register({
        id: `headless-${task.id}`,
        pid: child.pid,
        command: `${this.opts.claudeBinary} -p (headless sub-agent ${task.agent_id})`,
        description: `Headless sub-agent for task ${task.id}`,
        agent_id: task.agent_id,
      });
    }

    const log = this.openLog(task.id);
    child.stdout?.on('data', (c: Buffer) => { try { log?.write(c); } catch { /* log errors must not kill the agent */ } });
    child.stderr?.on('data', (c: Buffer) => { try { log?.write(c); } catch { /* ignore */ } });

    child.on('error', (err) => {
      this.engine.logActionEvent({
        description: `Headless sub-agent process error: ${err.message}`,
        event_type: 'instrumentation_warning',
        category: 'system',
        result_classification: 'failure',
        agent_id: task.agent_id,
        linked_agent_task_id: task.id,
        details: { reason: 'headless_spawn_error', error: err.message },
      });
      this.finalize(task.id, configPath, log, 'failed', `headless process error: ${err.message}`);
    });

    child.on('exit', (code, signal) => {
      try { log?.end(); } catch { /* ignore */ }
      this.registry.unregister(task.id);
      this.cleanupConfig(configPath);
      const ok = code === 0;
      this.processTracker.update(`headless-${task.id}`, ok ? 'completed' : 'failed');
      this.engine.logActionEvent({
        description: `Headless sub-agent exited (code=${code ?? 'null'}, signal=${signal ?? 'null'})`,
        event_type: 'instrumentation_warning',
        category: 'system',
        result_classification: ok ? 'neutral' : 'failure',
        agent_id: task.agent_id,
        linked_agent_task_id: task.id,
        details: { reason: 'headless_exited', exit_code: code, signal },
      });
      // Reconcile: if the agent died without closing out its task (no
      // update_agent / submit_agent_transcript), mark it interrupted so the
      // frontier lease releases instead of leaking.
      const current = this.engine.getTask(task.id);
      if (current && current.status === 'running') {
        this.engine.updateAgentStatus(task.id, 'interrupted', 'headless agent exited without submitting a transcript');
      }
    });

    this.engine.logActionEvent({
      description: `Headless sub-agent launched for task ${task.id}`,
      event_type: 'instrumentation_warning',
      category: 'system',
      result_classification: 'neutral',
      agent_id: task.agent_id,
      linked_agent_task_id: task.id,
      details: { reason: 'headless_launched', pid: child.pid, backend: 'headless_mcp' },
    });

    return child;
  }

  // ---- helpers ----

  private buildArgs(task: AgentTask, configPath: string): string[] {
    // An explicit archetype wins; else fall back to the legacy role; else default.
    const archetype = getArchetype(task.archetype ?? task.role);
    const args = [
      '-p', this.bootstrapPrompt(task),
      '--mcp-config', configPath,
      '--allowedTools', allowedToolsFor(archetype.id),
      '--output-format', 'stream-json',
      '--verbose',
    ];
    if (this.opts.permissionMode) args.push('--permission-mode', this.opts.permissionMode);
    if (this.opts.maxTurns) args.push('--max-turns', String(this.opts.maxTurns));
    if (this.opts.extraArgs?.length) args.push(...this.opts.extraArgs);
    return args;
  }

  private bootstrapPrompt(task: AgentTask): string {
    // The mission is per-archetype (decoupled from the legacy role bucket), so a
    // specialized type gets a brief that matches its real tools + job. The
    // objective is appended for EVERY type (raw quick-deploys carry the target
    // only in the objective), and a uniform close handles the lifecycle.
    const common = [
      `You are an Overwatch headless sub-agent. Your agent task_id is "${task.id}" (agent_id "${task.agent_id}").`,
      `The Overwatch tools load on demand: first use ToolSearch to find the "overwatch" MCP tools`,
      `(get_system_prompt, get_agent_context, agent_heartbeat, report_finding, submit_agent_transcript, update_agent).`,
      `Then call get_system_prompt(role="sub_agent", agent_id="${task.agent_id}") for your full operating instructions,`,
      `and get_agent_context(task_id="${task.id}") for your scoped subgraph and objective.`,
    ];
    const mission = bootstrapMission(task.archetype ?? task.role);
    // Point the agent at its methodology skill. The full text is inlined in the
    // get_system_prompt(role="sub_agent") result it's told to fetch first, and
    // available on demand via get_skill — so a pointer here, not a duplicate snippet.
    const skillId = getArchetype(task.archetype ?? task.role).defaultSkill ?? task.skill;
    const skill = skillId
      ? `Your methodology skill is "${skillId}" — it's inlined in your get_system_prompt(role="sub_agent") result, or call get_skill(skill_id="${skillId}") for the full text.`
      : '';
    const objective = task.objective ? `OBJECTIVE: ${task.objective}` : '';
    const close = `When done — or if you cannot proceed — call submit_agent_transcript, then update_agent(task_id="${task.id}", status="completed").`;
    return [...common, mission, skill, objective, close].filter(Boolean).join(' ');
  }

  private writeMcpConfig(task_id: string, endpoint: HeadlessEndpoint): string {
    const server: Record<string, unknown> = { type: 'http', url: endpoint.url };
    if (endpoint.token) server.headers = { Authorization: `Bearer ${endpoint.token}` };
    const config = { mcpServers: { overwatch: server } };
    const path = join(tmpdir(), `overwatch-mcp-${task_id}.json`);
    // 0600: the file carries the bearer token; keep it owner-only.
    writeFileSync(path, JSON.stringify(config), { mode: 0o600 });
    return path;
  }

  private cleanupConfig(configPath: string | undefined): void {
    if (!configPath) return;
    try { unlinkSync(configPath); } catch { /* already gone */ }
  }

  private openLog(task_id: string): WriteStream | null {
    try {
      mkdirSync(this.opts.logDir, { recursive: true });
      return createWriteStream(join(this.opts.logDir, `${task_id}.ndjson`), { flags: 'a' });
    } catch {
      return null; // logging is best-effort; never block the agent
    }
  }

  private finalize(task_id: string, configPath: string | undefined, log: WriteStream | null, status: 'failed' | 'interrupted', summary: string): void {
    try { log?.end(); } catch { /* ignore */ }
    this.registry.unregister(task_id);
    this.cleanupConfig(configPath);
    const current = this.engine.getTask(task_id);
    if (current && current.status === 'running') {
      this.engine.updateAgentStatus(task_id, status, summary);
    }
  }
}
