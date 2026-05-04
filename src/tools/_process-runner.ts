// ============================================================
// Overwatch — shared instrumented process runner
//
// Backs both `run_bash` (shell form) and `run_tool` (argv form).
// Owns the entire action lifecycle:
//   validate \u2192 approval gate \u2192 action_started \u2192 spawn \u2192
//   capture stdout/stderr \u2192 store evidence \u2192 action_completed/failed
//   \u2192 optional parse_with ingest.
//
// Callers supply the spawn shape (binary + argv) and lifecycle metadata.
// Everything tool-agnostic lives here.
// ============================================================

import { spawn } from 'child_process';
import { v4 as uuidv4 } from 'uuid';
import type { GraphEngine } from '../services/graph-engine.js';
import { parseOutput, getSupportedParsers } from '../services/parsers/index.js';
import { prepareFindingForIngest } from '../services/finding-validation.js';
import type { ParseContext } from '../types.js';

export const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;       // 5 minutes
export const MAX_TIMEOUT_MS = 60 * 60 * 1000;          // 1 hour
const STREAM_INLINE_CAP = 256 * 1024;                  // 256 KiB inline per stream
const TRUNCATION_MARKER = '\n…[output truncated; full output stored in evidence]…\n';

// Env keys the agent should never be able to leak into a child process.
const ENV_DENYLIST = new Set<string>([
  'OVERWATCH_CONFIG',
  'OVERWATCH_SKILLS',
  'OVERWATCH_BOOTSTRAP',
  'OVERWATCH_DASHBOARD_PORT',
]);

function buildChildEnv(extra: Record<string, string> | undefined): NodeJS.ProcessEnv {
  const base: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (ENV_DENYLIST.has(k)) continue;
    if (v !== undefined) base[k] = v;
  }
  if (extra) {
    for (const [k, v] of Object.entries(extra)) {
      base[k] = v;
    }
  }
  return base;
}

function captureStream(buf: Buffer[], chunk: Buffer, totalLenRef: { len: number }, cap: number): boolean {
  totalLenRef.len += chunk.length;
  buf.push(chunk);
  return totalLenRef.len <= cap;
}

function joinAndCap(buf: Buffer[], cap: number): { text: string; truncated: boolean; total: number } {
  const full = Buffer.concat(buf).toString('utf8');
  if (full.length <= cap) return { text: full, truncated: false, total: full.length };
  const head = full.slice(0, Math.floor(cap * 0.75));
  const tail = full.slice(full.length - Math.floor(cap * 0.25));
  return { text: head + TRUNCATION_MARKER + tail, truncated: true, total: full.length };
}

interface ProcessResult {
  exit_code: number | null;
  signal: NodeJS.Signals | null;
  stdout: Buffer[];
  stderr: Buffer[];
  duration_ms: number;
  timed_out: boolean;
  spawn_error?: string;
}

function runProcess(binary: string, args: string[], opts: {
  cwd?: string;
  env?: Record<string, string>;
  timeout_ms: number;
}): Promise<ProcessResult> {
  return new Promise((resolve) => {
    const start = Date.now();
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    const stdoutLen = { len: 0 };
    const stderrLen = { len: 0 };
    let timedOut = false;

    let child;
    try {
      child = spawn(binary, args, {
        cwd: opts.cwd,
        env: buildChildEnv(opts.env),
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (err) {
      resolve({
        exit_code: null,
        signal: null,
        stdout: [],
        stderr: [],
        duration_ms: Date.now() - start,
        timed_out: false,
        spawn_error: err instanceof Error ? err.message : String(err),
      });
      return;
    }

    const timer = setTimeout(() => {
      timedOut = true;
      try { child.kill('SIGTERM'); } catch { /* already gone */ }
      setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* ok */ } }, 5000).unref();
    }, opts.timeout_ms);
    timer.unref();

    child.stdout?.on('data', (c: Buffer) => captureStream(stdout, c, stdoutLen, STREAM_INLINE_CAP * 8));
    child.stderr?.on('data', (c: Buffer) => captureStream(stderr, c, stderrLen, STREAM_INLINE_CAP * 8));

    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({
        exit_code: null,
        signal: null,
        stdout,
        stderr,
        duration_ms: Date.now() - start,
        timed_out: timedOut,
        spawn_error: err.message,
      });
    });

    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({
        exit_code: code,
        signal,
        stdout,
        stderr,
        duration_ms: Date.now() - start,
        timed_out: timedOut,
      });
    });
  });
}

export interface InstrumentedProcessOpts {
  // Spawn shape
  binary: string;
  args: string[];
  /** Human-readable representation of the command (used for description and evidence detail). */
  command_repr: string;
  cwd?: string;
  env?: Record<string, string>;
  timeout_ms?: number;

  // Lifecycle metadata
  action_id?: string;
  frontier_item_id?: string;
  agent_id?: string;
  description?: string;
  tool_name?: string;
  technique?: string;
  target_node?: string;
  target_node_ids?: string[];
  target_ip?: string;
  target_ips?: string[];
  target_url?: string;
  cloud_resource?: string;
  validate?: boolean;
  parse_with?: string;
  parser_context?: ParseContext;
  noise_estimate?: number;

  /**
   * Tool name reported in MCP error responses / activity descriptions. Distinct
   * from `tool_name` (technique attribution); this identifies which Overwatch
   * tool wrapper invoked the runner (`run_bash` or `run_tool`).
   */
  invoking_tool: 'run_bash' | 'run_tool';
}

export interface InstrumentedProcessResponse {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
  [key: string]: unknown;
}

/**
 * Execute a child process with full action-lifecycle instrumentation.
 * Returns an MCP-shaped tool response.
 */
export async function runInstrumentedProcess(
  engine: GraphEngine,
  opts: InstrumentedProcessOpts,
): Promise<InstrumentedProcessResponse> {
  const {
    binary, args, command_repr,
    cwd, env,
    action_id,
    frontier_item_id,
    agent_id,
    description,
    tool_name: rawToolName,
    technique,
    target_node,
    target_node_ids,
    target_ip,
    target_ips,
    target_url,
    cloud_resource,
    validate,
    parse_with,
    parser_context,
    noise_estimate: noiseOverride,
  } = opts;

  const normalizedActionId = action_id || uuidv4();
  const tool_name = rawToolName || command_repr.trim().split(/\s+/)[0] || binary;
  const resolvedDescription = description || command_repr;
  const effectiveTimeout = opts.timeout_ms ?? DEFAULT_TIMEOUT_MS;
  const shouldValidate = validate !== false;
  const allTargetNodeIds = [
    ...(target_node ? [target_node] : []),
    ...(target_node_ids ?? []),
  ].filter((v, i, a) => a.indexOf(v) === i);
  const allTargetIps = [
    ...(target_ip ? [target_ip] : []),
    ...(target_ips ?? []),
  ].filter((v, i, a) => a.indexOf(v) === i);
  const frontierType = frontier_item_id ? engine.getFrontierItem(frontier_item_id)?.type : undefined;

  // ---- 1. Validation ----
  let noiseEstimate = noiseOverride;
  if (shouldValidate) {
    const v = engine.validateAction({
      target_node,
      target_ip,
      target_url,
      cloud_resource,
      technique,
    });
    const validationResult = !v.valid ? 'invalid' : v.warnings.length > 0 ? 'warning_only' : 'valid';
    if (noiseEstimate === undefined) noiseEstimate = v.opsec_context.global_noise_spent;

    engine.logActionEvent({
      description: resolvedDescription,
      agent_id,
      action_id: normalizedActionId,
      event_type: 'action_validated',
      category: 'frontier',
      frontier_type: frontierType,
      tool_name,
      technique,
      target_node_ids: allTargetNodeIds.length > 0 ? allTargetNodeIds : undefined,
      target_ips: allTargetIps.length > 0 ? allTargetIps : undefined,
      frontier_item_id,
      validation_result: validationResult,
      noise_estimate: noiseEstimate,
      result_classification: !v.valid ? 'failure' : v.warnings.length > 0 ? 'partial' : 'success',
      details: { errors: v.errors, warnings: v.warnings, opsec_context: v.opsec_context },
    });

    if (!v.valid) {
      engine.logActionEvent({
        description: `Refused to execute: ${resolvedDescription}`,
        agent_id,
        action_id: normalizedActionId,
        event_type: 'action_failed',
        category: 'frontier',
        frontier_type: frontierType,
        tool_name,
        technique,
        target_node_ids: allTargetNodeIds.length > 0 ? allTargetNodeIds : undefined,
        target_ips: allTargetIps.length > 0 ? allTargetIps : undefined,
        frontier_item_id,
        result_classification: 'failure',
        details: { reason: 'validation_failed', validation_errors: v.errors },
      });
      engine.persist();
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            action_id: normalizedActionId,
            executed: false,
            validation_result: 'invalid',
            errors: v.errors,
            warnings: v.warnings,
          }, null, 2),
        }],
        isError: true,
      };
    }

    // Approval gate
    const queue = engine.getPendingActionQueue();
    if (queue.needsApproval(v.opsec_context, technique)) {
      const approval = await queue.submit({
        action_id: normalizedActionId,
        technique,
        target_node,
        target_ip,
        description: resolvedDescription,
        opsec_context: v.opsec_context,
        validation_result: validationResult as 'valid' | 'warning_only',
        frontier_item_id,
      });

      engine.logActionEvent({
        description: `Action ${approval.status}: ${resolvedDescription}`,
        agent_id,
        action_id: normalizedActionId,
        event_type: 'action_validated',
        category: 'frontier',
        frontier_item_id,
        result_classification: approval.status === 'denied' ? 'failure' : 'success',
        details: { approval_status: approval.status, operator_notes: approval.operator_notes, reason: approval.reason },
      });

      if (approval.status === 'denied') {
        engine.logActionEvent({
          description: `Operator denied: ${resolvedDescription}`,
          agent_id,
          action_id: normalizedActionId,
          event_type: 'action_failed',
          category: 'frontier',
          frontier_item_id,
          tool_name,
          technique,
          result_classification: 'failure',
          details: { reason: 'operator_denied', approval_reason: approval.reason },
        });
        engine.persist();
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              action_id: normalizedActionId,
              executed: false,
              approval_status: 'denied',
              reason: approval.reason,
            }, null, 2),
          }],
          isError: true,
        };
      }
    }
  }

  // ---- 2. action_started ----
  engine.logActionEvent({
    description: resolvedDescription,
    agent_id,
    action_id: normalizedActionId,
    event_type: 'action_started',
    category: 'frontier',
    frontier_type: frontierType,
    tool_name,
    technique,
    target_node_ids: allTargetNodeIds.length > 0 ? allTargetNodeIds : undefined,
    target_ips: allTargetIps.length > 0 ? allTargetIps : undefined,
    frontier_item_id,
    noise_estimate: noiseEstimate,
    details: {
      command: command_repr,
      binary,
      args,
      cwd,
      timeout_ms: effectiveTimeout,
      invoking_tool: opts.invoking_tool,
    },
  });
  if (noiseEstimate !== undefined) {
    engine.recordOpsecNoise({
      action_id: normalizedActionId,
      host_id: allTargetNodeIds[0],
      noise_estimate: noiseEstimate,
    });
  }
  engine.persist();

  // ---- 3. Execute ----
  const result = await runProcess(binary, args, { cwd, env, timeout_ms: effectiveTimeout });
  const stdoutInfo = joinAndCap(result.stdout, STREAM_INLINE_CAP);
  const stderrInfo = joinAndCap(result.stderr, STREAM_INLINE_CAP);

  // ---- 4. Store evidence ----
  const evidenceStore = engine.getEvidenceStore();
  let stdout_evidence_id: string | undefined;
  let stderr_evidence_id: string | undefined;
  if (stdoutInfo.total > 0) {
    stdout_evidence_id = evidenceStore.store({
      action_id: normalizedActionId,
      evidence_type: 'command_output',
      filename: 'stdout',
      raw_output: Buffer.concat(result.stdout).toString('utf8'),
    });
  }
  if (stderrInfo.total > 0) {
    stderr_evidence_id = evidenceStore.store({
      action_id: normalizedActionId,
      evidence_type: 'command_output',
      filename: 'stderr',
      raw_output: Buffer.concat(result.stderr).toString('utf8'),
    });
  }

  // ---- 5. Terminal lifecycle event ----
  const succeeded = !result.spawn_error && !result.timed_out && result.exit_code === 0;
  const terminalEventType = succeeded ? 'action_completed' as const : 'action_failed' as const;
  const failureReason = result.spawn_error
    ? 'spawn_error'
    : result.timed_out
      ? 'timeout'
      : result.exit_code !== 0
        ? 'nonzero_exit'
        : undefined;

  engine.logActionEvent({
    description: resolvedDescription,
    agent_id,
    action_id: normalizedActionId,
    event_type: terminalEventType,
    category: 'frontier',
    frontier_type: frontierType,
    tool_name,
    technique,
    target_node_ids: allTargetNodeIds.length > 0 ? allTargetNodeIds : undefined,
    target_ips: allTargetIps.length > 0 ? allTargetIps : undefined,
    frontier_item_id,
    result_classification: succeeded ? 'success' : 'failure',
    details: {
      exit_code: result.exit_code,
      signal: result.signal,
      duration_ms: result.duration_ms,
      timed_out: result.timed_out,
      stdout_evidence_id,
      stderr_evidence_id,
      stdout_truncated: stdoutInfo.truncated,
      stderr_truncated: stderrInfo.truncated,
      stdout_total_bytes: stdoutInfo.total,
      stderr_total_bytes: stderrInfo.total,
      spawn_error: result.spawn_error,
      reason: failureReason,
      command: command_repr,
      binary,
      args,
      invoking_tool: opts.invoking_tool,
    },
  });
  engine.persist();

  // ---- 6. Optional inline parse + ingest ----
  let parse_summary: Record<string, unknown> | undefined;
  if (parse_with && succeeded) {
    const supported = getSupportedParsers();
    if (!supported.includes(parse_with)) {
      parse_summary = { error: `No parser found for: ${parse_with}`, supported_parsers: supported };
    } else {
      const ctx: ParseContext = { ...(parser_context as ParseContext | undefined) };
      if (!ctx.domain_aliases) {
        const aliases: Record<string, string> = {};
        for (const node of engine.getNodesByType('domain')) {
          const fqdn = (node.domain_name || node.label || '') as string;
          if (fqdn && fqdn.includes('.')) {
            aliases[fqdn.split('.')[0].toUpperCase()] = fqdn.toLowerCase();
            if (typeof node.netbios_name === 'string' && node.netbios_name.length > 0) {
              aliases[node.netbios_name.toUpperCase()] = fqdn.toLowerCase();
            }
          }
        }
        if (Object.keys(aliases).length > 0) ctx.domain_aliases = aliases;
      }

      const fullStdout = Buffer.concat(result.stdout).toString('utf8');
      const finding = parseOutput(parse_with, fullStdout, agent_id, ctx);
      if (!finding) {
        parse_summary = { error: `Parser '${parse_with}' returned no finding` };
        engine.logActionEvent({
          description: `Parser '${parse_with}' produced no finding`,
          agent_id,
          action_id: normalizedActionId,
          event_type: 'parse_output',
          category: 'finding',
          tool_name: parse_with,
          frontier_item_id,
          frontier_type: frontierType,
          result_classification: 'failure',
        });
      } else {
        finding.action_id = normalizedActionId;
        finding.tool_name = parse_with;
        finding.frontier_item_id = frontier_item_id;

        const prepared = prepareFindingForIngest(finding, nodeId => engine.getNode(nodeId));
        if (prepared.errors.length > 0) {
          parse_summary = { parsed: true, validation_errors: prepared.errors };
          engine.logActionEvent({
            description: `Parsed output rejected: invalid graph mutation`,
            agent_id,
            action_id: normalizedActionId,
            event_type: 'parse_output',
            category: 'finding',
            tool_name: parse_with,
            frontier_item_id,
            frontier_type: frontierType,
            linked_finding_ids: [finding.id],
            result_classification: 'failure',
            details: { validation_errors: prepared.errors },
          });
        } else {
          const ingestResult = engine.ingestFinding(prepared.finding);
          parse_summary = {
            parsed: true,
            tool: parse_with,
            finding_id: finding.id,
            nodes_parsed: finding.nodes.length,
            edges_parsed: finding.edges.length,
            ingested: {
              new_nodes: ingestResult.new_nodes.length,
              new_edges: ingestResult.new_edges.length,
              inferred_edges: ingestResult.inferred_edges.length,
            },
          };
          engine.logActionEvent({
            description: `Output parsed and ingested for ${parse_with}`,
            agent_id,
            action_id: normalizedActionId,
            event_type: 'parse_output',
            category: 'finding',
            tool_name: parse_with,
            frontier_item_id,
            frontier_type: frontierType,
            linked_finding_ids: [finding.id],
            result_classification: 'success',
            details: {
              parsed_nodes: finding.nodes.length,
              parsed_edges: finding.edges.length,
              ingested: true,
              new_nodes: ingestResult.new_nodes.length,
              new_edges: ingestResult.new_edges.length,
              inferred_edges: ingestResult.inferred_edges.length,
            },
          });
        }
      }
      engine.persist();
    }
  }

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        action_id: normalizedActionId,
        executed: true,
        binary,
        args,
        exit_code: result.exit_code,
        signal: result.signal,
        duration_ms: result.duration_ms,
        timed_out: result.timed_out,
        spawn_error: result.spawn_error,
        stdout: stdoutInfo.text,
        stderr: stderrInfo.text,
        stdout_truncated: stdoutInfo.truncated,
        stderr_truncated: stderrInfo.truncated,
        stdout_total_bytes: stdoutInfo.total,
        stderr_total_bytes: stderrInfo.total,
        stdout_evidence_id,
        stderr_evidence_id,
        parse_summary,
      }, null, 2),
    }],
    isError: !succeeded,
  };
}
