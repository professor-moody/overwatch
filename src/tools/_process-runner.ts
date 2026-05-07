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
import type { GraphEngine } from '../services/graph-engine.js';
import { parseOutput, getSupportedParsers, isAcceptableParserExit } from '../services/parsers/index.js';
import { prepareFindingForIngest } from '../services/finding-validation.js';
import { actionIdOrUuid } from '../services/deterministic-id.js';
import type { ParseContext } from '../types.js';

// F3: argv/command target extraction.
//
// Several techniques are inherently target-facing — recon scans, web
// fuzzing, smb enumeration, brute-force, etc. When the caller forgets to
// populate `target_node*` / `target_ip*`, we previously fell through to a
// no-target validate() which trivially passed scope, allowing scans of
// arbitrary IPs/hosts/URLs to slip through. We now sniff the argv (and the
// raw command repr for shell form) for IPv4, IPv6, URL, and hostname-like
// tokens and feed them back through validateAction.
const TARGET_FACING_TECHNIQUES = new Set([
  'recon', 'scan', 'port_scan', 'service_scan', 'host_discovery',
  'enum', 'enum_smb', 'enum_dns', 'enum_ldap', 'enum_kerberos',
  'web_scan', 'web_fuzz', 'web_brute', 'dir_brute', 'vuln_scan',
  'smb_enum', 'rpc_enum', 'snmp_enum',
  'cred_brute', 'auth_brute', 'spray', 'password_spray',
]);

// F3.1: target-facing detection by binary name. If a caller invokes a known
// scanner / brute-forcer / web fuzzer without supplying technique, we still
// want to sniff implicit targets out of argv so scope cannot be silently
// bypassed by omitting metadata. This must be a tight allowlist of tools
// that are unambiguously target-facing — adding generic binaries (curl, git,
// ssh) here would create false positives on URLs/hosts used for non-attack
// purposes.
const TARGET_FACING_BINARIES = new Set([
  'nmap', 'masscan', 'rustscan', 'naabu',
  'nxc', 'netexec', 'crackmapexec', 'cme',
  'enum4linux', 'enum4linux-ng', 'smbclient', 'smbmap', 'rpcclient',
  'kerbrute', 'impacket-GetNPUsers', 'impacket-GetUserSPNs',
  'GetNPUsers.py', 'GetUserSPNs.py', 'GetTGT.py', 'getST.py',
  'ldapsearch', 'windapsearch', 'bloodhound-python',
  'responder', 'inveigh',
  'ffuf', 'gobuster', 'feroxbuster', 'wfuzz', 'dirb', 'dirbuster',
  'wpscan', 'nikto', 'whatweb',
  'nuclei', 'sqlmap', 'sslscan', 'testssl.sh', 'testssl',
  'hydra', 'medusa', 'patator',
  'certipy', 'certipy-ad',
  'wmiexec.py', 'psexec.py', 'smbexec.py', 'atexec.py',
]);

function basename(s: string): string {
  const i = s.lastIndexOf('/');
  return i >= 0 ? s.slice(i + 1) : s;
}

function isTargetFacing(technique: string | undefined, toolName: string, binary: string): boolean {
  if (technique && TARGET_FACING_TECHNIQUES.has(technique)) return true;
  const tn = basename(toolName).toLowerCase();
  const bn = basename(binary).toLowerCase();
  for (const b of TARGET_FACING_BINARIES) {
    const lb = b.toLowerCase();
    if (tn === lb || bn === lb) return true;
  }
  return false;
}

const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\/\d{1,2})?\b/g;
// Bracketed IPv6 (with optional :port) or bare IPv6 with at least two colons.
const IPV6 = /\[([0-9a-fA-F:]+)\](?::\d+)?|\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:]*\b/g;
const URL_RE = /\b(?:https?|ftp|smb|ssh|ldaps?|rdp):\/\/[^\s'"`]+/gi;
const HOSTNAME = /\b(?=[a-zA-Z0-9.-]{1,253}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;

interface ImplicitTargets {
  ips: string[];
  urls: string[];
  hostnames: string[];
}

function extractImplicitTargets(_toolName: string, args: string[], commandRepr: string): ImplicitTargets {
  const ips = new Set<string>();
  const urls = new Set<string>();
  const hostnames = new Set<string>();

  const stringsToScan: string[] = [];
  for (const a of args) {
    if (typeof a === 'string' && a.length > 0 && !a.startsWith('-')) stringsToScan.push(a);
  }
  if (commandRepr) stringsToScan.push(commandRepr);

  for (const s of stringsToScan) {
    for (const m of s.matchAll(IPV4)) ips.add(m[0]);
    for (const m of s.matchAll(IPV6)) ips.add(m[1] ?? m[0]);
    for (const m of s.matchAll(URL_RE)) urls.add(m[0]);
  }
  // Hostname pass — exclude tokens that already matched as a URL host or
  // are obviously a binary path / file extension noise.
  for (const s of stringsToScan) {
    for (const m of s.matchAll(HOSTNAME)) {
      const host = m[0];
      if (host.startsWith('.') || host.endsWith('.')) continue;
      // Skip host-looking strings that are actually file basenames.
      if (/\.(?:py|sh|conf|json|xml|txt|log|yaml|yml|html|js|ts|md|out|csv)$/i.test(host)) continue;
      // Skip if it overlaps with an already-extracted URL.
      let inUrl = false;
      for (const u of urls) { if (u.includes(host)) { inUrl = true; break; } }
      if (inUrl) continue;
      hostnames.add(host);
    }
  }

  return { ips: [...ips], urls: [...urls], hostnames: [...hostnames] };
}


export const MAX_TIMEOUT_MS = 60 * 60 * 1000;          // 1 hour
export const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;       // 5 minutes
const STREAM_INLINE_CAP = 256 * 1024;                  // 256 KiB inline per stream
/**
 * Hard memory cap per stream. Beyond this we keep a head + rolling tail
 * window only and drop the middle, so a runaway noisy command can't OOM
 * the MCP server before evidence is written.
 */
export const STREAM_HARD_CAP = 16 * 1024 * 1024;       // 16 MiB per stream
export const STREAM_HEAD_KEEP = 4 * 1024 * 1024;       // 4 MiB head
export const STREAM_TAIL_KEEP = 4 * 1024 * 1024;       // 4 MiB tail
const TRUNCATION_MARKER = '\n…[output truncated; full output stored in evidence]…\n';
const HARD_CAP_DROPPED_MARKER = '\n…[output exceeded in-memory cap; middle bytes dropped]…\n';

// Per-technique noise defaults (0–1 ratio, same scale as opsec.max_noise).
// Used only when the caller does not provide an explicit noise_estimate;
// previously the runner substituted `global_noise_spent`, which double-
// counted cumulative spend back onto the action and inflated the tracker.
//
// These values are conservative starting points — they're meant to be
// "rough technique floor" rather than precise. When a technique isn't
// listed we fall back to UNKNOWN_TECHNIQUE_DEFAULT so unknown actions
// don't get a free 0 ride past the ceiling.
const TECHNIQUE_NOISE_DEFAULTS: Record<string, number> = {
  // Recon / discovery
  recon: 0.1,
  port_scan: 0.3,
  service_scan: 0.3,
  host_discovery: 0.2,
  scan: 0.3,
  // Enumeration
  enum: 0.1,
  enum_smb: 0.15,
  enum_dns: 0.05,
  enum_ldap: 0.1,
  enum_kerberos: 0.1,
  smb_enum: 0.15,
  rpc_enum: 0.15,
  snmp_enum: 0.15,
  // Web
  web_scan: 0.3,
  web_fuzz: 0.4,
  web_brute: 0.5,
  dir_brute: 0.4,
  vuln_scan: 0.4,
  // Auth-pressure
  cred_brute: 0.6,
  auth_brute: 0.6,
  spray: 0.4,
  password_spray: 0.4,
  // Common AD-style techniques
  kerberoast: 0.2,
  asreproast: 0.2,
};
const UNKNOWN_TECHNIQUE_DEFAULT_NOISE = 0.1;

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

/**
 * Bounded per-stream byte sink. Keeps every chunk until the running total
 * exceeds STREAM_HARD_CAP, then retains only:
 *   - the first STREAM_HEAD_KEEP bytes ever seen, and
 *   - a rolling tail of the most recent STREAM_TAIL_KEEP bytes,
 * dropping everything in between. `total_bytes` counts what was produced,
 * not what is retained.
 */
export class BoundedStreamBuffer {
  private head: Buffer[] = [];
  private headBytes = 0;
  private tailChunks: Buffer[] = [];
  private tailBytes = 0;
  private totalBytes = 0;
  private droppedBytes = 0;
  private capExceeded = false;

  push(chunk: Buffer): void {
    this.totalBytes += chunk.length;

    // Phase 1: still under the hard cap → keep everything in head.
    if (!this.capExceeded && this.headBytes + chunk.length <= STREAM_HARD_CAP) {
      this.head.push(chunk);
      this.headBytes += chunk.length;
      return;
    }

    // Transition: split the incoming chunk between completing the head
    // window and starting the tail buffer.
    if (!this.capExceeded) {
      this.capExceeded = true;
      const headRoom = Math.max(0, STREAM_HEAD_KEEP - this.headBytes);
      if (headRoom > 0) {
        const toHead = chunk.subarray(0, headRoom);
        this.head.push(toHead);
        this.headBytes += toHead.length;
        chunk = chunk.subarray(headRoom);
      } else if (this.headBytes > STREAM_HEAD_KEEP) {
        // Trim accumulated head down to the keep window; the trimmed bytes
        // become the start of the tail buffer.
        const flat = Buffer.concat(this.head, this.headBytes);
        this.head = [flat.subarray(0, STREAM_HEAD_KEEP)];
        this.headBytes = STREAM_HEAD_KEEP;
        const overflow = flat.subarray(STREAM_HEAD_KEEP);
        if (overflow.length > 0) {
          this.tailChunks.push(overflow);
          this.tailBytes += overflow.length;
        }
      }
    }

    if (chunk.length === 0) return;

    // Phase 2: rolling tail window.
    this.tailChunks.push(chunk);
    this.tailBytes += chunk.length;
    while (this.tailBytes > STREAM_TAIL_KEEP && this.tailChunks.length > 0) {
      const first = this.tailChunks[0];
      const overflow = this.tailBytes - STREAM_TAIL_KEEP;
      if (first.length <= overflow) {
        this.tailChunks.shift();
        this.tailBytes -= first.length;
        this.droppedBytes += first.length;
      } else {
        this.tailChunks[0] = first.subarray(overflow);
        this.tailBytes -= overflow;
        this.droppedBytes += overflow;
      }
    }
  }

  get total_bytes(): number { return this.totalBytes; }
  get dropped_bytes(): number { return this.droppedBytes; }
  get cap_exceeded(): boolean { return this.capExceeded; }

  /** Concatenated retained output as utf-8, with a marker if middle bytes were dropped. */
  toFullString(): string {
    if (!this.capExceeded) {
      return Buffer.concat(this.head, this.headBytes).toString('utf8');
    }
    const headStr = Buffer.concat(this.head, this.headBytes).toString('utf8');
    const tailStr = Buffer.concat(this.tailChunks, this.tailBytes).toString('utf8');
    return headStr + HARD_CAP_DROPPED_MARKER + tailStr;
  }
}

function captureStream(buf: BoundedStreamBuffer, chunk: Buffer): void {
  buf.push(chunk);
}

function joinAndCap(buf: BoundedStreamBuffer, cap: number): { text: string; truncated: boolean; total: number } {
  const full = buf.toFullString();
  const total = buf.total_bytes;
  if (full.length <= cap) return { text: full, truncated: total > full.length, total };
  const head = full.slice(0, Math.floor(cap * 0.75));
  const tail = full.slice(full.length - Math.floor(cap * 0.25));
  return { text: head + TRUNCATION_MARKER + tail, truncated: true, total };
}

interface ProcessResult {
  exit_code: number | null;
  signal: NodeJS.Signals | null;
  stdout: BoundedStreamBuffer;
  stderr: BoundedStreamBuffer;
  duration_ms: number;
  timed_out: boolean;
  spawn_error?: string;
}

function runProcess(binary: string, args: string[], opts: {
  cwd?: string;
  env?: Record<string, string>;
  timeout_ms: number;
  /** Optional streaming sinks. Receive every byte of stdout/stderr regardless of inline cap. */
  stdoutSink?: { write: (chunk: Buffer) => void };
  stderrSink?: { write: (chunk: Buffer) => void };
}): Promise<ProcessResult> {
  return new Promise((resolve) => {
    const start = Date.now();
    const stdout = new BoundedStreamBuffer();
    const stderr = new BoundedStreamBuffer();
    let timedOut = false;

    let child;
    try {
      child = spawn(binary, args, {
        cwd: opts.cwd,
        env: buildChildEnv(opts.env),
        stdio: ['ignore', 'pipe', 'pipe'],
        // R2-1: put the child in its own process group on POSIX so the
        // timeout path can signal the entire descendant tree via -pid.
        // Without this, bash -c 'tool & wait' style invocations leave
        // grandchildren running after Overwatch reports the action killed.
        // No-op on Windows (where spawn ignores `detached:true` for
        // signaling purposes); we document the gap rather than fake it.
        detached: process.platform !== 'win32',
      });
    } catch (err) {
      resolve({
        exit_code: null,
        signal: null,
        stdout,
        stderr,
        duration_ms: Date.now() - start,
        timed_out: false,
        spawn_error: err instanceof Error ? err.message : String(err),
      });
      return;
    }

    // Helper: kill the entire child process group (POSIX) or the direct
    // child (Windows). Returns whether the group-kill path was used.
    const killTree = (sig: NodeJS.Signals): boolean => {
      const pid = child!.pid;
      if (pid && process.platform !== 'win32') {
        try {
          // Negative PID targets the process group.
          process.kill(-pid, sig);
          return true;
        } catch {
          // Group may have already exited; fall through to direct kill.
        }
      }
      try { child!.kill(sig); } catch { /* already gone */ }
      return false;
    };

    const timer = setTimeout(() => {
      timedOut = true;
      killTree('SIGTERM');
      setTimeout(() => { killTree('SIGKILL'); }, 5000).unref();
    }, opts.timeout_ms);
    timer.unref();

    child.stdout?.on('data', (c: Buffer) => {
      captureStream(stdout, c);
      try { opts.stdoutSink?.write(c); } catch { /* sink errors must not kill the process */ }
    });
    child.stderr?.on('data', (c: Buffer) => {
      captureStream(stderr, c);
      try { opts.stderrSink?.write(c); } catch { /* sink errors must not kill the process */ }
    });

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
  /** Operator override: skip the fail-closed check for unverified host/service/share targets. */
  allow_unverified_scope?: boolean;
  parse_with?: string;
  parser_context?: ParseContext;
  /**
   * Which captured stream feeds the parser.
   *  - `stdout` (default for most parsers): only stdout.
   *  - `stderr`: only stderr (for tools that emit machine-readable output to stderr).
   *  - `combined`: stdout + stderr concatenated.
   *  - `auto`: stdout if non-empty, else stderr.
   */
  parse_stream?: 'stdout' | 'stderr' | 'combined' | 'auto';
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
    parse_stream,
    noise_estimate: noiseOverride,
    allow_unverified_scope,
  } = opts;

  // P1.2: when the engagement carries a nonce, derive action_id
  // deterministically from (nonce | agent_id | now | command | seq).
  // Otherwise fall through to uuidv4 — strict migration: legacy
  // engagements (pre-nonce) keep their UUID-based action IDs forever.
  const ctxConfig = engine.getConfig();
  const nowForId = engine.now();
  const normalizedActionId = action_id || actionIdOrUuid(
    ctxConfig.engagement_nonce
      ? {
        engagement_nonce: ctxConfig.engagement_nonce,
        agent_id,
        timestamp: nowForId,
        command_signature: command_repr,
        sequence: engine.nextDeterministicSeq(),
      }
      : null,
  );
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
  // Validate every target in the action — not just the singular target_node /
  // target_ip. A command like `nmap 8.8.8.8 9.9.9.9` arrives via target_ips
  // and must be scope-checked per-IP; otherwise out-of-scope hosts can ride
  // along inside a multi-target invocation. We dedupe per (kind,value),
  // run validateAction once per target, and aggregate errors/warnings.
  let noiseEstimate = noiseOverride;
  if (shouldValidate) {
    const validationTargets: Array<Parameters<typeof engine.validateAction>[0]> = [];
    for (const id of allTargetNodeIds) validationTargets.push({ target_node: id, technique, allow_unverified_scope });
    for (const ip of allTargetIps) validationTargets.push({ target_ip: ip, technique, allow_unverified_scope });
    if (target_url) validationTargets.push({ target_url, technique, allow_unverified_scope });
    if (cloud_resource) validationTargets.push({ cloud_resource, technique, allow_unverified_scope });

    // F3: if the caller declared no targets but the action is target-facing
    // (recon/scan/web/etc., recognized by either technique or binary name),
    // fall back to extracting implicit targets from argv + command. Without
    // this a `nmap 8.8.8.8` invocation that never populated target_ip — and
    // omitted technique entirely — would slip through scope. We fail closed
    // when implicit targets are found and `allow_unverified_scope` is not set.
    if (validationTargets.length === 0 && isTargetFacing(technique, tool_name, binary)) {
      const implicit = extractImplicitTargets(tool_name, args, command_repr);
      for (const ip of implicit.ips) {
        validationTargets.push({ target_ip: ip, technique, allow_unverified_scope });
      }
      for (const u of implicit.urls) {
        validationTargets.push({ target_url: u, technique, allow_unverified_scope });
      }
      for (const h of implicit.hostnames) {
        // Hostnames go through target_ip (validateAction resolves both forms).
        validationTargets.push({ target_ip: h, technique, allow_unverified_scope });
      }
    }

    if (validationTargets.length === 0) validationTargets.push({ technique, allow_unverified_scope });

    const aggregatedErrors: string[] = [];
    const aggregatedWarnings: string[] = [];
    let worstOpsecContext: ReturnType<typeof engine.validateAction>['opsec_context'] | undefined;
    let aggregateValid = true;
    // Pick the "worst" per-target OPSEC context to drive the approval gate.
    // Otherwise a multi-target action whose last target is clean would skip
    // approval even when an earlier target is under defensive pressure.
    // Severity ordering, most restrictive first:
    //   1. lower noise_budget_remaining wins (less headroom = more pressure)
    //   2. quiet > normal > loud recommended_approach
    //   3. more defensive_signals wins
    const approachRank = { quiet: 2, normal: 1, loud: 0 } as const;
    const isWorse = (a: typeof worstOpsecContext, b: typeof worstOpsecContext): boolean => {
      if (!a) return true;
      if (!b) return false;
      if (a.noise_budget_remaining !== b.noise_budget_remaining) {
        return b.noise_budget_remaining < a.noise_budget_remaining;
      }
      const ar = approachRank[a.recommended_approach];
      const br = approachRank[b.recommended_approach];
      if (ar !== br) return br > ar;
      return (b.defensive_signals?.length ?? 0) > (a.defensive_signals?.length ?? 0);
    };
    for (const t of validationTargets) {
      const r = engine.validateAction(t);
      if (isWorse(worstOpsecContext, r.opsec_context)) {
        worstOpsecContext = r.opsec_context;
      }
      if (!r.valid) aggregateValid = false;
      for (const e of r.errors) if (!aggregatedErrors.includes(e)) aggregatedErrors.push(e);
      for (const w of r.warnings) if (!aggregatedWarnings.includes(w)) aggregatedWarnings.push(w);
    }
    const v = {
      valid: aggregateValid,
      errors: aggregatedErrors,
      warnings: aggregatedWarnings,
      opsec_context: worstOpsecContext!,
    };

    // 0.3: noise estimation + ceiling enforcement. OPSEC is opt-in: when
    // `opsec.enabled !== true`, the entire noise-budget pipeline stays inert
    // — no per-technique default substitution, no recording, no ceiling
    // rejection. The caller can still opt in for a single action by passing
    // an explicit `noise_estimate`, in which case we honor and record it
    // (without enforcing a ceiling). Only when OPSEC is enabled do we both
    // substitute defaults for missing estimates AND reject actions that
    // would exceed `max_noise`.
    //
    // This replaces the prior buggy fallback (`noiseEstimate = global_noise_spent`),
    // which was always-on and double-counted cumulative spend back onto each
    // action.
    const opsecEnabled = engine.isOpsecEnforcementEnabled();
    if (noiseEstimate === undefined && opsecEnabled) {
      noiseEstimate = technique
        ? (TECHNIQUE_NOISE_DEFAULTS[technique] ?? UNKNOWN_TECHNIQUE_DEFAULT_NOISE)
        : UNKNOWN_TECHNIQUE_DEFAULT_NOISE;
    }
    if (opsecEnabled && typeof noiseEstimate === 'number' && noiseEstimate > 0) {
      const maxNoise = engine.getMaxNoise();
      const headroom = v.opsec_context.noise_budget_remaining;
      if (noiseEstimate > headroom) {
        const ceilingMsg =
          `Action exceeds OPSEC noise ceiling: estimate ${noiseEstimate.toFixed(3)} ` +
          `> remaining budget ${headroom.toFixed(3)} (max_noise=${maxNoise}, ` +
          `spent=${v.opsec_context.global_noise_spent.toFixed(3)}).`;
        v.errors.push(ceilingMsg);
        v.valid = false;
      }
    }
    const validationResult = !v.valid ? 'invalid' : v.warnings.length > 0 ? 'warning_only' : 'valid';

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
    // P4.1: pass the phase-effective approval config so per-phase
    // overrides (e.g., approve-all during exploitation) are honored.
    if (queue.needsApproval(v.opsec_context, technique, engine.getEffectiveApprovalConfig())) {
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
        description: approval.unattended_execute
          ? `Action auto-approved on timeout (unattended): ${resolvedDescription}`
          : `Action ${approval.status}: ${resolvedDescription}`,
        agent_id,
        action_id: normalizedActionId,
        event_type: 'action_validated',
        category: 'frontier',
        frontier_item_id,
        result_classification: approval.status === 'denied' ? 'failure' : 'success',
        details: {
          approval_status: approval.status,
          operator_notes: approval.operator_notes,
          reason: approval.reason,
          auto_approved: approval.auto_approved,
          unattended_execute: approval.unattended_execute,
        },
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
  // Phase H: pipe stdout/stderr to evidence files as the process runs so
  // the full-fidelity output is captured even when it exceeds the in-memory
  // BoundedStreamBuffer cap. The bounded buffer still drives the inline
  // tool response and truncation flags; the streamed evidence files hold
  // the complete bytes for later inspection via get_evidence.
  const evidenceStore = engine.getEvidenceStore();
  const stdoutSink = evidenceStore.createBlobStream({
    action_id: normalizedActionId,
    evidence_type: 'command_output',
    filename: 'stdout',
    kind: 'raw_output',
  });
  const stderrSink = evidenceStore.createBlobStream({
    action_id: normalizedActionId,
    evidence_type: 'command_output',
    filename: 'stderr',
    kind: 'raw_output',
  });
  const result = await runProcess(binary, args, {
    cwd,
    env,
    timeout_ms: effectiveTimeout,
    stdoutSink,
    stderrSink,
  });
  const stdoutInfo = joinAndCap(result.stdout, STREAM_INLINE_CAP);
  const stderrInfo = joinAndCap(result.stderr, STREAM_INLINE_CAP);

  // ---- 4. Finalize evidence ----
  // The streaming sinks always emit a manifest record (so action lifecycle
  // events can reference them by ID) but we only surface the IDs in the
  // lifecycle event when there was actually output to record.
  // Sink finalization may reject if a write failed (ENOSPC, EIO, etc.).
  // We capture the error rather than throwing so the action lifecycle
  // event can record `evidence_capture_error` instead of silently
  // claiming evidence that does not exist.
  const finalizeResults = await Promise.allSettled([stdoutSink.end(), stderrSink.end()]);
  const stdoutCaptureError = finalizeResults[0].status === 'rejected'
    ? (finalizeResults[0].reason instanceof Error
        ? finalizeResults[0].reason.message
        : String(finalizeResults[0].reason))
    : (stdoutSink.error()?.message);
  const stderrCaptureError = finalizeResults[1].status === 'rejected'
    ? (finalizeResults[1].reason instanceof Error
        ? finalizeResults[1].reason.message
        : String(finalizeResults[1].reason))
    : (stderrSink.error()?.message);
  // If a write failed, do not claim a usable evidence_id on the event —
  // the manifest record is preserved but downstream consumers should
  // know not to trust the blob.
  const stdout_evidence_id = stdoutInfo.total > 0 && !stdoutCaptureError ? stdoutSink.evidence_id : undefined;
  const stderr_evidence_id = stderrInfo.total > 0 && !stderrCaptureError ? stderrSink.evidence_id : undefined;

  // ---- 5. Terminal lifecycle event ----
  // Phase I: a non-zero exit no longer suppresses parsing. Tools like
  // nuclei/sqlmap/gobuster routinely return 1 to signal "no match" — the
  // captured output is still parseable. Parsing is gated only on having a
  // captured stream and not having crashed before producing output.
  const parseable = !result.spawn_error && (result.stdout.total_bytes > 0 || result.stderr.total_bytes > 0);
  const parserExitOk = parse_with ? isAcceptableParserExit(parse_with, result.exit_code) : true;
  // F8: when an explicit parser is supplied, let parser-aware exit handling
  // drive overall success — a known "no findings" exit (e.g. nuclei exit 1
  // with empty result set) should not surface as `action_failed`/isError:true.
  // Without `parse_with`, fall back to strict exit-code 0.
  const succeeded = !result.spawn_error && !result.timed_out && (
    parse_with ? parserExitOk : result.exit_code === 0
  );
  const partialParse = parseable && parse_with !== undefined && !parserExitOk;
  const terminalEventType = succeeded ? 'action_completed' as const : 'action_failed' as const;
  const failureReason = result.spawn_error
    ? 'spawn_error'
    : result.timed_out
      ? 'timeout'
      : !succeeded && result.exit_code !== 0
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
      stdout_dropped_bytes: result.stdout.dropped_bytes || undefined,
      stderr_dropped_bytes: result.stderr.dropped_bytes || undefined,
      evidence_capture_error: stdoutCaptureError || stderrCaptureError
        ? { stdout: stdoutCaptureError, stderr: stderrCaptureError }
        : undefined,
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
  if (parse_with && parseable) {
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

      const fullStdoutInline = result.stdout.toFullString();
      const fullStderrInline = result.stderr.toFullString();

      // Phase D3: when stdout was truncated by the bounded buffer but the
      // streamed evidence captured the whole thing, parse from the evidence
      // file so large outputs (nuclei/nmap/azurehound) are not silently
      // mis-parsed. If the evidence read fails for any reason, fall back to
      // the bounded inline buffer and flag the parse as partial.
      let parseFromEvidence = false;
      let parseFromEvidenceError: string | undefined;
      let fullStdout = fullStdoutInline;
      let fullStderr = fullStderrInline;
      if (stdoutInfo.truncated && stdout_evidence_id) {
        try {
          const onDisk = engine.getEvidenceStore().getRawOutput(stdout_evidence_id);
          if (onDisk !== null) {
            fullStdout = onDisk;
            parseFromEvidence = true;
          } else {
            parseFromEvidenceError = 'evidence_blob_missing';
          }
        } catch (err) {
          parseFromEvidenceError = err instanceof Error ? err.message : String(err);
        }
      }
      if (stderrInfo.truncated && stderr_evidence_id) {
        try {
          const onDisk = engine.getEvidenceStore().getRawOutput(stderr_evidence_id);
          if (onDisk !== null) fullStderr = onDisk;
        } catch {
          // best-effort — stderr fallback is not common
        }
      }

      // Phase D4: choose which stream feeds the parser.
      const stream = parse_stream ?? 'stdout';
      let parserInput: string;
      switch (stream) {
        case 'stderr':
          parserInput = fullStderr;
          break;
        case 'combined':
          parserInput = fullStdout + (fullStderr ? `\n${fullStderr}` : '');
          break;
        case 'auto':
          parserInput = fullStdout.trim().length > 0 ? fullStdout : fullStderr;
          break;
        case 'stdout':
        default:
          parserInput = fullStdout;
          break;
      }
      const usedStream: 'stdout' | 'stderr' | 'combined' | 'auto' =
        stream === 'auto'
          ? (fullStdout.trim().length > 0 ? 'stdout' : 'stderr')
          : stream;

      const finding = parseOutput(parse_with, parserInput, agent_id, ctx);
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
        // Phase I: when the run finished with an unexpected non-zero exit,
        // OR when we parsed from the bounded inline buffer because the
        // streamed evidence was unavailable, mark every parsed node so
        // downstream consumers (UI, retrospectives, inference) can
        // recognize that the data may be incomplete.
        const boundedFallback = stdoutInfo.truncated && !parseFromEvidence;
        const partialAny = partialParse || boundedFallback;
        if (partialAny) {
          for (const node of finding.nodes) {
            (node as Record<string, unknown>).partial = true;
          }
        }

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
            partial: partialAny || undefined,
            partial_reason: partialAny
              ? (partialParse && boundedFallback
                  ? 'nonzero_exit_and_bounded_buffer_only'
                  : partialParse
                    ? 'nonzero_exit'
                    : 'bounded_buffer_only')
              : undefined,
            parse_stream: usedStream,
            parsed_from_evidence: parseFromEvidence || undefined,
            evidence_read_error: parseFromEvidenceError,
            exit_code: result.exit_code,
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
