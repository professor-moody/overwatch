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
import { parseOutput, getSupportedParsers, isAcceptableParserExit, isParserError } from '../services/parsers/index.js';
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
  // Track D (Phase 6 enterprise): live token replay against IdP/cloud
  // APIs. Quiet by default but always target-facing — the curl
  // invocation always carries an explicit endpoint URL.
  'token_replay',
]);

// Phase D: network-capable binaries that aren't unambiguously target-facing
// (so they're not in TARGET_FACING_BINARIES below) but DO reach out to the
// network. When such a binary is invoked under a non-target-facing technique
// AND argv contains a URL/IP/hostname AND no scope metadata is set, we fail
// closed — this is the operator-misuse pattern from the assessment:
//   run_bash({ command: 'curl https://target/admin', technique: 'note' })
// Generic / shell-only binaries (echo, cat, grep, awk, sed, …) are NOT in
// here, so an `echo connecting-to-https://example.com/...` log line still
// runs untouched.
const NETWORK_CAPABLE_BINARIES = new Set([
  'curl', 'wget',
  'ssh', 'scp', 'sftp', 'rsync',
  'nc', 'ncat', 'netcat',
  'openssl',
  'mysql', 'psql', 'mongo', 'redis-cli',
  'ftp',
  'telnet',
]);

function isNetworkCapableBinary(toolName: string, binary: string): boolean {
  const tn = basename(toolName).toLowerCase();
  const bn = basename(binary).toLowerCase();
  if (NETWORK_CAPABLE_BINARIES.has(tn) || NETWORK_CAPABLE_BINARIES.has(bn)) return true;
  return false;
}

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
  cidrs: string[];
  urls: string[];
  hostnames: string[];
}

function tokenizeCommandLike(command: string): string[] {
  const tokens: string[] = [];
  const re = /"([^"\\]*(?:\\.[^"\\]*)*)"|'([^']*)'|(\S+)/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(command)) !== null) {
    tokens.push(match[1] ?? match[2] ?? match[3]);
  }
  return tokens;
}

function isNmapLike(toolName: string): boolean {
  const name = basename(toolName).toLowerCase();
  return name === 'nmap' || name === 'rustscan' || name === 'masscan';
}

function scanArgsForTargets(toolName: string, args: string[], commandRepr: string): string[] {
  if (!isNmapLike(toolName)) {
    const stringsToScan = args.filter(a => typeof a === 'string' && a.length > 0 && !a.startsWith('-'));
    if (commandRepr) stringsToScan.push(commandRepr);
    return stringsToScan;
  }

  const sourceArgs = args.length === 2 && args[0] === '-c'
    ? tokenizeCommandLike(commandRepr).slice(1)
    : args;
  const skipValueOptions = new Set([
    '-oA', '-oG', '-oN', '-oS', '-oX', '-iL', '-iR',
    '--exclude', '--excludefile',
  ]);
  const stringsToScan: string[] = [];
  for (let i = 0; i < sourceArgs.length; i += 1) {
    const token = sourceArgs[i];
    if (!token) continue;
    if (skipValueOptions.has(token)) {
      i += 1;
      continue;
    }
    if (token.startsWith('--exclude=') || token.startsWith('--excludefile=')) continue;
    if (token.startsWith('-')) continue;
    stringsToScan.push(token);
  }
  return stringsToScan;
}

function extractImplicitTargets(toolName: string, args: string[], commandRepr: string): ImplicitTargets {
  const ips = new Set<string>();
  const cidrs = new Set<string>();
  const urls = new Set<string>();
  const hostnames = new Set<string>();

  const stringsToScan = scanArgsForTargets(toolName, args, commandRepr);

  for (const s of stringsToScan) {
    for (const m of s.matchAll(IPV4)) {
      const value = m[0];
      if (value.includes('/')) cidrs.add(value);
      else ips.add(value);
    }
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

  return { ips: [...ips], cidrs: [...cidrs], urls: [...urls], hostnames: [...hostnames] };
}


export const MAX_TIMEOUT_MS = 4 * 60 * 60 * 1000;      // 4 hours
export const DEFAULT_TIMEOUT_MS = 60 * 60 * 1000;      // 1 hour — enterprise scans (nmap full-port, nuclei) routinely exceed 5 min
const STREAM_INLINE_CAP = 256 * 1024;                  // 256 KiB inline per stream
/**
 * Hard memory cap per stream. Beyond this we keep a head + rolling tail
 * window only and drop the middle, so a runaway noisy command can't OOM
 * the MCP server before evidence is written.
 */
export const STREAM_HARD_CAP = 16 * 1024 * 1024;       // 16 MiB per stream
export const STREAM_HEAD_KEEP = 4 * 1024 * 1024;       // 4 MiB head
export const STREAM_TAIL_KEEP = 4 * 1024 * 1024;       // 4 MiB tail

/**
 * Phase E: maximum evidence bytes we'll load into memory when re-reading
 * a streamed blob for parser ingestion. Bigger files fall back to a head
 * window via `getRawOutputHead` and the parse is marked partial. Picked
 * to comfortably accommodate large nuclei/azurehound outputs without
 * risking the MCP server's heap on a runaway capture.
 */
export const EVIDENCE_PARSE_MAX_BYTES = 50 * 1024 * 1024; // 50 MiB
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
  // Track D: token replay is a single quiet HTTPS call per invocation.
  token_replay: 0.05,
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
  /** Optional live tee (e.g. the Analysis live-output buffer). Never blocks the process. */
  onStdout?: (chunk: Buffer) => void;
  onStderr?: (chunk: Buffer) => void;
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
      try { opts.onStdout?.(c); } catch { /* tee errors must not kill the process */ }
    });
    child.stderr?.on('data', (c: Buffer) => {
      captureStream(stderr, c);
      try { opts.stderrSink?.write(c); } catch { /* sink errors must not kill the process */ }
      try { opts.onStderr?.(c); } catch { /* tee errors must not kill the process */ }
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
  target_cidr?: string;
  target_cidrs?: string[];
  target_url?: string;
  cloud_resource?: string;
  validate?: boolean;
  /** Operator override: skip the fail-closed check for unverified host/service/share targets. */
  allow_unverified_scope?: boolean;
  /** Local operator infrastructure helper command (listeners, bridges, port cleanup). */
  operator_infra?: boolean;
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

  /**
   * Per-request AbortSignal from the MCP SDK (`extra.signal`). If the requesting
   * client disconnects / cancels while this action is blocked on operator
   * approval, the pending approval resolves as 'aborted' and the action is not
   * executed, instead of orphaning the request until the approval timeout.
   */
  abortSignal?: AbortSignal;
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
    target_cidr,
    target_cidrs,
    target_url,
    cloud_resource,
    validate,
    parse_with,
    parser_context,
    parse_stream,
    noise_estimate: noiseOverride,
    allow_unverified_scope,
    operator_infra,
    abortSignal,
  } = opts;

  // Auto-register a synthetic running task for this agent_id if none
  // exists. Lets sub-agents that bypass `register_agent` /
  // `dispatch_agents` (e.g. Claude Code's built-in Agent tool) still
  // surface on the dashboard's AgentsPanel. No-op when agent_id is blank
  // or already registered.
  engine.ensureRunningAgent(agent_id);

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
  const allTargetCidrs = [
    ...(target_cidr ? [target_cidr] : []),
    ...(target_cidrs ?? []),
  ].filter((v, i, a) => a.indexOf(v) === i);
  const observedTargetCidrs = new Set(allTargetCidrs);
  const targetCidrsForEvents = (): string[] | undefined => {
    const values = [...observedTargetCidrs];
    return values.length > 0 ? values : undefined;
  };
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
    for (const cidr of allTargetCidrs) validationTargets.push({ target_cidr: cidr, technique, allow_unverified_scope });
    if (target_url) validationTargets.push({ target_url, technique, allow_unverified_scope });
    if (cloud_resource) validationTargets.push({ cloud_resource, technique, allow_unverified_scope });

    // F3: if the caller declared no targets but the action is target-facing
    // (recon/scan/web/etc., recognized by either technique or binary name),
    // fall back to extracting implicit targets from argv + command. Without
    // this a `nmap 8.8.8.8` invocation that never populated target_ip — and
    // omitted technique entirely — would slip through scope. We fail closed
    // when implicit targets are found and `allow_unverified_scope` is not set.
    if (validationTargets.length === 0 && !operator_infra && isTargetFacing(technique, tool_name, binary)) {
      const implicit = extractImplicitTargets(tool_name, args, command_repr);
      for (const ip of implicit.ips) {
        validationTargets.push({ target_ip: ip, technique, allow_unverified_scope });
      }
      for (const cidr of implicit.cidrs) {
        observedTargetCidrs.add(cidr);
        validationTargets.push({ target_cidr: cidr, technique, allow_unverified_scope });
      }
      for (const u of implicit.urls) {
        validationTargets.push({ target_url: u, technique, allow_unverified_scope });
      }
      for (const h of implicit.hostnames) {
        // Hostnames go through target_ip (validateAction resolves both forms).
        validationTargets.push({ target_ip: h, technique, allow_unverified_scope });
      }
    }

    // Phase D: argv-token guard. If we still have no validation targets and
    // the binary is network-capable (curl/ssh/nc/...) AND argv (or the raw
    // command) contains a URL/IP/hostname, the caller is running a target-
    // touching command under a non-target-facing technique label. Fail
    // closed unless `allow_unverified_scope` is set.
    //
    // We deliberately limit this to the NETWORK_CAPABLE_BINARIES allowlist:
    // a benign `echo connecting-to-https://example.com/...` log line must
    // still run, so the guard skips for shell-only / non-network binaries.
    //
    // The pattern this closes:
    //   run_bash({ command: 'curl https://target/admin', technique: 'note' })
    // where `note` is not in TARGET_FACING_TECHNIQUES so the F3 path above
    // didn't run, but the argv clearly references an external target.
    if (
      validationTargets.length === 0
      && !allow_unverified_scope
      && !operator_infra
      && isNetworkCapableBinary(tool_name, binary)
    ) {
      const sniff = extractImplicitTargets(tool_name, args, command_repr);
      const found = [...sniff.ips, ...sniff.cidrs, ...sniff.urls, ...sniff.hostnames];
      if (found.length > 0) {
        engine.logActionEvent({
          description: `Refused: target tokens in argv with no scope metadata`,
          agent_id,
          action_id: normalizedActionId,
          event_type: 'action_failed',
          category: 'frontier',
          tool_name,
          technique,
          frontier_item_id,
          result_classification: 'failure',
          details: {
            reason: 'target_tokens_in_argv_without_scope',
            argv_tokens_found: found.slice(0, 8),
            hint: 'Pass target_url/target_ip explicitly, or set allow_unverified_scope=true if the tokens are intentional non-target references.',
          },
        });
        engine.persist();
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              action_id: normalizedActionId,
              executed: false,
              validation_result: 'invalid',
              errors: [
                'target_tokens_in_argv_without_scope: pass target_url/target_ip explicitly, or set allow_unverified_scope=true if intentional.',
              ],
              argv_tokens_found: found.slice(0, 8),
            }, null, 2),
          }],
          isError: true,
        };
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
      target_cidrs: targetCidrsForEvents(),
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
        target_cidrs: targetCidrsForEvents(),
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
    // P4.1: pass the phase-effective approval config so per-phase overrides
    // (e.g., approve-all during exploitation) are honored. The action context
    // (target ip/node/technique) also lets operator-policy approval rules
    // escalate the mode (e.g. approve-all on a production subnet).
    if (queue.needsApproval(v.opsec_context, technique, engine.getEffectiveApprovalConfig({ ip: target_ip, nodeId: target_node, technique }))) {
      const pendingApproval = {
        action_id: normalizedActionId,
        technique,
        target_node,
        target_ip,
        target_cidr,
        description: resolvedDescription,
        opsec_context: v.opsec_context,
        validation_result: validationResult as 'valid' | 'warning_only',
        frontier_item_id,
        agent_id,
      };
      engine.recordApprovalRequest(pendingApproval);
      const approval = await queue.submit(pendingApproval, { signal: abortSignal });
      engine.resolveApprovalRequest(approval);

      engine.logActionEvent({
        description: approval.unattended_execute
          ? `Action auto-approved on timeout (unattended): ${resolvedDescription}`
          : `Action ${approval.status}: ${resolvedDescription}`,
        agent_id,
        action_id: normalizedActionId,
        event_type: 'action_validated',
        category: 'frontier',
        frontier_item_id,
        result_classification: approval.status === 'denied' || approval.status === 'aborted' ? 'failure' : 'success',
        details: {
          approval_status: approval.status,
          operator_notes: approval.operator_notes,
          reason: approval.reason,
          auto_approved: approval.auto_approved,
          unattended_execute: approval.unattended_execute,
        },
      });

      // Both 'denied' (operator decision) and 'aborted' (client disconnected
      // before a decision) block execution — the command must not run.
      if (approval.status === 'denied' || approval.status === 'aborted') {
        const aborted = approval.status === 'aborted';
        engine.logActionEvent({
          description: aborted
            ? `Approval aborted (client disconnected): ${resolvedDescription}`
            : `Operator denied: ${resolvedDescription}`,
          agent_id,
          action_id: normalizedActionId,
          event_type: 'action_failed',
          category: 'frontier',
          frontier_item_id,
          tool_name,
          technique,
          target_cidrs: targetCidrsForEvents(),
          result_classification: 'failure',
          details: aborted
            ? { reason: 'approval_aborted', approval_reason: approval.reason }
            : { reason: 'operator_denied', approval_reason: approval.reason },
        });
        engine.persist();
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              action_id: normalizedActionId,
              executed: false,
              approval_status: approval.status,
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
    command_repr,
    target_node_ids: allTargetNodeIds.length > 0 ? allTargetNodeIds : undefined,
    target_ips: allTargetIps.length > 0 ? allTargetIps : undefined,
    target_cidrs: targetCidrsForEvents(),
    frontier_item_id,
    noise_estimate: noiseEstimate,
    details: {
      command: command_repr,
      binary,
      args,
      cwd,
      timeout_ms: effectiveTimeout,
      invoking_tool: opts.invoking_tool,
      operator_infra: operator_infra || undefined,
    },
  });
  if (noiseEstimate !== undefined) {
    engine.recordOpsecNoise({
      action_id: normalizedActionId,
      host_id: allTargetNodeIds[0],
      agent_id,
      frontier_item_id,
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
    agent_id,
    evidence_type: 'command_output',
    filename: 'stdout',
    kind: 'raw_output',
  });
  const stderrSink = evidenceStore.createBlobStream({
    action_id: normalizedActionId,
    agent_id,
    evidence_type: 'command_output',
    filename: 'stderr',
    kind: 'raw_output',
  });
  // Live-output buffer: tee chunks so the Analysis workspace can stream a
  // running action in real time. Durable bytes still go to the evidence sinks.
  const liveOutput = engine.getActionOutputBuffer();
  liveOutput.open(normalizedActionId);
  const result = await runProcess(binary, args, {
    cwd,
    env,
    timeout_ms: effectiveTimeout,
    stdoutSink,
    stderrSink,
    onStdout: (c) => liveOutput.append(normalizedActionId, 'stdout', c),
    onStderr: (c) => liveOutput.append(normalizedActionId, 'stderr', c),
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
    command_repr,
    target_node_ids: allTargetNodeIds.length > 0 ? allTargetNodeIds : undefined,
    target_ips: allTargetIps.length > 0 ? allTargetIps : undefined,
    target_cidrs: targetCidrsForEvents(),
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
      operator_infra: operator_infra || undefined,
    },
  });
  engine.persist();
  // Live stream is finished now that the terminal event + evidence are
  // persisted; connected viewers get `action_done` and fall back to the
  // durable evidence route. The buffer self-evicts shortly after.
  liveOutput.markDone(normalizedActionId);

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
      //
      // Phase E: bound the readback so a 100 MB+ scanner output can't OOM
      // the MCP server during parser ingestion. When the evidence file is
      // larger than EVIDENCE_PARSE_MAX_BYTES, fall back to a head window
      // streamed via getRawOutputHead and mark the parse as partial.
      let parseFromEvidence = false;
      let parseFromEvidenceError: string | undefined;
      let evidenceSizeExceeded = false;
      let fullStdout = fullStdoutInline;
      let fullStderr = fullStderrInline;
      if (stdoutInfo.truncated && stdout_evidence_id) {
        try {
          const evstore = engine.getEvidenceStore();
          const onDisk = evstore.getRawOutput(stdout_evidence_id, { max_bytes: EVIDENCE_PARSE_MAX_BYTES });
          if (onDisk !== null) {
            fullStdout = onDisk;
            parseFromEvidence = true;
          } else {
            // Either the file is missing OR it exceeds the size cap. Try a
            // head read to see which case we're in; null again means missing.
            const head = evstore.getRawOutputHead(stdout_evidence_id, EVIDENCE_PARSE_MAX_BYTES);
            if (head === null) {
              parseFromEvidenceError = 'evidence_blob_missing';
            } else if (head.truncated) {
              fullStdout = head.text;
              parseFromEvidence = true;
              evidenceSizeExceeded = true;
              parseFromEvidenceError = `evidence_too_large_for_full_parse: ${head.total_bytes} bytes (cap ${EVIDENCE_PARSE_MAX_BYTES})`;
            } else {
              fullStdout = head.text;
              parseFromEvidence = true;
            }
          }
        } catch (err) {
          parseFromEvidenceError = err instanceof Error ? err.message : String(err);
        }
      }
      if (stderrInfo.truncated && stderr_evidence_id) {
        try {
          const evstore = engine.getEvidenceStore();
          const onDisk = evstore.getRawOutput(stderr_evidence_id, { max_bytes: EVIDENCE_PARSE_MAX_BYTES });
          if (onDisk !== null) {
            fullStderr = onDisk;
          } else {
            const head = evstore.getRawOutputHead(stderr_evidence_id, EVIDENCE_PARSE_MAX_BYTES);
            if (head !== null) {
              fullStderr = head.text;
              if (head.truncated) evidenceSizeExceeded = true;
            }
          }
        } catch {
          // best-effort — stderr fallback is not common
        }
      }
      if (evidenceSizeExceeded) {
        engine.logActionEvent({
          description: 'Evidence too large for full parse — used head window',
          agent_id,
          action_id: normalizedActionId,
          event_type: 'instrumentation_warning',
          category: 'system',
          details: {
            stdout_evidence_id,
            stderr_evidence_id,
            max_bytes: EVIDENCE_PARSE_MAX_BYTES,
            error: parseFromEvidenceError,
          },
        });
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
      } else if (isParserError(finding)) {
        // F0-1: parser threw — surface the exception so the operator's LLM
        // does not mistake it for a clean parse with no results.
        parse_summary = { error: `Parser '${parse_with}' threw`, parser_exception: finding.raw_output };
        engine.logActionEvent({
          description: `Parser '${parse_with}' threw an exception`,
          agent_id,
          action_id: normalizedActionId,
          event_type: 'parse_output',
          category: 'finding',
          tool_name: parse_with,
          frontier_item_id,
          frontier_type: frontierType,
          result_classification: 'failure',
          details: { parse_status: 'parser_exception' },
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
        // Phase E: an evidence file larger than EVIDENCE_PARSE_MAX_BYTES is
        // parsed against its head window only — every produced node carries
        // partial=true so consumers can flag the gap.
        const partialAny = partialParse || boundedFallback || evidenceSizeExceeded;
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
              ? (evidenceSizeExceeded
                  ? 'evidence_too_large_for_full_parse'
                  : partialParse && boundedFallback
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
