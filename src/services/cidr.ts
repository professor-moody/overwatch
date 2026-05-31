// ============================================================
// Overwatch — CIDR Utilities
// ============================================================

/**
 * Detect whether a string looks like an IPv6 address.
 * Matches any string containing a colon (`:`) — covers full, compressed, and
 * link-local forms.  All CIDR helpers in this module are IPv4-only; this guard
 * lets callers reject IPv6 input cleanly instead of producing bogus results
 * from 32-bit math on 128-bit addresses.
 */
export function isIPv6(addr: string): boolean {
  return addr.includes(':');
}

export function isIPv4(addr: string): boolean {
  const match = addr.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) return false;
  return match.slice(1).map(Number).every(octet => octet >= 0 && octet <= 255);
}

export interface CidrExpansionResult {
  ips: string[];
  truncated: boolean;
  total_hosts?: number;
}

const EXPANSION_CAP = 4094; // /20 equivalent — usable hosts in a /20

export function expandCidrDetailed(cidr: string): CidrExpansionResult {
  if (isIPv6(cidr)) return { ips: [], truncated: false };
  const [base, maskStr] = cidr.split('/');
  if (!maskStr) return { ips: [base], truncated: false };

  const mask = parseInt(maskStr);
  if (mask < 0 || mask > 32) return { ips: [base], truncated: false };
  if (mask === 32) return { ips: [base], truncated: false };

  const parts = base.split('.').map(Number);
  const ip = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;

  const hostBits = 32 - mask;
  const numHosts = 2 ** hostBits; // avoid 1<<hostBits which overflows at hostBits>=31
  const usableHosts = numHosts - 2; // exclude network + broadcast
  const truncated = usableHosts > EXPANSION_CAP;
  const limit = truncated ? EXPANSION_CAP : usableHosts;

  const networkMask = hostBits >= 32 ? 0 : (0xFFFFFFFF << hostBits) >>> 0;
  const network = (ip & networkMask) >>> 0;
  const ips: string[] = [];

  // Skip network and broadcast addresses
  for (let i = 1; i <= limit; i++) {
    const addr = (network + i) >>> 0;
    ips.push([
      (addr >>> 24) & 0xFF,
      (addr >>> 16) & 0xFF,
      (addr >>> 8) & 0xFF,
      addr & 0xFF
    ].join('.'));
  }

  return truncated
    ? { ips, truncated: true, total_hosts: usableHosts }
    : { ips, truncated: false };
}

/** Backward-compatible wrapper — returns just the IP array. */
export function expandCidr(cidr: string): string[] {
  return expandCidrDetailed(cidr).ips;
}

export function isIpInCidr(ip: string, cidr: string): boolean {
  if (!isIPv4(ip) || isIPv6(cidr)) return false;
  const [base, maskStr] = cidr.split('/');
  if (!isIPv4(base)) return false;
  if (!maskStr) return ip === base;

  const mask = parseInt(maskStr);
  // Defensive clamp: an out-of-range mask (e.g. /33 from a hand-rolled
  // config that bypassed isValidCidr) would otherwise produce a bogus
  // mask via signed-shift wraparound and broaden the in-scope range.
  // Fail closed.
  if (!Number.isFinite(mask) || mask < 0 || mask > 32) return false;
  const ipNum = ipToNum(ip);
  const baseNum = ipToNum(base);
  const maskBits = mask === 0 ? 0 : (0xFFFFFFFF << (32 - mask)) >>> 0;

  return (ipNum & maskBits) === (baseNum & maskBits);
}

export function isIpInScope(ip: string, cidrs: string[], exclusions: string[]): boolean {
  if (!isIPv4(ip)) return false;
  // Check exclusions first
  for (const excl of exclusions) {
    if (excl.includes('/')) {
      if (isIpInCidr(ip, excl)) return false;
    } else {
      if (ip === excl) return false;
    }
  }
  if (cidrs.length === 0) return false;
  // Check inclusion
  for (const cidr of cidrs) {
    if (cidr.includes('/')) {
      if (isIpInCidr(ip, cidr)) return true;
    } else {
      if (ip === cidr) return true;
    }
  }
  return false;
}

export function isHostnameInScope(hostname: string, domains: string[], exclusions: string[]): boolean {
  const lower = hostname.toLowerCase();
  // Check exclusions first (exact match or domain suffix)
  for (const excl of exclusions) {
    if (!excl.includes('/')) {
      const exclLower = excl.toLowerCase();
      if (lower === exclLower || lower.endsWith('.' + exclLower)) return false;
    }
  }
  if (domains.length === 0) return false;
  // Check if hostname belongs to any scope domain
  for (const domain of domains) {
    const domainLower = domain.toLowerCase();
    if (lower === domainLower || lower.endsWith('.' + domainLower)) return true;
  }
  return false;
}

export function isHostExcluded(host: string, exclusions: string[]): boolean {
  const lower = host.toLowerCase();
  for (const excl of exclusions) {
    if (excl.includes('/')) {
      if (isIPv4(host) && isIpInCidr(host, excl)) return true;
      continue;
    }
    const exclLower = excl.toLowerCase();
    if (lower === exclLower || lower.endsWith('.' + exclLower)) return true;
  }
  return false;
}

export function isHostInScope(
  host: string,
  scope: { cidrs?: string[]; domains?: string[]; exclusions?: string[]; hosts?: string[] },
): boolean {
  const exclusions = scope.exclusions || [];
  if (isHostExcluded(host, exclusions)) return false;

  if (isIPv4(host) && isIpInScope(host, scope.cidrs || [], exclusions)) return true;

  const lower = host.toLowerCase();
  if ((scope.hosts || []).some(scopedHost => scopedHost.toLowerCase() === lower)) return true;

  return isHostnameInScope(host, scope.domains || [], exclusions);
}

export function isValidCidr(cidr: string): boolean {
  const match = cidr.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
  if (!match) return false;
  const octets = [match[1], match[2], match[3], match[4]].map(Number);
  if (octets.some(o => o > 255)) return false;
  if (match[5] !== undefined) {
    const mask = Number(match[5]);
    if (mask < 0 || mask > 32) return false;
  }
  return true;
}

export function inferCidrFromIps(ips: string[]): string[] {
  const subnets = new Map<string, Set<string>>();
  for (const ip of ips) {
    if (isIPv6(ip)) continue;
    const parts = ip.split('.');
    if (parts.length !== 4) continue;
    const prefix = `${parts[0]}.${parts[1]}.${parts[2]}`;
    if (!subnets.has(prefix)) subnets.set(prefix, new Set());
    subnets.get(prefix)!.add(ip);
  }
  return Array.from(subnets.keys())
    .sort()
    .map(prefix => `${prefix}.0/24`);
}

// --- URL scope matching (glob-like patterns) ---

/**
 * Host-glob: `*` matches one-or-more non-dot, non-slash characters. Tighter
 * than the old behavior where `*` was `[^/]*` and could span dots, which
 * let `*.example.com` accidentally match `aaa.bbbexample.com`. Use `**`
 * to match anything including dots (matches the old `*` behavior).
 */
function hostGlobToRegex(pattern: string): RegExp {
  // The escape pass does NOT cover `*` (we handle that ourselves), so the
  // post-escape string still contains bare `*` characters that we then
  // turn into the glob expansions below. Two-star protected first so it
  // does not get consumed by the single-star pass.
  const re = pattern
    .replace(/([.+?^${}()|[\]\\])/g, '\\$1')
    .replace(/\*\*/g, '\0G\0')
    .replace(/\*/g, '[^./]+')
    .replace(/\0G\0/g, '.*');
  return new RegExp(`^${re}$`, 'i');
}

/**
 * Path-glob: original glob semantics. `*` is non-slash; `**` is anything.
 * Patterns are anchored at both ends so an explicit path scope (e.g.
 * `/api`) does not accidentally match `/api/v1` — operators add `/api/*`
 * if they want subpath coverage.
 */
function pathGlobToRegex(pattern: string): RegExp {
  const re = pattern
    .replace(/([.+?^${}()|[\]\\])/g, '\\$1')
    .replace(/\*\*/g, '\0G\0')
    .replace(/\*/g, '[^/]*')
    .replace(/\0G\0/g, '.*');
  return new RegExp(`^${re}$`, 'i');
}

interface ParsedScopePattern {
  host: string;
  port: string; // '' = any port, otherwise exact match required (digits) or '*' wildcard
  path: string; // '' = match any path
}

function parseScopePattern(raw: string): ParsedScopePattern {
  // Strip leading protocol so callers can write either form.
  let p = raw.replace(/^https?:\/\//i, '');
  // Split off path on first slash.
  const slashIdx = p.indexOf('/');
  const hostPort = slashIdx < 0 ? p : p.slice(0, slashIdx);
  const path = slashIdx < 0 ? '' : p.slice(slashIdx);
  // Host and optional :port — handle bracketed IPv6 first so the colons
  // inside ::1 don't get mistaken for the port separator.
  let host = hostPort;
  let port = '';
  if (hostPort.startsWith('[')) {
    const close = hostPort.indexOf(']');
    if (close > 0) {
      host = hostPort.slice(1, close);
      const tail = hostPort.slice(close + 1);
      if (tail.startsWith(':')) port = tail.slice(1);
    }
  } else {
    const colonIdx = hostPort.lastIndexOf(':');
    // Only treat as host:port if the colon is followed by digits or `*`.
    if (colonIdx > 0 && /^(\d+|\*)$/.test(hostPort.slice(colonIdx + 1))) {
      host = hostPort.slice(0, colonIdx);
      port = hostPort.slice(colonIdx + 1);
    }
  }
  return { host: host.toLowerCase(), port, path };
}

export function isUrlInScope(url: string, patterns: string[], exclusions: string[] = []): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    // Malformed URL — fail closed.
    return false;
  }
  // Normalize host: lowercase, strip IPv6 brackets if URL kept them (Node
  // returns hostname WITH brackets for IPv6, while parseScopePattern
  // strips them; normalize both sides so the comparison is symmetric).
  const urlHost = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (isHostExcluded(urlHost, exclusions)) return false;
  const urlPort = parsed.port || (parsed.protocol === 'https:' ? '443' : parsed.protocol === 'http:' ? '80' : '');
  const urlPath = parsed.pathname || '/';

  for (const pattern of patterns) {
    const { host: pHost, port: pPort, path: pPath } = parseScopePattern(pattern);

    // Port: empty pattern port = any; '*' = any; otherwise exact.
    if (pPort && pPort !== '*' && pPort !== urlPort) continue;

    if (!hostGlobToRegex(pHost).test(urlHost)) continue;

    // Path: empty pattern path matches any URL path.
    if (pPath && !pathGlobToRegex(pPath).test(urlPath)) continue;

    return true;
  }
  return false;
}

// --- Cloud resource scope matching ---

export function isCloudResourceInScope(
  resource: string,
  scope: { aws_accounts?: string[]; azure_subscriptions?: string[]; gcp_projects?: string[] }
): { in_scope: boolean; reason: string } {
  // AWS ARN: arn:aws:SERVICE:REGION:ACCOUNT_ID:...
  const arnMatch = resource.match(/^arn:aws[^:]*:[^:]*:[^:]*:(\d{12}):/);
  if (arnMatch) {
    const accountId = arnMatch[1];
    if (!scope.aws_accounts?.length) {
      return { in_scope: false, reason: `AWS account ${accountId} — no aws_accounts defined in scope` };
    }
    if (scope.aws_accounts.includes(accountId)) {
      return { in_scope: true, reason: '' };
    }
    return { in_scope: false, reason: `AWS account ${accountId} not in scope` };
  }

  // Azure: /subscriptions/SUBSCRIPTION_ID/...
  const azureMatch = resource.match(/^\/subscriptions\/([^/]+)/i);
  if (azureMatch) {
    const subId = azureMatch[1].toLowerCase();
    if (!scope.azure_subscriptions?.length) {
      return { in_scope: false, reason: `Azure subscription ${subId} — no azure_subscriptions defined in scope` };
    }
    if (scope.azure_subscriptions.some(s => s.toLowerCase() === subId)) {
      return { in_scope: true, reason: '' };
    }
    return { in_scope: false, reason: `Azure subscription ${subId} not in scope` };
  }

  // GCP: projects/PROJECT_ID/...
  const gcpMatch = resource.match(/^projects\/([^/]+)/i);
  if (gcpMatch) {
    const projectId = gcpMatch[1];
    if (!scope.gcp_projects?.length) {
      return { in_scope: false, reason: `GCP project ${projectId} — no gcp_projects defined in scope` };
    }
    if (scope.gcp_projects.map(p => p.toLowerCase()).includes(projectId.toLowerCase())) {
      return { in_scope: true, reason: '' };
    }
    return { in_scope: false, reason: `GCP project ${projectId} not in scope` };
  }

  return { in_scope: false, reason: `Unrecognized cloud resource format: ${resource}` };
}

function ipToNum(ip: string): number {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}
