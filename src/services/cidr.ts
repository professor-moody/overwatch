// ============================================================
// Overwatch — CIDR Utilities
// ============================================================

export interface CidrExpansionResult {
  ips: string[];
  truncated: boolean;
  total_hosts?: number;
}

const EXPANSION_CAP = 4094; // /20 equivalent — usable hosts in a /20

export function expandCidrDetailed(cidr: string): CidrExpansionResult {
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
  const [base, maskStr] = cidr.split('/');
  if (!maskStr) return ip === base;

  const mask = parseInt(maskStr);
  const ipNum = ipToNum(ip);
  const baseNum = ipToNum(base);
  const maskBits = (0xFFFFFFFF << (32 - mask)) >>> 0;

  return (ipNum & maskBits) === (baseNum & maskBits);
}

export function isIpInScope(ip: string, cidrs: string[], exclusions: string[]): boolean {
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
  // If no scope domains configured, can't determine — allow
  if (domains.length === 0) return true;
  // Check if hostname belongs to any scope domain
  for (const domain of domains) {
    const domainLower = domain.toLowerCase();
    if (lower === domainLower || lower.endsWith('.' + domainLower)) return true;
  }
  return false;
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
 * Convert a glob-like URL pattern to a RegExp.
 * Supports: `*` (any non-/ chars), `**` (anything), literal `.` escaped.
 * Examples: "*.example.com" matches "app.example.com"
 *           "app.corp.io/api/*" matches "app.corp.io/api/v1"
 */
function globToRegex(pattern: string): RegExp {
  // Escape regex-special chars except * which we handle
  let re = pattern
    .replace(/([.+?^${}()|[\]\\])/g, '\\$1')  // escape specials (. becomes \.)
    .replace(/\*\*/g, '\0GLOBSTAR\0')            // protect ** before * replacement
    .replace(/\*/g, '[^/]*')                      // * → match non-slash
    .replace(/\0GLOBSTAR\0/g, '.*');              // restore ** → match anything
  return new RegExp(`^${re}$`, 'i');
}

export function isUrlInScope(url: string, patterns: string[]): boolean {
  // Strip protocol for matching — patterns are host/path only
  const normalized = url.replace(/^https?:\/\//, '');
  for (const pattern of patterns) {
    const normalizedPattern = pattern.replace(/^https?:\/\//, '');
    if (globToRegex(normalizedPattern).test(normalized)) return true;
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
    if (scope.gcp_projects.includes(projectId)) {
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
