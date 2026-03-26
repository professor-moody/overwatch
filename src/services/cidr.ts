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
  const numHosts = 1 << hostBits;
  const usableHosts = numHosts - 2; // exclude network + broadcast
  const truncated = usableHosts > EXPANSION_CAP;
  const limit = truncated ? EXPANSION_CAP : usableHosts;

  const network = (ip & (0xFFFFFFFF << hostBits)) >>> 0;
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
  if (cidrs.length === 0) return true;
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

function ipToNum(ip: string): number {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}
