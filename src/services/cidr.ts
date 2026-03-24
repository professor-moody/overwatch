// ============================================================
// Overwatch — CIDR Utilities
// ============================================================

export function expandCidr(cidr: string): string[] {
  const [base, maskStr] = cidr.split('/');
  if (!maskStr) return [base];

  const mask = parseInt(maskStr);
  if (mask < 0 || mask > 32) return [base];
  if (mask === 32) return [base];

  const parts = base.split('.').map(Number);
  const ip = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;

  const hostBits = 32 - mask;
  const numHosts = 1 << hostBits;

  // Cap expansion at /20 (4094 hosts) to prevent memory issues
  if (numHosts > 4096) {
    console.error(`CIDR ${cidr} expands to ${numHosts - 2} hosts, capping at /20 equivalent. Use smaller subnets.`);
    return [base];
  }

  const network = (ip & (0xFFFFFFFF << hostBits)) >>> 0;
  const ips: string[] = [];

  // Skip network and broadcast addresses
  for (let i = 1; i < numHosts - 1; i++) {
    const addr = (network + i) >>> 0;
    ips.push([
      (addr >>> 24) & 0xFF,
      (addr >>> 16) & 0xFF,
      (addr >>> 8) & 0xFF,
      addr & 0xFF
    ].join('.'));
  }

  return ips;
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

function ipToNum(ip: string): number {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}
