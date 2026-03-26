import { describe, it, expect } from 'vitest';
import { expandCidr, expandCidrDetailed, isIpInCidr, isIpInScope, isHostnameInScope, isValidCidr, inferCidrFromIps } from '../cidr.js';

describe('expandCidr', () => {
  it('expands a /24 to 254 hosts (skips network + broadcast)', () => {
    const ips = expandCidr('10.10.10.0/24');
    expect(ips.length).toBe(254);
    expect(ips[0]).toBe('10.10.10.1');
    expect(ips[253]).toBe('10.10.10.254');
  });

  it('returns single IP for /32', () => {
    const ips = expandCidr('10.10.10.5/32');
    expect(ips).toEqual(['10.10.10.5']);
  });

  it('returns single IP for bare address (no mask)', () => {
    const ips = expandCidr('192.168.1.1');
    expect(ips).toEqual(['192.168.1.1']);
  });

  it('caps expansion at 4094 hosts for subnets larger than /20', () => {
    const ips = expandCidr('10.0.0.0/16');
    expect(ips.length).toBe(4094);
    expect(ips[0]).toBe('10.0.0.1');
  });

  it('handles /30 (2 usable hosts)', () => {
    const ips = expandCidr('10.10.10.0/30');
    expect(ips.length).toBe(2);
    expect(ips[0]).toBe('10.10.10.1');
    expect(ips[1]).toBe('10.10.10.2');
  });

  it('handles /28 (14 usable hosts)', () => {
    const ips = expandCidr('172.16.0.0/28');
    expect(ips.length).toBe(14);
    expect(ips[0]).toBe('172.16.0.1');
    expect(ips[13]).toBe('172.16.0.14');
  });

  it('returns base for invalid mask > 32', () => {
    expect(expandCidr('10.0.0.1/33')).toEqual(['10.0.0.1']);
  });

  it('returns base for negative mask', () => {
    expect(expandCidr('10.0.0.1/-1')).toEqual(['10.0.0.1']);
  });
});

describe('isIpInCidr', () => {
  it('matches IP inside CIDR', () => {
    expect(isIpInCidr('10.10.10.5', '10.10.10.0/24')).toBe(true);
  });

  it('rejects IP outside CIDR', () => {
    expect(isIpInCidr('10.10.11.5', '10.10.10.0/24')).toBe(false);
  });

  it('handles exact match for bare IP (no mask)', () => {
    expect(isIpInCidr('10.10.10.5', '10.10.10.5')).toBe(true);
    expect(isIpInCidr('10.10.10.6', '10.10.10.5')).toBe(false);
  });

  it('handles /32 (single host)', () => {
    expect(isIpInCidr('10.10.10.5', '10.10.10.5/32')).toBe(true);
    expect(isIpInCidr('10.10.10.6', '10.10.10.5/32')).toBe(false);
  });

  it('handles boundary IPs', () => {
    expect(isIpInCidr('10.10.10.0', '10.10.10.0/24')).toBe(true);   // network addr
    expect(isIpInCidr('10.10.10.255', '10.10.10.0/24')).toBe(true); // broadcast
    expect(isIpInCidr('10.10.9.255', '10.10.10.0/24')).toBe(false);
    expect(isIpInCidr('10.10.11.0', '10.10.10.0/24')).toBe(false);
  });
});

describe('isIpInScope', () => {
  const cidrs = ['10.10.10.0/24', '192.168.1.0/24'];
  const exclusions = ['10.10.10.254', '192.168.1.0/28'];

  it('returns true for IP in scope CIDR', () => {
    expect(isIpInScope('10.10.10.5', cidrs, exclusions)).toBe(true);
  });

  it('returns false for IP not in any CIDR', () => {
    expect(isIpInScope('172.16.0.1', cidrs, exclusions)).toBe(false);
  });

  it('returns false for excluded single IP', () => {
    expect(isIpInScope('10.10.10.254', cidrs, exclusions)).toBe(false);
  });

  it('returns false for IP in excluded CIDR range', () => {
    expect(isIpInScope('192.168.1.5', cidrs, exclusions)).toBe(false);
  });

  it('returns true for IP in scope CIDR but outside excluded sub-range', () => {
    expect(isIpInScope('192.168.1.20', cidrs, exclusions)).toBe(true);
  });

  it('returns true with empty CIDRs when IP is not excluded', () => {
    expect(isIpInScope('10.10.10.5', [], [])).toBe(true);
  });

  it('still honors exclusions when CIDRs are empty', () => {
    expect(isIpInScope('10.10.10.5', [], ['10.10.10.5'])).toBe(false);
  });

  it('returns true with empty exclusions', () => {
    expect(isIpInScope('10.10.10.5', cidrs, [])).toBe(true);
  });
});

describe('isHostnameInScope', () => {
  const domains = ['test.local', 'corp.example.com'];
  const exclusions = ['bad.test.local', '10.10.10.14'];

  it('returns true for hostname matching a scope domain', () => {
    expect(isHostnameInScope('dc01.test.local', domains, exclusions)).toBe(true);
  });

  it('returns true for exact domain match', () => {
    expect(isHostnameInScope('test.local', domains, exclusions)).toBe(true);
  });

  it('returns true for subdomain of scope domain', () => {
    expect(isHostnameInScope('web.corp.example.com', domains, exclusions)).toBe(true);
  });

  it('returns false for hostname not matching any scope domain', () => {
    expect(isHostnameInScope('dc01.other.local', domains, exclusions)).toBe(false);
  });

  it('returns false for excluded hostname (exact match)', () => {
    expect(isHostnameInScope('bad.test.local', domains, exclusions)).toBe(false);
  });

  it('returns false for subdomain of excluded hostname', () => {
    expect(isHostnameInScope('sub.bad.test.local', domains, exclusions)).toBe(false);
  });

  it('is case-insensitive', () => {
    expect(isHostnameInScope('DC01.TEST.LOCAL', domains, exclusions)).toBe(true);
    expect(isHostnameInScope('BAD.TEST.LOCAL', domains, exclusions)).toBe(false);
  });

  it('returns true when no domains configured (cannot determine)', () => {
    expect(isHostnameInScope('anything.random.com', [], [])).toBe(true);
  });

  it('ignores CIDR exclusions (only hostname matching)', () => {
    expect(isHostnameInScope('dc01.test.local', domains, ['10.0.0.0/8'])).toBe(true);
  });
});

describe('expandCidrDetailed', () => {
  it('returns non-truncated result for /24', () => {
    const result = expandCidrDetailed('10.10.10.0/24');
    expect(result.truncated).toBe(false);
    expect(result.ips.length).toBe(254);
    expect(result.total_hosts).toBeUndefined();
  });

  it('returns truncated result with total_hosts for /16', () => {
    const result = expandCidrDetailed('10.0.0.0/16');
    expect(result.truncated).toBe(true);
    expect(result.ips.length).toBe(4094);
    expect(result.total_hosts).toBe(65534);
    expect(result.ips[0]).toBe('10.0.0.1');
  });

  it('returns non-truncated single IP for /32', () => {
    const result = expandCidrDetailed('10.10.10.5/32');
    expect(result).toEqual({ ips: ['10.10.10.5'], truncated: false });
  });

  it('returns non-truncated single IP for bare address', () => {
    const result = expandCidrDetailed('192.168.1.1');
    expect(result).toEqual({ ips: ['192.168.1.1'], truncated: false });
  });

  it('returns non-truncated single IP for invalid mask', () => {
    const result = expandCidrDetailed('10.0.0.1/33');
    expect(result).toEqual({ ips: ['10.0.0.1'], truncated: false });
  });
});

describe('isValidCidr', () => {
  it('accepts valid CIDR notation', () => {
    expect(isValidCidr('10.10.10.0/24')).toBe(true);
    expect(isValidCidr('172.16.1.0/24')).toBe(true);
    expect(isValidCidr('192.168.1.1/32')).toBe(true);
  });

  it('accepts bare IP (no mask)', () => {
    expect(isValidCidr('10.10.10.1')).toBe(true);
  });

  it('rejects non-IP strings', () => {
    expect(isValidCidr('not-a-cidr')).toBe(false);
    expect(isValidCidr('')).toBe(false);
    expect(isValidCidr('10.10.10')).toBe(false);
  });

  it('rejects out-of-range octets', () => {
    expect(isValidCidr('256.1.1.1/24')).toBe(false);
    expect(isValidCidr('10.10.10.300')).toBe(false);
  });

  it('rejects out-of-range mask', () => {
    expect(isValidCidr('10.10.10.0/33')).toBe(false);
  });
});

describe('inferCidrFromIps', () => {
  it('groups IPs into /24 CIDRs', () => {
    const result = inferCidrFromIps(['172.16.1.5', '172.16.1.10', '172.16.2.1']);
    expect(result).toEqual(['172.16.1.0/24', '172.16.2.0/24']);
  });

  it('returns empty for empty input', () => {
    expect(inferCidrFromIps([])).toEqual([]);
  });

  it('deduplicates IPs in the same subnet', () => {
    const result = inferCidrFromIps(['10.0.0.1', '10.0.0.1', '10.0.0.2']);
    expect(result).toEqual(['10.0.0.0/24']);
  });

  it('sorts output by prefix', () => {
    const result = inferCidrFromIps(['192.168.1.1', '10.0.0.1', '172.16.0.1']);
    expect(result).toEqual(['10.0.0.0/24', '172.16.0.0/24', '192.168.1.0/24']);
  });
});
