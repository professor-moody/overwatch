import { describe, it, expect } from 'vitest';
import { expandCidr, isIpInCidr, isIpInScope } from '../cidr.js';

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

  it('caps expansion for subnets larger than /20', () => {
    const ips = expandCidr('10.0.0.0/16');
    // Should return just the base address, not 65534 hosts
    expect(ips).toEqual(['10.0.0.0']);
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

  it('returns false with empty CIDRs', () => {
    expect(isIpInScope('10.10.10.5', [], [])).toBe(false);
  });

  it('returns true with empty exclusions', () => {
    expect(isIpInScope('10.10.10.5', cidrs, [])).toBe(true);
  });
});
