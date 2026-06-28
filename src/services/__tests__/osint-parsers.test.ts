import { describe, it, expect } from 'vitest';
import { parseCrtSh, parseSubfinder, parseWhois } from '../parsers/index.js';

type AnyNode = Record<string, unknown> & { id: string; type: string };
const n = (f: { nodes: unknown[] }) => f.nodes as AnyNode[];

describe('OSINT parsers (Phase 2C)', () => {
  it('crt.sh JSON → subdomain nodes + SUBDOMAIN_OF edges (wildcard + apex handled)', () => {
    const out = JSON.stringify([
      { name_value: 'api.example.com\n*.example.com', common_name: 'www.example.com' },
      { name_value: 'example.com' }, // apex — not a subdomain
    ]);
    const f = parseCrtSh(out, 'agent');
    const subs = n(f).filter(x => x.type === 'subdomain').map(x => x.subdomain_name).sort();
    expect(subs).toEqual(['api.example.com', 'www.example.com']); // wildcard dropped, apex excluded
    expect(n(f).some(x => x.type === 'domain' && x.domain_name === 'example.com')).toBe(true);
    const api = n(f).find(x => x.subdomain_name === 'api.example.com')!;
    expect(f.edges.some(e => e.source === api.id && e.properties.type === 'SUBDOMAIN_OF')).toBe(true);
  });

  it('crt.sh non-JSON input → empty finding (no crash)', () => {
    const f = parseCrtSh('<html>rate limited</html>', 'agent');
    expect(f.nodes).toEqual([]);
    expect(f.edges).toEqual([]);
  });

  it('subfinder plaintext and JSON-lines → subdomains', () => {
    const plain = parseSubfinder('api.example.com\nwww.example.com\n\n', 'agent');
    expect(n(plain).filter(x => x.type === 'subdomain')).toHaveLength(2);
    const jsonl = parseSubfinder('{"host":"mail.example.com","source":"crtsh"}', 'agent');
    expect(n(jsonl).some(x => x.subdomain_name === 'mail.example.com')).toBe(true);
  });

  it('domain whois → organization OWNS_ASSET domain', () => {
    const f = parseWhois('Domain Name: example.com\nRegistrant Organization: Acme Corp\n', 'agent');
    const org = n(f).find(x => x.type === 'organization') as AnyNode;
    expect(org?.org_name).toBe('Acme Corp');
    expect(n(f).some(x => x.type === 'domain' && x.domain_name === 'example.com')).toBe(true);
    expect(f.edges.some(e => e.properties.type === 'OWNS_ASSET' && e.source === org.id)).toBe(true);
  });

  it('IP whois → asn (number + cidr) OWNS_ASSET from org', () => {
    const f = parseWhois('OrgName: Acme Networks\nCIDR: 1.2.3.0/24\nOriginAS: AS13335\n', 'agent');
    const asn = n(f).find(x => x.type === 'asn') as AnyNode;
    expect(asn).toBeTruthy();
    expect(asn.id).toBe('asn-13335');
    expect(asn.asn_number).toBe(13335);
    expect(asn.cidr_ranges).toEqual(['1.2.3.0/24']);
    const org = n(f).find(x => x.type === 'organization') as AnyNode;
    expect(f.edges.some(e => e.properties.type === 'OWNS_ASSET' && e.source === org.id && e.target === asn.id)).toBe(true);
  });
});
