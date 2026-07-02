import { describe, it, expect } from 'vitest';
import { parseAmass, parseDnsx, parseHttpx, parseTheHarvester } from '../parsers/index.js';

type AnyNode = Record<string, unknown> & { id: string; type: string };
const nodesOf = (f: { nodes: unknown[] }) => f.nodes as AnyNode[];
const edgeTypes = (f: { edges: Array<{ properties: { type: string } }> }) => f.edges.map(e => e.properties.type);

describe('OSINT parsers — phase 2C-2', () => {
  it('amass JSONL → subdomain + host (RESOLVES_TO) + asn (IN_NETBLOCK)', () => {
    const out = JSON.stringify({ name: 'api.example.com', domain: 'example.com', addresses: [{ ip: '1.2.3.4', cidr: '1.2.3.0/24', asn: 13335, desc: 'ACME' }] });
    const f = parseAmass(out, 'a');
    expect(nodesOf(f).some(n => n.type === 'subdomain' && n.subdomain_name === 'api.example.com')).toBe(true);
    const host = nodesOf(f).find(n => n.type === 'host') as AnyNode;
    expect(host?.ip).toBe('1.2.3.4');
    const asn = nodesOf(f).find(n => n.type === 'asn') as AnyNode;
    expect(asn?.asn_number).toBe(13335);
    expect(asn?.cidr_ranges).toEqual(['1.2.3.0/24']);
    expect(asn?.asn_org).toBe('ACME');
    expect(edgeTypes(f).sort()).toEqual(['IN_NETBLOCK', 'RESOLVES_TO', 'SUBDOMAIN_OF']);
  });

  it('amass accumulates multiple CIDRs onto one asn node', () => {
    const out = JSON.stringify({ name: 'a.example.com', domain: 'example.com', addresses: [
      { ip: '1.2.3.4', cidr: '1.2.3.0/24', asn: 13335 },
      { ip: '5.6.7.8', cidr: '5.6.7.0/24', asn: 13335 },
    ] });
    const f = parseAmass(out, 'a');
    const asns = nodesOf(f).filter(n => n.type === 'asn');
    expect(asns).toHaveLength(1);
    expect((asns[0] as AnyNode).cidr_ranges).toEqual(['1.2.3.0/24', '5.6.7.0/24']);
  });

  it('amass tolerates null/non-object address elements (no crash, batch survives)', () => {
    const out = [
      JSON.stringify({ name: 'ok.example.com', domain: 'example.com', addresses: [{ ip: '1.1.1.1' }] }),
      JSON.stringify({ name: 'bad.example.com', domain: 'example.com', addresses: [null, 'x', 42] }),
    ].join('\n');
    const f = parseAmass(out, 'a');
    // The valid record still lands despite the malformed one in the same batch.
    expect(nodesOf(f).some(n => n.type === 'subdomain' && n.subdomain_name === 'ok.example.com')).toBe(true);
    expect(nodesOf(f).some(n => n.type === 'host' && n.ip === '1.1.1.1')).toBe(true);
  });

  it('dnsx JSONL → subdomain resolves to its A/AAAA hosts; IP-literal host skipped', () => {
    const out = '{"host":"mail.example.com","a":["1.1.1.1"],"aaaa":["2606:4700::1"]}';
    const f = parseDnsx(out, 'a');
    expect(nodesOf(f).filter(n => n.type === 'host')).toHaveLength(2);
    expect(edgeTypes(f).filter(t => t === 'RESOLVES_TO')).toHaveLength(2);
    expect(edgeTypes(f)).toContain('SUBDOMAIN_OF');
    // Reverse-PTR mode puts an IP in `host` — must NOT become a bogus subdomain.
    const ptr = parseDnsx('{"host":"1.2.3.4","a":["1.2.3.4"]}', 'a');
    expect(nodesOf(ptr).some(n => n.type === 'subdomain')).toBe(false);
  });

  it('httpx JSONL → origin-level webapp node with merged tech + status', () => {
    const out = '{"url":"https://api.example.com","status_code":200,"title":"API","tech":["php"],"webserver":"nginx"}';
    const f = parseHttpx(out, 'a');
    const app = nodesOf(f).find(n => n.type === 'webapp') as AnyNode;
    expect(app?.url).toBe('https://api.example.com');
    expect(app?.technology).toBe('php, nginx');
    expect(app?.http_status).toBe(200);
    expect(String(app.id).startsWith('webapp-')).toBe(true);

    // Now also models the backing host → RUNS → service(https) → HOSTS → webapp,
    // so the discovered web target participates in scope + credential coverage.
    const svc = nodesOf(f).find(n => n.type === 'service') as AnyNode;
    expect(svc?.service_name).toBe('https');
    expect(svc?.port).toBe(443);
    const host = nodesOf(f).find(n => n.type === 'host') as AnyNode;
    expect(host?.hostname).toBe('api.example.com');
    const edges = (f as { edges: Array<{ properties: { type: string } }> }).edges;
    expect(edges.some(e => e.properties.type === 'RUNS')).toBe(true);
    expect(edges.some(e => e.properties.type === 'HOSTS')).toBe(true);
  });

  it('theHarvester JSON → email nodes + harvested subdomains (ip suffix + IP-literal stripped)', () => {
    const out = JSON.stringify({ emails: ['jane@example.com', 'bad-entry'], hosts: ['vpn.example.com:9.9.9.9', 'www.example.com', '8.8.8.8'] });
    const f = parseTheHarvester(out, 'a');
    expect(nodesOf(f).filter(n => n.type === 'email')).toHaveLength(1);
    expect(nodesOf(f).some(n => n.type === 'email' && n.email_address === 'jane@example.com')).toBe(true);
    expect(nodesOf(f).some(n => n.type === 'subdomain' && n.subdomain_name === 'vpn.example.com')).toBe(true);
    expect(nodesOf(f).filter(n => n.type === 'subdomain')).toHaveLength(2); // IP 8.8.8.8 excluded
  });

  it('theHarvester tolerates the bare JSON null literal (no crash)', () => {
    const f = parseTheHarvester('null', 'a');
    expect(f.nodes).toEqual([]);
    expect(f.edges).toEqual([]);
  });
});
