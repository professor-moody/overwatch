import { describe, it, expect } from 'vitest';
import { parseSecurityHeaders } from '../parsers/index.js';
import { prepareFindingForIngest } from '../finding-validation.js';
import { classifyFinding, VULN_TYPE_TO_CWE, CWE_TO_OWASP, CWE_TO_NIST } from '../finding-classifier.js';
import type { ReportFinding } from '../report-generator.js';
import type { ExportedGraph, NodeProperties } from '../../types.js';

type AnyNode = Record<string, unknown> & { id: string; type: string };
const nodesOf = (f: { nodes: unknown[] }) => f.nodes as AnyNode[];
const vulns = (f: { nodes: unknown[] }) => nodesOf(f).filter(n => n.type === 'vulnerability');
const vulnOf = (f: { nodes: unknown[] }, t: string) => vulns(f).find(n => n.vuln_type === t) as AnyNode | undefined;
const edgeTypes = (f: { edges: Array<{ properties: { type: string } }> }) => f.edges.map(e => e.properties.type);

function assertNoDangling(f: { nodes: AnyNode[]; edges: Array<{ source: string; target: string }> }) {
  const ids = new Set(f.nodes.map(n => n.id));
  for (const e of f.edges) { expect(ids.has(e.source)).toBe(true); expect(ids.has(e.target)).toBe(true); }
  expect(prepareFindingForIngest(f as any, () => null).errors).toEqual([]);
}

const ctx = (h: string) => ({ source_host: h } as any);

describe('security-headers: raw curl -I text', () => {
  it('flags missing baseline headers on an https target (HSTS included)', () => {
    const raw = [
      'HTTP/1.1 200 OK',
      'Server: nginx',
      'Content-Type: text/html',
    ].join('\n');
    const f = parseSecurityHeaders(raw, 'a', ctx('https://app.acme.com'));
    const v = vulnOf(f, 'missing_security_header')!;
    expect(v).toBeDefined();
    const missing = v.missing_security_headers as string[];
    expect(missing).toEqual(expect.arrayContaining([
      'Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy',
    ]));
    expect(v.exploitable).toBe(false);
    expect(nodesOf(f).some(n => n.type === 'webapp' && n.url === 'https://app.acme.com')).toBe(true);
    expect(edgeTypes(f)).toContain('VULNERABLE_TO');
    assertNoDangling(f);
  });

  it('does not flag HSTS on a plain http target', () => {
    const raw = 'HTTP/1.1 200 OK\nContent-Security-Policy: default-src \'self\'\nX-Frame-Options: DENY\nX-Content-Type-Options: nosniff\nReferrer-Policy: no-referrer';
    const f = parseSecurityHeaders(raw, 'a', ctx('http://app.acme.com'));
    // everything present except HSTS, which is http-inapplicable → fully clean → no nodes
    expect(vulns(f)).toHaveLength(0);
    expect(nodesOf(f)).toHaveLength(0);
  });

  it('takes the FINAL response block across a redirect chain', () => {
    const raw = [
      'HTTP/1.1 301 Moved Permanently',
      'Location: https://app.acme.com/',
      '',
      'HTTP/1.1 200 OK',
      'Strict-Transport-Security: max-age=63072000',
      'Content-Security-Policy: default-src \'self\'',
      'X-Frame-Options: DENY',
      'X-Content-Type-Options: nosniff',
      'Referrer-Policy: no-referrer',
    ].join('\n');
    const f = parseSecurityHeaders(raw, 'a', ctx('https://app.acme.com'));
    expect(vulns(f)).toHaveLength(0); // final block is fully hardened
  });

  it('a CSP frame-ancestors directive satisfies X-Frame-Options', () => {
    const raw = 'HTTP/1.1 200 OK\nStrict-Transport-Security: max-age=1\nContent-Security-Policy: frame-ancestors \'none\'\nX-Content-Type-Options: nosniff\nReferrer-Policy: origin';
    const f = parseSecurityHeaders(raw, 'a', ctx('https://app.acme.com'));
    expect(vulns(f)).toHaveLength(0); // XFO absent but frame-ancestors covers it
  });

  it('raw text with no source_host yields nothing (no webapp to key)', () => {
    const f = parseSecurityHeaders('HTTP/1.1 200 OK\nServer: nginx', 'a');
    expect(nodesOf(f)).toHaveLength(0);
  });

  it('final response wins: headers on a 301 but NOT the final 200 are flagged missing', () => {
    // The 301 is fully hardened; the final 200 carries none. The final page is
    // unprotected, so every baseline header must be reported missing.
    const raw = [
      'HTTP/1.1 301 Moved Permanently',
      'Strict-Transport-Security: max-age=63072000',
      'Content-Security-Policy: default-src \'self\'',
      'X-Frame-Options: DENY',
      'X-Content-Type-Options: nosniff',
      'Referrer-Policy: no-referrer',
      'Location: /home',
      '',
      'HTTP/1.1 200 OK',
      'Content-Type: text/html',
    ].join('\n');
    const f = parseSecurityHeaders(raw, 'a', ctx('https://app.acme.com'));
    const missing = vulnOf(f, 'missing_security_header')!.missing_security_headers as string[];
    expect(missing).toEqual(expect.arrayContaining([
      'Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy',
    ]));
  });

  it('an obs-folded CSP frame-ancestors still exempts X-Frame-Options', () => {
    const raw = [
      'HTTP/1.1 200 OK',
      'Content-Security-Policy: default-src \'self\';',
      '\tframe-ancestors \'none\'',
      'Strict-Transport-Security: max-age=1',
      'X-Content-Type-Options: nosniff',
      'Referrer-Policy: origin',
    ].join('\n');
    const f = parseSecurityHeaders(raw, 'a', ctx('https://app.acme.com'));
    expect(vulns(f)).toHaveLength(0); // XFO absent but folded frame-ancestors covers it
  });
});

describe('security-headers: present-but-ineffective values', () => {
  const base = (extra: Record<string, string>) => JSON.stringify({
    url: 'https://app.acme.com',
    headers: { 'Strict-Transport-Security': 'max-age=1', 'Content-Security-Policy': 'default-src \'self\'', 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'origin', ...extra },
  });

  it('an empty header value counts as missing', () => {
    const f = parseSecurityHeaders(base({ 'X-Frame-Options': '', 'Content-Security-Policy': '  ' }), 'a');
    const missing = vulnOf(f, 'missing_security_header')!.missing_security_headers as string[];
    expect(missing).toEqual(expect.arrayContaining(['X-Frame-Options', 'Content-Security-Policy']));
  });

  it('X-Content-Type-Options must be exactly nosniff', () => {
    const f = parseSecurityHeaders(base({ 'X-Content-Type-Options': 'sniff' }), 'a');
    expect((vulnOf(f, 'missing_security_header')!.missing_security_headers as string[])).toContain('X-Content-Type-Options');
  });

  it('X-Frame-Options ALLOWALL is not effective', () => {
    const f = parseSecurityHeaders(base({ 'X-Frame-Options': 'ALLOWALL' }), 'a');
    expect((vulnOf(f, 'missing_security_header')!.missing_security_headers as string[])).toContain('X-Frame-Options');
  });

  it('a permissive CSP frame-ancestors * does NOT exempt X-Frame-Options', () => {
    const f = parseSecurityHeaders(JSON.stringify({
      url: 'https://app.acme.com',
      headers: { 'Strict-Transport-Security': 'max-age=1', 'Content-Security-Policy': 'default-src \'self\'; frame-ancestors *', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'origin' },
    }), 'a');
    expect((vulnOf(f, 'missing_security_header')!.missing_security_headers as string[])).toContain('X-Frame-Options');
  });

  it('a look-alike CSP directive (frame-ancestorsX) does NOT exempt X-Frame-Options', () => {
    const f = parseSecurityHeaders(JSON.stringify({
      url: 'https://app.acme.com',
      headers: { 'Strict-Transport-Security': 'max-age=1', 'Content-Security-Policy': "frame-ancestorsX 'none'", 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'origin' },
    }), 'a');
    expect((vulnOf(f, 'missing_security_header')!.missing_security_headers as string[])).toContain('X-Frame-Options');
  });

  it('DENY/SAMEORIGIN and a restrictive frame-ancestors are both effective', () => {
    expect(vulns(parseSecurityHeaders(base({ 'X-Frame-Options': 'SAMEORIGIN' }), 'a'))).toHaveLength(0);
    const restrictive = JSON.stringify({ url: 'https://app.acme.com', headers: { 'Strict-Transport-Security': 'max-age=1', 'Content-Security-Policy': 'frame-ancestors \'self\'', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'origin' } });
    expect(vulns(parseSecurityHeaders(restrictive, 'a'))).toHaveLength(0);
  });
});

describe('security-headers: CORS', () => {
  it('wildcard ACAO → cors_misconfig (not exploitable, cvss 4.3)', () => {
    const f = parseSecurityHeaders(JSON.stringify({ url: 'https://api.acme.com', headers: { 'Access-Control-Allow-Origin': '*' } }), 'a');
    const v = vulnOf(f, 'cors_misconfig')!;
    expect(v).toBeDefined();
    expect(v.cors_allow_origin).toBe('*');
    expect(v.cors_allow_credentials).toBe(false);
    expect(v.exploitable).toBe(false);
    expect(v.cvss).toBe(4.3);
  });

  it('wildcard + credentials → higher cvss', () => {
    const f = parseSecurityHeaders(JSON.stringify({ url: 'https://api.acme.com', headers: { 'access-control-allow-origin': '*', 'Access-Control-Allow-Credentials': 'true' } }), 'a');
    const v = vulnOf(f, 'cors_misconfig')!;
    expect(v.cors_allow_credentials).toBe(true);
    expect(v.cvss).toBe(6.1);
  });

  it('null origin → cors_misconfig (cvss 5.3)', () => {
    const f = parseSecurityHeaders(JSON.stringify({ url: 'https://api.acme.com', headers: { 'Access-Control-Allow-Origin': 'null', 'Content-Security-Policy': 'x', 'Strict-Transport-Security': 'x', 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'x' } }), 'a');
    expect(vulnOf(f, 'cors_misconfig')!.cvss).toBe(5.3);
  });

  it('a fixed trusted origin is NOT flagged', () => {
    const f = parseSecurityHeaders(JSON.stringify({ url: 'https://api.acme.com', headers: { 'Access-Control-Allow-Origin': 'https://trusted.acme.com', 'Content-Security-Policy': 'x', 'Strict-Transport-Security': 'x', 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'x' } }), 'a');
    expect(vulnOf(f, 'cors_misconfig')).toBeUndefined();
  });
});

describe('security-headers: JSON shapes', () => {
  it('array of {url, headers} → one target each', () => {
    const f = parseSecurityHeaders(JSON.stringify([
      { url: 'https://a.acme.com', headers: { 'Access-Control-Allow-Origin': '*' } },
      { url: 'https://b.acme.com', headers: { 'Access-Control-Allow-Origin': '*' } },
    ]), 'a');
    expect(vulns(f).filter(v => v.vuln_type === 'cors_misconfig')).toHaveLength(2);
    assertNoDangling(f as any);
  });

  it('httpx-style JSON-lines with a raw header string', () => {
    const lines = [
      JSON.stringify({ url: 'https://a.acme.com', raw_header: 'HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n' }),
      JSON.stringify({ url: 'https://b.acme.com', header: { 'access-control-allow-origin': 'null' } }),
    ].join('\n');
    const f = parseSecurityHeaders(lines, 'a');
    expect(vulns(f).filter(v => v.vuln_type === 'cors_misconfig')).toHaveLength(2);
  });

  it('per-target fault tolerance: a malformed element is skipped, not fatal', () => {
    const f = parseSecurityHeaders(JSON.stringify([
      null,
      'nope',
      { url: 'https://ok.acme.com', headers: { 'Access-Control-Allow-Origin': '*' } },
    ]), 'a');
    expect(vulnOf(f, 'cors_misconfig')).toBeDefined();
    assertNoDangling(f as any);
  });

  it('item url overrides source_host; falls back to source_host when absent', () => {
    const f = parseSecurityHeaders(JSON.stringify({ headers: { 'Access-Control-Allow-Origin': '*' } }), 'a', ctx('https://fallback.acme.com'));
    expect(nodesOf(f).some(n => n.type === 'webapp' && n.url === 'https://fallback.acme.com')).toBe(true);
  });

  it('empty / whitespace output → empty finding', () => {
    expect(nodesOf(parseSecurityHeaders('', 'a'))).toHaveLength(0);
    expect(nodesOf(parseSecurityHeaders('   \n  ', 'a'))).toHaveLength(0);
  });
});

describe('security-headers: classifier wiring', () => {
  // Every new CWE the parser can emit must resolve to a full framework mapping —
  // an entry in VULN_TYPE_TO_CWE whose CWE lacks OWASP/NIST rows silently drops
  // the framework attribution. Assert the concrete control values, not just
  // presence, so a wrong NIST choice is caught.
  it('cors_misconfig → CWE-942 with SC-7/AC-4 NIST controls + OWASP A05', () => {
    expect(VULN_TYPE_TO_CWE['cors_misconfig'].cwe).toBe('CWE-942');
    expect(CWE_TO_OWASP['CWE-942']).toContain('A05');
    expect(CWE_TO_NIST['CWE-942']).toEqual(['SC-7', 'AC-4']);
  });

  it('missing_security_header → CWE-16 (a real A05 member, not the discouraged CWE-693 Pillar)', () => {
    expect(VULN_TYPE_TO_CWE['missing_security_header'].cwe).toBe('CWE-16');
    expect(CWE_TO_OWASP['CWE-16']).toContain('A05');
    // CWE-693 must NOT be introduced — it is not an A05 member.
    expect(CWE_TO_OWASP['CWE-693']).toBeUndefined();
  });

  const classify = (vulnType: string) => {
    const nodes: ExportedGraph['nodes'] = [
      { id: 'v1', properties: { type: 'vulnerability', vuln_type: vulnType } as NodeProperties },
    ];
    const finding: ReportFinding = {
      id: 'f1', title: 't', severity: 'medium', category: 'vulnerability',
      description: 'd', affected_assets: ['v1'], evidence: [], remediation: 'fix', risk_score: 5,
    };
    return classifyFinding(finding, new Map(nodes.map(n => [n.id, n.properties])), { nodes, edges: [] });
  };

  it('classifyFinding maps a cors_misconfig node end-to-end → CWE-942 / A05 / T1190', () => {
    const c = classify('cors_misconfig');
    expect(c.cwe).toBe('CWE-942');
    expect(c.owasp_category).toContain('A05');
    expect(c.nist_controls).toContain('SC-7');
    expect(c.attack_techniques.some(t => t.id === 'T1190')).toBe(true);
  });

  it('classifyFinding maps a missing_security_header node end-to-end → CWE-16 / A05', () => {
    const c = classify('missing_security_header');
    expect(c.cwe).toBe('CWE-16');
    expect(c.owasp_category).toContain('A05');
    expect(c.nist_controls.length).toBeGreaterThan(0);
  });
});
