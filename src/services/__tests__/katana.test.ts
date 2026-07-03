import { describe, it, expect } from 'vitest';
import { parseKatana } from '../parsers/index.js';
import { prepareFindingForIngest } from '../finding-validation.js';

type AnyNode = Record<string, unknown> & { id: string; type: string };
const nodesOf = (f: { nodes: unknown[] }) => f.nodes as AnyNode[];
const eps = (f: { nodes: unknown[] }) => nodesOf(f).filter(n => n.type === 'api_endpoint');
const webapps = (f: { nodes: unknown[] }) => nodesOf(f).filter(n => n.type === 'webapp');
const ep = (f: { nodes: unknown[] }, path: string) => eps(f).find(n => n.path === path) as AnyNode | undefined;
const edgeTypes = (f: { edges: Array<{ properties: { type: string } }> }) => f.edges.map(e => e.properties.type);

function assertNoDangling(f: { nodes: AnyNode[]; edges: Array<{ source: string; target: string }> }) {
  const ids = new Set(f.nodes.map(n => n.id));
  for (const e of f.edges) { expect(ids.has(e.source)).toBe(true); expect(ids.has(e.target)).toBe(true); }
  expect(prepareFindingForIngest(f as any, () => null).errors).toEqual([]);
}

describe('katana: -jsonl', () => {
  const jsonl = [
    JSON.stringify({ timestamp: 't', request: { method: 'GET', endpoint: 'https://app.acme.com/dashboard' }, response: { status_code: 200 } }),
    JSON.stringify({ timestamp: 't', request: { method: 'POST', endpoint: 'https://app.acme.com/api/users?page=1' }, response: { status_code: 403 } }),
  ].join('\n');

  it('emits api_endpoint per crawled URL (method + http_status) + HAS_ENDPOINT + has_api', () => {
    const f = parseKatana(jsonl, 'a');
    expect(webapps(f)).toHaveLength(1);
    expect(webapps(f)[0].url).toBe('https://app.acme.com');
    expect((webapps(f)[0] as AnyNode).has_api).toBe(true);
    const dash = ep(f, '/dashboard')!;
    expect(dash.method).toBe('GET');
    expect(dash.http_status).toBe(200);
    // query stripped
    const users = ep(f, '/api/users')!;
    expect(users.method).toBe('POST');
    expect(users.http_status).toBe(403);
    expect(edgeTypes(f).every(t => t === 'HAS_ENDPOINT')).toBe(true);
    assertNoDangling(f);
  });
});

describe('katana: plain URL list (hakrawler / gau)', () => {
  it('same-site subdomains kept; off-site trackers/CDNs dropped', () => {
    const list = [
      'https://app.acme.com/login',
      'https://app.acme.com/admin/panel',
      'https://api.acme.com/v1/health',              // same eTLD+1 (acme.com) → kept
      'https://www.googletagmanager.com/gtm.js',      // off-site tracker → dropped
      'https://fonts.googleapis.com/css2',            // off-site CDN → dropped
      'not a url',                                    // skipped
      'ftp://app.acme.com/x',                          // non-http → skipped
    ].join('\n');
    const f = parseKatana(list, 'a', { source_host: 'https://app.acme.com' } as any);
    expect(webapps(f).map(w => w.url).sort()).toEqual(['https://api.acme.com', 'https://app.acme.com']);
    expect(ep(f, '/login')).toBeDefined();
    expect(ep(f, '/admin/panel')).toBeDefined();
    expect(ep(f, '/v1/health')).toBeDefined();
    expect(ep(f, '/gtm.js')).toBeUndefined();
    expect(ep(f, '/css2')).toBeUndefined();
    assertNoDangling(f);
  });

  it('with no source_host, the FIRST URL sets the site anchor', () => {
    const f = parseKatana([
      'https://app.acme.com/a',
      'https://evil-tracker.com/b', // different eTLD+1 than the first → dropped
    ].join('\n'), 'a');
    expect(webapps(f)).toHaveLength(1);
    expect(webapps(f)[0].url).toBe('https://app.acme.com');
  });
});

describe('katana: robustness', () => {
  it('collapses query/fragment + trailing slash to one endpoint per path', () => {
    const f = parseKatana([
      'https://app.acme.com/search?q=a',
      'https://app.acme.com/search?q=b',
      'https://app.acme.com/search/',
      'https://app.acme.com/search#frag',
    ].join('\n'), 'a');
    expect(eps(f)).toHaveLength(1);
    expect(ep(f, '/search')).toBeDefined();
  });

  it('a malformed JSONL line is skipped, not fatal', () => {
    const f = parseKatana([
      '{ not valid json',
      JSON.stringify({ request: { endpoint: 'https://app.acme.com/ok' } }),
    ].join('\n'), 'a');
    expect(ep(f, '/ok')).toBeDefined();
    assertNoDangling(f);
  });

  it('katana JSONL with a bad status_code (0) omits http_status', () => {
    const f = parseKatana(JSON.stringify({ request: { endpoint: 'https://app.acme.com/x' }, response: { status_code: 0 } }), 'a');
    expect(ep(f, '/x')!.http_status).toBeUndefined();
  });

  it('root path normalizes to /', () => {
    const f = parseKatana('https://app.acme.com/', 'a');
    expect(ep(f, '/')).toBeDefined();
  });

  it('empty / whitespace output → empty finding', () => {
    expect(nodesOf(parseKatana('', 'a'))).toHaveLength(0);
    expect(nodesOf(parseKatana('  \n ', 'a'))).toHaveLength(0);
  });

  it('bounds a pathological dump at MAX_ENDPOINTS (5000) with no dangling edge or stray webapp', () => {
    const lines: string[] = [];
    for (let i = 0; i < 5000; i++) lines.push(`https://app.acme.com/p${i}`);
    // A fresh same-site origin arriving AFTER the cap is saturated must NOT leave
    // a bare webapp node (cap is checked before webapp materialization).
    lines.push('https://late.acme.com/only');
    const f = parseKatana(lines.join('\n'), 'a', { source_host: 'https://app.acme.com' } as any);
    expect(eps(f).length).toBe(5000);
    expect(webapps(f).map(w => w.url)).toEqual(['https://app.acme.com']); // no stray late.acme.com webapp
    assertNoDangling(f);
  });
});
