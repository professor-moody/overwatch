import { describe, it, expect } from 'vitest';
import { parseGowitness } from '../parsers/index.js';
import { prepareFindingForIngest } from '../finding-validation.js';

type AnyNode = Record<string, unknown> & { id: string; type: string };
const nodesOf = (f: { nodes: unknown[] }) => f.nodes as AnyNode[];
const webapps = (f: { nodes: unknown[] }) => nodesOf(f).filter(n => n.type === 'webapp');
const webappFor = (f: { nodes: unknown[] }, url: string) => webapps(f).find(n => n.url === url) as AnyNode | undefined;
const edgeTypes = (f: { edges: Array<{ properties: { type: string } }> }) => f.edges.map(e => e.properties.type);

function assertNoDangling(f: { nodes: AnyNode[]; edges: Array<{ source: string; target: string }> }) {
  const ids = new Set(f.nodes.map(n => n.id));
  for (const e of f.edges) { expect(ids.has(e.source)).toBe(true); expect(ids.has(e.target)).toBe(true); }
  expect(prepareFindingForIngest(f as any, () => null).errors).toEqual([]);
}

describe('gowitness: v3 JSON-lines (real schema)', () => {
  // Real gowitness v3 keys: url, final_url, response_code, title, file_name,
  // failed, technologies:[{value}].
  const jsonl = [
    JSON.stringify({ url: 'https://app.acme.com', response_code: 200, title: 'Login', file_name: 'https-app-acme-com.png', technologies: [{ value: 'nginx' }, { value: 'react' }] }),
    JSON.stringify({ url: 'https://api.acme.com', response_code: 403, title: 'Forbidden', file_name: 'https-api-acme-com.png', technologies: ['express'] }),
  ].join('\n');

  it('reads file_name → screenshot_path, plus title/status/tech + host→service→webapp chain', () => {
    const f = parseGowitness(jsonl, 'a');
    expect(webapps(f)).toHaveLength(2);
    const app = webappFor(f, 'https://app.acme.com')!;
    expect(app.title).toBe('Login');
    expect(app.http_status).toBe(200);
    expect(app.technology).toBe('nginx, react');
    expect(app.screenshot_path).toBe('https-app-acme-com.png');
    expect(edgeTypes(f)).toEqual(expect.arrayContaining(['RUNS', 'HOSTS']));
    expect(nodesOf(f).some(n => n.type === 'host' && n.hostname === 'app.acme.com')).toBe(true);
    expect(nodesOf(f).some(n => n.type === 'service' && n.service_name === 'https')).toBe(true);
    assertNoDangling(f);
  });

  it('skips a failed:true capture (no webapp/host/service for an unreachable URL)', () => {
    const withFailed = jsonl + '\n' + JSON.stringify({ url: 'https://dead.acme.com', failed: true, failed_reason: 'timeout', response_code: 0 });
    const f = parseGowitness(withFailed, 'a');
    expect(webappFor(f, 'https://dead.acme.com')).toBeUndefined();
    expect(webapps(f)).toHaveLength(2);
  });

  it('response_code 0 (no-response sentinel) does not become http_status:0', () => {
    const f = parseGowitness(JSON.stringify({ url: 'https://x.acme.com', response_code: 0, file_name: 'x.png' }), 'a');
    expect(webappFor(f, 'https://x.acme.com')!.http_status).toBeUndefined();
  });
});

describe('gowitness: cross-origin redirect keys on the SCANNED origin', () => {
  it('keys the webapp on url (converges with httpx), records final_url as a property', () => {
    const f = parseGowitness(JSON.stringify({ url: 'http://old.acme.com', final_url: 'https://new.acme.com', response_code: 200, file_name: 's.png' }), 'a');
    // Node keyed on the scanned origin, NOT the redirect target.
    const wa = webappFor(f, 'http://old.acme.com')!;
    expect(wa).toBeDefined();
    expect(wa.final_url).toBe('https://new.acme.com');
    expect(webappFor(f, 'https://new.acme.com')).toBeUndefined();
    // Backing host is the scanned host.
    expect(nodesOf(f).some(n => n.type === 'host' && n.hostname === 'old.acme.com')).toBe(true);
    assertNoDangling(f);
  });
});

describe('gowitness: v2 capitalized fields', () => {
  it('handles {URL, ResponseCode, Title, Filename}', () => {
    const arr = JSON.stringify([
      { URL: 'https://legacy.acme.com', ResponseCode: 200, Title: 'Legacy', Filename: 'legacy.png' },
    ]);
    const f = parseGowitness(arr, 'a');
    const wa = webappFor(f, 'https://legacy.acme.com')!;
    expect(wa.http_status).toBe(200);
    expect(wa.screenshot_path).toBe('legacy.png');
    expect(wa.title).toBe('Legacy');
    assertNoDangling(f);
  });
});

describe('gowitness: aquatone session.json (status line)', () => {
  const session = JSON.stringify({
    pages: {
      'page-1': { url: 'https://a.acme.com', hostname: 'a.acme.com', status: '200 OK', pageTitle: 'A', screenshotPath: 'screenshots/a.png' },
      'page-2': { url: 'https://b.acme.com', hostname: 'b.acme.com', status: '500 Internal Server Error', pageTitle: 'B', screenshotPath: 'screenshots/b.png' },
    },
  });

  it('reads the pages{} map and parses the leading code from a full status line', () => {
    const f = parseGowitness(session, 'a');
    expect(webapps(f)).toHaveLength(2);
    const a = webappFor(f, 'https://a.acme.com')!;
    expect(a.title).toBe('A');
    expect(a.screenshot_path).toBe('screenshots/a.png');
    expect(a.http_status).toBe(200); // from "200 OK"
    expect(webappFor(f, 'https://b.acme.com')!.http_status).toBe(500); // from "500 Internal Server Error"
    assertNoDangling(f);
  });
});

describe('gowitness: robustness', () => {
  it('an entry with no URL is skipped; a malformed line is not fatal', () => {
    const mixed = [
      '{ this is not json',
      JSON.stringify({ title: 'no url here', file_name: 'x.png' }),
      JSON.stringify({ url: 'https://ok.acme.com', file_name: 'ok.png' }),
    ].join('\n');
    const f = parseGowitness(mixed, 'a');
    expect(webapps(f)).toHaveLength(1);
    expect(webappFor(f, 'https://ok.acme.com')!.screenshot_path).toBe('ok.png');
    assertNoDangling(f);
  });

  it('missing optional fields → webapp still emitted, sparse', () => {
    const f = parseGowitness(JSON.stringify({ url: 'https://bare.acme.com' }), 'a');
    const wa = webappFor(f, 'https://bare.acme.com')!;
    expect(wa.screenshot_path).toBeUndefined();
    expect(wa.title).toBeUndefined();
    expect(wa.http_status).toBeUndefined();
    expect(wa.label).toBe('https://bare.acme.com');
  });

  it('multiple paths on one host merge (fill-if-missing) rather than dropping the richer record', () => {
    const dupes = [
      JSON.stringify({ url: 'https://app.acme.com/redirect', file_name: 'r.png' }),          // sparse: no title/status
      JSON.stringify({ url: 'https://app.acme.com/login', title: 'Login', response_code: 200, file_name: 'l.png' }),
    ].join('\n');
    const f = parseGowitness(dupes, 'a');
    expect(webapps(f)).toHaveLength(1); // origin collapsed
    const wa = webappFor(f, 'https://app.acme.com')!;
    expect(wa.title).toBe('Login');       // filled from the later record
    expect(wa.http_status).toBe(200);     // filled from the later record
    expect(wa.screenshot_path).toBe('r.png'); // first capture's screenshot kept
  });

  it('empty / whitespace output → empty finding', () => {
    expect(nodesOf(parseGowitness('', 'a'))).toHaveLength(0);
    expect(nodesOf(parseGowitness('   \n ', 'a'))).toHaveLength(0);
  });

  it('http vs https of the same host are distinct origins', () => {
    const f = parseGowitness([
      JSON.stringify({ url: 'http://app.acme.com', file_name: 'h.png' }),
      JSON.stringify({ url: 'https://app.acme.com', file_name: 's.png' }),
    ].join('\n'), 'a');
    expect(webapps(f)).toHaveLength(2);
  });
});
