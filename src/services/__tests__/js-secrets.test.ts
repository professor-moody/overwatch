import { describe, it, expect } from 'vitest';
import { parseTrufflehog, parseSecretfinder, parseLinkfinder } from '../parsers/index.js';
import { prepareFindingForIngest } from '../finding-validation.js';

type AnyNode = Record<string, unknown> & { id: string; type: string };
const nodesOf = (f: { nodes: unknown[] }) => f.nodes as AnyNode[];
const edgeTypes = (f: { edges: Array<{ properties: { type: string } }> }) => f.edges.map(e => e.properties.type);
const CTX = { source_host: 'https://app.acme.com/static/bundle.js' } as any;

/** Every edge endpoint must be a node in the finding (no dangling → ingest-safe). */
function assertNoDangling(f: { nodes: AnyNode[]; edges: Array<{ source: string; target: string }> }) {
  const ids = new Set(f.nodes.map(n => n.id));
  for (const e of f.edges) {
    expect(ids.has(e.source)).toBe(true);
    expect(ids.has(e.target)).toBe(true);
  }
  expect(prepareFindingForIngest(f as any, () => null).errors).toEqual([]);
}

describe('js-secrets: trufflehog', () => {
  it('a verified secret → usable credential + information-disclosure vuln + VULNERABLE_TO + EXPLOITS', () => {
    const out = JSON.stringify({ DetectorName: 'AWS', Verified: true, Raw: 'AKIAEXAMPLE12345', Redacted: 'AKIA****', SourceMetadata: { Data: { Filesystem: { file: '/bundle.js' } } } });
    const f = parseTrufflehog(out, 'a', CTX);
    const cred = nodesOf(f).find(n => n.type === 'credential') as AnyNode;
    expect(cred?.cred_value).toBe('AKIAEXAMPLE12345');
    expect(cred?.cred_material_kind).toBe('token');
    expect(cred?.cred_evidence_kind).toBe('dump');
    expect(cred?.cred_usable_for_auth).toBe(true);
    expect(nodesOf(f).some(n => n.type === 'vulnerability' && n.vuln_type === 'hardcoded_secret')).toBe(true);
    expect(nodesOf(f).some(n => n.type === 'webapp' && n.url === 'https://app.acme.com')).toBe(true);
    expect(edgeTypes(f)).toContain('VULNERABLE_TO');
    expect(edgeTypes(f)).toContain('EXPLOITS');
    assertNoDangling(f);
  });

  it('an unverified secret is NOT usable-for-auth and lower confidence', () => {
    const out = JSON.stringify({ DetectorName: 'Generic', Verified: false, Raw: 'maybe-a-secret-xyz' });
    const f = parseTrufflehog(out, 'a', CTX);
    const cred = nodesOf(f).find(n => n.type === 'credential') as AnyNode;
    expect(cred?.cred_usable_for_auth).toBe(false);
    expect(cred?.confidence).toBe(0.6);
    assertNoDangling(f);
  });

  it('github detector maps to a pat material kind', () => {
    const out = JSON.stringify({ DetectorName: 'Github', Verified: true, Raw: 'ghp_exampletoken' });
    const f = parseTrufflehog(out, 'a', CTX);
    expect((nodesOf(f).find(n => n.type === 'credential') as AnyNode)?.cred_material_kind).toBe('pat');
  });

  it('without a source webapp (no context) emits a standalone credential, no vuln/webapp — still ingest-safe', () => {
    const out = JSON.stringify({ DetectorName: 'AWS', Verified: true, Raw: 'AKIAEXAMPLE12345' });
    const f = parseTrufflehog(out, 'a');
    const cred = nodesOf(f).find(n => n.type === 'credential') as AnyNode;
    expect(cred?.cred_usable_for_auth).toBe(true);
    expect(cred?.cred_material_kind).toBe('token'); // material present → no credential_material_missing
    expect(nodesOf(f).some(n => n.type === 'webapp' || n.type === 'vulnerability')).toBe(false);
    expect(f.edges).toHaveLength(0);
    assertNoDangling(f);
  });

  it('a Redacted-only record (no Raw/RawV2) does NOT create a credential with a masked value', () => {
    const out = JSON.stringify({ DetectorName: 'AWS', Verified: false, Raw: '', Redacted: 'AKIA****WXYZ' });
    const f = parseTrufflehog(out, 'a', CTX);
    expect(nodesOf(f).some(n => n.type === 'credential')).toBe(false);
  });

  it('an SSH / private-key detector maps to the ssh_key material kind', () => {
    const out = JSON.stringify({ DetectorName: 'PrivateKey', Verified: true, Raw: '-----BEGIN RSA PRIVATE KEY-----\nabc' });
    const f = parseTrufflehog(out, 'a', CTX);
    expect((nodesOf(f).find(n => n.type === 'credential') as AnyNode)?.cred_material_kind).toBe('ssh_key');
  });

  it('a non-http source (ftp/mailto/ssh/javascript) is rejected — no fabricated webapp', () => {
    const out = JSON.stringify({ DetectorName: 'AWS', Verified: true, Raw: 'AKIA1' });
    for (const source_host of ['ftp://host/x', 'mailto:a@b.com', 'file:///etc/passwd', 'ssh://git@h/r', 'javascript:alert(1)']) {
      const f = parseTrufflehog(out, 'a', { source_host } as any);
      expect(nodesOf(f).some(n => n.type === 'webapp')).toBe(false);
    }
  });

  it('a schemeless host:port source_host is accepted (not misparsed as a scheme)', () => {
    const out = JSON.stringify({ DetectorName: 'AWS', Verified: true, Raw: 'AKIA1' });
    const f = parseTrufflehog(out, 'a', { source_host: 'app.acme.com:8080' } as any);
    expect(nodesOf(f).some(n => n.type === 'webapp' && n.url === 'https://app.acme.com:8080')).toBe(true);
    expect(edgeTypes(f)).toContain('EXPLOITS');
  });

  it('cred_type is consistent with the material kind (ssh_key / pat, not always token)', () => {
    const ssh = parseTrufflehog(JSON.stringify({ DetectorName: 'PrivateKey', Verified: true, Raw: '-----BEGIN OPENSSH PRIVATE KEY-----' }), 'a', CTX);
    expect((nodesOf(ssh).find(n => n.type === 'credential') as AnyNode)?.cred_type).toBe('ssh_key');
    const pat = parseTrufflehog(JSON.stringify({ DetectorName: 'Github', Verified: true, Raw: 'ghp_x' }), 'a', CTX);
    expect((nodesOf(pat).find(n => n.type === 'credential') as AnyNode)?.cred_type).toBe('pat');
  });

  it('the same secret seen unverified then verified upgrades BOTH the credential and its vuln', () => {
    const out = [
      JSON.stringify({ DetectorName: 'AWS', Verified: false, Raw: 'AKIA-SAME' }),
      JSON.stringify({ DetectorName: 'AWS', Verified: true, Raw: 'AKIA-SAME' }),
    ].join('\n');
    const f = parseTrufflehog(out, 'a', CTX);
    const creds = nodesOf(f).filter(n => n.type === 'credential');
    expect(creds).toHaveLength(1);
    expect((creds[0] as AnyNode).cred_usable_for_auth).toBe(true);
    expect((creds[0] as AnyNode).confidence).toBe(0.95);
    // The exploiting vulnerability is upgraded too (not left exploitable:false).
    expect((nodesOf(f).find(n => n.type === 'vulnerability') as AnyNode)?.exploitable).toBe(true);
  });

  it('JSONL: parses multiple lines and tolerates a malformed line (batch survives)', () => {
    const out = [
      JSON.stringify({ DetectorName: 'AWS', Verified: true, Raw: 'AKIA1' }),
      '{ not json',
      JSON.stringify({ DetectorName: 'Slack', Verified: false, Raw: 'xoxb-2' }),
    ].join('\n');
    const f = parseTrufflehog(out, 'a', CTX);
    expect(nodesOf(f).filter(n => n.type === 'credential')).toHaveLength(2);
    assertNoDangling(f);
  });
});

describe('js-secrets: secretfinder', () => {
  it('{url, results:[{name, matches}]} → credentials attached to the url webapp', () => {
    const out = JSON.stringify({ url: 'https://app.acme.com/app.js', results: [
      { name: 'AWS Access Key', matches: ['AKIAEXAMPLE'] },
      { name: 'Google API Key', matches: ['AIzaEXAMPLE'] },
    ] });
    const f = parseSecretfinder(out, 'a');
    expect(nodesOf(f).filter(n => n.type === 'credential')).toHaveLength(2);
    expect(nodesOf(f).some(n => n.type === 'webapp' && n.url === 'https://app.acme.com')).toBe(true);
    expect(edgeTypes(f)).toContain('EXPLOITS');
    assertNoDangling(f);
  });

  it('tolerates a malformed results entry (skipped, not fatal)', () => {
    const out = JSON.stringify({ url: 'https://app.acme.com/app.js', results: [
      { name: 'AWS', matches: ['AKIA1'] },
      null,
      { garbage: true },
      { name: 'Stripe', match: 'sk_live_2' },
    ] });
    const f = parseSecretfinder(out, 'a');
    expect(nodesOf(f).filter(n => n.type === 'credential')).toHaveLength(2);
    assertNoDangling(f);
  });

  it('supports the {results:{name:[values]}} map shape', () => {
    const out = JSON.stringify({ url: 'https://app.acme.com/app.js', results: { 'JWT': ['eyJ.a.b'], 'AWS': ['AKIA1'] } });
    const f = parseSecretfinder(out, 'a');
    expect(nodesOf(f).filter(n => n.type === 'credential')).toHaveLength(2);
    assertNoDangling(f);
  });

  it('standalone (no per-record url, no context) still emits usable creds ingest-safely', () => {
    const out = JSON.stringify([{ name: 'AWS', matches: ['AKIA1'] }]);
    const f = parseSecretfinder(out, 'a');
    expect(nodesOf(f).filter(n => n.type === 'credential')).toHaveLength(1);
    expect(nodesOf(f).some(n => n.type === 'webapp')).toBe(false);
    assertNoDangling(f);
  });

  it('parses a JSON-lines stream (one {url,results} object per line)', () => {
    const out = [
      JSON.stringify({ url: 'https://app.acme.com/a.js', results: [{ name: 'AWS', matches: ['AKIA1'] }] }),
      JSON.stringify({ url: 'https://app.acme.com/b.js', results: [{ name: 'Stripe', match: 'sk_live_2' }] }),
    ].join('\n');
    const f = parseSecretfinder(out, 'a');
    expect(nodesOf(f).filter(n => n.type === 'credential')).toHaveLength(2);
    assertNoDangling(f);
  });
});

describe('js-secrets: linkfinder', () => {
  it('array of endpoint strings → api_endpoint nodes + HAS_ENDPOINT + has_api on webapp', () => {
    const out = JSON.stringify(['/api/v1/users', '/api/v1/admin', '/graphql']);
    const f = parseLinkfinder(out, 'a', CTX);
    expect(nodesOf(f).filter(n => n.type === 'api_endpoint')).toHaveLength(3);
    expect(edgeTypes(f)).toContain('HAS_ENDPOINT');
    expect((nodesOf(f).find(n => n.type === 'webapp') as AnyNode)?.has_api).toBe(true);
    expect((nodesOf(f).find(n => n.type === 'api_endpoint') as AnyNode)?.path).toBe('/api/v1/users');
    assertNoDangling(f);
  });

  it('{endpoints:[...]} wrapper and plain-text (one per line) both work', () => {
    const wrapped = parseLinkfinder(JSON.stringify({ endpoints: ['/a', '/b'] }), 'a', CTX);
    expect(nodesOf(wrapped).filter(n => n.type === 'api_endpoint')).toHaveLength(2);
    const text = parseLinkfinder('/x\n/y\n\n/z', 'a', CTX);
    expect(nodesOf(text).filter(n => n.type === 'api_endpoint')).toHaveLength(3);
    assertNoDangling(wrapped);
    assertNoDangling(text);
  });

  it('without a source webapp, endpoints are still captured (standalone, no HAS_ENDPOINT)', () => {
    const f = parseLinkfinder(JSON.stringify(['/api/x']), 'a');
    expect(nodesOf(f).filter(n => n.type === 'api_endpoint')).toHaveLength(1);
    expect(edgeTypes(f)).not.toContain('HAS_ENDPOINT');
    assertNoDangling(f);
  });

  it('skips bare "/" and empty endpoints', () => {
    const f = parseLinkfinder(JSON.stringify(['/', '', '/real']), 'a', CTX);
    expect(nodesOf(f).filter(n => n.type === 'api_endpoint')).toHaveLength(1);
  });

  it('drops off-origin absolute + protocol-relative links; keeps same-origin (reduced to a path)', () => {
    const f = parseLinkfinder(JSON.stringify([
      'https://evil.com/x',            // off-origin absolute → dropped
      '//cdn.foo/y',                   // protocol-relative → dropped
      'https://app.acme.com/api/me',   // same-origin absolute → kept as /api/me
      '/api/local',                    // relative → kept
    ]), 'a', { source_host: 'https://app.acme.com' } as any);
    const paths = nodesOf(f).filter(n => n.type === 'api_endpoint').map(n => n.path).sort();
    expect(paths).toEqual(['/api/local', '/api/me']);
    assertNoDangling(f);
  });

  it('normalizes query/fragment/trailing-slash so one endpoint is one node', () => {
    const f = parseLinkfinder(JSON.stringify(['/a', '/a/', '/a?x=1', '/a#frag']), 'a', CTX);
    const eps = nodesOf(f).filter(n => n.type === 'api_endpoint');
    expect(eps).toHaveLength(1);
    expect(eps[0].path).toBe('/a');
  });

  it('resolves dir-relative + dot-segment paths against the origin and dedups with the absolute form', () => {
    const f = parseLinkfinder(JSON.stringify(['api/v1/users', '/api/v1/users', './x', '../y']), 'a', CTX);
    const paths = nodesOf(f).filter(n => n.type === 'api_endpoint').map(n => n.path).sort();
    expect(paths).toEqual(['/api/v1/users', '/x', '/y']); // 'api/v1/users' collapses with '/api/v1/users'
    assertNoDangling(f);
  });

  it('keeps a same-host link whose scheme differs from the source webapp (http link on an https app)', () => {
    const f = parseLinkfinder(JSON.stringify(['http://app.acme.com/insecure', '//app.acme.com/rel']), 'a', { source_host: 'https://app.acme.com' } as any);
    const paths = nodesOf(f).filter(n => n.type === 'api_endpoint').map(n => n.path).sort();
    expect(paths).toEqual(['/insecure', '/rel']);
  });

  it('keeps a same-host link across a port-representation difference (default port vs explicit)', () => {
    const f = parseLinkfinder(JSON.stringify(['https://app.acme.com/api']), 'a', { source_host: 'https://app.acme.com:8443' } as any);
    expect(nodesOf(f).some(n => n.type === 'api_endpoint' && n.path === '/api')).toBe(true);
  });

  it('collapses internal duplicate slashes so /api//users == /api/users', () => {
    const f = parseLinkfinder(JSON.stringify(['/api//users', '/api/users']), 'a', CTX);
    const eps = nodesOf(f).filter(n => n.type === 'api_endpoint');
    expect(eps).toHaveLength(1);
    expect(eps[0].path).toBe('/api/users');
  });

  it('a single {link} JSON object is handled structurally (not fed to the text parser)', () => {
    const f = parseLinkfinder(JSON.stringify({ link: '/api/single', method: 'get' }), 'a', CTX);
    const ep = nodesOf(f).find(n => n.type === 'api_endpoint') as AnyNode;
    expect(ep?.path).toBe('/api/single');
    expect(ep?.method).toBe('GET');
  });

  it('a lone quoted JSON string endpoint is captured', () => {
    const f = parseLinkfinder('"/api/lone"', 'a', CTX);
    expect(nodesOf(f).some(n => n.type === 'api_endpoint' && n.path === '/api/lone')).toBe(true);
  });

  it('preserves an embedded absolute URL in a proxy-style path (keeps ://) while dedup still collapses typos', () => {
    const f = parseLinkfinder(JSON.stringify(['/proxy/https://internal.acme.com/admin', '/a//b']), 'a', CTX);
    const paths = nodesOf(f).filter(n => n.type === 'api_endpoint').map(n => n.path).sort();
    expect(paths).toContain('/proxy/https://internal.acme.com/admin');
    expect(paths).toContain('/a/b');
  });
});
