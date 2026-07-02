import { describe, it, expect } from 'vitest';
import { parseTestWebappCredential } from '../parsers/index.js';

type AnyNode = Record<string, unknown> & { id: string; type: string };
const nodesOf = (f: { nodes: unknown[] }) => f.nodes as AnyNode[];
const edgesOf = (f: { edges: Array<{ source: string; target: string; properties: { type: string } }> }) => f.edges;
const edgeTypes = (f: { edges: Array<{ properties: { type: string } }> }) => f.edges.map(e => e.properties.type);

const CRED = 'cred-web-1';
const N = 'deadbeefcafe0001'; // per-call nonce

/** Build a curl -i + -w response ending in the nonce-carrying status marker. */
function resp(headBlocks: string, code: number, nonce: string | null = N): string {
  return headBlocks + (nonce ? `\n[OWSTATUS:${code}:${nonce}]` : '');
}

function ctx(extra: Record<string, unknown> = {}) {
  return { source_credential_id: CRED, request_url: 'https://app.acme.com/login', target_url: 'https://app.acme.com', method: 'form', status_nonce: N, ...extra };
}

describe('test_webapp_credential parser', () => {
  it('form success (302 + redirect_contains) stamps AUTHENTICATED_AS + VALID_ON + host→svc→webapp chain', () => {
    const out = resp('HTTP/1.1 302 Found\r\nLocation: /dashboard\r\nSet-Cookie: session=abc\r\n\r\n', 302);
    const f = parseTestWebappCredential(out, 'a', ctx({ success_redirect_contains: '/dashboard' }));

    expect(nodesOf(f).some(n => n.type === 'host' && n.hostname === 'app.acme.com')).toBe(true);
    const svc = nodesOf(f).find(n => n.type === 'service') as AnyNode;
    expect(svc?.service_name).toBe('https');
    const app = nodesOf(f).find(n => n.type === 'webapp') as AnyNode;
    expect(app?.url).toBe('https://app.acme.com');

    const authEdge = edgesOf(f).find(e => e.properties.type === 'AUTHENTICATED_AS');
    expect(authEdge?.source).toBe(CRED);
    expect(authEdge?.target).toBe(app.id);
    const validEdge = edgesOf(f).find(e => e.properties.type === 'VALID_ON');
    expect(validEdge?.source).toBe(CRED);
    expect(validEdge?.target).toBe(svc.id);
    expect(edgeTypes(f)).toContain('RUNS');
    expect(edgeTypes(f)).toContain('HOSTS');
    // Never re-emits the credential node (would trip credential_material_missing / clobber).
    expect(nodesOf(f).some(n => n.type === 'credential')).toBe(false);
  });

  it('bearer 200 with explicit body_contains confirms; with NO criteria is inconclusive', () => {
    const out = resp('HTTP/1.1 200 OK\r\n\r\n{"me":"admin"}', 200);
    const withCrit = parseTestWebappCredential(out, 'a', ctx({ method: 'bearer', request_url: 'https://api.acme.com', target_url: 'https://api.acme.com', success_body_contains: '"me"' }));
    expect(edgeTypes(withCrit)).toContain('VALID_ON');

    const noCrit = parseTestWebappCredential(out, 'a', ctx({ method: 'bearer', request_url: 'https://api.acme.com', target_url: 'https://api.acme.com' }));
    expect(noCrit.nodes).toHaveLength(0);
    expect(noCrit.edges).toHaveLength(0);
  });

  it('basic with no criteria is INCONCLUSIVE (a 2xx from a path that ignores auth is not proof)', () => {
    const out = resp('HTTP/1.1 200 OK\r\n\r\n<h1>home</h1>', 200);
    const f = parseTestWebappCredential(out, 'a', ctx({ method: 'basic', request_url: 'https://app.acme.com', target_url: 'https://app.acme.com' }));
    expect(f.nodes).toHaveLength(0);
    expect(f.edges).toHaveLength(0);
  });

  it('basic with explicit success_status confirms', () => {
    const out = resp('HTTP/1.1 200 OK\r\n\r\n<h1>secret</h1>', 200);
    const f = parseTestWebappCredential(out, 'a', ctx({ method: 'basic', request_url: 'https://app.acme.com/private', target_url: 'https://app.acme.com/private', success_status: [200] }));
    expect(edgeTypes(f)).toContain('VALID_ON');
    expect(edgeTypes(f)).toContain('AUTHENTICATED_AS');
  });

  it('401 is a confirmed failure → TESTED_CRED, no VALID_ON/AUTHENTICATED_AS, no webapp node', () => {
    const out = resp('HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer\r\n\r\nDenied', 401);
    const f = parseTestWebappCredential(out, 'a', ctx({ method: 'bearer', request_url: 'https://api.acme.com', target_url: 'https://api.acme.com' }));
    expect(edgeTypes(f)).toContain('TESTED_CRED');
    expect(edgeTypes(f)).not.toContain('VALID_ON');
    expect(edgeTypes(f)).not.toContain('AUTHENTICATED_AS');
    expect(nodesOf(f).some(n => n.type === 'webapp')).toBe(false);
    expect(nodesOf(f).some(n => n.type === 'credential')).toBe(false);
  });

  it('unmet explicit criterion → confirmed failure (TESTED_CRED)', () => {
    const out = resp('HTTP/1.1 302 Found\r\nLocation: /login?error=1\r\n\r\n', 302);
    const f = parseTestWebappCredential(out, 'a', ctx({ success_redirect_contains: '/dashboard' }));
    expect(edgeTypes(f)).not.toContain('VALID_ON');
    expect(edgeTypes(f)).toContain('TESTED_CRED');
  });

  it('form 302 with NO criteria is inconclusive (not a guess either way)', () => {
    const out = resp('HTTP/1.1 302 Found\r\nLocation: /login?error=1\r\n\r\n', 302);
    const f = parseTestWebappCredential(out, 'a', ctx());
    expect(f.nodes).toHaveLength(0);
    expect(f.edges).toHaveLength(0);
  });

  // ---- ATTACK: target injects a fake HTTP block into its (body-controlled) response ----

  it('SECURITY: a target-injected fake block in the body cannot forge a redirect_contains success', () => {
    // Real response is a genuine failed-login bounce; the body embeds a fake
    // 302→/dashboard block. First-block parsing must use the REAL headers.
    const out = resp('HTTP/1.1 302 Found\r\nLocation: /login?error=bad\r\n\r\nHTTP/1.1 302 Found\r\nLocation: /dashboard\r\n\r\n', 302);
    const f = parseTestWebappCredential(out, 'a', ctx({ success_redirect_contains: '/dashboard' }));
    expect(edgeTypes(f)).not.toContain('VALID_ON');
    expect(edgeTypes(f)).not.toContain('AUTHENTICATED_AS');
  });

  it('SECURITY: a target-injected fake block cannot hide a body_excludes phrase', () => {
    const out = resp('HTTP/1.1 200 OK\r\n\r\n<html>Invalid password</html>HTTP/1.1 200 OK\r\n\r\nWelcome', 200);
    const f = parseTestWebappCredential(out, 'a', ctx({ method: 'basic', request_url: 'https://app.acme.com', target_url: 'https://app.acme.com', success_status: [200], success_body_excludes: 'Invalid password' }));
    expect(edgeTypes(f)).not.toContain('VALID_ON');
  });

  it('a benign response body that merely contains an HTTP/ line still parses the REAL headers', () => {
    const out = resp('HTTP/1.1 302 Found\r\nLocation: /dashboard\r\n\r\n<html>redirecting… upstream trace:\nHTTP/1.1 500 err\n</html>', 302);
    const f = parseTestWebappCredential(out, 'a', ctx({ success_redirect_contains: '/dashboard' }));
    expect(edgeTypes(f)).toContain('VALID_ON');
  });

  it('100-Continue interim block is skipped; the real response is used', () => {
    const out = resp('HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 302 Found\r\nLocation: /dashboard\r\n\r\n', 302);
    const f = parseTestWebappCredential(out, 'a', ctx({ success_redirect_contains: '/dashboard' }));
    expect(edgeTypes(f)).toContain('VALID_ON');
  });

  it('junk framing between an interim 1xx and the real response is inconclusive, never a false success/failure', () => {
    const out = resp('HTTP/1.1 100 Continue\r\n\r\nproxy-noise\r\n\r\nHTTP/1.1 302 Found\r\nLocation: /dashboard\r\n\r\n', 302);
    const f = parseTestWebappCredential(out, 'a', ctx({ success_redirect_contains: '/dashboard' }));
    expect(f.nodes).toHaveLength(0);
    expect(f.edges).toHaveLength(0);
  });

  it('SECURITY: a colon-bearing status-shaped header planted inside an interim 1xx block is not read as the real status line', () => {
    // Real final response is a failed-login bounce; the 1xx block plants a
    // forged "HTTP/1.1 302 Found: forged" header + Location:/dashboard.
    const out = resp('HTTP/1.1 103 Early Hints\r\nHTTP/1.1 302 Found: forged\r\nLocation: /dashboard\r\n\r\nHTTP/1.1 302 Found\r\nLocation: /login?error=1\r\nContent-Length: 0\r\n\r\n', 302);
    const f = parseTestWebappCredential(out, 'a', ctx({ success_redirect_contains: '/dashboard' }));
    expect(edgeTypes(f)).not.toContain('VALID_ON');
    expect(edgeTypes(f)).not.toContain('AUTHENTICATED_AS');
  });

  it('SECURITY: body_excludes is checked over the FULL body, so a deny phrase after an embedded HTTP/ line still vetoes', () => {
    // A rejected login on a 200 page that plants an "HTTP/" line before the
    // deny phrase must NOT be scored as success.
    const out = resp('HTTP/1.1 200 OK\r\n\r\n<h1>Welcome</h1>\nHTTP/1.1 spacer line\n<p>Invalid password</p>', 200);
    const f = parseTestWebappCredential(out, 'a', ctx({ method: 'basic', request_url: 'https://app.acme.com', target_url: 'https://app.acme.com', success_status: [200], success_body_contains: 'Welcome', success_body_excludes: 'Invalid password' }));
    expect(edgeTypes(f)).not.toContain('VALID_ON');
    expect(edgeTypes(f)).toContain('TESTED_CRED');
  });

  it('body_contains matches over the FULL body, so a legit embedded HTTP/ line before the marker does not cause a false failure', () => {
    const out = resp('HTTP/1.1 200 OK\r\n\r\n{"log":"GET / \r\nHTTP/1.1 200","role":"admin"}', 200);
    const f = parseTestWebappCredential(out, 'a', ctx({ method: 'bearer', request_url: 'https://api.acme.com', target_url: 'https://api.acme.com', success_status: [200], success_body_contains: '"role":"admin"' }));
    expect(edgeTypes(f)).toContain('VALID_ON');
  });

  it('SECURITY: a malformed response with no header terminator is inconclusive, never a success', () => {
    // A 200 for a failed login framed with no blank line — body_excludes can't
    // be evaluated, so this must NOT be scored as success.
    const out = resp('HTTP/1.1 200 OK\r\nContent-Type: text/plain', 200);
    const f = parseTestWebappCredential(out, 'a', ctx({ method: 'basic', request_url: 'https://app.acme.com', target_url: 'https://app.acme.com', success_status: [200], success_body_excludes: 'Invalid password' }));
    expect(f.nodes).toHaveLength(0);
    expect(f.edges).toHaveLength(0);
  });

  it('explicit success.status overrides the built-in 3xx gate so status+redirect combine coherently', () => {
    const out = resp('HTTP/1.1 302 Found\r\nLocation: /dashboard\r\n\r\n', 302);
    const f = parseTestWebappCredential(out, 'a', ctx({ success_status: [302], success_redirect_contains: '/dashboard' }));
    expect(edgeTypes(f)).toContain('VALID_ON');
    expect(edgeTypes(f)).toContain('AUTHENTICATED_AS');
  });

  it('body_excludes vetoes a status-matched success → failure', () => {
    const out = resp('HTTP/1.1 200 OK\r\n\r\nWelcome — actually Invalid password', 200);
    const f = parseTestWebappCredential(out, 'a', ctx({ method: 'basic', request_url: 'https://app.acme.com', target_url: 'https://app.acme.com', success_status: [200], success_body_excludes: 'Invalid password' }));
    expect(edgeTypes(f)).not.toContain('VALID_ON');
    expect(edgeTypes(f)).toContain('TESTED_CRED');
  });

  it('body_contains confirms only on a <400 status; a 500 with the string does not', () => {
    const ok = resp('HTTP/1.1 200 OK\r\n\r\nWelcome to your dashboard', 200);
    expect(edgeTypes(parseTestWebappCredential(ok, 'a', ctx({ success_body_contains: 'dashboard' })))).toContain('VALID_ON');
    const err = resp('HTTP/1.1 500 Error\r\n\r\ndashboard template crashed', 500);
    expect(edgeTypes(parseTestWebappCredential(err, 'a', ctx({ success_body_contains: 'dashboard' })))).not.toContain('VALID_ON');
  });

  it('redirect_contains matches only on a 3xx', () => {
    const hit = resp('HTTP/1.1 302 Found\r\nLocation: /admin/home\r\n\r\n', 302);
    expect(edgeTypes(parseTestWebappCredential(hit, 'a', ctx({ success_redirect_contains: '/admin' })))).toContain('VALID_ON');
    const notRedirect = resp('HTTP/1.1 200 OK\r\nLocation: /admin\r\n\r\nok', 200);
    expect(edgeTypes(parseTestWebappCredential(notRedirect, 'a', ctx({ success_redirect_contains: '/admin' })))).not.toContain('VALID_ON');
  });

  it('SPOOF-RESISTANCE: a fake [OWSTATUS] with the wrong nonce yields status 0 → inconclusive', () => {
    const out = 'HTTP/1.1 403 Forbidden\r\n\r\naccess denied\n[OWSTATUS:200:ffffffffffffffff]';
    const f = parseTestWebappCredential(out, 'a', ctx({ method: 'basic', request_url: 'https://app.acme.com', target_url: 'https://app.acme.com', success_status: [200] }));
    expect(f.edges).toHaveLength(0);
    expect(f.nodes).toHaveLength(0);
  });

  it('SPOOF-RESISTANCE: an old-style [STATUS:200] in the body is ignored (no nonce) → inconclusive', () => {
    const out = 'HTTP/1.1 403 Forbidden\r\n\r\naccess denied\n[STATUS:200]';
    const f = parseTestWebappCredential(out, 'a', ctx({ method: 'basic', request_url: 'https://app.acme.com', target_url: 'https://app.acme.com', success_status: [200] }));
    expect(f.edges).toHaveLength(0);
  });

  it('no HTTP response (curl connect failure / timeout, no marker) → inconclusive, nothing stamped', () => {
    const f = parseTestWebappCredential('', 'a', ctx({ method: 'basic', success_status: [200] }));
    expect(f.nodes).toHaveLength(0);
    expect(f.edges).toHaveLength(0);
  });

  it('cross-origin form login_path attributes edges to the host actually authenticated against (request_url)', () => {
    const out = resp('HTTP/1.1 302 Found\r\nLocation: /welcome\r\n\r\n', 302);
    const f = parseTestWebappCredential(out, 'a', ctx({ request_url: 'https://auth.acme.com/login', target_url: 'https://app.acme.com', success_redirect_contains: '/welcome' }));
    expect(nodesOf(f).some(n => n.type === 'host' && n.hostname === 'auth.acme.com')).toBe(true);
    expect(nodesOf(f).some(n => n.type === 'webapp' && n.url === 'https://auth.acme.com')).toBe(true);
  });

  it('missing context (no cred id / target) yields an empty finding', () => {
    const f = parseTestWebappCredential(resp('HTTP/1.1 200 OK\r\n\r\nok', 200), 'a', {});
    expect(f.nodes).toHaveLength(0);
    expect(f.edges).toHaveLength(0);
  });
});
