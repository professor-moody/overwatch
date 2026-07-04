import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

vi.mock('../_process-runner.js', () => ({
  MAX_TIMEOUT_MS: 4 * 60 * 60 * 1000,
  runInstrumentedProcess: vi.fn(async (_engine, opts) => ({
    content: [{ type: 'text', text: JSON.stringify(opts, null, 2) }],
  })),
}));

import { registerTestWebappCredentialTool } from '../test-webapp-credential.js';
import { runInstrumentedProcess } from '../_process-runner.js';

function buildHandlers(credential: Record<string, unknown> | null) {
  const handlers: Record<string, (args: any) => Promise<any>> = {};
  const fakeServer = {
    registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
      handlers[name] = handler;
    },
  } as unknown as McpServer;
  const engine = {
    getNode: vi.fn((id: string) => (credential && id === credential.id ? credential : null)),
    getStateFilePath: vi.fn(() => '/tmp/ow-test-state/state.json'),
  };
  registerTestWebappCredentialTool(fakeServer, engine as any);
  return { handlers, engine };
}

const usableCred = (extra: Record<string, unknown> = {}) => ({
  id: 'cred-1',
  type: 'credential',
  label: 'web login',
  cred_user: 'admin',
  cred_value: 'p@ss word',
  cred_material_kind: 'plaintext_password',
  cred_usable_for_auth: true,
  ...extra,
});

function lastOpts() {
  const mock = vi.mocked(runInstrumentedProcess);
  return mock.mock.calls[mock.mock.calls.length - 1][1];
}

describe('test_webapp_credential tool', () => {
  beforeEach(() => vi.clearAllMocks());

  it('form: POSTs username/password to the resolved login endpoint, redacting the secret', async () => {
    const { handlers } = buildHandlers(usableCred());
    await handlers.test_webapp_credential({
      credential_id: 'cred-1',
      target_url: 'https://app.acme.com',
      method: 'form',
      login_path: '/login',
    });
    const opts = lastOpts();
    expect(opts.binary).toBe('curl');
    expect(opts.technique).toBe('web_credential_test');
    expect(opts.parse_with).toBe('test_webapp_credential');
    expect(opts.validate).toBe(true);
    // Raw argv is withheld from the persisted log + response.
    expect(opts.redact_args_in_log).toBe(true);
    // scope is enforced on the actual request URL (the login endpoint).
    expect(opts.target_url).toBe('https://app.acme.com/login');
    expect(opts.args).toContain('-X');
    expect(opts.args).toContain('POST');
    // Body carries url-encoded creds.
    expect(opts.args.some((a: string) => a.includes('username=admin') && a.includes('password='))).toBe(true);
    // Neither the raw nor the url-encoded secret leaks into command_repr.
    expect(opts.command_repr).not.toContain('p@ss word');
    expect(opts.command_repr).not.toContain('p%40ss%20word');
    expect(opts.command_repr).toContain('redacted secret');
    // Parser gets the request URL (attribution) + a per-call status nonce.
    const pc = opts.parser_context as any;
    expect(pc.request_url).toBe('https://app.acme.com/login');
    expect(typeof pc.status_nonce).toBe('string');
    expect(pc.status_nonce.length).toBeGreaterThanOrEqual(8);
    // The -w marker carries the nonce so the status can't be spoofed.
    expect(opts.args.some((a: string) => a.includes(`OWSTATUS:%{http_code}:${pc.status_nonce}`))).toBe(true);
  });

  it('hands the runner the reflected-secret scrub list (raw + url-encoded) so captured output is redacted centrally', async () => {
    const { handlers } = buildHandlers(usableCred({ cred_value: 'p@ss word' }));
    await handlers.test_webapp_credential({ credential_id: 'cred-1', target_url: 'https://app.acme.com', method: 'form', login_path: '/login', success: { redirect_contains: '/dashboard' } });
    const opts = lastOpts();
    expect(opts.redact_secrets).toContain('p@ss word');
    expect(opts.redact_secrets).toContain('p%40ss%20word'); // url-encoded form-body reflection
  });

  it('derives curl --max-time from timeout_ms and gives the runner kill-timeout +5s headroom', async () => {
    const { handlers } = buildHandlers(usableCred({ cred_value: 'tok-abc-1234', cred_material_kind: 'token' }));
    await handlers.test_webapp_credential({ credential_id: 'cred-1', target_url: 'https://api.acme.com', method: 'bearer', timeout_ms: 3000 });
    const opts = lastOpts();
    const i = opts.args.indexOf('--max-time');
    expect(opts.args[i + 1]).toBe('3');
    expect(opts.timeout_ms).toBe(8000);
  });

  it('defaults curl --max-time to 20 and leaves the runner timeout unset when timeout_ms is omitted', async () => {
    const { handlers } = buildHandlers(usableCred({ cred_value: 'tok-abc-1234', cred_material_kind: 'token' }));
    await handlers.test_webapp_credential({ credential_id: 'cred-1', target_url: 'https://api.acme.com', method: 'bearer' });
    const opts = lastOpts();
    const i = opts.args.indexOf('--max-time');
    expect(opts.args[i + 1]).toBe('20');
    expect(opts.timeout_ms).toBeUndefined();
  });

  it('clamps the runner timeout (timeout_ms + 5s) to the runner ceiling', async () => {
    const MAX = 4 * 60 * 60 * 1000; // mirrors the mocked MAX_TIMEOUT_MS
    const { handlers } = buildHandlers(usableCred({ cred_value: 'tok-abc-1234', cred_material_kind: 'token' }));
    await handlers.test_webapp_credential({ credential_id: 'cred-1', target_url: 'https://api.acme.com', method: 'bearer', timeout_ms: MAX });
    expect(lastOpts().timeout_ms).toBe(MAX);
  });

  it('a very short secret does not over-redact unrelated tokens in command_repr', async () => {
    const { handlers } = buildHandlers(usableCred({ cred_value: 'a', cred_material_kind: 'token' }));
    await handlers.test_webapp_credential({ credential_id: 'cred-1', target_url: 'https://api.acme.com', method: 'bearer' });
    const opts = lastOpts();
    expect(opts.command_repr).toContain('--max-time');
    expect(opts.command_repr).toContain('https://api.acme.com');
    expect(opts.command_repr).toContain('redacted secret');
  });

  it('basic: uses -u user:secret and redacts it', async () => {
    const { handlers } = buildHandlers(usableCred({ cred_value: 'hunter2' }));
    await handlers.test_webapp_credential({ credential_id: 'cred-1', target_url: 'https://app.acme.com/private', method: 'basic' });
    const opts = lastOpts();
    expect(opts.args).toContain('-u');
    expect(opts.args).toContain('admin:hunter2');
    expect(opts.command_repr).not.toContain('hunter2');
  });

  it('bearer: default Authorization header; header_name sends a raw custom header', async () => {
    const { handlers } = buildHandlers(usableCred({ cred_value: 'tok-abc', cred_material_kind: 'token' }));
    await handlers.test_webapp_credential({ credential_id: 'cred-1', target_url: 'https://api.acme.com', method: 'bearer' });
    expect(lastOpts().args).toContain('Authorization: Bearer tok-abc');

    await handlers.test_webapp_credential({ credential_id: 'cred-1', target_url: 'https://api.acme.com', method: 'bearer', header_name: 'X-API-Key' });
    const opts = lastOpts();
    expect(opts.args).toContain('X-API-Key: tok-abc');
    expect(opts.command_repr).not.toContain('tok-abc');
  });

  it('cookie: replays Cookie header with the configured cookie name', async () => {
    const { handlers } = buildHandlers(usableCred({ cred_value: 'PHPSESSID-xyz', cred_material_kind: 'session_cookie' }));
    await handlers.test_webapp_credential({ credential_id: 'cred-1', target_url: 'https://app.acme.com', method: 'cookie', header_name: 'PHPSESSID' });
    const opts = lastOpts();
    expect(opts.args).toContain('-b');
    expect(opts.args).toContain('PHPSESSID=PHPSESSID-xyz');
    expect(opts.command_repr).not.toContain('PHPSESSID-xyz');
  });

  it('rejects a credential that is not usable for auth', async () => {
    const { handlers } = buildHandlers(usableCred({ credential_status: 'expired' }));
    const res = await handlers.test_webapp_credential({ credential_id: 'cred-1', target_url: 'https://app.acme.com', method: 'bearer' });
    expect(res.isError).toBe(true);
    expect(runInstrumentedProcess).not.toHaveBeenCalled();
  });

  it('rejects a credential with no cred_value', async () => {
    const { handlers } = buildHandlers({ id: 'cred-1', type: 'credential', cred_usable_for_auth: true });
    const res = await handlers.test_webapp_credential({ credential_id: 'cred-1', target_url: 'https://app.acme.com', method: 'bearer' });
    expect(res.isError).toBe(true);
    expect(runInstrumentedProcess).not.toHaveBeenCalled();
  });

  it('rejects form/basic auth when the credential has no username', async () => {
    const { handlers } = buildHandlers({ id: 'cred-1', type: 'credential', cred_value: 'x', cred_usable_for_auth: true });
    const res = await handlers.test_webapp_credential({ credential_id: 'cred-1', target_url: 'https://app.acme.com', method: 'form' });
    expect(res.isError).toBe(true);
    expect(runInstrumentedProcess).not.toHaveBeenCalled();
  });

  it('returns an error for an unknown credential', async () => {
    const { handlers } = buildHandlers(null);
    const res = await handlers.test_webapp_credential({ credential_id: 'nope', target_url: 'https://app.acme.com', method: 'bearer' });
    expect(res.isError).toBe(true);
  });

  it('session_jar_id adds curl -c/-b <jar> so the login persists its session', async () => {
    const { handlers } = buildHandlers(usableCred());
    await handlers.test_webapp_credential({
      credential_id: 'cred-1', target_url: 'https://app.acme.com', method: 'form', login_path: '/login',
      success: { redirect_contains: '/dashboard' }, session_jar_id: 'sess-1',
    });
    const opts = lastOpts();
    const jar = '/tmp/ow-test-state/session-jars/sess-1.jar';
    // -c saves Set-Cookie, -b replays saved cookies; the path is in both the
    // real argv and the redacted repr (it isn't a secret).
    expect(opts.args).toContain('-c');
    expect(opts.args).toContain('-b');
    expect(opts.args).toContain(jar);
    expect(opts.command_repr).toContain(jar);
  });

  it('cookie method with a jar gets -c (save) but NOT a second -b (would shadow the tested cookie)', async () => {
    const { handlers } = buildHandlers(usableCred({ cred_material_kind: 'session_cookie' }));
    await handlers.test_webapp_credential({
      credential_id: 'cred-1', target_url: 'https://app.acme.com', method: 'cookie',
      success: { status: 200 }, session_jar_id: 'sess-1',
    });
    const opts = lastOpts();
    const jar = '/tmp/ow-test-state/session-jars/sess-1.jar';
    expect(opts.args).toContain('-c');
    expect(opts.args).toContain(jar); // -c <jar> present
    // The only -b value is the tested cookie (name=value), never the jar path.
    const bIdxs = opts.args.reduce((acc: number[], a: string, i: number) => (a === '-b' ? [...acc, i] : acc), []);
    for (const i of bIdxs) expect(opts.args[i + 1]).not.toBe(jar);
  });

  it('surfaces the jar PATH (not the cookie) in the response so an auth crawl can target it', async () => {
    const { handlers } = buildHandlers(usableCred());
    const res = await handlers.test_webapp_credential({
      credential_id: 'cred-1', target_url: 'https://app.acme.com', method: 'form', login_path: '/login',
      success: { redirect_contains: '/dashboard' }, session_jar_id: 'sess-1',
    });
    const jar = '/tmp/ow-test-state/session-jars/sess-1.jar';
    // The handoff note the tool appends (the mock echoes opts separately; the
    // real runner redacts those args — covered by the redact_secrets test).
    const handoff = res.content.find((c: { text: string }) => c.text.includes('--load-cookies'));
    expect(handoff).toBeDefined();
    expect(handoff!.text).toContain(jar);        // path surfaced for the crawl handoff
    expect(handoff!.text).toContain('parse_output');
    expect(handoff!.text).not.toContain('p@ss word'); // the note never carries the secret
  });

  it('does NOT append the handoff note when the run errored (isError:true)', async () => {
    const { handlers } = buildHandlers(usableCred());
    vi.mocked(runInstrumentedProcess).mockResolvedValueOnce({ content: [{ type: 'text', text: 'boom' }], isError: true });
    const res = await handlers.test_webapp_credential({
      credential_id: 'cred-1', target_url: 'https://app.acme.com', method: 'form', login_path: '/login',
      success: { redirect_contains: '/dashboard' }, session_jar_id: 'sess-1',
    });
    expect(res.content.some((c: { text: string }) => c.text.includes('--load-cookies'))).toBe(false);
  });

  it('omitting session_jar_id spawns no cookie-jar args and adds no handoff note', async () => {
    const { handlers } = buildHandlers(usableCred());
    const res = await handlers.test_webapp_credential({ credential_id: 'cred-1', target_url: 'https://app.acme.com', method: 'bearer' });
    const opts = lastOpts();
    expect(opts.args).not.toContain('-c');
    expect(opts.args.some((a: string) => a.includes('session-jars'))).toBe(false);
    expect(res.content.map((c: { text: string }) => c.text).join('\n')).not.toContain('session-jars');
  });

  it('rejects an unsafe session_jar_id before spawning (path-traversal guard), flagged isError', async () => {
    const { handlers } = buildHandlers(usableCred());
    const res = await handlers.test_webapp_credential({
      credential_id: 'cred-1', target_url: 'https://app.acme.com', method: 'bearer', session_jar_id: '../../etc/evil',
    });
    expect(res.isError).toBe(true);
    expect(res.content[0].text).toContain('Invalid session_jar_id');
    // No spawn happened.
    expect(vi.mocked(runInstrumentedProcess)).not.toHaveBeenCalled();
  });
});
