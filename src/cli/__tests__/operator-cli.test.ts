import { describe, expect, it, beforeEach } from 'vitest';
import { setColorEnabled, formatTable, truncate, keyValues } from '../operator/format.js';
import { resolveClientOptions, createClient, ApiError, type ApiClient } from '../operator/client.js';
import { READ_COMMANDS, WRITE_COMMANDS } from '../operator/commands.js';
import { renderStatus, renderApprovals, renderQueries, renderOpsec, renderFindings, renderDeploy, renderDispatch } from '../operator/render.js';

// Deterministic output: force color off for all assertions.
beforeEach(() => setColorEnabled(false));

describe('format', () => {
  it('truncate adds an ellipsis past the limit', () => {
    expect(truncate('abcdef', 4)).toBe('abc…');
    expect(truncate('abc', 4)).toBe('abc');
    expect(truncate('abc', 0)).toBe('');
  });

  it('color helpers are plain when disabled (no ANSI)', () => {
    setColorEnabled(false);
    const out = formatTable(['A', 'B'], [['x', 'y']]);
    // eslint-disable-next-line no-control-regex
    expect(/\x1b\[/.test(out)).toBe(false);
  });

  it('formatTable aligns columns and shows (none) when empty', () => {
    expect(formatTable(['A'], [])).toContain('(none)');
    const out = formatTable(['STATUS', 'ID'], [['running', 'a1'], ['pending', 'a22']]);
    const lines = out.split('\n');
    expect(lines[0]).toMatch(/^STATUS/);
    expect(lines).toHaveLength(3); // header + 2 rows
  });

  it('keyValues right-pads keys', () => {
    const out = keyValues([['a', '1'], ['bbb', '2']]);
    expect(out).toContain('a:');
    expect(out).toContain('bbb:');
  });
});

describe('client option resolution', () => {
  it('prefers --url/--token flags over env and default', () => {
    const opts = resolveClientOptions(['--url', 'http://host:9/', '--token', 'tok']);
    expect(opts.url).toBe('http://host:9'); // trailing slash stripped
    expect(opts.token).toBe('tok');
  });

  it('falls back to the loopback default with no token', () => {
    const prevUrl = process.env.OVERWATCH_URL; const prevTok = process.env.OVERWATCH_DASHBOARD_TOKEN;
    delete process.env.OVERWATCH_URL; delete process.env.OVERWATCH_DASHBOARD_TOKEN;
    const opts = resolveClientOptions([]);
    expect(opts.url).toBe('http://127.0.0.1:8384');
    expect(opts.token).toBeUndefined();
    if (prevUrl !== undefined) process.env.OVERWATCH_URL = prevUrl;
    if (prevTok !== undefined) process.env.OVERWATCH_DASHBOARD_TOKEN = prevTok;
  });

  it('sends a Bearer header only when a token is set, and never an Origin header', async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (url: string | URL, init: RequestInit) => {
      calls.push({ url: String(url), init });
      return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
    }) as typeof fetch;
    try {
      await createClient({ url: 'http://h:8384', token: 'secret123' }).get('/api/state');
      const withTok = (calls[0].init.headers ?? {}) as Record<string, string>;
      expect(withTok.Authorization).toBe('Bearer secret123');
      expect(withTok.Origin).toBeUndefined(); // CLI never sends Origin → server CSRF check is skipped
      calls.length = 0;
      await createClient({ url: 'http://h:8384' }).get('/api/state');
      expect(((calls[0].init.headers ?? {}) as Record<string, string>).Authorization).toBeUndefined();
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it('raises an unreachable ApiError when the server cannot be reached', async () => {
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async () => { throw new TypeError('fetch failed'); }) as typeof fetch;
    try {
      const err = await createClient({ url: 'http://127.0.0.1:9' }).get('/api/state').catch(e => e);
      expect(err).toBeInstanceOf(ApiError);
      expect((err as ApiError).unreachable).toBe(true);
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});

// Fake client returning canned API payloads keyed by path.
function fakeClient(map: Record<string, unknown>): ApiClient {
  return {
    get: async <T>(p: string) => map[p] as T,
    post: async <T>() => ({}) as T,
  };
}

describe('read commands', () => {
  it('frontier filters by --type and caps with --max', async () => {
    const state = { state: { frontier: [
      { id: 'f1', type: 'network_discovery', description: 'a' },
      { id: 'f2', type: 'incomplete_node', description: 'b' },
      { id: 'f3', type: 'network_discovery', description: 'c' },
    ] } };
    const client = fakeClient({ '/api/state': state });
    const filtered = await READ_COMMANDS.frontier.run({ client, args: ['--type', 'network_discovery'] });
    expect((filtered.data as unknown[]).length).toBe(2);
    const capped = await READ_COMMANDS.frontier.run({ client, args: ['--max', '1'] });
    expect((capped.data as unknown[]).length).toBe(1);
  });

  it('findings filters by --severity', async () => {
    const resp = { total: 2, severity_summary: { critical: 1, high: 1, medium: 0, low: 0, info: 0 },
      findings: [
        { id: 'a', severity: 'critical', title: 'x', risk_score: 9, affected_assets: ['h1'] },
        { id: 'b', severity: 'high', title: 'y', risk_score: 6, affected_assets: [] },
      ] };
    const client = fakeClient({ '/api/findings': resp });
    const out = await READ_COMMANDS.findings.run({ client, args: ['--severity', 'critical'] });
    expect((out.data as { findings: unknown[] }).findings.length).toBe(1);
  });

  it('approvals returns the pending array as data', async () => {
    const client = fakeClient({ '/api/actions/pending': { pending: [{ action_id: 'a1', description: 'd' }] } });
    const out = await READ_COMMANDS.approvals.run({ client, args: [] });
    expect((out.data as unknown[]).length).toBe(1);
  });
});

// Client that records POST calls + returns a canned response.
function recordingClient(response: unknown = {}): { client: ApiClient; calls: Array<{ path: string; body: unknown }> } {
  const calls: Array<{ path: string; body: unknown }> = [];
  const client: ApiClient = {
    get: async <T>() => ({}) as T,
    post: async <T>(path: string, body?: unknown) => { calls.push({ path, body }); return response as T; },
  };
  return { client, calls };
}

describe('write commands', () => {
  it('approve posts to the action approve endpoint', async () => {
    const { client, calls } = recordingClient();
    const out = await WRITE_COMMANDS.approve.run({ client, args: ['a11c'] });
    expect(calls[0].path).toBe('/api/actions/a11c/approve');
    expect(out.text).toContain('Approved a11c');
  });

  it('deny passes --reason in the body', async () => {
    const { client, calls } = recordingClient();
    await WRITE_COMMANDS.deny.run({ client, args: ['a11c', '--reason', 'too noisy'] });
    expect(calls[0].path).toBe('/api/actions/a11c/deny');
    expect(calls[0].body).toEqual({ reason: 'too noisy' });
  });

  it('answer joins the trailing words into the answer body', async () => {
    const { client, calls } = recordingClient({ ok: true });
    await WRITE_COMMANDS.answer.run({ client, args: ['q1', 'stay', 'quiet', 'and', 'pivot'] });
    expect(calls[0].path).toBe('/api/agent-queries/q1/answer');
    expect(calls[0].body).toEqual({ answer: 'stay quiet and pivot' });
  });

  it('deploy reads the positional target even when a value-flag precedes it', async () => {
    const { client, calls } = recordingClient({ dispatched: true, task: { id: 't1', agent_id: 'ag1', archetype: 'recon_scanner' } });
    await WRITE_COMMANDS.deploy.run({ client, args: ['--archetype', 'recon_scanner', '10.0.0.5'] });
    expect(calls[0].path).toBe('/api/agents/quick-deploy');
    expect(calls[0].body).toEqual({ target: '10.0.0.5', archetype: 'recon_scanner' });
  });

  it('dispatch collects repeated --node values', async () => {
    const { client, calls } = recordingClient({ dispatched: true, task: { id: 't1', agent_id: 'ag1' } });
    await WRITE_COMMANDS.dispatch.run({ client, args: ['--node', 'n1', '--node', 'n2', '--skill', 'network-recon'] });
    expect(calls[0].body).toEqual({ target_node_ids: ['n1', 'n2'], skill: 'network-recon', archetype: undefined });
  });

  it('missing required args throw before any request', async () => {
    const { client, calls } = recordingClient();
    await expect(WRITE_COMMANDS.approve.run({ client, args: [] })).rejects.toThrow(/action-id/);
    await expect(WRITE_COMMANDS.dispatch.run({ client, args: [] })).rejects.toThrow(/--node/);
    expect(calls).toHaveLength(0);
  });
});

describe('renderers', () => {
  it('renderStatus shows name, objective progress, and frontier', () => {
    const out = renderStatus({
      state: {
        engagement: { id: 'eng-1', name: 'Acme Test' },
        graph_summary: { total_nodes: 5, total_edges: 4, confirmed_edges: 3, inferred_edges: 1 },
        objectives: [{ description: 'Get DA', achieved: false }, { description: 'Read flag', achieved: true }],
        frontier: [{ id: 'f1', type: 'network_discovery', description: 'sweep' }],
        agents: [{ id: 'a1', status: 'running', task: 't' }],
      },
      history_count: 12,
    } as never);
    expect(out).toContain('Acme Test');
    expect(out).toContain('1/2 achieved');
    expect(out).toContain('Get DA');
  });

  it('empty approvals + queries render friendly messages', () => {
    expect(renderApprovals([])).toContain('No pending approvals');
    expect(renderQueries([])).toContain('No agents waiting');
  });

  it('renderOpsec shows budget + approach', () => {
    const out = renderOpsec({ global_noise_spent: 0.3, noise_budget_remaining: 0.4, max_noise: 0.7, recommended_approach: 'normal' } as never);
    expect(out).toContain('noise spent');
    expect(out).toContain('normal');
  });

  it('renderDeploy/renderDispatch confirm success and surface refusals', () => {
    expect(renderDeploy({ dispatched: true, task: { id: 't1', agent_id: 'ag1', archetype: 'recon_scanner' } } as never, '10.0.0.5'))
      .toMatch(/Deployed.*10\.0\.0\.5.*t1/);
    expect(renderDeploy({ dispatched: false, reason: 'out of scope' } as never, '9.9.9.9')).toContain('out of scope');
    expect(renderDispatch({ dispatched: true, task: { id: 't2', agent_id: 'ag2' } } as never)).toContain('t2');
    expect(renderDispatch({ dispatched: false, reason: 'leased', existing_task_id: 'tX' } as never)).toMatch(/leased.*tX/);
  });

  it('renderFindings shows the severity summary header', () => {
    const out = renderFindings({ total: 1, severity_summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      findings: [{ id: 'a', severity: 'critical', title: 'x', risk_score: 9, affected_assets: ['h1'] }] } as never);
    expect(out).toContain('1 findings');
    expect(out).toContain('1 critical');
  });
});
