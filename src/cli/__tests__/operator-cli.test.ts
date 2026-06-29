import { describe, expect, it, beforeEach } from 'vitest';
import { setColorEnabled, formatTable, truncate, keyValues } from '../operator/format.js';
import { resolveClientOptions, type ApiClient } from '../operator/client.js';
import { READ_COMMANDS } from '../operator/commands.js';
import { renderStatus, renderApprovals, renderQueries, renderOpsec, renderFindings } from '../operator/render.js';

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

  it('renderFindings shows the severity summary header', () => {
    const out = renderFindings({ total: 1, severity_summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      findings: [{ id: 'a', severity: 'critical', title: 'x', risk_score: 9, affected_assets: ['h1'] }] } as never);
    expect(out).toContain('1 findings');
    expect(out).toContain('1 critical');
  });
});
