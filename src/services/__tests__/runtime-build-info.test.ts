import { describe, expect, it, vi } from 'vitest';
import { probeRunningDashboard } from '../runtime-build-info.js';

describe('runtime build identity', () => {
  it('reads build identity from a running dashboard', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({
      runtime_build: {
        schema_version: 1,
        git_sha: 'abc123',
        input_sha256: 'a'.repeat(64),
        runtime_pid: 42,
        runtime_started_at: '2026-07-16T00:00:00.000Z',
      },
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));

    await expect(probeRunningDashboard(8384, fetchImpl as typeof fetch, async () => true)).resolves.toMatchObject({
      running: true,
      runtime_build: {
        input_sha256: 'a'.repeat(64),
        runtime_pid: 42,
      },
    });
    expect(fetchImpl).toHaveBeenCalledWith(
      'http://127.0.0.1:8384/api/runtime',
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
  });

  it('uses configured authentication for protected runtime identity', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({}), { status: 200 }));
    await probeRunningDashboard(
      8384,
      fetchImpl as typeof fetch,
      async () => true,
      'Bearer dashboard-secret',
    );
    expect(fetchImpl).toHaveBeenCalledWith(
      'http://127.0.0.1:8384/api/runtime',
      expect.objectContaining({ headers: { Authorization: 'Bearer dashboard-secret' } }),
    );
  });

  it('identifies a legacy dashboard without pretending its build is known', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));

    await expect(probeRunningDashboard(8384, fetchImpl as typeof fetch, async () => true)).resolves.toEqual({
      running: true,
    });
  });

  it.each([401, 403, 500])('fails closed when an occupied port returns HTTP %s', async status => {
    const fetchImpl = vi.fn(async () => new Response('protected', { status }));
    await expect(probeRunningDashboard(8384, fetchImpl as typeof fetch, async () => true)).resolves.toEqual({
      running: true,
    });
  });

  it('fails closed when an occupied port is slow or does not speak JSON', async () => {
    const fetchImpl = vi.fn(async () => new Response('not-json', { status: 200 }));
    await expect(probeRunningDashboard(8384, fetchImpl as typeof fetch, async () => true)).resolves.toEqual({
      running: true,
    });
  });

  it('does not probe HTTP when the ownership port is free', async () => {
    const fetchImpl = vi.fn();
    await expect(probeRunningDashboard(8384, fetchImpl as typeof fetch, async () => false)).resolves.toEqual({
      running: false,
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
