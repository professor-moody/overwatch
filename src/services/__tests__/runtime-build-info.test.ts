import { describe, expect, it, vi } from 'vitest';
import { probeRunningDashboard } from '../runtime-build-info.js';

describe('runtime build identity', () => {
  it('reads build identity from a running dashboard', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({
      health_checks: { status: 'healthy' },
      runtime_build: {
        schema_version: 1,
        git_sha: 'abc123',
        input_sha256: 'a'.repeat(64),
        runtime_pid: 42,
        runtime_started_at: '2026-07-16T00:00:00.000Z',
      },
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));

    await expect(probeRunningDashboard(8384, fetchImpl as typeof fetch)).resolves.toMatchObject({
      running: true,
      runtime_build: {
        input_sha256: 'a'.repeat(64),
        runtime_pid: 42,
      },
    });
  });

  it('identifies a legacy dashboard without pretending its build is known', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({
      health_checks: { status: 'healthy' },
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));

    await expect(probeRunningDashboard(8384, fetchImpl as typeof fetch)).resolves.toEqual({
      running: true,
    });
  });
});
