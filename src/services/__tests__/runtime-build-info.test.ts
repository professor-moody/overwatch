import { describe, expect, it, vi } from 'vitest';
import { createServer } from 'node:net';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  isDashboardPortOccupied,
  probeRunningDashboard,
  readRuntimeBuildInfo,
} from '../runtime-build-info.js';

describe('runtime build identity', () => {
  it('derives a stable identity when build metadata is absent', () => {
    const root = mkdtempSync(join(tmpdir(), 'overwatch-runtime-source-'));
    try {
      mkdirSync(join(root, 'src'));
      writeFileSync(join(root, 'src', 'index.ts'), 'export const source = true;\n');
      writeFileSync(join(root, 'package.json'), '{"name":"source-fixture"}\n');

      const first = readRuntimeBuildInfo({ metadataCandidates: [], fallbackRoot: root });
      const second = readRuntimeBuildInfo({ metadataCandidates: [], fallbackRoot: root });

      expect(first).toMatchObject({
        input_sha256: expect.stringMatching(/^[0-9a-f]{64}$/),
        input_file_count: 2,
        runtime_pid: process.pid,
      });
      expect(second.input_sha256).toBe(first.input_sha256);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

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

  it('checks real ownership on the configured bind host', async () => {
    const server = createServer();
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    expect(address && typeof address === 'object').toBe(true);
    const port = typeof address === 'object' && address ? address.port : 0;
    try {
      await expect(isDashboardPortOccupied(port, '127.0.0.1')).resolves.toBe(true);
    } finally {
      await new Promise<void>(resolve => server.close(() => resolve()));
    }
    await expect(isDashboardPortOccupied(port, '127.0.0.1')).resolves.toBe(false);
  });

  it('formats an IPv6-specific runtime probe and forwards the bind host', async () => {
    const fetchImpl = vi.fn(async () => new Response('{}', { status: 200 }));
    const portProbe = vi.fn(async () => true);
    await probeRunningDashboard(8384, fetchImpl as typeof fetch, portProbe, undefined, '::1');
    expect(portProbe).toHaveBeenCalledWith(8384, '::1');
    expect(fetchImpl).toHaveBeenCalledWith(
      'http://[::1]:8384/api/runtime',
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
  });

  it('probes an IPv6 wildcard listener through the IPv6 loopback address', async () => {
    const fetchImpl = vi.fn(async () => new Response('{}', { status: 200 }));
    const portProbe = vi.fn(async () => true);
    await probeRunningDashboard(8384, fetchImpl as typeof fetch, portProbe, undefined, '::');
    expect(portProbe).toHaveBeenCalledWith(8384, '::');
    expect(fetchImpl).toHaveBeenCalledWith(
      'http://[::1]:8384/api/runtime',
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
  });
});
