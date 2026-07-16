import { afterEach, describe, expect, it, vi } from 'vitest';
import { DashboardApiError, getRecovery, resolveConfigDivergence, updateConfig } from '../api';
import { useEngagementStore } from '../../stores/engagement-store';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  useEngagementStore.getState().setPersistenceRecovery(null);
});

const configRecovery = {
  status: 'diverged',
  resolution_required: true,
  intent_present: false,
  file_valid: true,
  file_hash: 'a'.repeat(64),
  state_hash: 'b'.repeat(64),
  allowed_resolutions: ['use_file', 'use_state'],
};

const recovery = {
  outcome: 'incomplete',
  source: 'state',
  complete: false,
  writable: false,
  reason: 'configuration differs',
  base_checkpoint: 2,
  highest_allocated_seq: 2,
  highest_allocated_logical_seq: 2,
  highest_allocated_frame_seq: 8,
  highest_on_disk_seq: 2,
  highest_physical_frame_seq: 8,
  highest_contiguous_applied_seq: 2,
  highest_contiguous_applied_logical_seq: 2,
  consecutive_persistence_failures: 0,
  journal: {
    enabled: true,
    read: 0,
    attempted: 0,
    applied: 0,
    skipped: 0,
    failed: 0,
    malformed: false,
    preserved: true,
  },
  config_recovery: configRecovery,
};

describe('recovery API adapter', () => {
  it('parses the GET recovery envelope through the shared transport', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => new Response(JSON.stringify({ recovery }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(getRecovery()).resolves.toMatchObject({
      writable: false,
      highest_allocated_frame_seq: 8,
      highest_physical_frame_seq: 8,
      config_recovery: { status: 'diverged' },
    });
    expect(fetchMock).toHaveBeenCalledWith('/api/recovery', expect.objectContaining({
      cache: 'no-store',
      headers: expect.any(Headers),
    }));
  });

  it('posts the strict resolution body using resolution and parses response mode', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => new Response(JSON.stringify({
      resolved: true,
      mode: 'use_state',
      config: {
        id: 'engagement-1',
        name: 'Recovered',
        config_revision: 3,
        config_hash: 'c'.repeat(64),
      },
      recovery: { ...configRecovery, status: 'recovered', resolution_required: false },
      additive: true,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetchMock);

    const result = await resolveConfigDivergence({
      resolution: 'use_state',
      expected_file_hash: 'a'.repeat(64),
      expected_state_hash: 'b'.repeat(64),
    });
    expect(result.mode).toBe('use_state');
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/recovery/config/resolve');
    expect(init?.method).toBe('POST');
    expect(JSON.parse(String(init?.body))).toEqual({
      resolution: 'use_state',
      expected_file_hash: 'a'.repeat(64),
      expected_state_hash: 'b'.repeat(64),
    });
    expect(JSON.parse(String(init?.body))).not.toHaveProperty('mode');
  });

  it('retains structured 503 recovery and updates the global banner state', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => new Response(JSON.stringify({
      error: 'Durable mutations are disabled',
      code: 'PERSISTENCE_READ_ONLY',
      recovery,
    }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetchMock);

    let caught: unknown;
    try {
      await updateConfig({ name: 'must not land' });
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(DashboardApiError);
    expect(caught).toMatchObject({
      status: 503,
      code: 'PERSISTENCE_READ_ONLY',
      body: { recovery: { writable: false } },
    });
    expect(useEngagementStore.getState().persistenceRecovery).toMatchObject({
      writable: false,
      config_recovery: { status: 'diverged' },
    });
  });
});
