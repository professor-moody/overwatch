import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DashboardApiError,
  requestDashboardEndpoint,
} from '../api.generated';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('generated dashboard response contracts', () => {
  it('throws a normal DashboardApiError for a valid common-error envelope', async () => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>(async () => new Response(JSON.stringify({
      error: 'Engagement not found',
      code: 'ENGAGEMENT_NOT_FOUND',
    }), { status: 404, headers: { 'Content-Type': 'application/json' } })));

    await expect(requestDashboardEndpoint('getEngagement', {
      path: { engagement_id: 'missing' },
    })).rejects.toMatchObject({
      status: 404,
      code: 'ENGAGEMENT_NOT_FOUND',
    });
  });

  it('rejects a malformed common-error envelope as contract drift', async () => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>(async () => new Response(JSON.stringify({
      message: 'wrong error envelope',
    }), { status: 404, headers: { 'Content-Type': 'application/json' } })));

    let caught: unknown;
    try {
      await requestDashboardEndpoint('getEngagement', {
        path: { engagement_id: 'missing' },
      });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(DashboardApiError);
    expect(caught).toMatchObject({
      status: 404,
      code: 'DASHBOARD_RESPONSE_CONTRACT_FAILED',
    });
  });

  it('returns explicitly registered dispatch refusal envelopes', async () => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>(async () => new Response(JSON.stringify({
      dispatched: false,
      reason: 'dispatch_cap_exceeded',
      retry_after_ms: 1_000,
      command_id: 'command-1',
      idempotency_key: 'dispatch-1',
      replayed: false,
    }), { status: 429, headers: { 'Content-Type': 'application/json' } })));

    await expect(requestDashboardEndpoint('dispatchAgent', {
      body: { target_node_ids: ['host-1'] },
    })).resolves.toMatchObject({
      dispatched: false,
      reason: 'dispatch_cap_exceeded',
    });
  });

  it('accepts durable planner previews without imposing a browser deadline', async () => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>(async () => new Response(JSON.stringify({
      ops: [],
      summary: 'Planner is working',
      unresolved: [{ text: 'inspect the unusual host', reason: 'requires planning' }],
      needs_planner: true,
      planner_task_id: 'planner-task-1',
      command_id: 'command-1',
      planner_status: 'running',
      planner_available: true,
    }), { status: 200, headers: { 'Content-Type': 'application/json' } })));

    await expect(requestDashboardEndpoint('interpretCommand', {
      body: { command: 'inspect the unusual host' },
    })).resolves.toMatchObject({
      needs_planner: true,
      planner_task_id: 'planner-task-1',
      command_id: 'command-1',
    });
  });

  it('discovers an active planner without relying on browser storage', async () => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>(async () => new Response(JSON.stringify({
      commands: [{
        command_id: 'command-1',
        idempotency_key: 'operator-plan:command-1',
        input_sha256: 'a'.repeat(64),
        validated_input: { command: 'inspect the unusual host' },
        command_kind: 'operator.plan',
        transport: 'dashboard',
        actor_task_id: null,
        status: 'running',
        created_at: '2026-07-16T12:00:00.000Z',
        entity_refs: { planner_task_id: 'planner-task-1' },
      }],
    }), { status: 200, headers: { 'Content-Type': 'application/json' } })));

    await expect(requestDashboardEndpoint('getActiveApplicationCommands'))
      .resolves.toMatchObject({
        commands: [{
          command_id: 'command-1',
          status: 'running',
          entity_refs: { planner_task_id: 'planner-task-1' },
        }],
      });
  });

  it('rejects a planner response that omits its stable preview fields', async () => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>(async () => new Response(JSON.stringify({
      needs_planner: true,
      planner_task_id: 'planner-task-1',
    }), { status: 200, headers: { 'Content-Type': 'application/json' } })));

    await expect(requestDashboardEndpoint('interpretCommand', {
      body: { command: 'inspect the unusual host' },
    })).rejects.toMatchObject({
      status: 200,
      code: 'DASHBOARD_RESPONSE_CONTRACT_FAILED',
    });
  });
});
