import { PassThrough } from 'stream';
import { mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { EngagementConfig, PersistenceRecoveryStatus } from '../../types.js';
import { DashboardServer } from '../dashboard-server.js';
import { buildEngagementConfig } from '../engagement-builder.js';
import { EngagementManager, EngagementManagerError } from '../engagement-manager.js';
import { GraphEngine } from '../graph-engine.js';

function config(): EngagementConfig {
  return {
    id: 'dashboard-persistence-errors',
    name: 'Dashboard persistence errors',
    created_at: '2026-07-15T00:00:00.000Z',
    scope: { cidrs: ['10.72.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', enabled: false, max_noise: 0.5 },
    subagent_isolation: 'in_process',
  };
}

describe('dashboard durable mutation error responses', () => {
  let dir: string;
  let engine: GraphEngine;
  let dashboard: DashboardServer;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'ow-dashboard-persistence-errors-'));
    engine = new GraphEngine(config(), join(dir, 'state.json'));
    dashboard = new DashboardServer(engine, 0);
    // The active-engagement handler only needs this attachment as an
    // availability guard. Active edits themselves route through GraphEngine.
    (dashboard as unknown as { engagementManager: unknown }).engagementManager = {
      updateEngagement: vi.fn(),
    };
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await dashboard.stop().catch(() => undefined);
    engine.dispose();
    rmSync(dir, { recursive: true, force: true });
  });

  async function invoke(
    method: 'handleUpdateConfig' | 'handleUpdateScope' | 'handleUpdateEngagement',
    body: Record<string, unknown>,
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const req = new PassThrough() as PassThrough & {
      headers: Record<string, string>;
      method: string;
      url: string;
    };
    req.headers = { host: 'localhost', 'content-type': 'application/json' };
    req.method = 'PATCH';
    req.url = method === 'handleUpdateScope'
      ? '/api/config/scope'
      : method === 'handleUpdateEngagement'
        ? `/api/engagements/${engine.getConfig().id}`
        : '/api/config';

    let status = 0;
    let raw = '';
    let finish!: () => void;
    const finished = new Promise<void>(resolve => { finish = resolve; });
    const res = {
      writeHead(nextStatus: number) { status = nextStatus; },
      end(nextBody?: string) {
        raw = nextBody ?? '';
        finish();
      },
      setHeader() {},
    };

    if (method === 'handleUpdateEngagement') {
      (dashboard as any)[method](engine.getConfig().id, req, res);
    } else {
      (dashboard as any)[method](req, res);
    }
    req.end(JSON.stringify(body));
    await finished;
    return { status, body: JSON.parse(raw) as Record<string, unknown> };
  }

  async function invokeDurableSurface(
    method: 'handleAddObjective' | 'handleUpdateObjective' | 'handleDeleteObjective' | 'handleQuickDeploy' | 'handleGraphCorrect',
    body: Record<string, unknown> = {},
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const req = new PassThrough() as PassThrough & {
      headers: Record<string, string>;
      method: string;
      url: string;
    };
    req.headers = { host: 'localhost', 'content-type': 'application/json' };
    req.method = method === 'handleDeleteObjective'
      ? 'DELETE'
      : method === 'handleUpdateObjective'
        ? 'PATCH'
        : 'POST';
    req.url = method === 'handleQuickDeploy'
      ? '/api/agents/quick-deploy'
      : method === 'handleGraphCorrect'
        ? '/api/graph/correct'
        : '/api/objectives/objective-test';

    let status = 0;
    let raw = '';
    let finish!: () => void;
    const finished = new Promise<void>(resolve => { finish = resolve; });
    const res = {
      writeHead(nextStatus: number) { status = nextStatus; },
      end(nextBody?: string) {
        raw = nextBody ?? '';
        finish();
      },
      setHeader() {},
    };

    if (method === 'handleUpdateObjective' || method === 'handleDeleteObjective') {
      (dashboard as any)[method]('objective-test', req, res);
    } else {
      (dashboard as any)[method](req, res);
    }
    req.end(JSON.stringify(body));
    await finished;
    return { status, body: JSON.parse(raw) as Record<string, unknown> };
  }

  async function invokeEngagementSurface(
    method: 'handleCreateEngagement' | 'handleCreateFromTemplate' | 'handleUpdateEngagement',
    body: Record<string, unknown>,
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const req = new PassThrough() as PassThrough & {
      headers: Record<string, string>;
      method: string;
      url: string;
    };
    req.headers = { host: 'localhost', 'content-type': 'application/json' };
    req.method = method === 'handleUpdateEngagement' ? 'PATCH' : 'POST';
    req.url = method === 'handleCreateEngagement'
      ? '/api/engagements'
      : method === 'handleCreateFromTemplate'
        ? '/api/engagements/from-template'
        : '/api/engagements/inactive-engagement';

    let status = 0;
    let raw = '';
    let finish!: () => void;
    const finished = new Promise<void>(resolve => { finish = resolve; });
    const res = {
      writeHead(nextStatus: number) { status = nextStatus; },
      end(nextBody?: string) {
        raw = nextBody ?? '';
        finish();
      },
      setHeader() {},
    };

    if (method === 'handleUpdateEngagement') {
      (dashboard as any)[method]('inactive-engagement', req, res);
    } else {
      (dashboard as any)[method](req, res);
    }
    req.end(JSON.stringify(body));
    await finished;
    return { status, body: JSON.parse(raw) as Record<string, unknown> };
  }

  function persistenceRefusal(): Error & { code: string } {
    return Object.assign(new Error('Durable persistence became read-only'), {
      code: 'PERSISTENCE_READ_ONLY',
    });
  }

  function expectPersistenceRefusal(response: { status: number; body: Record<string, unknown> }): void {
    expect(response).toMatchObject({
      status: 503,
      body: {
        code: 'PERSISTENCE_READ_ONLY',
        recovery: expect.any(Object),
      },
    });
  }

  it('maps a coded config write-incomplete failure to stable 503 recovery', async () => {
    const error = new Error('Configuration write did not complete durably');
    (error as Error & { code: string }).code = 'CONFIG_WRITE_INCOMPLETE';
    vi.spyOn(engine, 'updateConfig').mockImplementation(() => { throw error; });

    const response = await invoke('handleUpdateConfig', { name: 'must not land' });

    expect(response).toMatchObject({
      status: 503,
      body: {
        code: 'PERSISTENCE_READ_ONLY',
        error: expect.stringContaining('did not complete'),
        recovery: expect.objectContaining({ writable: expect.any(Boolean) }),
      },
    });
  });

  it('uses post-failure config recovery state when the raw scope error is generic', async () => {
    const initial = engine.getPersistenceRecoveryStatus();
    const recovery: PersistenceRecoveryStatus = {
      ...initial,
      outcome: 'incomplete',
      complete: false,
      writable: false,
      reason: 'configuration write intent remains',
      config_recovery: {
        ...initial.config_recovery!,
        status: 'write_incomplete',
        resolution_required: true,
        intent_present: true,
        allowed_resolutions: [],
        reason: 'configuration write intent remains',
      },
    };
    vi.spyOn(engine, 'getPersistenceRecoveryStatus').mockReturnValue(recovery);
    vi.spyOn(engine, 'updateScopeConfig').mockImplementation(() => {
      throw new Error('Atomic replacement failed unexpectedly');
    });

    const response = await invoke('handleUpdateScope', { cidrs: ['10.73.0.0/24'] });

    expect(response).toMatchObject({
      status: 503,
      body: {
        code: 'PERSISTENCE_READ_ONLY',
        recovery: {
          writable: false,
          config_recovery: { status: 'write_incomplete', intent_present: true },
        },
      },
    });
  });

  it('maps a late active-engagement persistence refusal to the same 503 envelope', async () => {
    const error = new Error('Durable persistence became read-only');
    (error as Error & { code: string }).code = 'PERSISTENCE_READ_ONLY';
    vi.spyOn(engine, 'updateConfig').mockImplementation(() => { throw error; });

    const response = await invoke('handleUpdateEngagement', { name: 'must not land' });

    expect(response).toMatchObject({
      status: 503,
      body: {
        code: 'PERSISTENCE_READ_ONLY',
        recovery: expect.any(Object),
      },
    });
  });

  it.each([
    ['ENGAGEMENT_NOT_FOUND', 404],
    ['ENGAGEMENT_VALIDATION_FAILED', 400],
    ['ENGAGEMENT_CONFLICT', 409],
  ] as const)('maps inactive engagement %s without disguising it as storage failure', async (code, status) => {
    (dashboard as any).engagementManager = {
      updateEngagement: vi.fn(() => {
        throw new EngagementManagerError(code, `classified ${code}`);
      }),
    };

    const response = await invokeEngagementSurface('handleUpdateEngagement', { name: 'classified edit' });

    expect(response).toEqual({
      status,
      body: { code, error: `classified ${code}` },
    });
  });

  it('returns 400 for a real inactive PATCH whose semantic value would otherwise be ignored', async () => {
    const manager = new EngagementManager(join(dir, 'engagement.json'));
    const stored = buildEngagementConfig({ name: 'Inactive HTTP Validation' });
    stored.id = 'inactive-engagement';
    const summary = manager.persistConfig(stored);
    const before = readFileSync(summary.config_path);
    (dashboard as any).engagementManager = manager;

    const invalid = await invokeEngagementSurface('handleUpdateEngagement', { name: 42 });

    expect(invalid).toMatchObject({
      status: 400,
      body: { code: 'ENGAGEMENT_VALIDATION_FAILED' },
    });
    expect(readFileSync(summary.config_path)).toEqual(before);

    const valid = await invokeEngagementSurface('handleUpdateEngagement', {
      name: 'Inactive HTTP Updated',
      scope: { domains: ['example.test'] },
    });
    expect(valid).toEqual({ status: 200, body: { updated: true } });
    expect(manager.getEngagement(stored.id)).toMatchObject({
      name: 'Inactive HTTP Updated',
      scope: { domains: ['example.test'] },
    });
  });

  it('rejects malformed active and inactive PATCH bodies with matching validation envelopes', async () => {
    const manager = new EngagementManager(join(dir, 'engagement.json'));
    const stored = buildEngagementConfig({ name: 'Inactive HTTP Parity' });
    stored.id = 'inactive-engagement';
    const summary = manager.persistConfig(stored);
    const inactiveBefore = readFileSync(summary.config_path);
    const activeBefore = engine.getConfig();
    (dashboard as any).engagementManager = manager;

    const activeUpdate = vi.spyOn(engine, 'updateConfig');
    const inactiveUpdate = vi.spyOn(manager, 'updateEngagement');
    const invalidUpdates: Record<string, unknown>[] = [
      {},
      { name: 42 },
      { ignored_setting: true },
      { scope: { cidrs: '10.0.0.0/24' } },
      { scope: { cidrs: [], ignored_scope_key: true } },
      { opsec: { approval_timeout_seconds: 30 } },
      { available_models: ['valid-model', 42] },
    ];

    for (const invalidUpdate of invalidUpdates) {
      const active = await invoke('handleUpdateEngagement', invalidUpdate);
      const inactive = await invokeEngagementSurface('handleUpdateEngagement', invalidUpdate);

      for (const response of [active, inactive]) {
        expect(response).toMatchObject({
          status: 400,
          body: {
            code: 'ENGAGEMENT_VALIDATION_FAILED',
            error: expect.stringContaining('is invalid'),
          },
        });
        expect(Object.keys(response.body).sort()).toEqual(['code', 'error']);
      }
      expect(active.body.code).toBe(inactive.body.code);
    }

    expect(activeUpdate).not.toHaveBeenCalled();
    expect(inactiveUpdate).not.toHaveBeenCalled();
    expect(engine.getConfig()).toEqual(activeBefore);
    expect(readFileSync(summary.config_path)).toEqual(inactiveBefore);
  });

  it.each([
    ['handleCreateEngagement', 'createEngagement', { name: 'New engagement' }],
    ['handleCreateFromTemplate', 'persistConfig', { template_id: 'ctf', overrides: { id: 'template-engagement' } }],
    ['handleUpdateEngagement', 'updateEngagement', { name: 'Updated engagement' }],
  ] as const)('maps %s durable storage failure to the stable engagement 503 envelope', async (method, failingCall, body) => {
    (dashboard as any).engagementManager = {
      createEngagement: vi.fn(),
      persistConfig: vi.fn(),
      updateEngagement: vi.fn(),
      [failingCall]: vi.fn(() => {
        throw new EngagementManagerError(
          'ENGAGEMENT_PERSISTENCE_FAILED',
          'Inactive engagement was not durably persisted: disk full',
        );
      }),
    };

    const response = await invokeEngagementSurface(method, body);

    expect(response).toEqual({
      status: 503,
      body: {
        code: 'ENGAGEMENT_PERSISTENCE_FAILED',
        error: 'Inactive engagement was not durably persisted: disk full',
      },
    });
  });

  it('keeps invalid template overrides at 400 before persistence', async () => {
    const persistConfig = vi.fn();
    (dashboard as any).engagementManager = { persistConfig };

    const response = await invokeEngagementSurface('handleCreateFromTemplate', {
      template_id: 'ctf',
      overrides: { id: 'invalid-template-engagement', created_at: 'not-a-date' },
    });

    expect(response).toMatchObject({
      status: 400,
      body: { code: 'ENGAGEMENT_VALIDATION_FAILED' },
    });
    expect(persistConfig).not.toHaveBeenCalled();
  });

  it('keeps optimistic configuration conflicts at 409', async () => {
    const error = new Error('Configuration changed after it was inspected');
    (error as Error & { code: string }).code = 'CONFIG_HASH_CONFLICT';
    vi.spyOn(engine, 'updateConfig').mockImplementation(() => { throw error; });

    const response = await invoke('handleUpdateConfig', { name: 'stale edit' });

    expect(response).toEqual({
      status: 409,
      body: {
        code: 'CONFIG_HASH_CONFLICT',
        error: 'Configuration changed after it was inspected',
      },
    });
  });

  it('promotes a late config conflict to recovery 503 when a durable intent now exists', async () => {
    const initial = engine.getPersistenceRecoveryStatus();
    const recovery: PersistenceRecoveryStatus = {
      ...initial,
      outcome: 'incomplete',
      complete: false,
      writable: false,
      reason: 'configuration write intent remains',
      config_recovery: {
        ...initial.config_recovery!,
        status: 'write_incomplete',
        resolution_required: true,
        intent_present: true,
        allowed_resolutions: [],
        reason: 'configuration write intent remains',
      },
    };
    vi.spyOn(engine, 'getPersistenceRecoveryStatus').mockReturnValue(recovery);
    const error = Object.assign(
      new Error('Configuration changed while its durable write intent was being prepared.'),
      { code: 'CONFIG_HASH_CONFLICT' },
    );
    vi.spyOn(engine, 'updateConfig').mockImplementation(() => { throw error; });

    const response = await invoke('handleUpdateConfig', { name: 'raced edit' });

    expect(response).toMatchObject({
      status: 503,
      body: {
        code: 'PERSISTENCE_READ_ONLY',
        error: expect.stringContaining('durable write intent'),
        recovery: {
          writable: false,
          config_recovery: { status: 'write_incomplete', intent_present: true },
        },
      },
    });
  });

  it('keeps ordinary scope validation failures at 400', async () => {
    vi.spyOn(engine, 'updateScopeConfig').mockImplementation(() => {
      throw new Error('Invalid scope update: invalid CIDR');
    });

    const response = await invoke('handleUpdateScope', { cidrs: ['not-a-cidr'] });

    expect(response).toEqual({
      status: 400,
      body: { error: 'Invalid scope update: invalid CIDR' },
    });
  });

  it('maps a late objective-create persistence refusal to 503 recovery', async () => {
    vi.spyOn(engine, 'addObjective').mockImplementation(() => { throw persistenceRefusal(); });

    const response = await invokeDurableSurface('handleAddObjective', { description: 'Must persist' });

    expectPersistenceRefusal(response);
  });

  it('maps a late objective-update persistence refusal to 503 recovery', async () => {
    vi.spyOn(engine, 'updateObjective').mockImplementation(() => { throw persistenceRefusal(); });

    const response = await invokeDurableSurface('handleUpdateObjective', { description: 'Must persist' });

    expectPersistenceRefusal(response);
  });

  it('maps a late objective-delete persistence refusal to 503 recovery', async () => {
    vi.spyOn(engine, 'removeObjective').mockImplementation(() => { throw persistenceRefusal(); });

    const response = await invokeDurableSurface('handleDeleteObjective');

    expectPersistenceRefusal(response);
  });

  it('maps a late quick-deploy scope persistence refusal to 503 recovery', async () => {
    vi.spyOn(engine, 'updateScope').mockImplementation(() => { throw persistenceRefusal(); });

    const response = await invokeDurableSurface('handleQuickDeploy', { target: '10.72.0.5' });

    expectPersistenceRefusal(response);
  });

  it('maps a late graph-correction persistence refusal to 503 recovery', async () => {
    vi.spyOn(engine, 'correctGraph').mockImplementation(() => { throw persistenceRefusal(); });

    const response = await invokeDurableSurface('handleGraphCorrect', {
      reason: 'durable correction',
      operations: [{ op: 'drop_node', node_id: 'missing' }],
    });

    expectPersistenceRefusal(response);
  });

  it('preserves objective not-found and graph-correction validation responses', async () => {
    vi.spyOn(engine, 'updateObjective').mockReturnValue(false);

    const notFound = await invokeDurableSurface('handleUpdateObjective', { description: 'Unknown objective' });
    const invalidCorrection = await invokeDurableSurface('handleGraphCorrect', { reason: 'missing operations' });

    expect(notFound).toEqual({ status: 404, body: { error: 'Objective not found' } });
    expect(invalidCorrection).toEqual({
      status: 400,
      body: { error: 'reason (string) and operations (array) are required' },
    });
  });
});
