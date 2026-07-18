// ============================================================
// Dashboard API integration test — every /api/* endpoint with shape
// assertions against a single seeded engine.
//
// Complementary to dashboard-server.test.ts:
//   - dashboard-server.test.ts focuses on auth/CSRF/edge cases for ~10
//     endpoints and uses direct method invocation (no HTTP bind).
//   - This file boots a real DashboardServer on port 0, hits each
//     endpoint via fetch(), asserts response shape and cross-endpoint
//     consistency. The goal is to catch routing typos, response-shape
//     drift between backend and frontend, and missing fields the way
//     dogfooding the smoke harness already caught three.
//
// Each test asserts only structural invariants (status code + key
// presence). Behavior is covered by per-feature tests elsewhere.
// ============================================================

import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { existsSync, unlinkSync, mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { DashboardServer } from '../dashboard-server.js';
import { GraphEngine } from '../graph-engine.js';
import type { EngagementConfig } from '../../types.js';
import {
  FrontierWeightsResetResultSchema,
  FrontierWeightsUpdateResultSchema,
  GraphCorrectionResultSchema,
  HealthDtoSchema,
  ObjectiveDeleteResponseSchema,
  ObjectiveCreateResponseSchema,
  ObjectiveUpdateResponseSchema,
  RawGraphDtoSchema,
  SettingsDtoSchema,
  SettingsUpdateResultSchema,
  PlaybookRunListResponseSchema,
  PlaybookRunResponseSchema,
  PlaybookStepClaimResponseSchema,
} from '../../contracts/dashboard-v1.js';
import { PlaybookRunService } from '../playbook-run-service.js';
import { buildToolDescriptor } from '../tool-descriptor-registry.js';
import { InProcessTapeController } from '../in-process-tape.js';

let dashboard: DashboardServer;
let engine: GraphEngine;
let baseUrl: string;
let tempDir: string;
let stateFile: string;

const NOW = '2026-05-09T00:00:00Z';

function makeConfig(): EngagementConfig {
  return {
    id: 'api-integration',
    name: 'API Integration',
    created_at: NOW,
    scope: {
      cidrs: ['10.0.0.0/24'],
      domains: ['acme.local'],
      exclusions: [],
      aws_accounts: ['111122223333'],
    },
    objectives: [{
      id: 'obj-power',
      description: 'Reach AWS PowerUser',
      target_node_type: 'cloud_identity',
      target_criteria: { arn: 'arn:aws:iam::111122223333:role/PowerUser' },
      achieved: false,
    }],
    opsec: { name: 'pentest', max_noise: 0.7, enabled: true },
    available_models: ['claude-opus-4-8'],
  } as EngagementConfig;
}

function seedGraph(eng: GraphEngine) {
  // Cloud identity (the objective target).
  eng.addNode({
    id: 'cloud-id-power', type: 'cloud_identity',
    label: 'arn:aws:iam::111122223333:role/PowerUser',
    arn: 'arn:aws:iam::111122223333:role/PowerUser',
    cloud_provider: 'aws', cloud_account: '111122223333',
    principal_type: 'role', discovered_at: NOW, confidence: 1.0,
  } as never);
  // IdP application that issues tokens for the role.
  eng.addNode({
    id: 'idp-app-gha', type: 'idp_application',
    label: 'gha-prod-deploy', idp_kind: 'ci_github_actions',
    audience: 'sts.amazonaws.com', tenant_id: 'acme',
    discovered_at: NOW, confidence: 1.0,
  } as never);
  eng.addEdge('idp-app-gha', 'cloud-id-power', {
    type: 'ISSUES_TOKENS_FOR', confidence: 0.95, discovered_at: NOW,
  } as never);
  // Captured OIDC token + jumpbox start point.
  eng.addNode({
    id: 'cred-oidc', type: 'credential',
    label: 'gha-oidc-prod', cred_type: 'token',
    cred_material_kind: 'oidc_access_token',
    cred_audience: 'sts.amazonaws.com', credential_status: 'active',
    cred_token_expires_at: '2099-01-01T00:00:00Z',
    discovered_at: NOW, confidence: 1.0,
  } as never);
  eng.addNode({
    id: 'host-jump', type: 'host',
    label: 'jumpbox.acme.local', ip: '10.0.0.5',
    discovered_at: NOW, confidence: 1.0,
  } as never);
  eng.addEdge('host-jump', 'cred-oidc', {
    type: 'OWNS_CRED', confidence: 1.0, discovered_at: NOW,
  } as never);
  eng.addNode({
    id: 'user-op', type: 'user', label: 'operator',
    username: 'operator', domain: 'acme.local',
    discovered_at: NOW, confidence: 1.0,
  } as never);
  eng.addEdge('user-op', 'host-jump', {
    type: 'ADMIN_TO', confidence: 1.0, discovered_at: NOW,
  } as never);
  // No-op ingest to trigger inference (so OIDC_FEDERATION_PIVOT
  // emits the inferred ASSUMES_ROLE edge for /api/paths).
  eng.ingestFinding({
    id: 'seed-trigger', agent_id: 'integration-seed', timestamp: NOW,
    nodes: [], edges: [],
  });
  eng.logActionEvent({
    description: 'AzureHound ingest dropped one malformed record',
    event_type: 'parse_output',
    result_classification: 'partial',
    target_node_ids: ['cred-oidc'],
    details: {
      ingest_summary: [{
        processed_records: 2,
        dropped_records: 1,
        dropped_by_reason: { 'azusers.missing_object_id': 1 },
      }],
    },
  });
}

beforeAll(async () => {
  tempDir = mkdtempSync(join(tmpdir(), 'overwatch-api-'));
  stateFile = join(tempDir, 'state.json');
  engine = new GraphEngine(makeConfig(), stateFile);
  seedGraph(engine);
  // Ephemeral port; loopback => mutations don't require a token.
  dashboard = new DashboardServer(engine, 0, '127.0.0.1', undefined, undefined);
  dashboard.attachTape(new InProcessTapeController(engine, {
    defaultDir: join(tempDir, 'tapes'),
  }));
  dashboard.attachMcpTools([
    ['get_state', 'state'],
    ['validate_action', 'validate'],
    ['run_bash', 'bash'],
    ['parse_output', 'parse'],
    ['report_finding', 'report'],
    ['get_system_prompt', 'prompt'],
    ['get_recovery_status', 'recovery status'],
    ['resolve_config_divergence', 'config reconciliation'],
  ].map(([name, description]) => buildToolDescriptor(name, {
    description,
    inputSchema: {},
    annotations: {
      readOnlyHint: name.startsWith('get_'),
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  })));
  const result = await dashboard.start();
  if (!result.started) throw new Error(`dashboard failed to start: ${result.error}`);
  baseUrl = dashboard.address;
});

afterAll(async () => {
  await dashboard.stop().catch(() => {});
  engine.dispose();
  if (existsSync(stateFile)) try { unlinkSync(stateFile); } catch { /* */ }
  if (tempDir && existsSync(tempDir)) try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* */ }
});

async function getJson<T = unknown>(path: string): Promise<{ status: number; body: T }> {
  const res = await fetch(`${baseUrl}${path}`);
  const body = res.headers.get('content-type')?.includes('json')
    ? await res.json() as T
    : await res.text() as T;
  return { status: res.status, body };
}

async function postJson<T = unknown>(
  path: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<{ status: number; body: T }> {
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  const responseBody = res.headers.get('content-type')?.includes('json')
    ? await res.json() as T
    : await res.text() as T;
  return { status: res.status, body: responseBody };
}

async function patchJson<T = unknown>(path: string, body: unknown): Promise<{ status: number; body: T }> {
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const responseBody = res.headers.get('content-type')?.includes('json')
    ? await res.json() as T
    : await res.text() as T;
  return { status: res.status, body: responseBody };
}

describe('POST /api/tape/toggle', () => {
  it('replays explicit enable and disable responses without reversing either action', async () => {
    const enableHeaders = {
      'X-Overwatch-Command-Id': 'tape-enable-command',
      'Idempotency-Key': 'tape-enable-retry',
    };
    const enabled = await postJson<{ enabled: boolean }>('/api/tape/toggle', {
      action: 'enable',
    }, enableHeaders);
    expect(enabled).toMatchObject({ status: 200, body: { enabled: true } });
    const enabledReplay = await postJson<{ enabled: boolean }>('/api/tape/toggle', {
      action: 'enable',
    }, enableHeaders);
    expect(enabledReplay).toEqual(enabled);
    expect((await getJson<{ enabled: boolean }>('/api/tape')).body.enabled).toBe(true);

    const disableHeaders = {
      'X-Overwatch-Command-Id': 'tape-disable-command',
      'Idempotency-Key': 'tape-disable-retry',
    };
    const disabled = await postJson<{ enabled: boolean }>('/api/tape/toggle', {
      action: 'disable',
    }, disableHeaders);
    expect(disabled).toMatchObject({ status: 200, body: { enabled: false } });
    const disabledReplay = await postJson<{ enabled: boolean }>('/api/tape/toggle', {
      action: 'disable',
    }, disableHeaders);
    expect(disabledReplay).toEqual(disabled);
    expect((await getJson<{ enabled: boolean }>('/api/tape')).body.enabled).toBe(false);

    expect(engine.getFullHistory().filter(event =>
      event.event_type === 'tape_session_started'
      || event.event_type === 'tape_session_stopped')).toHaveLength(2);
  });
});

// =============================================
// Top-level state + graph
// =============================================

describe('GET /api/state', () => {
  it('returns state, graph, history_count with the wired keys the frontend reads', async () => {
    const { status, body } = await getJson<{
      state: Record<string, unknown>;
      graph: { nodes: unknown[]; edges: unknown[] };
      history_count: number;
      runtime_build: { input_sha256: string; runtime_pid: number };
    }>('/api/state');
    expect(status).toBe(200);
    expect(body).toHaveProperty('state');
    expect(body).toHaveProperty('graph');
    expect(body).toHaveProperty('history_count');
    expect(body.runtime_build).toMatchObject({
      release_version: '0.2.0',
      input_sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
      runtime_pid: process.pid,
    });
    // Field names that previously drifted (B.0 audit fixes):
    expect(body.state).toHaveProperty('agents');             // was missing — only active_agents existed
    expect(body.state).toHaveProperty('sessions');           // injected by buildFrontendState
    expect(body.state).toHaveProperty('graph_summary');
    expect(body.state).toHaveProperty('persistence_recovery');
    expect((body.state as { persistence_recovery: Record<string, unknown> }).persistence_recovery).toMatchObject({
      outcome: expect.any(String),
      complete: expect.any(Boolean),
      writable: expect.any(Boolean),
      highest_allocated_logical_seq: expect.any(Number),
      highest_allocated_frame_seq: expect.any(Number),
      highest_physical_frame_seq: expect.any(Number),
      highest_contiguous_applied_logical_seq: expect.any(Number),
      journal: expect.any(Object),
    });
    expect((body.state as { graph_summary: { nodes_by_type: unknown } }).graph_summary).toHaveProperty('nodes_by_type');
    expect(body.graph.nodes.length).toBeGreaterThan(0);
    // frontier_hidden: counts of intentionally-filtered frontier items so the
    // dashboard can explain the gap instead of looking like it drops items.
    expect(body.state).toHaveProperty('frontier_hidden');
    const hidden = (body.state as { frontier_hidden: { total: number; by_reason: Record<string, number> } }).frontier_hidden;
    expect(typeof hidden.total).toBe('number');
    expect(hidden.by_reason).toMatchObject({
      lease: expect.any(Number), opsec: expect.any(Number), dead_host: expect.any(Number), scope: expect.any(Number),
    });
  });
});

describe('GET /api/graph', () => {
  it('returns nodes + edges arrays', async () => {
    const { status, body } = await getJson('/api/graph');
    expect(status).toBe(200);
    const graph = RawGraphDtoSchema.parse(body);
    expect(Array.isArray(graph.nodes)).toBe(true);
    expect(Array.isArray(graph.edges)).toBe(true);
    expect(graph.nodes[0]).toHaveProperty('properties');
  });

  it('keeps the raw wrapped graph shape on explicit JSON export', async () => {
    const exported = await postJson('/api/graph/export', {});
    expect(exported.status).toBe(200);
    const graph = RawGraphDtoSchema.parse(exported.body);
    expect(graph.nodes.some(node => node.id === 'cloud-id-power')).toBe(true);
    expect(graph.nodes.find(node => node.id === 'cloud-id-power')?.properties.type).toBe('cloud_identity');
  });
});

describe('POST /api/graph/correct', () => {
  it('rejects the legacy patch shape and applies set_properties exactly once', async () => {
    engine.addNode({
      id: 'graph-correction-api-node',
      type: 'host',
      label: 'before correction',
      ip: '10.0.0.88',
      discovered_at: NOW,
      confidence: 1,
    });
    const legacy = await postJson('/api/graph/correct', {
      reason: 'legacy no-op shape',
      operations: [{
        kind: 'patch_node',
        node_id: 'graph-correction-api-node',
        patch: { label: 'must not apply' },
      }],
    });
    expect(legacy.status).toBe(400);
    expect(engine.getNode('graph-correction-api-node')?.label)
      .toBe('before correction');

    const headers = {
      'Idempotency-Key': 'dashboard-graph-correction-retry',
      'X-Overwatch-Command-Id': 'dashboard-graph-correction-command',
    };
    const body = {
      reason: 'apply canonical patch',
      operations: [{
        kind: 'patch_node',
        node_id: 'graph-correction-api-node',
        set_properties: { label: 'after correction' },
      }],
    };
    const first = await postJson('/api/graph/correct', body, headers);
    expect(first.status).toBe(200);
    expect(GraphCorrectionResultSchema.parse(first.body)).toMatchObject({
      patched_nodes: ['graph-correction-api-node'],
      command_id: 'dashboard-graph-correction-command',
      replayed: false,
    });
    expect(engine.getNode('graph-correction-api-node')?.label)
      .toBe('after correction');
    const second = await postJson('/api/graph/correct', body, headers);
    expect(second.status).toBe(200);
    expect(second.body).toMatchObject({
      command_id: 'dashboard-graph-correction-command',
      // The external receipt replays the exact first wire response. Its own
      // replay status is exposed by X-Overwatch-Command-Replayed.
      replayed: false,
    });
    expect(engine.getFullHistory().filter(event =>
      event.event_type === 'graph_corrected'
      && event.details?.reason === 'apply canonical patch',
    )).toHaveLength(1);
  });

  it('returns a reusable receipt and replays the exact response without a second effect', async () => {
    const headers = {
      'Content-Type': 'application/json',
      'X-Overwatch-Command-Id': 'dashboard-boundary-receipt-command',
      'Idempotency-Key': 'dashboard-boundary-receipt-retry',
      Origin: 'http://localhost:8384',
    };
    const requestBody = JSON.stringify({
      description: 'Boundary receipt objective',
      target_node_type: 'host',
    });
    const before = engine.getConfig().objectives.length;
    const first = await fetch(`${baseUrl}/api/config/objectives`, {
      method: 'POST',
      headers,
      body: requestBody,
    });
    const firstBody = await first.text();
    const retryToken = first.headers.get('x-overwatch-retry-token');
    expect(first.status).toBe(201);
    expect(first.headers.get('x-overwatch-boundary-command-id'))
      .toMatch(/^boundary_[a-f0-9]{48}$/);
    expect(first.headers.get('x-overwatch-command-replayed')).toBe('false');
    expect(first.headers.get('x-overwatch-command-status')).toBe('succeeded');
    expect(first.headers.get('x-overwatch-command-response-available')).toBe('1');
    expect(first.headers.get('access-control-allow-origin')).toBe('http://localhost:8384');
    expect(retryToken).toMatch(/^idem_[a-f0-9]{64}$/);

    const replay = await fetch(`${baseUrl}/api/config/objectives`, {
      method: 'POST',
      headers: {
        ...headers,
        Origin: 'http://127.0.0.1:9393',
        'X-Overwatch-Retry-Token': retryToken!,
      },
      body: requestBody,
    });
    expect(replay.status).toBe(201);
    expect(await replay.text()).toBe(firstBody);
    expect(replay.headers.get('x-overwatch-command-replayed')).toBe('true');
    expect(replay.headers.get('access-control-allow-origin')).toBe('http://127.0.0.1:9393');
    expect(engine.getConfig().objectives).toHaveLength(before + 1);

    const conflict = await fetch(`${baseUrl}/api/config/objectives`, {
      method: 'POST',
      headers: {
        ...headers,
        'X-Overwatch-Retry-Token': retryToken!,
      },
      body: JSON.stringify({
        description: 'Changed input must not reuse the receipt',
        target_node_type: 'host',
      }),
    });
    expect(conflict.status).toBe(409);
    expect(engine.getConfig().objectives).toHaveLength(before + 1);
  });
});

describe('GET /api/history', () => {
  it('returns entries[] with order=desc default', async () => {
    const { status, body } = await getJson<{ entries: unknown[]; total: number; order: string }>('/api/history?limit=10');
    expect(status).toBe(200);
    expect(body.order).toBe('desc');
    expect(Array.isArray(body.entries)).toBe(true);
  });

  it('retains the compatibility order=asc query through the strict registry', async () => {
    const { status, body } = await getJson<{ entries: unknown[]; order: string }>('/api/history?limit=10&order=asc');
    expect(status).toBe(200);
    expect(body.order).toBe('asc');
  });
});

// =============================================
// Sessions, Agents, Templates, Health, Tools, Inference
// =============================================

describe('GET /api/sessions', () => {
  it('returns sessions[] with total + active counts', async () => {
    const { status, body } = await getJson<{ sessions: unknown[]; total: number; active: number }>('/api/sessions');
    expect(status).toBe(200);
    expect(body).toHaveProperty('sessions');
    expect(typeof body.total).toBe('number');
    expect(typeof body.active).toBe('number');
  });
});

describe('GET /api/agents', () => {
  it('returns agents[] with total', async () => {
    const { status, body } = await getJson<{ agents: unknown[]; total: number }>('/api/agents');
    expect(status).toBe(200);
    expect(Array.isArray(body.agents)).toBe(true);
    expect(typeof body.total).toBe('number');
  });
});

describe('GET /api/templates', () => {
  it('returns templates[] including the bundled engagement templates', async () => {
    const { status, body } = await getJson<{ templates: Array<{ id: string }>; total: number }>('/api/templates');
    expect(status).toBe(200);
    expect(Array.isArray(body.templates)).toBe(true);
    expect(body.total).toBe(body.templates.length);
  });
});

describe('GET /api/health', () => {
  it('returns graph_stats + health report', async () => {
    const { status, body } = await getJson('/api/health');
    expect(status).toBe(200);
    const health = HealthDtoSchema.parse(body);
    expect(health.graph_stats.nodes).toBeGreaterThan(0);
    expect(health.health_checks).toHaveProperty('status');
    expect(health.health_checks).toHaveProperty('counts_by_severity');
    expect(Array.isArray(health.health_checks.issues)).toBe(true);
    expect(health.runtime_build).toMatchObject({
      release_version: '0.2.0',
      input_sha256: expect.stringMatching(/^[0-9a-f]{64}$/),
      runtime_pid: process.pid,
    });
  });

  it('preserves critical status, severity counts, and issues', async () => {
    const spy = vi.spyOn(engine, 'getHealthReport').mockReturnValue({
      status: 'critical', counts_by_severity: { warning: 1, critical: 1 },
      issues: [{ severity: 'critical', check: 'test-critical', message: 'Critical test issue' }],
    });
    try {
      const response = await getJson('/api/health');
      const health = HealthDtoSchema.parse(response.body);
      expect(health.health_checks.status).toBe('critical');
      expect(health.health_checks.counts_by_severity.critical).toBe(1);
      expect(health.health_checks.issues[0].message).toBe('Critical test issue');
    } finally {
      spy.mockRestore();
    }
  });
});

describe('GET /api/runtime', () => {
  it('returns build identity without running graph health or export work', async () => {
    const healthSpy = vi.spyOn(engine, 'getHealthReport');
    const exportSpy = vi.spyOn(engine, 'exportGraph');
    const { status, body } = await getJson<{ runtime_build?: { input_sha256?: string; runtime_pid?: number } }>('/api/runtime');
    expect(status).toBe(200);
    expect(body.runtime_build).toMatchObject({
      release_version: '0.2.0',
      input_sha256: expect.stringMatching(/^[0-9a-f]{64}$/),
      runtime_pid: process.pid,
    });
    expect(healthSpy).not.toHaveBeenCalled();
    expect(exportSpy).not.toHaveBeenCalled();
  });
});

describe('GET /api/tools', () => {
  it('returns host binary inventory with installed/missing counts', async () => {
    const { status, body } = await getJson<{ installed_count: number; missing_count: number; tools: unknown[] }>('/api/tools');
    expect(status).toBe(200);
    expect(Array.isArray(body.tools)).toBe(true);
    expect(typeof body.installed_count).toBe('number');
    expect(typeof body.missing_count).toBe('number');
    expect(body.installed_count + body.missing_count).toBe(body.tools.length);
  });
});

describe('GET /api/mcp-tools', () => {
  it('returns the registered MCP tool surface separately from host tools', async () => {
    const { status, body } = await getJson<{ total: number; registry_sha256: string; categories: Record<string, number>; tools: Array<{ name: string; category: string }> }>('/api/mcp-tools');
    expect(status).toBe(200);
    expect(Array.isArray(body.tools)).toBe(true);
    expect(body.total).toBe(body.tools.length);
    expect(body.registry_sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(body.tools.map(tool => tool.name)).toContain('get_state');
    expect(body.categories).toHaveProperty('state-readiness');
    expect(body.tools).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: 'get_recovery_status', category: 'state-readiness' }),
      expect.objectContaining({ name: 'resolve_config_divergence', category: 'config-scope' }),
    ]));
  });
});

describe('GET /api/readiness', () => {
  it('returns dashboard-ready health, tape, session, action, agent, and persistence summary', async () => {
    const { status, body } = await getJson<Record<string, any>>('/api/readiness');
    expect(status).toBe(200);
    expect(['ready', 'warning', 'critical']).toContain(body.status);
    expect(body).toHaveProperty('graph');
    expect(body).toHaveProperty('api');
    expect(body).toHaveProperty('tape');
    expect(body).toHaveProperty('sessions');
    expect(body).toHaveProperty('actions');
    expect(body).toHaveProperty('agents');
    expect(body).toHaveProperty('persistence');
    expect(body.persistence).toHaveProperty('recovery');
    expect(typeof body.api.mcp_tools_registered).toBe('number');
  });

  it('nests recovery status under persistence and raises an existing readiness issue', async () => {
    const getState = engine.getState.bind(engine);
    const getStateSpy = vi.spyOn(engine, 'getState').mockImplementation(options => ({
      ...getState(options),
      persistence_recovery: {
        outcome: 'incomplete',
        source: 'state',
        complete: false,
        writable: false,
        reason: 'sequence gap',
        base_checkpoint: 2,
        highest_allocated_seq: 6,
        highest_allocated_logical_seq: 6,
        highest_allocated_frame_seq: 18,
        highest_on_disk_seq: 6,
        highest_physical_frame_seq: 18,
        highest_contiguous_applied_seq: 4,
        highest_contiguous_applied_logical_seq: 4,
        consecutive_persistence_failures: 0,
        journal: {
          enabled: true,
          read: 4,
          attempted: 2,
          applied: 2,
          skipped: 0,
          failed: 0,
          malformed: false,
          preserved: true,
        },
      },
    }));

    try {
      const { status, body } = await getJson<Record<string, any>>('/api/readiness');
      expect(status).toBe(200);
      expect(body.status).toBe('critical');
      expect(body.persistence.recovery).toMatchObject({
        outcome: 'incomplete',
        writable: false,
        highest_contiguous_applied_seq: 4,
        highest_contiguous_applied_logical_seq: 4,
        highest_on_disk_seq: 6,
        highest_physical_frame_seq: 18,
      });
      expect(body.issues[0]).toContain('sequence gap');
    } finally {
      getStateSpy.mockRestore();
    }
  });

  it('raises a readiness warning for unresolved runtime ownership', async () => {
    const getState = engine.getState.bind(engine);
    const getStateSpy = vi.spyOn(engine, 'getState').mockImplementation(options => {
      const state = getState(options);
      return {
        ...state,
        persistence_recovery: {
          ...state.persistence_recovery!,
          runtime_ownership_warnings: [{
            run_id: 'runtime-readiness-warning',
            pid: 4242,
            lifecycle: 'unknown',
            message: 'PID identity could not be verified.',
          }],
        },
      };
    });

    try {
      const { status, body } = await getJson<Record<string, any>>('/api/readiness');
      expect(status).toBe(200);
      expect(['warning', 'critical']).toContain(body.status);
      expect(body.persistence.recovery.runtime_ownership_warnings).toEqual([
        expect.objectContaining({ run_id: 'runtime-readiness-warning' }),
      ]);
      expect(body.issues).toContainEqual(expect.stringContaining('unresolved process ownership'));
    } finally {
      getStateSpy.mockRestore();
    }
  });
});

describe('degraded persistence gate', () => {
  it('keeps reads and pure previews available while rejecting dashboard mutations', async () => {
    const writableSpy = vi.spyOn(engine, 'isPersistenceWritable').mockReturnValue(false);
    try {
      const objectiveCount = engine.getConfig().objectives.length;
      const blocked = await postJson<Record<string, unknown>>('/api/config/objectives', {
        description: 'must not be created',
      });
      expect(blocked.status).toBe(503);
      expect(blocked.body).toMatchObject({ code: 'PERSISTENCE_READ_ONLY' });
      expect(engine.getConfig().objectives).toHaveLength(objectiveCount);

      const state = await getJson('/api/state');
      expect(state.status).toBe(200);

      const bundle = await getJson<Record<string, unknown>>('/api/bundle');
      expect(bundle.status).toBe(200);
      expect(typeof bundle.body).toBe('string');

      const preview = await postJson('/api/config/scope/preview', {
        ...engine.getConfig().scope,
        cidrs: [...engine.getConfig().scope.cidrs, '10.1.0.0/24'],
      });
      expect(preview.status).toBe(200);
    } finally {
      writableSpy.mockRestore();
    }
  });
});

describe('GET /api/trust-signals', () => {
  it('returns operator verification signals with counts and links', async () => {
    const { status, body } = await getJson<Record<string, any>>('/api/trust-signals');
    expect(status).toBe(200);
    expect(body).toHaveProperty('generated_at');
    expect(body).toHaveProperty('counts');
    expect(Array.isArray(body.signals)).toBe(true);
    expect(body.total).toBe(body.signals.length);
    expect(body.signals.some((signal: any) => signal.label === 'Dropped records')).toBe(true);
  });

  it('can filter operator verification signals by node', async () => {
    const { status, body } = await getJson<Record<string, any>>('/api/trust-signals?node_id=cred-oidc');
    expect(status).toBe(200);
    expect(Array.isArray(body.signals)).toBe(true);
    expect(body.signals.every((signal: any) => signal.node_ids?.includes('cred-oidc'))).toBe(true);
  });
});

describe('GET /api/inference-rules', () => {
  it('returns rules[] with built-in inference rules', async () => {
    const { status, body } = await getJson<{ rules: Array<{ name: string }> }>('/api/inference-rules');
    expect(status).toBe(200);
    expect(Array.isArray(body.rules)).toBe(true);
    expect(body.rules.length).toBeGreaterThan(0);
  });
});

describe('GET /api/telemetry', () => {
  it('returns the structured telemetry payload', async () => {
    const { status, body } = await getJson<Record<string, unknown>>('/api/telemetry');
    expect(status).toBe(200);
    expect(body).toHaveProperty('inference_effectiveness');
  });
});

// =============================================
// Settings / Config
// =============================================

describe('GET /api/settings', () => {
  it('returns nested opsec block with approval_mode + approval_timeout_ms', async () => {
    const { status, body } = await getJson<{ opsec: { approval_mode: string; approval_timeout_ms: number } }>('/api/settings');
    expect(status).toBe(200);
    expect(body).toHaveProperty('opsec');
    expect(body.opsec).toHaveProperty('approval_mode');
    expect(body.opsec).toHaveProperty('approval_timeout_ms');
    expect(SettingsDtoSchema.parse(body).opsec.enabled).toBe(true);
  });
});

describe('PATCH /api/settings', () => {
  it('round-trips approval_timeout_ms (nested opsec.* update payload)', async () => {
    const patchRes = await patchJson('/api/settings', { approval_timeout_ms: 600000 });
    expect(patchRes.status).toBe(200);
    const after = await getJson<{ opsec: { approval_timeout_ms: number } }>('/api/settings');
    expect(after.body.opsec.approval_timeout_ms).toBe(600000);
  });

  it('round-trips enabled and explicit time_window null', async () => {
    const enabled = await patchJson('/api/settings', {
      enabled: false, time_window: { start_hour: 9, end_hour: 17 },
    });
    expect(SettingsUpdateResultSchema.parse(enabled.body).updated).toBe(true);
    let current = SettingsDtoSchema.parse((await getJson('/api/settings')).body);
    expect(current.opsec).toMatchObject({ enabled: false, time_window: { start_hour: 9, end_hour: 17 } });

    const cleared = await patchJson('/api/settings', { enabled: true, time_window: null });
    expect(SettingsUpdateResultSchema.parse(cleared.body).updated).toBe(true);
    current = SettingsDtoSchema.parse((await getJson('/api/settings')).body);
    expect(current.opsec).toMatchObject({ enabled: true, time_window: null });
  });
});

describe('encoded objective IDs', () => {
  it('accepts canonical objective vocabulary and rejects invalid graph types', async () => {
    const created = await postJson('/api/config/objectives', {
      description: 'Reach a managed host',
      target_node_type: 'host',
      target_criteria: { environment: 'production' },
      achievement_edge_types: ['ADMIN_TO'],
    });
    expect(created.status).toBe(201);
    const objective = ObjectiveCreateResponseSchema.parse(created.body).objective;
    expect(objective).toMatchObject({
      target_node_type: 'host', target_criteria: { environment: 'production' },
      achievement_edge_types: ['ADMIN_TO'],
    });

    const invalid = await postJson('/api/config/objectives', {
      description: 'Invalid vocabulary', target_node_type: 'invented_node_type',
    });
    expect(invalid.status).toBe(400);
    await fetch(`${baseUrl}/api/config/objectives/${encodeURIComponent(objective.id)}`, { method: 'DELETE' });
  });

  it('updates any non-slash ID and retains target_criteria', async () => {
    const id = 'objective:power user';
    engine.updateConfig({
      objectives: [...engine.getConfig().objectives, {
        id, description: 'Custom objective', target_node_type: 'host',
        target_criteria: { label: 'before' }, achieved: false,
      }],
    });
    const path = `/api/config/objectives/${encodeURIComponent(id)}`;
    const updated = await patchJson(path, {
      description: 'Updated objective', target_criteria: { label: 'after', tier: 0 },
    });
    expect(ObjectiveUpdateResponseSchema.parse(updated.body)).toMatchObject({
      updated: true,
      command_id: expect.any(String),
      idempotency_key: expect.any(String),
      replayed: false,
    });
    expect(engine.getConfig().objectives.find(objective => objective.id === id)?.target_criteria)
      .toEqual({ label: 'after', tier: 0 });

    const deleted = await fetch(`${baseUrl}${path}`, { method: 'DELETE' });
    expect(deleted.status, await deleted.clone().text()).toBe(200);
    expect(ObjectiveDeleteResponseSchema.parse(await deleted.json())).toMatchObject({
      deleted: true,
      command_id: expect.any(String),
      idempotency_key: expect.any(String),
      replayed: false,
    });
  });
});

describe('GET /api/config', () => {
  it('returns the engagement config with id matching the seed', async () => {
    const { status, body } = await getJson<{ id: string; name: string; scope: unknown }>('/api/config');
    expect(status).toBe(200);
    expect(body.id).toBe('api-integration');
    expect(body).toHaveProperty('scope');
  });
});

describe('PATCH /api/config/scope', () => {
  it('round-trips a scope update (adds a domain) — body is a flat ScopeConfig replacement', async () => {
    const { status } = await patchJson('/api/config/scope', {
      cidrs: ['10.0.0.0/24'],
      domains: ['acme.local', 'acme-corp.com'],
      exclusions: [],
    });
    expect(status).toBe(200);
    const after = await getJson<{ scope: { domains: string[] } }>('/api/config');
    expect(after.body.scope.domains).toContain('acme-corp.com');
  });
});

interface ScopePreviewBody {
  nodes_entering_scope: number;
  nodes_leaving_scope: number;
  pending_suggestions_resolved: string[];
  added: { cidrs: string[]; domains: string[]; exclusions: string[] };
  removed: { cidrs: string[]; domains: string[]; exclusions: string[] };
}

describe('POST /api/config/scope/preview', () => {
  // Current scope after the PATCH test above: cidrs ['10.0.0.0/24']; the seed
  // has host-jump @ 10.0.0.5 (in scope).
  it('echoes the add delta and reports entering count for a new CIDR', async () => {
    const { status, body } = await postJson<ScopePreviewBody>('/api/config/scope/preview', {
      cidrs: ['10.0.0.0/24', '10.99.0.0/24'],
      domains: ['acme.local', 'acme-corp.com'],
      exclusions: [],
    });
    expect(status).toBe(200);
    expect(body.added.cidrs).toContain('10.99.0.0/24');
    expect(body.removed.cidrs).toEqual([]);
    expect(typeof body.nodes_entering_scope).toBe('number');
  });

  it('counts nodes leaving scope when a CIDR is removed', async () => {
    const { status, body } = await postJson<ScopePreviewBody>('/api/config/scope/preview', {
      cidrs: [],
      domains: ['acme.local', 'acme-corp.com'],
      exclusions: [],
    });
    expect(status).toBe(200);
    expect(body.removed.cidrs).toContain('10.0.0.0/24');
    // host-jump @ 10.0.0.5 was in 10.0.0.0/24 and now isn't.
    expect(body.nodes_leaving_scope).toBeGreaterThanOrEqual(1);
  });

  it('is read-only — the live scope is unchanged after previewing', async () => {
    const before = await getJson<{ scope: { cidrs: string[] } }>('/api/config');
    await postJson('/api/config/scope/preview', { cidrs: [], domains: [], exclusions: [] });
    const after = await getJson<{ scope: { cidrs: string[] } }>('/api/config');
    expect(after.body.scope.cidrs).toEqual(before.body.scope.cidrs);
    expect(after.body.scope.cidrs).toContain('10.0.0.0/24');
  });

  it('400s on a non-object body', async () => {
    const { status } = await postJson('/api/config/scope/preview', 42);
    expect(status).toBe(400);
  });
});

describe('GET /api/agent-archetypes', () => {
  it('returns the agent-type catalog', async () => {
    const { status, body } = await getJson<{ archetypes: Array<{ id: string; label: string }> }>('/api/agent-archetypes');
    expect(status).toBe(200);
    const ids = body.archetypes.map(a => a.id);
    expect(ids).toContain('recon_scanner');
    expect(ids).toContain('default');
    expect(body.archetypes.every(a => typeof a.label === 'string')).toBe(true);
  });
});

describe('POST /api/agents/dispatch with an archetype', () => {
  it('expands the archetype into the task (role/skill/archetype)', async () => {
    const { status, body } = await postJson<{ dispatched: boolean; task: { archetype?: string; role?: string; skill?: string; status?: string; objective?: string } }>(
      '/api/agents/dispatch',
      { target_node_ids: ['cloud-id-power'], archetype: 'recon_scanner' },
    );
    expect(status).toBe(201);
    expect(body.dispatched).toBe(true);
    expect(body.task.archetype).toBe('recon_scanner');
    expect(body.task.role).toBe('default');
    expect(body.task.skill).toBe('network-recon'); // archetype defaultSkill = real skill basename
    // 'running' so a runner actually picks it up (not a dormant 'pending').
    expect(body.task.status).toBe('running');
    // The explicit-archetype path must NOT inject the archetype's defaultObjective:
    // those carry an uninterpolated `{target}` placeholder (only quick-deploy
    // interpolates it), so a leaked objective would feed the runner literal text.
    expect(body.task.objective ?? '').not.toContain('{target}');
  });
});

describe('POST /api/agents/dispatch — duplicate at the same node is refused (node dedup)', () => {
  it('a second same-archetype deploy at a node returns 409 node_dispatch_conflict, not a bogus frontier lease error', async () => {
    engine.addNode({
      id: 'host-dupe', type: 'host', label: '10.20.30.40', ip: '10.20.30.40',
      discovered_at: NOW, discovered_by: 'test', confidence: 1.0,
    });
    const first = await postJson<{ dispatched: boolean; task: { agent_id: string } }>(
      '/api/agents/dispatch', { target_node_ids: ['host-dupe'], archetype: 'recon_scanner' });
    expect(first.status).toBe(201);
    expect(first.body.dispatched).toBe(true);

    const dup = await postJson<{ dispatched: boolean; reason: string; node_id?: string; existing_agent_id?: string }>(
      '/api/agents/dispatch', { target_node_ids: ['host-dupe'], archetype: 'recon_scanner' });
    expect(dup.status).toBe(409);
    expect(dup.body.dispatched).toBe(false);
    expect(dup.body.reason).toBe('node_dispatch_conflict'); // NOT 'frontier_lease_conflict'
    expect(dup.body.node_id).toBe('host-dupe');
    expect(dup.body.existing_agent_id).toBe(first.body.task.agent_id);
  });
});

describe('POST /api/agents/dispatch to an arbitrary node (no archetype)', () => {
  it('auto-picks an explore-safe archetype (never full-surface default) + a default objective', async () => {
    // `user-op` has type `user`, which recommendArchetype maps to the full-surface
    // `default`. Node-scoped "deploy here" must downgrade that to recon_scanner and
    // attach a default explore objective, so the agent grounds before acting.
    const { status, body } = await postJson<{ dispatched: boolean; task: { archetype?: string; objective?: string; status?: string } }>(
      '/api/agents/dispatch',
      { target_node_ids: ['user-op'] },
    );
    expect(status).toBe(201);
    expect(body.dispatched).toBe(true);
    expect(body.task.archetype).not.toBe('default');
    expect(body.task.archetype).toBe('recon_scanner');
    expect(typeof body.task.objective).toBe('string');
    expect(body.task.objective).toContain('get_agent_context');
    expect(body.task.status).toBe('running');
  });
});

describe('POST /api/agents/dispatch-batch (fan-out)', () => {
  type BatchResult = {
    dispatched: Array<{ node_ids: string[]; task_id: string; agent_id: string }>;
    skipped: Array<{ node_ids: string[]; reason: string; existing_agent_id?: string }>;
    deferred: Array<{ node_ids: string[]; reason: string }>;
    summary: { dispatched: number; skipped: number; deferred: number; groups: number };
  };

  it('per-batch groups fresh nodes per agent (ceil(n/batch_size)) and de-dupes ids', async () => {
    // Fresh, un-dispatched seed nodes (cloud-id-power/user-op are claimed by earlier
    // tests). No operator_policy → no dispatch cap, so all register. A duplicate id
    // is de-duped before grouping. 3 distinct fresh → ceil(3/2) = 2 groups/agents.
    const { status, body } = await postJson<BatchResult>('/api/agents/dispatch-batch', {
      target_node_ids: ['idp-app-gha', 'idp-app-gha', 'cred-oidc', 'host-jump'],
      mode: 'per-batch',
      batch_size: 2,
    });
    expect(status).toBe(200);
    expect(body.summary.groups).toBe(2);
    expect(body.summary.dispatched).toBe(2);
    // Distinct agents; every fresh node dispatched exactly once (no overlap).
    expect(new Set(body.dispatched.map(d => d.agent_id)).size).toBe(2);
    const allNodes = body.dispatched.flatMap(d => d.node_ids).sort();
    expect(allNodes).toEqual(['cred-oidc', 'host-jump', 'idp-app-gha']);
  });

  it('re-running over already-worked nodes skips each node individually (per-node)', async () => {
    // All three nodes are now being worked (previous test) — each is skipped on its
    // own so counts are per-node, and nothing fresh remains to dispatch.
    const { status, body } = await postJson<BatchResult>('/api/agents/dispatch-batch', {
      target_node_ids: ['idp-app-gha', 'cred-oidc', 'host-jump'],
      mode: 'per-node',
    });
    expect(status).toBe(200);
    expect(body.summary.dispatched).toBe(0);
    expect(body.summary.skipped).toBe(3);
    expect(body.summary.groups).toBe(0);
    expect(body.skipped.every(s => s.reason === 'already_being_worked')).toBe(true);
    expect(body.skipped.every(s => s.node_ids.length === 1 && typeof s.existing_agent_id === 'string')).toBe(true);
  });

  it('a fresh node batched with a worked node still dispatches (no stranding)', async () => {
    // idp-app-gha is being worked; user-idp is fresh. Even grouped together in a
    // single per-batch lane, the worked node is skipped and the fresh one dispatches.
    engine.addNode({
      id: 'user-idp', type: 'idp_application', label: 'fresh-idp-app',
      idp_kind: 'ci_github_actions', discovered_at: NOW, confidence: 1.0,
    } as never);
    const { status, body } = await postJson<BatchResult>('/api/agents/dispatch-batch', {
      target_node_ids: ['idp-app-gha', 'user-idp'],
      mode: 'per-batch',
      batch_size: 5,
    });
    expect(status).toBe(200);
    expect(body.summary.skipped).toBe(1);
    expect(body.skipped[0].node_ids).toEqual(['idp-app-gha']);
    expect(body.summary.dispatched).toBe(1);
    expect(body.dispatched[0].node_ids).toEqual(['user-idp']);
  });

  it('rejects an unknown archetype for the whole request (400)', async () => {
    const { status, body } = await postJson<{ error?: string }>('/api/agents/dispatch-batch', {
      target_node_ids: ['idp-app-gha'],
      archetype: 'not_a_real_archetype',
    });
    expect(status).toBe(400);
    expect(body.error).toContain('Unknown agent type');
  });

  it('rejects an empty selection (400)', async () => {
    const { status } = await postJson('/api/agents/dispatch-batch', { target_node_ids: [] });
    expect(status).toBe(400);
  });
});

describe('POST /api/agents/:id/dismiss — force-remove a live agent', () => {
  it('non-force dismiss of a running agent still 409s (unchanged legacy behavior)', async () => {
    engine.registerAgent({ id: 'task-live-1', agent_id: 'agent-live-1', assigned_at: NOW, status: 'running', subgraph_node_ids: [] });
    const { status } = await postJson('/api/agents/task-live-1/dismiss', {});
    expect(status).toBe(409);
    expect(engine.getTask('task-live-1')?.status).toBe('running');
  });

  it('force dismiss terminates AND removes a still-running agent in one call', async () => {
    engine.registerAgent({ id: 'task-live-2', agent_id: 'agent-live-2', assigned_at: NOW, status: 'running', subgraph_node_ids: [] });
    const { status, body } = await postJson<{ dismissed: boolean; forced: boolean }>('/api/agents/task-live-2/dismiss', { force: true });
    expect(status).toBe(200);
    expect(body.dismissed).toBe(true);
    expect(body.forced).toBe(true);
    expect(engine.getTask('task-live-2')).toBeNull();
  });
});

describe('POST /api/agents/quick-deploy', () => {
  it('scopes a raw IP and dispatches the recommended recon agent in one step', async () => {
    const { status, body } = await postJson<{ dispatched: boolean; archetype: string; scope: { added_cidrs: string[] }; task: { objective?: string; status?: string } }>(
      '/api/agents/quick-deploy',
      { target: '10.30.0.5' },
    );
    expect(status).toBe(201);
    expect(body.dispatched).toBe(true);
    expect(body.archetype).toBe('recon_scanner');
    expect(body.scope.added_cidrs).toContain('10.30.0.5/32');
    expect(body.task.objective).toContain('10.30.0.5');
    expect(body.task.status).toBe('running');
    // the target is now really in scope (ad-hoc deploy auto-scopes)
    const cfg = await getJson<{ scope: { cidrs: string[] } }>('/api/config');
    expect(cfg.body.scope.cidrs).toContain('10.30.0.5/32');
  });

  it('honors a manually chosen archetype', async () => {
    const { status, body } = await postJson<{ archetype: string }>('/api/agents/quick-deploy', { target: 'shop.acme.local', archetype: 'web_tester' });
    expect(status).toBe(201);
    expect(body.archetype).toBe('web_tester');
  });

  it('400s on a target with no valid IPv4/CIDR/domain', async () => {
    const { status } = await postJson('/api/agents/quick-deploy', { target: 'not_a_host ::1' });
    expect(status).toBe(400);
  });

  it('rejects a disallowed model WITHOUT mutating scope (validate before updateScope)', async () => {
    const before = await getJson<{ scope: { cidrs: string[] } }>('/api/config');
    const { status } = await postJson('/api/agents/quick-deploy', { target: '10.44.0.9', model: 'not-a-real-model' });
    expect(status).toBe(400);
    // The rejected dispatch must not have widened engagement scope.
    const after = await getJson<{ scope: { cidrs: string[] } }>('/api/config');
    expect(after.body.scope.cidrs).not.toContain('10.44.0.9/32');
    expect(after.body.scope.cidrs).toEqual(before.body.scope.cidrs);
  });

  it('accepts an allowed model and dispatches', async () => {
    const { status, body } = await postJson<{ dispatched: boolean }>('/api/agents/quick-deploy', { target: '10.45.0.9', model: 'claude-opus-4-8' });
    expect(status).toBe(201);
    expect(body.dispatched).toBe(true);
  });

  it('rejects a no-model dispatch when default_agent_model is NOT in available_models', async () => {
    const prev = engine.getConfig().default_agent_model;
    engine.updateConfig({ default_agent_model: 'not-in-the-allowlist' }); // misconfigured default
    try {
      const before = await getJson<{ scope: { cidrs: string[] } }>('/api/config');
      // No model → falls back to the (disallowed) default; must not silently reach claude -p.
      const { status } = await postJson('/api/agents/quick-deploy', { target: '10.46.0.9' });
      expect(status).toBe(400);
      const after = await getJson<{ scope: { cidrs: string[] } }>('/api/config');
      expect(after.body.scope.cidrs).toEqual(before.body.scope.cidrs); // no scope mutation
    } finally {
      engine.updateConfig({ default_agent_model: prev ?? null });
    }
  });

  it('accepts a no-model dispatch when default_agent_model IS allowed', async () => {
    const prev = engine.getConfig().default_agent_model;
    engine.updateConfig({ default_agent_model: 'claude-opus-4-8' }); // valid default
    try {
      const { status, body } = await postJson<{ dispatched: boolean }>('/api/agents/quick-deploy', { target: '10.47.0.9' });
      expect(status).toBe(201);
      expect(body.dispatched).toBe(true);
    } finally {
      engine.updateConfig({ default_agent_model: prev ?? null });
    }
  });
});

// =============================================
// Frontier weights / OPSEC budget / Phases / Pending Actions
// =============================================

describe('GET /api/frontier/weights', () => {
  it('returns weights map', async () => {
    const { status, body } = await getJson<Record<string, unknown>>('/api/frontier/weights');
    expect(status).toBe(200);
    expect(body).toBeTypeOf('object');
  });
});

describe('PATCH then POST /api/frontier/weights/reset', () => {
  it('round-trips weights and reset', async () => {
    const before = await getJson<{ fan_out: Record<string, number>; noise: Record<string, number> }>('/api/frontier/weights');
    const { status: patchStatus, body: patchBody } = await patchJson(
      '/api/frontier/weights',
      { fan_out: { host: 99 } },
    );
    expect(patchStatus).toBe(200);
    expect(FrontierWeightsUpdateResultSchema.parse(patchBody)).toMatchObject({ updated: true, weights: { fan_out: { host: 99 } } });
    const { status: resetStatus, body: resetBody } = await postJson('/api/frontier/weights/reset', {});
    expect(resetStatus).toBe(200);
    expect(FrontierWeightsResetResultSchema.parse(resetBody)).toMatchObject({ reset: true, weights: before.body });
    const after = await getJson<{ fan_out: Record<string, number>; noise: Record<string, number> }>('/api/frontier/weights');
    expect(after.body).toEqual(before.body);
  });
});

describe('GET /api/opsec/budget', () => {
  it('returns the noise-budget snapshot', async () => {
    const { status, body } = await getJson<{ global_noise_spent?: number }>('/api/opsec/budget');
    expect(status).toBe(200);
    expect(body).toBeTypeOf('object');
  });
});

describe('GET /api/phases', () => {
  it('returns phases + current_phase', async () => {
    const { status, body } = await getJson<{ phases: unknown[]; current_phase: unknown }>('/api/phases');
    expect(status).toBe(200);
    expect(body).toHaveProperty('phases');
  });
});

describe('GET /api/actions/pending', () => {
  it('returns pending[] and count (empty in this harness)', async () => {
    const { status, body } = await getJson<{ pending: unknown[]; count: number }>('/api/actions/pending');
    expect(status).toBe(200);
    expect(Array.isArray(body.pending)).toBe(true);
    expect(body.count).toBe(body.pending.length);
  });
});

describe('POST /api/actions/{approve,deny}-batch', () => {
  // Seed a live pending approval; submit() returns a promise that resolves when the
  // operator (here, the batch endpoint) approves/denies it.
  const seed = (id: string) => {
    const pending = {
      action_id: id,
      technique: 'enumeration',
      description: `test ${id}`,
      target_ip: '10.0.0.9',
      opsec_context: {
        global_noise_spent: 0,
        noise_budget_remaining: 1,
        recommended_approach: 'normal' as const,
        defensive_signals: [],
      },
      validation_result: 'valid' as const,
    };
    engine.recordApprovalRequest(pending);
    return engine.getPendingActionQueue().submit(pending) as Promise<{
      status: string;
      reason?: string;
    }>;
  };

  it('approve-batch resolves the listed actions and skips unknown ids', async () => {
    const p1 = seed('batch-a1');
    const p2 = seed('batch-a2');
    const headers = {
      'Idempotency-Key': 'dashboard-batch-approve-1',
      'X-Overwatch-Command-Id': 'dashboard-batch-approve-command-1',
    };
    const { status, body } = await postJson<{ ok: boolean; resolved: number; total: number }>(
      '/api/actions/approve-batch',
      { action_ids: ['batch-a1', 'batch-a2', 'ghost-id'] },
      headers,
    );
    expect(status).toBe(200);
    expect(body.resolved).toBe(2);   // 2 real, unknown id skipped (not an error)
    expect(body.total).toBe(3);
    const [r1, r2] = await Promise.all([p1, p2]);
    expect(r1.status).toBe('approved');
    expect(r2.status).toBe('approved');

    const replay = await postJson<{ ok: boolean; resolved: number; total: number }>(
      '/api/actions/approve-batch',
      { action_ids: ['batch-a1', 'batch-a2', 'ghost-id'] },
      headers,
    );
    expect(replay).toEqual({
      status: 200,
      body: { ok: true, resolved: 2, total: 3 },
    });
  });

  it('deny-batch requires a non-empty reason', async () => {
    const { status } = await postJson('/api/actions/deny-batch', { action_ids: ['x'], reason: '   ' });
    expect(status).toBe(400);
  });

  it('deny-batch resolves with the shared reason', async () => {
    const p = seed('batch-d1');
    const { status, body } = await postJson<{ resolved: number }>(
      '/api/actions/deny-batch', { action_ids: ['batch-d1'], reason: 'too noisy for this window' });
    expect(status).toBe(200);
    expect(body.resolved).toBe(1);
    const res = await p;
    expect(res.status).toBe('denied');
    expect(res.reason).toBe('too noisy for this window');
  });

  it('empty action_ids → 400', async () => {
    const { status } = await postJson('/api/actions/approve-batch', { action_ids: [] });
    expect(status).toBe(400);
  });
});

describe('GET /api/campaigns', () => {
  it('returns campaigns[]', async () => {
    const { status, body } = await getJson<{ campaigns: unknown[] }>('/api/campaigns');
    expect(status).toBe(200);
    expect(Array.isArray(body.campaigns)).toBe(true);
  });
});

describe('durable playbook HTTP lifecycle', () => {
  let runId = '';

  it('lists, reads, idempotently claims, reports ownership conflicts, releases, and retries', async () => {
    const service = new PlaybookRunService(engine);
    const opened = service.open({
      definition: { definition_id: 'http-playbook', definition_version: 1, provider: 'aws', title: 'HTTP playbook' },
      credential_id: 'cred-oidc',
      normalized_inputs: {},
      steps: [{ step_id: 'identity', step: 1, description: 'Resolve identity', runner: 'run_tool', binary: 'aws', args: ['sts', 'get-caller-identity'], ready: true, status: 'ready' }],
    });
    runId = opened.run.run_id;

    const skippedRun = service.open({
      definition: { definition_id: 'http-skipped', definition_version: 1, provider: 'aws', title: 'Skipped HTTP playbook' },
      credential_id: 'cred-oidc', normalized_inputs: {},
      steps: [{ step_id: 'skip-me', step: 1, description: 'Skip me', runner: 'run_tool', binary: 'true', ready: true, status: 'ready' }],
      new_run: true,
    });
    service.skipStep(skippedRun.run.run_id, 'skip-me', 'Not applicable.');

    const list = await getJson(`/api/playbook-runs?credential_id=cred-oidc&open_only=true`);
    expect(list.status).toBe(200);
    const openRuns = PlaybookRunListResponseSchema.parse(list.body).runs;
    expect(openRuns.some(run => run.run_id === runId)).toBe(true);
    expect(openRuns.some(run => run.run_id === skippedRun.run.run_id)).toBe(false);
    const detail = await getJson(`/api/playbook-runs/${encodeURIComponent(runId)}`);
    expect(PlaybookRunResponseSchema.parse(detail.body).run.run_id).toBe(runId);

    const headers = {
      'Idempotency-Key': 'dashboard-playbook-claim-1',
      'X-Overwatch-Actor-Task-Id': 'task-dashboard',
    };
    const path = `/api/playbook-runs/${encodeURIComponent(runId)}/steps/identity/start`;
    const first = await postJson(path, {}, headers);
    expect(first.status).toBe(200);
    const claim = PlaybookStepClaimResponseSchema.parse(first.body);
    expect(claim.attempt).toMatchObject({ claimed_via: 'dashboard' });
    expect(claim.attempt.claimed_by_task_id).toBeUndefined();
    expect(claim.execution).toMatchObject({
      command_id: claim.attempt.execution_command_id,
      idempotency_key: claim.attempt.execution_idempotency_key,
    });
    const replay = await postJson(path, {}, headers);
    expect(replay).toEqual(first);

    const conflict = await postJson(path, {}, {
      'Idempotency-Key': 'terminal-playbook-claim-2',
      'X-Overwatch-Actor-Task-Id': 'task-terminal',
      'X-Overwatch-Client': 'cli',
    });
    expect(conflict.status).toBe(409);
    expect(JSON.stringify(conflict.body)).toContain('dashboard');

    const interrupted = await postJson(`/api/playbook-runs/${encodeURIComponent(runId)}/steps/identity/interrupt`, {
      reason: 'Dashboard descriptor was not executed.',
    });
    expect(interrupted.status).toBe(200);
    expect(PlaybookRunResponseSchema.parse(interrupted.body).run).toMatchObject({ status: 'interrupted' });

    const retry = await postJson(`/api/playbook-runs/${encodeURIComponent(runId)}/steps/identity/retry`, {}, {
      'Idempotency-Key': 'terminal-playbook-retry-1',
      'X-Overwatch-Actor-Task-Id': 'task-terminal',
      'X-Overwatch-Client': 'cli',
    });
    expect(retry.status).toBe(200);
    expect(PlaybookStepClaimResponseSchema.parse(retry.body).attempt).toMatchObject({
      attempt_number: 2, claimed_via: 'cli',
    });
    expect(PlaybookStepClaimResponseSchema.parse(retry.body).attempt.claimed_by_task_id)
      .toBeUndefined();
  });

  it('rejects invalid queries and bodies and returns precise missing-run errors', async () => {
    expect((await getJson('/api/playbook-runs?open_only=perhaps')).status).toBe(400);
    expect((await getJson('/api/playbook-runs/not-found')).status).toBe(404);
    expect((await postJson(`/api/playbook-runs/${encodeURIComponent(runId)}/steps/identity/skip`, { reason: 42 })).status).toBe(400);
  });
});

// =============================================
// Engagements / Tape
// =============================================

describe('GET /api/engagements', () => {
  it('returns engagements[]', async () => {
    const { status, body } = await getJson<{ engagements: unknown[] }>('/api/engagements');
    // 503 is acceptable when engagement-manager isn't configured (no configPath
    // on this harness); the smoke run uses a configPath, but this test boots
    // without one to keep setup minimal.
    expect([200, 503]).toContain(status);
    if (status === 200) expect(body).toHaveProperty('engagements');
  });
});

describe('GET /api/tape', () => {
  it('returns the attached recorder status', async () => {
    const { status, body } = await getJson<{ enabled: boolean }>('/api/tape');
    expect(status).toBe(200);
    expect(body.enabled).toBe(false);
  });
});

// =============================================
// Findings / Reports (B.2 + B.3)
// =============================================

describe('GET /api/findings', () => {
  it('returns findings[] + total + severity_summary', async () => {
    const { status, body } = await getJson<{ findings: unknown[]; total: number; severity_summary: Record<string, number> }>('/api/findings');
    expect(status).toBe(200);
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.severity_summary).toHaveProperty('critical');
    expect(body.severity_summary).toHaveProperty('high');
    expect(body.total).toBe(body.findings.length);
  });
});

describe('registered compatibility 404 envelopes', () => {
  it('preserves the action-explanation not-found envelope', async () => {
    const response = await fetch(`${baseUrl}/api/actions/missing-action/explain`);
    expect(response.status).toBe(404);
    expect(await response.json()).toMatchObject({
      action_id: 'missing-action',
      found: false,
    });
  });

  it('preserves the report-delete not-found envelope', async () => {
    const response = await fetch(`${baseUrl}/api/reports/missing-report`, {
      method: 'DELETE',
    });
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ deleted: false });
  });
});

describe('Reports lifecycle: render → list → get → delete', () => {
  it('round-trips a markdown report through the archive', async () => {
    const render = await postJson<{ report: { id: string; format: string; size_bytes: number } }>('/api/reports/render', {
      format: 'markdown',
      include_attack_paths: true,
    });
    expect(render.status).toBe(201);
    expect(render.body.report.format).toBe('markdown');
    expect(render.body.report.size_bytes).toBeGreaterThan(0);

    const list = await getJson<{ reports: Array<{ id: string }>; total: number }>('/api/reports');
    expect(list.status).toBe(200);
    expect(list.body.total).toBeGreaterThan(0);

    const downloadRes = await fetch(`${baseUrl}/api/reports/${render.body.report.id}`);
    expect(downloadRes.status).toBe(200);
    expect(downloadRes.headers.get('content-disposition')).toContain('attachment');
    const text = await downloadRes.text();
    expect(text).toContain('# Penetration Test Report');

    const del = await fetch(`${baseUrl}/api/reports/${render.body.report.id}`, { method: 'DELETE' });
    expect(del.status).toBe(200);

    const list2 = await getJson<{ total: number }>('/api/reports');
    expect(list2.body.total).toBe(list.body.total - 1);
  });

  it('rejects unsupported format with 400', async () => {
    const { status } = await postJson('/api/reports/render', { format: 'xml' });
    expect(status).toBe(400);
  });

  it('returns 503 and keeps serving when report recovery rejects before a handle is acquired', async () => {
    const archive = engine.getReportArchive();
    const verify = vi.spyOn(archive, 'verifyForRead')
      .mockRejectedValueOnce(new Error('synthetic report recovery failure'));
    try {
      const response = await fetch(`${baseUrl}/api/reports/recovery-failure`);
      expect(response.status).toBe(503);
      expect(await response.json()).toMatchObject({
        error: 'report is temporarily unavailable',
        reason: 'synthetic report recovery failure',
      });
      expect((await fetch(`${baseUrl}/api/health`)).status).toBe(200);
    } finally {
      verify.mockRestore();
    }
  });

  it('attack-paths section is rendered for objectives with reachable target', async () => {
    const render = await postJson<{ report: { id: string } }>('/api/reports/render', {
      format: 'markdown', include_attack_paths: true,
    });
    expect(render.status).toBe(201);
    const downloadRes = await fetch(`${baseUrl}/api/reports/${render.body.report.id}`);
    const text = await downloadRes.text();
    expect(text).toContain('## Attack Paths');
    expect(text).toContain('PowerUser');
    // Inferred edge from OIDC_FEDERATION_PIVOT must be flagged as inferred.
    expect(text).toMatch(/inferred by `oidc_federation_pivot`/);
  });
});

// =============================================
// Parameterized routes: paths, evidence-chains
// =============================================

describe('GET /api/paths/:objectiveId', () => {
  it('returns paths array (ASSUMES_ROLE chain to PowerUser)', async () => {
    const { status, body } = await getJson<{ count: number; paths: Array<{ nodes: string[] }> }>('/api/paths/obj-power');
    expect(status).toBe(200);
    expect(body.count).toBeGreaterThanOrEqual(1);
    expect(body.paths[0].nodes).toContain('cloud-id-power');
  });

  it('returns empty paths for unknown objective rather than 404', async () => {
    const { status, body } = await getJson<{ count: number }>('/api/paths/obj-does-not-exist');
    expect(status).toBe(200);
    expect(body.count).toBe(0);
  });
});

describe('GET /api/evidence-chains/:nodeId', () => {
  it('returns chains array for a known node id (empty when no findings link)', async () => {
    const { status, body } = await getJson<{ chains?: unknown[] }>('/api/evidence-chains/cloud-id-power');
    expect([200, 404]).toContain(status);
    if (status === 200) expect(body).toBeTypeOf('object');
  });
});

// =============================================
// Cross-endpoint consistency
// =============================================

describe('cross-endpoint consistency', () => {
  it('/api/state.agents matches /api/agents.agents', async () => {
    const state = await getJson<{ state: { agents: unknown[] } }>('/api/state');
    const agents = await getJson<{ agents: unknown[] }>('/api/agents');
    expect((state.body.state.agents ?? []).length).toBe(agents.body.agents.length);
  });

  it('/api/state.sessions matches /api/sessions.sessions', async () => {
    const state = await getJson<{ state: { sessions: unknown[] } }>('/api/state');
    const sessions = await getJson<{ sessions: unknown[] }>('/api/sessions');
    expect((state.body.state.sessions ?? []).length).toBe(sessions.body.sessions.length);
  });

  it('/api/state.graph_summary.nodes_by_type total matches /api/graph.nodes.length', async () => {
    const state = await getJson<{ state: { graph_summary: { nodes_by_type: Record<string, number> } } }>('/api/state');
    const graph = await getJson<{ nodes: unknown[] }>('/api/graph');
    const total = Object.values(state.body.state.graph_summary.nodes_by_type).reduce((s, c) => s + c, 0);
    expect(total).toBe(graph.body.nodes.length);
  });
});

// =============================================
// GET /api/find-paths (structured Attack Paths picker)
// =============================================

describe('GET /api/find-paths', () => {
  type FindPathsBody = { paths: unknown[]; analysis_status: string; warnings: string[]; count: number };
  const STATUSES = ['found', 'no_path', 'missing_endpoint', 'analysis_failed'];

  it('from+to returns 200 with a paths array + analysis_status (never 404)', async () => {
    const { status, body } = await getJson<FindPathsBody>('/api/find-paths?from=host-jump&to=cloud-id-power');
    expect(status).toBe(200);
    expect(Array.isArray(body.paths)).toBe(true);
    expect(STATUSES).toContain(body.analysis_status);
    expect(body.count).toBe(body.paths.length);
  });

  it('a bogus endpoint is a 200 missing_endpoint answer, not a thrown 404', async () => {
    const { status, body } = await getJson<FindPathsBody>('/api/find-paths?from=does-not-exist&to=cloud-id-power');
    expect(status).toBe(200);
    expect(body.analysis_status).toBe('missing_endpoint');
    expect(body.paths).toEqual([]);
  });

  it('objective returns 200 with paths + found/no_path', async () => {
    const { status, body } = await getJson<FindPathsBody>('/api/find-paths?objective=obj-power');
    expect(status).toBe(200);
    expect(Array.isArray(body.paths)).toBe(true);
    expect(['found', 'no_path']).toContain(body.analysis_status);
  });

  it('optimize=balanced is accepted', async () => {
    const { status } = await getJson<FindPathsBody>('/api/find-paths?from=host-jump&to=cloud-id-power&optimize=balanced');
    expect(status).toBe(200);
  });

  it('neither from+to nor objective → 400', async () => {
    const { status, body } = await getJson<{ error?: string }>('/api/find-paths?optimize=stealth');
    expect(status).toBe(400);
    expect(body.error).toBeTruthy();
  });
});

// =============================================
// 404s / method gating
// =============================================

describe('routing surface', () => {
  it('returns a deterministic JSON 404 for an unknown API route', async () => {
    const res = await fetch(`${baseUrl}/api/this-endpoint-does-not-exist`);
    expect(res.status).toBe(404);
    expect(res.headers.get('content-type')).toContain('application/json');
    await expect(res.json()).resolves.toMatchObject({ code: 'ROUTE_NOT_FOUND' });
  });
});

describe('Evidence image route (/api/evidence/<id>/image)', () => {
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0xff, 0x2a, 0x80]);

  it('serves a screenshot blob as raw image bytes with the right content-type', async () => {
    const sink = engine.getEvidenceStore().createBlobStream({ evidence_type: 'screenshot', filename: 'shot.png', kind: 'content' });
    sink.write(png);
    await sink.end();
    const res = await fetch(`${baseUrl}/api/evidence/${sink.evidence_id}/image`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('image/png');
    const bytes = Buffer.from(await res.arrayBuffer());
    expect(bytes.equals(png)).toBe(true); // binary-safe, byte-identical
  });

  it('404 for an unknown evidence id', async () => {
    const res = await fetch(`${baseUrl}/api/evidence/does-not-exist/image`);
    expect(res.status).toBe(404);
  });

  it('415 for non-screenshot (text) evidence — not a viewable image', async () => {
    const id = engine.getEvidenceStore().store({ evidence_type: 'command_output', content: 'not an image' });
    const res = await fetch(`${baseUrl}/api/evidence/${id}/image`);
    expect(res.status).toBe(415);
  });

  it('413 for an oversized screenshot record (bounds the read, no OOM)', async () => {
    // A screenshot-typed record whose content exceeds the 25MB image cap
    // (plantable via report_finding); the route must refuse before reading it.
    const id = engine.getEvidenceStore().store({ evidence_type: 'screenshot', filename: 'huge.png', content: 'x'.repeat(64) });
    // Force an oversized content_length on the manifest record.
    const rec = engine.getEvidenceStore().getRecord(id)!;
    (rec as { content_length: number }).content_length = 26 * 1024 * 1024;
    const res = await fetch(`${baseUrl}/api/evidence/${id}/image`);
    expect(res.status).toBe(413);
  });

  it('serves screenshot bytes with nosniff + inline disposition', async () => {
    const p = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const sink = engine.getEvidenceStore().createBlobStream({ evidence_type: 'screenshot', filename: 's.png', kind: 'content' });
    sink.write(p); await sink.end();
    const res = await fetch(`${baseUrl}/api/evidence/${sink.evidence_id}/image`);
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('content-disposition')).toBe('inline');
  });
});
