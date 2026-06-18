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

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, unlinkSync, mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { DashboardServer } from '../dashboard-server.js';
import { GraphEngine } from '../graph-engine.js';
import type { EngagementConfig } from '../../types.js';

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
  dashboard.attachMcpTools([
    { name: 'get_state', description: 'state' },
    { name: 'validate_action', description: 'validate' },
    { name: 'run_bash', description: 'bash' },
    { name: 'parse_output', description: 'parse' },
    { name: 'report_finding', description: 'report' },
    { name: 'get_system_prompt', description: 'prompt' },
  ]);
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

async function postJson<T = unknown>(path: string, body: unknown): Promise<{ status: number; body: T }> {
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
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

// =============================================
// Top-level state + graph
// =============================================

describe('GET /api/state', () => {
  it('returns state, graph, history_count with the wired keys the frontend reads', async () => {
    const { status, body } = await getJson<{ state: Record<string, unknown>; graph: { nodes: unknown[]; edges: unknown[] }; history_count: number }>('/api/state');
    expect(status).toBe(200);
    expect(body).toHaveProperty('state');
    expect(body).toHaveProperty('graph');
    expect(body).toHaveProperty('history_count');
    // Field names that previously drifted (B.0 audit fixes):
    expect(body.state).toHaveProperty('agents');             // was missing — only active_agents existed
    expect(body.state).toHaveProperty('sessions');           // injected by buildFrontendState
    expect(body.state).toHaveProperty('graph_summary');
    expect((body.state as { graph_summary: { nodes_by_type: unknown } }).graph_summary).toHaveProperty('nodes_by_type');
    expect(body.graph.nodes.length).toBeGreaterThan(0);
  });
});

describe('GET /api/graph', () => {
  it('returns nodes + edges arrays', async () => {
    const { status, body } = await getJson<{ nodes: unknown[]; edges: unknown[] }>('/api/graph');
    expect(status).toBe(200);
    expect(Array.isArray(body.nodes)).toBe(true);
    expect(Array.isArray(body.edges)).toBe(true);
  });
});

describe('GET /api/history', () => {
  it('returns entries[] with order=desc default', async () => {
    const { status, body } = await getJson<{ entries: unknown[]; total: number; order: string }>('/api/history?limit=10');
    expect(status).toBe(200);
    expect(body.order).toBe('desc');
    expect(Array.isArray(body.entries)).toBe(true);
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
    const { status, body } = await getJson<{ graph_stats: { nodes: number }; health?: unknown }>('/api/health');
    expect(status).toBe(200);
    expect(body).toHaveProperty('graph_stats');
    expect(body.graph_stats.nodes).toBeGreaterThan(0);
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
    const { status, body } = await getJson<{ total: number; categories: Record<string, number>; tools: Array<{ name: string; category: string }> }>('/api/mcp-tools');
    expect(status).toBe(200);
    expect(Array.isArray(body.tools)).toBe(true);
    expect(body.total).toBe(body.tools.length);
    expect(body.tools.map(tool => tool.name)).toContain('get_state');
    expect(body.categories).toHaveProperty('state-readiness');
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
    expect(typeof body.api.mcp_tools_registered).toBe('number');
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
  });
});

describe('PATCH /api/settings', () => {
  it('round-trips approval_timeout_ms (nested opsec.* update payload)', async () => {
    const patchRes = await patchJson('/api/settings', { approval_timeout_ms: 600000 });
    expect(patchRes.status).toBe(200);
    const after = await getJson<{ opsec: { approval_timeout_ms: number } }>('/api/settings');
    expect(after.body.opsec.approval_timeout_ms).toBe(600000);
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
    const { status, body } = await postJson<{ dispatched: boolean; task: { archetype?: string; role?: string; skill?: string; status?: string } }>(
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
    const before = await getJson<Record<string, number>>('/api/frontier/weights');
    const { status: patchStatus } = await patchJson('/api/frontier/weights', { weights: { hops_to_objective: 99 } });
    expect(patchStatus).toBe(200);
    const { status: resetStatus } = await postJson('/api/frontier/weights/reset', {});
    expect(resetStatus).toBe(200);
    const after = await getJson<Record<string, number>>('/api/frontier/weights');
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

describe('GET /api/campaigns', () => {
  it('returns campaigns[]', async () => {
    const { status, body } = await getJson<{ campaigns: unknown[] }>('/api/campaigns');
    expect(status).toBe(200);
    expect(Array.isArray(body.campaigns)).toBe(true);
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
  it('returns 503 when no tape controller is attached', async () => {
    const { status } = await getJson('/api/tape');
    // No controller wired on the harness → 503 is correct.
    expect(status).toBe(503);
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
// 404s / method gating
// =============================================

describe('routing surface', () => {
  // Note: the dashboard serves a single-page-app shell on any unmatched
  // path, so unknown /api/* routes return 200 with the SPA's index.html
  // (Content-Type: text/html). The client-side router then surfaces a
  // "page not found" inside the SPA — there is no 404 from the server
  // for `/api/whatever`. This is intentional: the dashboard runs at the
  // same origin as the API and the SPA handles its own 404s.
  it('unknown /api/* path falls through to the SPA shell, not a JSON 404', async () => {
    const res = await fetch(`${baseUrl}/api/this-endpoint-does-not-exist`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');
  });
});
