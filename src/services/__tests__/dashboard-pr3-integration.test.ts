import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  CampaignActionResponseSchema,
  CampaignChildrenResponseSchema,
  CampaignCloneResponseSchema,
  CampaignCreateResponseSchema,
  CampaignDeleteResponseSchema,
  CampaignDetailResponseSchema,
  CampaignDispatchResponseSchema,
  CampaignListResponseSchema,
  CampaignSplitResponseSchema,
  CampaignUpdateResponseSchema,
} from '../../contracts/dashboard-v1.js';
import type { EngagementConfig, FrontierItem } from '../../types.js';
import { DashboardServer } from '../dashboard-server.js';
import { GraphEngine } from '../graph-engine.js';
import { parseAndMaybeIngest } from '../parse-ingest.js';
import { __registerParserForTest } from '../parsers/index.js';

let engine: GraphEngine;
let dashboard: DashboardServer;
let baseUrl: string;
let tempDir: string;

const metrics = { hops_to_objective: 1, fan_out_estimate: 2, node_degree: 1, confidence: 1.4 };
const base = (id: string, type: FrontierItem['type']) => ({
  id, type, description: `Work ${id}`, graph_metrics: metrics, opsec_noise: 0.2, staleness_seconds: 0,
});

const items = new Map<string, FrontierItem>([
  ['fi-node', { ...base('fi-node', 'incomplete_node'), type: 'incomplete_node', node_id: 'host-a' }],
  ['fi-edge', { ...base('fi-edge', 'untested_edge'), type: 'untested_edge', edge_source: 'cred-edge', edge_target: 'host-edge', edge_type: 'VALID_ON' }],
  ['fi-credential', { ...base('fi-credential', 'credential_test'), type: 'credential_test', credential_id: 'cred-test', node_id: 'host-credential' }],
  ['fi-pivot', { ...base('fi-pivot', 'network_pivot'), type: 'network_pivot', node_id: 'host-pivot', pivot_host_id: 'pivot-host', via_pivot: 'pivot-user' }],
  ['fi-cidr', { ...base('fi-cidr', 'network_discovery'), type: 'network_discovery', target_cidr: '10.0.0.0/24' }],
  ['fi-campaign', { ...base('fi-campaign', 'network_discovery'), type: 'network_discovery', target_cidr: '10.0.0.0/24' }],
  ['fi-paused', { ...base('fi-paused', 'network_discovery'), type: 'network_discovery', target_cidr: '10.0.0.0/24' }],
  ['fi-terminal', { ...base('fi-terminal', 'network_discovery'), type: 'network_discovery', target_cidr: '10.0.0.0/24' }],
  ['fi-terminal-other', { ...base('fi-terminal-other', 'network_discovery'), type: 'network_discovery', target_cidr: '10.0.0.0/24' }],
  ['fi-stale', { ...base('fi-stale', 'incomplete_node'), type: 'incomplete_node', node_id: 'host-a' }],
]);
const stale = new Set(['fi-stale']);
const scopes = new Map<string, string[]>([
  ['fi-node', ['host-a']],
  ['fi-edge', ['cred-edge', 'host-edge']],
  ['fi-credential', ['cred-test', 'host-credential']],
  ['fi-pivot', ['host-pivot', 'pivot-host', 'pivot-user']],
  ['fi-cidr', []],
  ['fi-campaign', []],
  ['fi-paused', []],
  ['fi-terminal', []],
  ['fi-terminal-other', []],
  ['fi-stale', ['host-a']],
]);

function config(): EngagementConfig {
  return {
    id: 'pr3-dashboard', name: 'PR3 dashboard', created_at: '2026-07-15T00:00:00Z',
    scope: { cidrs: ['10.0.0.0/24'], domains: ['example.test'], exclusions: [] },
    objectives: [], opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

async function request<T>(path: string, method = 'GET', body?: unknown): Promise<{ status: number; body: T }> {
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    ...(body === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  });
  return { status: response.status, body: await response.json() as T };
}

beforeAll(async () => {
  tempDir = mkdtempSync(join(tmpdir(), 'overwatch-pr3-dashboard-'));
  engine = new GraphEngine(config(), join(tempDir, 'state.json'));
  for (const node of [
    { id: 'host-a', type: 'host', label: 'host-a', ip: '10.0.0.10' },
    { id: 'host-edge', type: 'host', label: 'host-edge', ip: '10.0.0.11' },
    { id: 'host-credential', type: 'host', label: 'host-credential', ip: '10.0.0.12' },
    { id: 'host-pivot', type: 'host', label: 'host-pivot', ip: '10.0.0.13' },
    { id: 'pivot-host', type: 'host', label: 'pivot-host', ip: '10.0.0.14' },
    { id: 'cred-edge', type: 'credential', label: 'credential-edge', cred_type: 'token' },
    { id: 'cred-test', type: 'credential', label: 'credential-test', cred_type: 'token' },
    { id: 'pivot-user', type: 'user', label: 'pivot-user' },
  ]) engine.addNode({ ...node, discovered_at: '2026-07-15T00:00:00Z', confidence: 1 } as never);

  dashboard = new DashboardServer(engine, 0, '127.0.0.1');
  const result = await dashboard.start();
  if (!result.started) throw new Error(result.error);
  baseUrl = dashboard.address;
});

beforeEach(() => {
  vi.spyOn(engine, 'getFrontierItem').mockImplementation(id => items.get(id) ?? null);
  vi.spyOn(engine, 'getActionableFrontierItem').mockImplementation(id => stale.has(id) ? null : items.get(id) ?? null);
  vi.spyOn(engine, 'computeSubgraphNodeIds').mockImplementation(id => scopes.get(id) ?? []);
});

afterAll(async () => {
  await dashboard.stop();
  engine.dispose();
  rmSync(tempDir, { recursive: true, force: true });
});

describe('PR3 authoritative frontier dispatch over HTTP', () => {
  it('dispatches node, edge, credential, pivot, and CIDR shapes from canonical server scope', async () => {
    const canonicalCampaign = engine.createCampaign({
      name: 'Canonical membership', strategy: 'custom', item_ids: ['fi-node'], abort_conditions: [],
    });
    for (const id of ['fi-node', 'fi-edge', 'fi-credential', 'fi-pivot', 'fi-cidr']) {
      const result = await request<{ task: { subgraph_node_ids: string[]; archetype: string; objective: string; campaign_id?: string } }>(
        '/api/agents/dispatch', 'POST', {
          frontier_item_id: id,
          target_node_ids: ['forged-node'],
          archetype: 'report_scribe',
          campaign_id: 'forged-campaign',
        },
      );
      expect(result.status).toBe(201);
      expect(result.body.task.subgraph_node_ids).toEqual(scopes.get(id));
      expect(result.body.task.archetype).not.toBe('report_scribe');
      expect(result.body.task.objective).toBe(items.get(id)?.description);
      expect(result.body.task.campaign_id).toBe(id === 'fi-node' ? canonicalCampaign.id : undefined);
    }
    expect(engine.getCampaign(canonicalCampaign.id)?.status).toBe('active');
  });

  it('refuses canonical campaign work while paused', async () => {
    const campaign = engine.createCampaign({
      name: 'Paused membership', strategy: 'custom', item_ids: ['fi-paused'], abort_conditions: [],
    });
    engine.activateCampaign(campaign.id);
    engine.pauseCampaign(campaign.id);
    const result = await request<{ reason: string }>('/api/agents/dispatch', 'POST', { frontier_item_id: 'fi-paused' });
    expect(result.status).toBe(409);
    expect(result.body.reason).toBe('campaign_not_dispatchable');
    expect(engine.getRunningTaskForFrontierItem('fi-paused')).toBeNull();
  });

  it('does not redispatch a campaign item that already reached a terminal result', async () => {
    const campaign = engine.createCampaign({
      name: 'Partially complete', strategy: 'network_discovery',
      item_ids: ['fi-terminal', 'fi-terminal-other'], abort_conditions: [],
    });
    engine.activateCampaign(campaign.id);
    engine.updateCampaignProgress(campaign.id, 'fi-terminal', 'success');
    const result = await request<{ reason: string }>('/api/agents/dispatch', 'POST', { frontier_item_id: 'fi-terminal' });
    expect(result.status).toBe(409);
    expect(result.body.reason).toBe('already_succeeded');
    expect(engine.getRunningTaskForFrontierItem('fi-terminal')).toBeNull();
  });

  it('rejects missing, stale/filtered, and leased frontier IDs', async () => {
    expect((await request('/api/agents/dispatch', 'POST', { frontier_item_id: 'missing' })).status).toBe(404);
    expect((await request('/api/agents/dispatch', 'POST', { frontier_item_id: 'fi-stale' })).status).toBe(409);
    // fi-node was leased by the prior test; a duplicate cannot create another task.
    const leased = await request<{ reason: string }>('/api/agents/dispatch', 'POST', { frontier_item_id: 'fi-node' });
    expect(leased.status).toBe(409);
    expect(leased.body.reason).toBe('frontier_lease_conflict');
  });
});

describe('PR3 exact campaign HTTP contracts', () => {
  it('uses exact task campaign attribution for clones and never guesses from ambiguous membership', () => {
    const original = engine.createCampaign({
      name: 'Attribution original', strategy: 'custom', item_ids: ['clone-fi'], abort_conditions: [],
    });
    const clone = engine.cloneCampaign(original.id)!;
    expect(engine.linkFindingToCampaign({ finding_id: 'fallback-must-not-land', frontier_item_id: 'clone-fi' }))
      .toBeUndefined();
    engine.registerAgent({
      id: 'clone-task', agent_id: 'clone-agent', assigned_at: '2026-07-15T00:00:00Z', status: 'running',
      subgraph_node_ids: [], frontier_item_id: 'clone-fi', campaign_id: clone.id,
    });
    expect(engine.linkFindingToCampaign({ finding_id: 'clone-exact', task_id: 'clone-task', frontier_item_id: 'clone-fi' }))
      .toBe(clone.id);
    expect(engine.getCampaign(clone.id)?.findings).toEqual(['clone-exact']);
    expect(engine.getCampaign(original.id)?.findings).toEqual([]);
  });

  it('round-trips create, update, clone, and draft delete envelopes', async () => {
    const created = await request('/api/campaigns', 'POST', {
      name: 'Editable', strategy: 'custom', item_ids: ['camp-a', 'camp-b'],
    });
    const campaign = CampaignCreateResponseSchema.parse(created.body).campaign;
    expect(created.status).toBe(201);

    const updated = await request(`/api/campaigns/${encodeURIComponent(campaign.id)}`, 'PATCH', { name: 'Edited' });
    expect(CampaignUpdateResponseSchema.parse(updated.body).campaign.name).toBe('Edited');

    const cloned = await request(`/api/campaigns/${encodeURIComponent(campaign.id)}/clone`, 'POST', {});
    const clone = CampaignCloneResponseSchema.parse(cloned.body).campaign;
    const deleted = await request(`/api/campaigns/${encodeURIComponent(clone.id)}`, 'DELETE');
    expect(CampaignDeleteResponseSchema.parse(deleted.body)).toMatchObject({ deleted: true });
    expect(CampaignListResponseSchema.parse((await request('/api/campaigns')).body).campaigns.some(c => c.id === campaign.id)).toBe(true);
  });

  it('validates the campaign dispatch response envelope', async () => {
    const campaign = engine.createCampaign({
      name: 'Dispatch contract', strategy: 'network_discovery', item_ids: ['fi-campaign'], abort_conditions: [],
    });
    const response = await request(`/api/campaigns/${campaign.id}/dispatch`, 'POST', { max_agents: 1, hops: 0 });
    expect(response.status).toBe(200);
    expect(CampaignDispatchResponseSchema.parse(response.body)).toMatchObject({
      campaign_id: campaign.id,
      dispatched: [{ frontier_item_id: 'fi-campaign' }],
    });
  });

  it('splits only valid roots/counts, projects children, and guards structural deletion', async () => {
    const created = CampaignCreateResponseSchema.parse((await request('/api/campaigns', 'POST', {
      name: 'Split root', strategy: 'custom', item_ids: ['split-a', 'split-b', 'split-c'],
    })).body).campaign;
    expect((await request(`/api/campaigns/${created.id}/split`, 'POST', { count: 1 })).status).toBe(400);
    expect((await request(`/api/campaigns/${created.id}/split`, 'POST', { count: 4 })).status).toBe(400);

    const splitResponse = await request(`/api/campaigns/${created.id}/split`, 'POST', { count: 2 });
    const split = CampaignSplitResponseSchema.parse(splitResponse.body);
    expect(split).toMatchObject({ parent_id: created.id, count: 2 });
    const children = CampaignChildrenResponseSchema.parse((await request(`/api/campaigns/${created.id}/children`)).body);
    expect(children.children).toHaveLength(2);
    expect(children.aggregated_progress?.total).toBe(3);
    expect((await request(`/api/campaigns/${created.id}/split`, 'POST', { count: 2 })).status).toBe(409);
    expect((await request(`/api/campaigns/${split.children[0].id}/split`, 'POST', { count: 2 })).status).toBe(409);
    expect((await request(`/api/campaigns/${created.id}`, 'DELETE')).status).toBe(409);
  });

  it('cascades parent lifecycle from child-derived status and rejects invalid operations', async () => {
    const parent = CampaignCreateResponseSchema.parse((await request('/api/campaigns', 'POST', {
      name: 'Lifecycle root', strategy: 'custom', item_ids: ['life-a', 'life-b'],
    })).body).campaign;
    const split = CampaignSplitResponseSchema.parse((await request(`/api/campaigns/${parent.id}/split`, 'POST', { count: 2 })).body);
    const childId = split.children[0].id;
    expect(CampaignActionResponseSchema.parse((await request(`/api/campaigns/${childId}/action`, 'POST', { action: 'activate' })).body).campaign.status).toBe('active');
    expect(CampaignActionResponseSchema.parse((await request(`/api/campaigns/${parent.id}/action`, 'POST', { action: 'pause' })).body).campaign.status).toBe('paused');
    expect(CampaignActionResponseSchema.parse((await request(`/api/campaigns/${parent.id}/action`, 'POST', { action: 'resume' })).body).campaign.status).toBe('active');
    expect((await request(`/api/campaigns/${parent.id}/action`, 'POST', { action: 'complete' })).status).toBe(400);
    expect((await request('/api/campaigns/not-found/action', 'POST', { action: 'pause' })).status).toBe(404);
    expect((await request('/api/campaigns/not-found')).status).toBe(404);
    expect((await request('/api/campaigns/not-found/children')).status).toBe(404);
  });

  it('resolves durable finding IDs through activity and deduplicates parent/child projections', async () => {
    engine.addNode({
      id: 'finding-host', type: 'host', label: 'Finding host', ip: '10.0.0.50',
      discovered_at: '2026-07-15T00:00:00Z', confidence: 1,
    });
    const parent = engine.createCampaign({
      name: 'Finding root', strategy: 'custom', item_ids: ['finding-a', 'finding-b'], abort_conditions: [],
    });
    const children = engine.splitCampaign(parent.id, 2)!;
    const task = engine.registerAgent({
      id: 'finding-task', agent_id: 'same-label', assigned_at: '2026-07-15T00:00:00Z',
      status: 'running', subgraph_node_ids: ['finding-host'], frontier_item_id: 'finding-a', campaign_id: children[0].id,
    });
    expect(task.ok).toBe(true);
    engine.logActionEvent({
      description: 'Finding reported: Finding host', event_type: 'finding_reported', category: 'finding',
      linked_agent_task_id: 'finding-task', linked_finding_ids: ['finding-record-1'],
      details: { ingested_node_ids: ['finding-host'] },
    });
    engine.logActionEvent({
      description: 'Output parsed and ingested after the richer finding event', event_type: 'parse_output', category: 'finding',
      linked_agent_task_id: 'finding-task', linked_finding_ids: ['finding-record-1'],
      details: { parsed_nodes: 1, parsed_edges: 0 },
    });
    engine.linkFindingToCampaign({ finding_id: 'finding-record-1', task_id: 'finding-task', frontier_item_id: 'finding-a' });
    engine.linkFindingToCampaign({ finding_id: 'finding-record-1', task_id: 'finding-task', frontier_item_id: 'finding-a' });

    const detail = CampaignDetailResponseSchema.parse((await request(`/api/campaigns/${parent.id}`)).body);
    expect(detail.campaign.findings).toEqual(['finding-record-1']);
    expect(detail.campaign.findings_count).toBe(1);
    expect(detail.finding_details[0]).toMatchObject({
      id: 'finding-record-1', label: 'Finding host', type: 'host', created_at: expect.any(String),
    });
  });

  it('keeps canonical detail for duplicate-content parser findings with fresh IDs', async () => {
    let attempt = 0;
    const dispose = __registerParserForTest('campaign-detail-dedup-parser', () => ({
      id: `finding-dedup-${++attempt}`,
      agent_id: 'parser-agent',
      timestamp: `2026-07-15T00:00:0${attempt}Z`,
      tool_name: 'campaign-detail-dedup-parser',
      nodes: [{ id: 'parser-detail-host', type: 'host', label: 'Parser detail host', ip: '10.0.0.51' }],
      edges: [],
    }));
    try {
      const campaign = engine.createCampaign({
        name: 'Parser detail', strategy: 'custom', item_ids: ['parser-detail-fi'], abort_conditions: [],
      });
      for (const actionId of ['parser-detail-action-1', 'parser-detail-action-2']) {
        const result = parseAndMaybeIngest(engine, {
          tool_name: 'campaign-detail-dedup-parser', outputText: 'identical parser output',
          action_id: actionId, frontier_item_id: 'parser-detail-fi', agent_id: 'parser-agent', ingest: true,
        });
        expect(result.parse_outcome).toBe('ok');
      }
      const detail = CampaignDetailResponseSchema.parse((await request(`/api/campaigns/${campaign.id}`)).body);
      expect(detail.campaign.findings).toEqual(['finding-dedup-1', 'finding-dedup-2']);
      expect(detail.finding_details).toEqual([
        expect.objectContaining({ id: 'finding-dedup-1', label: 'Parser detail host', type: 'host' }),
        expect.objectContaining({ id: 'finding-dedup-2', label: 'Parser detail host', type: 'host' }),
      ]);
    } finally {
      dispose();
    }
  });
});
