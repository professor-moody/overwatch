import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  DASHBOARD_OPERATION_IDS,
  DashboardHttpRegistry,
  buildDashboardPath,
  getDashboardRouteManifest,
  matchDashboardEndpoint,
} from '../dashboard-api-v1.js';
import {
  DashboardWebSocketRegistry,
  buildDashboardWebSocketPath,
  matchDashboardWebSocketPath,
  normalizeLegacyAgentDispatchDescription,
} from '../dashboard-v1.js';

interface DashboardManifest {
  compatibility_version: number;
  routes: Array<{
    operation_id: string;
    method: string;
    path: string;
    success_statuses: number[];
  }>;
  schemas: Record<string, {
    path: string;
    query: string;
    body: string;
    responses: Record<string, string>;
  }>;
  websockets: Record<string, { operation_id: string; path: string }>;
  schema_hash: string;
}

const manifestPath = resolve(process.cwd(), 'src/contracts/dashboard-api-v1.manifest.json');
const generatedPath = resolve(process.cwd(), 'src/dashboard-next/src/lib/api.generated.ts');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as DashboardManifest;

function samplePathParams(template: string): Record<string, string> {
  return Object.fromEntries(
    [...template.matchAll(/\{([^}]+)\}/g)].map(([, name]) => [name, `${name} value/with spaces`]),
  );
}

describe('dashboard compatibility-v1 registry', () => {
  it('has 102 unique operation IDs and method/path pairs', () => {
    const registryIds = Object.keys(DashboardHttpRegistry);
    expect(registryIds).toHaveLength(102);
    expect(new Set(registryIds).size).toBe(registryIds.length);
    expect(registryIds.sort()).toEqual([...DASHBOARD_OPERATION_IDS].sort());

    const routeKeys = getDashboardRouteManifest().map(route => `${route.method} ${route.path}`);
    expect(new Set(routeKeys).size).toBe(routeKeys.length);
  });

  it('round-trips every route template through the shared builder and matcher', () => {
    for (const [operationId, endpoint] of Object.entries(DashboardHttpRegistry)) {
      const input = samplePathParams(endpoint.path);
      const pathname = buildDashboardPath(operationId as never, input as never);
      const matched = matchDashboardEndpoint(endpoint.method, pathname);
      expect(matched?.operation_id, `${endpoint.method} ${pathname}`).toBe(operationId);
      expect(matched?.path_params).toEqual(input);
    }
  });

  it('keeps route, response-schema, WebSocket, and generated hashes synchronized', () => {
    expect(manifest.routes).toEqual(getDashboardRouteManifest());
    expect(Object.keys(manifest.schemas).sort()).toEqual(Object.keys(DashboardHttpRegistry).sort());

    for (const [operationId, endpoint] of Object.entries(DashboardHttpRegistry)) {
      const schema = manifest.schemas[operationId];
      expect(schema.path).toMatch(/^[a-f0-9]{64}$/);
      expect(schema.query).toMatch(/^[a-f0-9]{64}$/);
      expect(schema.body).toMatch(/^[a-f0-9]{64}$/);
      expect(Object.keys(schema.responses).sort()).toEqual(Object.keys(endpoint.responses).sort());
      for (const hash of Object.values(schema.responses)) expect(hash).toMatch(/^[a-f0-9]{64}$/);
    }

    expect(Object.fromEntries(
      Object.entries(manifest.websockets).map(([channel, definition]) => [channel, {
        operation_id: definition.operation_id,
        path: definition.path,
      }]),
    )).toEqual(Object.fromEntries(
      Object.entries(DashboardWebSocketRegistry).map(([channel, definition]) => [channel, {
        operation_id: definition.operation_id,
        path: definition.path,
      }]),
    ));

    const generated = readFileSync(generatedPath, 'utf8');
    expect(manifest.schema_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(generated).toContain(`DASHBOARD_API_SCHEMA_HASH = "${manifest.schema_hash}"`);
    expect(generated).toContain(`schema SHA-256 ${manifest.schema_hash}`);
  });

  it('round-trips every registered WebSocket path and rejects unknown channels', () => {
    expect(matchDashboardWebSocketPath(buildDashboardWebSocketPath('main', {}))).toEqual({
      channel: 'main',
      params: {},
    });
    expect(matchDashboardWebSocketPath(buildDashboardWebSocketPath('session', {
      session_id: 'session value/with spaces',
    }))).toEqual({
      channel: 'session',
      params: { session_id: 'session value/with spaces' },
    });
    expect(matchDashboardWebSocketPath(buildDashboardWebSocketPath('action_output', {
      action_id: 'action value/with spaces',
    }))).toEqual({
      channel: 'action_output',
      params: { action_id: 'action value/with spaces' },
    });
    expect(matchDashboardWebSocketPath('/ws/typo')).toBeNull();
  });

  it('rejects unknown fields for every JSON mutation body', () => {
    for (const endpoint of Object.values(DashboardHttpRegistry)) {
      if (!['POST', 'PATCH', 'DELETE'].includes(endpoint.method)) continue;
      const baseline = endpoint.body_schema.safeParse({});
      const withUnexpected = endpoint.body_schema.safeParse({ __unexpected_dashboard_field: true });
      if (baseline.success) expect(withUnexpected.success, endpoint.operation_id).toBe(false);
    }
  });

  it('requires stable envelopes for operator-critical responses', () => {
    const operations = [
      'dispatchAgent',
      'dispatchAgentBatch',
      'quickDeployAgent',
      'getAgentArchetypes',
      'interpretCommand',
      'getProposedPlans',
      'getAgentQueries',
      'getApplicationCommand',
      'getActiveApplicationCommands',
      'getFindings',
      'listReports',
      'renderReport',
      'getConfig',
      'updateConfig',
      'closeSession',
      'resumeSession',
      'updateSession',
    ] as const;
    for (const operationId of operations) {
      for (const schema of Object.values(DashboardHttpRegistry[operationId].responses)) {
        expect(schema.safeParse({}).success, operationId).toBe(false);
      }
    }
  });

  it('repairs legacy undefined planner labels only for display', () => {
    const description = 'Agent dispatched: planner-1 for undefined';
    expect(normalizeLegacyAgentDispatchDescription({
      event_type: 'agent_registered',
      description,
      details: { role: 'planner' },
    })).toBe('Agent dispatched: planner-1 as operator planner');
    expect(normalizeLegacyAgentDispatchDescription({
      event_type: 'action_started',
      description,
    })).toBe(description);
    expect(normalizeLegacyAgentDispatchDescription({
      description: 'Agent dispatched: planner-old for undefined',
    })).toBe('Agent dispatched: planner-old as operator planner');
    expect(normalizeLegacyAgentDispatchDescription({
      description: 'Unrelated action for undefined',
    })).toBe('Unrelated action for undefined');
  });
});
