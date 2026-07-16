import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { MutationJournal } from '../../services/mutation-journal.js';
import { registerOperatorInfraTools, mockServiceId, registerMockServiceCore } from '../operator-infra.js';
import type { EngagementConfig } from '../../types.js';

let testDir: string;
let testStateFile: string;
const engines = new Set<GraphEngine>();

function makeConfig(): EngagementConfig {
  return {
    id: 'test-operator-infra',
    name: 'register_mock_service test',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: ['test.local'], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function createEngine(): GraphEngine {
  const engine = new GraphEngine(makeConfig(), testStateFile);
  engines.add(engine);
  return engine;
}

beforeEach(() => {
  testDir = mkdtempSync(join(tmpdir(), 'overwatch-operator-infra-'));
  testStateFile = join(testDir, 'state.json');
});

afterEach(() => {
  for (const engine of engines) engine.dispose();
  engines.clear();
  rmSync(testDir, { recursive: true, force: true });
});

function parse(result: any): any {
  return JSON.parse(result.content[0].text);
}

describe('register_mock_service', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;

  beforeEach(() => {
    engine = createEngine();
    handlers = {};
    const fakeServer = {
      registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
        handlers[name] = handler;
      },
    } as unknown as McpServer;
    registerOperatorInfraTools(fakeServer, engine);
  });

  it('creates a mock_service node and emits mock_service_registered event', async () => {
    const result = await handlers.register_mock_service({
      purpose: 'responder',
      protocol: 'smb',
      bind_host: '10.10.10.5',
      bind_port: 445,
    });
    const payload = parse(result);
    expect(payload.registered).toBe(true);
    expect(payload.new).toBe(true);

    const node = engine.getNode(payload.mock_service_id);
    expect(node).toBeTruthy();
    expect(node!.type).toBe('mock_service');
    expect(node!.mock_purpose).toBe('responder');
    expect(node!.bind_host).toBe('10.10.10.5');
    expect(node!.bind_port).toBe(445);
    expect(node!.opsec_loud).toBe(true);

    const events = engine.getFullHistory().filter(e => e.event_type === 'mock_service_registered');
    expect(events).toHaveLength(1);
  });

  it('is idempotent on (purpose, bind_host, bind_port, owner)', async () => {
    const args = {
      purpose: 'fake_ldap',
      protocol: 'ldap',
      bind_host: '127.0.0.1',
      bind_port: 389,
      agent_id: 'op-1',
    };
    const a = parse(await handlers.register_mock_service(args));
    const b = parse(await handlers.register_mock_service({ ...args, notes: 'second call' }));
    expect(a.mock_service_id).toBe(b.mock_service_id);
    expect(a.new).toBe(true);
    expect(b.new).toBe(false);

    // Refresh event distinct from registration event
    const refreshes = engine.getFullHistory().filter(e => e.event_type === 'mock_service_refreshed');
    expect(refreshes).toHaveLength(1);
  });

  it('different owners produce different mock_service ids for the same bind', () => {
    const a = mockServiceId('responder', '0.0.0.0', 445, 'op-a');
    const b = mockServiceId('responder', '0.0.0.0', 445, 'op-b');
    expect(a).not.toBe(b);
  });

  it('defaults opsec_loud=false for non-noisy purposes', async () => {
    const r = parse(await handlers.register_mock_service({
      purpose: 'reverse_shell_catcher',
      protocol: 'tcp',
      bind_host: '0.0.0.0',
      bind_port: 4444,
    }));
    expect(engine.getNode(r.mock_service_id)!.opsec_loud).toBe(false);
  });

  it('emits RUNS_ON edge when target_node is a host', () => {
    const nowIso = new Date().toISOString();
    engine.addNode({
      id: 'host-attacker',
      type: 'host',
      label: 'attacker',
      ip: '10.10.10.50',
      confidence: 1,
      discovered_at: nowIso,
    });
    const r = registerMockServiceCore(engine, {
      purpose: 'ntlmrelayx',
      protocol: 'smb',
      bind_host: '10.10.10.50',
      bind_port: 445,
      target_node: 'host-attacker',
    });
    expect(r.runs_on_edge.added).toBe(true);
  });

  it('does not commit a partial mock-service command when final audit construction fails', () => {
    engine.flushNow();
    const base = JSON.parse(readFileSync(testStateFile, 'utf8')).journalSnapshotSeq as number;
    vi.spyOn(engine, 'logActionEvent').mockImplementationOnce(() => {
      throw new Error('synthetic final mock-service failure');
    });
    const id = mockServiceId('http_capture', '127.0.0.1', 8080, undefined);

    expect(() => registerMockServiceCore(engine, {
      purpose: 'http_capture',
      protocol: 'http',
      bind_host: '127.0.0.1',
      bind_port: 8080,
      action_id: 'action-mock-service-failure',
    })).toThrow('synthetic final mock-service failure');

    expect(engine.getNode(id)).toBeNull();
    expect(new MutationJournal(testStateFile).readTransactionsSince(base)).toEqual([]);
  });
});

describe('mock_service node + edge schema', () => {
  it('is a registered NodeType', async () => {
    const { NODE_TYPES } = await import('../../types.js');
    expect(NODE_TYPES).toContain('mock_service');
  });

  it('has constraint definitions for OPERATED_BY, BAITED, RELAYED_VIA', async () => {
    const { EDGE_CONSTRAINTS } = await import('../../services/graph-schema.js');
    expect(EDGE_CONSTRAINTS.OPERATED_BY).toBeTruthy();
    expect(EDGE_CONSTRAINTS.BAITED).toBeTruthy();
    expect(EDGE_CONSTRAINTS.RELAYED_VIA).toBeTruthy();
    expect(EDGE_CONSTRAINTS.RUNS_ON!.source).toContain('mock_service');
  });
});

describe('BAITED inference rule', () => {
  let engine: GraphEngine;

  beforeEach(() => {
    engine = createEngine();
  });

  it('emits BAITED edge when a credential is reported with via_mock_service_id', () => {
    const nowIso = new Date().toISOString();
    const reg = registerMockServiceCore(engine, {
      purpose: 'responder',
      protocol: 'smb',
      bind_host: '0.0.0.0',
      bind_port: 445,
    });
    // Ingest a credential carrying via_mock_service_id; ingestFinding
    // triggers the inference engine.
    const r = engine.ingestFinding({
      id: 'finding-baited-1',
      timestamp: nowIso,
      tool_name: 'responder',
      nodes: [{
        id: 'cred-baited-1',
        type: 'credential',
        label: 'CORP\\victim:hash',
        confidence: 1,
        discovered_at: nowIso,
        cred_type: 'ntlmv2_challenge',
        cred_user: 'victim',
        cred_domain: 'CORP',
        via_mock_service_id: reg.mock_service_id,
      } as any],
      edges: [],
    } as any);

    const graph = (engine as any).ctx.graph as any;
    const baited = (graph.outEdges(reg.mock_service_id, 'cred-baited-1') as string[])
      .map(e => graph.getEdgeAttributes(e))
      .find((a: any) => a.type === 'BAITED');
    expect(baited).toBeTruthy();
    expect(r.inferred_edges.length).toBeGreaterThan(0);
  });

  it('does not emit BAITED when via_mock_service_id is missing', () => {
    const nowIso = new Date().toISOString();
    const r = engine.ingestFinding({
      id: 'finding-baited-2',
      timestamp: nowIso,
      tool_name: 'manual',
      nodes: [{
        id: 'cred-no-bait',
        type: 'credential',
        label: 'CORP\\u2:hash',
        confidence: 1,
        discovered_at: nowIso,
        cred_type: 'ntlmv2_challenge',
      } as any],
      edges: [],
    } as any);
    const graph = (engine as any).ctx.graph as any;
    const allInferred = (r.inferred_edges as string[]).map(e => graph.getEdgeAttributes(e));
    expect(allInferred.some((a: any) => a.type === 'BAITED')).toBe(false);
  });
});
