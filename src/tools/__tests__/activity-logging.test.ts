import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync, writeFileSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerLoggingTools } from '../logging.js';
import { registerScoringTools } from '../scoring.js';
import { registerFindingTools } from '../findings.js';
import { registerParseOutputTools } from '../parse-output.js';
import { registerAgentTools } from '../agents.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-activity-log.json';
const TEST_NMAP_FILE = './test-nmap.xml';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-activity-log',
    name: 'Activity Log Test Engagement',
    created_at: new Date().toISOString(),
    scope: {
      cidrs: ['10.10.10.0/30'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function cleanup(): void {
  try {
    if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
  } catch {}
  try {
    if (existsSync(TEST_NMAP_FILE)) unlinkSync(TEST_NMAP_FILE);
  } catch {}
}

describe('structured activity logging tools', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;
  let toolConfigs: Record<string, any>;

  beforeEach(() => {
    cleanup();
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    handlers = {};
    toolConfigs = {};

    const fakeServer = {
      registerTool(name: string, config: unknown, handler: (args: any) => Promise<any>) {
        toolConfigs[name] = config;
        handlers[name] = handler;
      },
    } as unknown as McpServer;

    registerLoggingTools(fakeServer, engine);
    registerScoringTools(fakeServer, engine);
    registerFindingTools(fakeServer, engine);
    registerParseOutputTools(fakeServer, engine);
    registerAgentTools(fakeServer, engine);
  });

  afterEach(() => {
    cleanup();
  });

  it('log_action_event generates event_id and action_id for planned actions', async () => {
    const result = await handlers.log_action_event({
      event_type: 'action_planned',
      description: 'Plan Nmap sweep',
      tool_name: 'nmap',
      target_node_ids: ['host-10-10-10-1'],
    });

    const payload = JSON.parse(result.content[0].text);
    expect(payload.event_id).toBeDefined();
    expect(payload.action_id).toBeDefined();

    const reloaded = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const history = reloaded.getFullHistory();
    const entry = history.find(candidate => candidate.action_id === payload.action_id);
    expect(entry?.event_type).toBe('action_planned');
    expect(entry?.tool_name).toBe('nmap');
  });

  it('validate_action logs a structured validation event and returns action_id', async () => {
    const result = await handlers.validate_action({
      target_node: 'host-10-10-10-1',
      technique: 'portscan',
      tool_name: 'nmap',
      description: 'Validate an nmap scan',
    });

    const payload = JSON.parse(result.content[0].text);
    expect(payload.action_id).toBeDefined();
    expect(payload.validation_result).toBeDefined();

    const history = engine.getFullHistory();
    const validationEvent = history.find(candidate => candidate.action_id === payload.action_id && candidate.event_type === 'action_validated');
    expect(validationEvent).toBeDefined();
    expect(validationEvent?.tool_name).toBe('nmap');
  });

  it('validate_action with target_ip logs target_ips instead of target_node_ids', async () => {
    const result = await handlers.validate_action({
      target_ip: '10.10.10.1',
      technique: 'portscan',
      tool_name: 'nmap',
      description: 'Pre-discovery scan of in-scope IP',
    });

    const payload = JSON.parse(result.content[0].text);
    expect(payload.action_id).toBeDefined();
    expect(payload.valid).toBe(true);

    const history = engine.getFullHistory();
    const event = history.find(candidate => candidate.action_id === payload.action_id && candidate.event_type === 'action_validated');
    expect(event).toBeDefined();
    expect(event?.target_ips).toEqual(['10.10.10.1']);
    expect(event?.target_node_ids).toBeUndefined();
  });

  it('validate_action rejects out-of-scope target_ip', async () => {
    const result = await handlers.validate_action({
      target_ip: '192.168.1.1',
      tool_name: 'nmap',
      description: 'Scan out-of-scope IP',
    });

    const payload = JSON.parse(result.content[0].text);
    expect(payload.valid).toBe(false);
    expect(payload.errors.some((e: string) => e.includes('out of scope'))).toBe(true);
  });

  it('validate_action is marked non-read-only and non-idempotent because it logs', () => {
    expect(toolConfigs.validate_action.annotations.readOnlyHint).toBe(false);
    expect(toolConfigs.validate_action.annotations.idempotentHint).toBe(false);
  });

  it('report_finding links finding_reported and finding_ingested to the same action_id', async () => {
    const actionId = 'action-find-1';
    await handlers.report_finding({
      agent_id: 'agent-1',
      action_id: actionId,
      tool_name: 'nxc',
      target_node_ids: ['host-10-10-10-1'],
      nodes: [
        { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', properties: { ip: '10.10.10.1' } },
        { id: 'svc-log-test', type: 'service', label: 'SMB test', properties: { port: 445, service_name: 'smb' } },
      ],
      edges: [
        { source: 'host-10-10-10-1', target: 'svc-log-test', type: 'RUNS', confidence: 1.0 },
      ],
    });

    const history = engine.getFullHistory().filter(candidate => candidate.action_id === actionId);
    expect(history.some(candidate => candidate.event_type === 'finding_reported')).toBe(true);
    expect(history.some(candidate => candidate.event_type === 'finding_ingested')).toBe(true);
    expect(history.find(candidate => candidate.event_type === 'finding_ingested')?.linked_finding_ids?.length).toBe(1);
  });

  it('report_finding generates and returns action_id when omitted', async () => {
    const result = await handlers.report_finding({
      agent_id: 'agent-implicit',
      tool_name: 'manual',
      nodes: [
        { id: 'host-manual-observation', type: 'host', label: 'manual host', properties: { ip: '10.10.10.3' } },
      ],
      edges: [],
    });

    const payload = JSON.parse(result.content[0].text);
    expect(payload.action_id).toBeDefined();

    const history = engine.getFullHistory().filter(candidate => candidate.action_id === payload.action_id);
    expect(history.some(candidate => candidate.event_type === 'finding_reported')).toBe(true);
    expect(history.some(candidate => candidate.event_type === 'finding_ingested')).toBe(true);
  });

  it('report_finding rejects invalid RUNS edges to shares with structured validation errors', async () => {
    // Pre-create host node so the edge validation focuses on type constraint
    engine.addNode({ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), discovered_by: 'test', confidence: 1.0 });
    const result = await handlers.report_finding({
      agent_id: 'agent-invalid-edge',
      tool_name: 'manual',
      nodes: [
        { id: 'share-invalid', type: 'share', label: 'public' },
      ],
      edges: [
        { source: 'host-10-10-10-1', target: 'share-invalid', type: 'RUNS', confidence: 1.0 },
      ],
    });

    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.validation_errors[0].code).toBe('edge_type_constraint');
    expect(engine.findEdgeId('host-10-10-10-1', 'share-invalid', 'RUNS')).toBeNull();
  });

  it('report_finding normalizes ad hoc credential fields before ingestion', async () => {
    await handlers.report_finding({
      agent_id: 'agent-normalize',
      tool_name: 'secretsdump',
      nodes: [
        { id: 'user-admin', type: 'user', label: 'admin' },
        {
          id: 'cred-admin',
          type: 'credential',
          label: 'admin hash',
          properties: {
            username: 'administrator',
            domain: 'test.local',
            nthash: '11223344556677889900aabbccddeeff',
            privileged: true,
            obtained: true,
          },
        },
      ],
      edges: [
        { source: 'user-admin', target: 'cred-admin', type: 'OWNS_CRED', confidence: 1.0 },
      ],
    });

    const graph = engine.exportGraph();
    const credNode = graph.nodes.find(n => n.properties.type === 'credential' && n.properties.cred_user === 'administrator');
    expect(credNode).toBeDefined();
    expect(credNode?.properties.cred_type).toBe('ntlm');
    expect(credNode?.properties.cred_material_kind).toBe('ntlm_hash');
    expect(credNode?.properties.cred_usable_for_auth).toBe(true);
    expect(credNode?.properties.cred_hash).toBe('11223344556677889900aabbccddeeff');
    expect(credNode?.properties.cred_domain).toBe('test.local');
  });

  it('parse_output logs parse metadata with the supplied action_id', async () => {
    const actionId = 'action-parse-1';
    await handlers.parse_output({
      tool_name: 'nxc',
      output: 'SMB  10.10.10.2  445  ACME\\\\scanner  [+]  Windows Server 2019',
      action_id: actionId,
      ingest: true,
    });

    const parseEvent = engine.getFullHistory().find(candidate => candidate.action_id === actionId && candidate.event_type === 'parse_output');
    expect(parseEvent).toBeDefined();
    expect(parseEvent?.tool_name).toBe('nxc');
    expect(parseEvent?.details?.ingested).toBe(true);
  });

  it('parse_output generates and returns action_id when omitted', async () => {
    const result = await handlers.parse_output({
      tool_name: 'nxc',
      output: 'SMB  10.10.10.2  445  ACME\\\\scanner  [+]  Windows Server 2019',
      ingest: true,
    });

    const payload = JSON.parse(result.content[0].text);
    expect(payload.action_id).toBeDefined();

    const history = engine.getFullHistory().filter(candidate => candidate.action_id === payload.action_id);
    expect(history.some(candidate => candidate.event_type === 'parse_output')).toBe(true);
    expect(history.some(candidate => candidate.event_type === 'finding_ingested')).toBe(true);
  });

  it('parse_output returns a warning when action context is omitted', async () => {
    const result = await handlers.parse_output({
      tool_name: 'nxc',
      output: 'SMB  10.10.10.2  445  ACME\\\\scanner  [+]  Windows Server 2019',
      ingest: true,
    });

    const payload = JSON.parse(result.content[0].text);
    expect(payload.warnings[0]).toContain('without prior action context');
    expect(engine.getFullHistory().some(candidate => candidate.event_type === 'instrumentation_warning')).toBe(true);
  });

  it('parse_output supports file_path for large artifacts', async () => {
    writeFileSync(
      TEST_NMAP_FILE,
      '<nmaprun><host><status state="up"/><address addr="10.10.10.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port></ports></host></nmaprun>',
      'utf8',
    );

    const result = await handlers.parse_output({
      tool_name: 'nmap',
      file_path: TEST_NMAP_FILE,
      ingest: true,
    });

    const payload = JSON.parse(result.content[0].text);
    expect(payload.parsed).toBe(true);
    expect(payload.parsed_from).toBe('file_path');
    expect(engine.getNode('host-10-10-10-2')).toBeTruthy();
  });

  it('parse_output rejects calls that provide both output and file_path', async () => {
    writeFileSync(TEST_NMAP_FILE, '<nmaprun></nmaprun>', 'utf8');

    const result = await handlers.parse_output({
      tool_name: 'nmap',
      output: '<nmaprun></nmaprun>',
      file_path: TEST_NMAP_FILE,
      ingest: true,
    });

    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.error).toContain('exactly one');
  });

  it('parse_output auto-builds both first-label and netbios_name domain aliases', async () => {
    engine.addNode({
      id: 'domain-corp-contoso-com',
      type: 'domain',
      label: 'corp.contoso.com',
      domain_name: 'corp.contoso.com',
      netbios_name: 'OLDNAME',
      discovered_at: new Date().toISOString(),
      discovered_by: 'test',
      confidence: 1.0,
    });

    await handlers.parse_output({
      tool_name: 'secretsdump',
      output: [
        'OLDNAME\\legacy.user:1103:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::',
        'CORP\\modern.user:1104:aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef:::',
      ].join('\n'),
      ingest: true,
    });

    expect(engine.getNode('user-corp-contoso-com-legacy-user')?.domain_name).toBe('corp.contoso.com');
    expect(engine.getNode('user-corp-contoso-com-modern-user')?.domain_name).toBe('corp.contoso.com');
    expect(engine.getNode('domain-corp-contoso-com')).toBeTruthy();
    expect(engine.getNode('user-oldname-legacy-user')).toBeNull();
    expect(engine.getNode('user-corp-modern-user')).toBeNull();
  });

  it('register_agent and update_agent create structured agent lifecycle events', async () => {
    const registration = await handlers.register_agent({
      agent_id: 'agent-ops',
      frontier_item_id: 'frontier-node-host-10-10-10-1',
      subgraph_node_ids: ['host-10-10-10-1'],
    });
    const taskId = JSON.parse(registration.content[0].text).task_id;

    await handlers.update_agent({
      task_id: taskId,
      status: 'completed',
      summary: 'Completed host enumeration',
    });

    const history = engine.getFullHistory();
    expect(history.some(candidate => candidate.event_type === 'agent_registered' && candidate.linked_agent_task_id === taskId)).toBe(true);
    expect(history.some(candidate => candidate.event_type === 'agent_updated' && candidate.linked_agent_task_id === taskId)).toBe(true);
  });

  it('update_agent is marked non-idempotent because it appends lifecycle history', () => {
    expect(toolConfigs.update_agent.annotations.readOnlyHint).toBe(false);
    expect(toolConfigs.update_agent.annotations.idempotentHint).toBe(false);
  });

  it('register_agent can omit subgraph_node_ids and get_agent_context auto-computes scope', async () => {
    // Pre-create host node so frontier resolution can find it
    engine.addNode({ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), discovered_by: 'test', confidence: 1.0 });
    const registration = await handlers.register_agent({
      agent_id: 'agent-auto-scope',
      frontier_item_id: 'frontier-node-host-10-10-10-1',
    });
    const taskId = JSON.parse(registration.content[0].text).task_id;

    const contextResult = await handlers.get_agent_context({
      task_id: taskId,
      hops: 1,
    });
    const payload = JSON.parse(contextResult.content[0].text);

    expect(payload.subgraph.nodes.some((node: { id: string }) => node.id === 'host-10-10-10-1')).toBe(true);
  });

  it('register_agent skips duplicate running tasks for the same frontier item', async () => {
    const first = await handlers.register_agent({
      agent_id: 'agent-one',
      frontier_item_id: 'frontier-node-host-10-10-10-1',
      subgraph_node_ids: ['host-10-10-10-1'],
    });
    const firstPayload = JSON.parse(first.content[0].text);

    const second = await handlers.register_agent({
      agent_id: 'agent-two',
      frontier_item_id: 'frontier-node-host-10-10-10-1',
      subgraph_node_ids: ['host-10-10-10-1'],
    });
    const secondPayload = JSON.parse(second.content[0].text);

    expect(secondPayload.skipped_existing).toBe(true);
    expect(secondPayload.task_id).toBe(firstPayload.task_id);
    expect(secondPayload.agent_id).toBe('agent-one');
  });

  it('dispatch_agents batch-registers frontier tasks and skips existing assignments', async () => {
    // Pre-create hosts so frontier generates incomplete_node items
    engine.addNode({ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), discovered_by: 'test', confidence: 1.0 });
    engine.addNode({ id: 'host-10-10-10-2', type: 'host', label: '10.10.10.2', ip: '10.10.10.2', discovered_at: new Date().toISOString(), discovered_by: 'test', confidence: 1.0 });
    const first = await handlers.dispatch_agents({
      count: 2,
      strategy: 'top_priority',
      types: ['incomplete_node'],
      hops: 1,
    });
    const firstPayload = JSON.parse(first.content[0].text);

    expect(firstPayload.dispatched).toHaveLength(2);
    expect(firstPayload.skipped_existing).toEqual([]);
    expect(firstPayload.dispatched.every((task: { frontier_type: string }) => task.frontier_type === 'incomplete_node')).toBe(true);

    const second = await handlers.dispatch_agents({
      count: 2,
      strategy: 'top_priority',
      types: ['incomplete_node'],
      hops: 1,
    });
    const secondPayload = JSON.parse(second.content[0].text);

    expect(secondPayload.skipped_existing.length).toBeGreaterThan(0);
    expect(secondPayload.dispatched.length).toBeLessThanOrEqual(2);
    const firstFrontierIds = new Set(firstPayload.dispatched.map((task: { frontier_item_id: string }) => task.frontier_item_id));
    expect(
      secondPayload.dispatched.every((task: { frontier_item_id: string }) => !firstFrontierIds.has(task.frontier_item_id)),
    ).toBe(true);
  });

  it('dispatch_agents includes total_candidates in response', async () => {
    engine.addNode({ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), discovered_by: 'test', confidence: 1.0 });
    engine.addNode({ id: 'host-10-10-10-2', type: 'host', label: '10.10.10.2', ip: '10.10.10.2', discovered_at: new Date().toISOString(), discovered_by: 'test', confidence: 1.0 });

    const result = await handlers.dispatch_agents({
      count: 1,
      strategy: 'top_priority',
      types: ['incomplete_node'],
      hops: 1,
    });
    const payload = JSON.parse(result.content[0].text);

    expect(typeof payload.total_candidates).toBe('number');
    expect(payload.total_candidates).toBeGreaterThanOrEqual(payload.dispatched.length);
  });

  it('dispatch_agents emits warning when no agents dispatched', async () => {
    // First exhaust all candidates of a given type
    engine.addNode({ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), discovered_by: 'test', confidence: 1.0 });
    await handlers.dispatch_agents({
      count: 100,
      strategy: 'top_priority',
      types: ['incomplete_node'],
      hops: 1,
    });

    // Second dispatch — all candidates already have running tasks
    const result = await handlers.dispatch_agents({
      count: 3,
      strategy: 'top_priority',
      types: ['incomplete_node'],
      hops: 1,
    });
    const payload = JSON.parse(result.content[0].text);

    expect(payload.dispatched).toHaveLength(0);
    expect(payload.warning).toContain('No agents dispatched');
  });

  it('dispatch_agents interleaves types in round-robin order for by_type strategy', async () => {
    engine.addNode({ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), discovered_by: 'test', confidence: 1.0 });
    engine.addNode({ id: 'host-10-10-10-2', type: 'host', label: '10.10.10.2', ip: '10.10.10.2', discovered_at: new Date().toISOString(), discovered_by: 'test', confidence: 1.0 });
    engine.addNode({
      id: 'svc-10-10-10-1-ldap',
      type: 'service',
      label: 'ldap/389',
      service_name: 'ldap',
      port: 389,
      discovered_at: new Date().toISOString(),
      discovered_by: 'test',
      confidence: 1.0,
    });
    engine.addNode({
      id: 'svc-10-10-10-2-smb',
      type: 'service',
      label: 'smb/445',
      service_name: 'smb',
      port: 445,
      discovered_at: new Date().toISOString(),
      discovered_by: 'test',
      confidence: 1.0,
    });
    engine.addEdge('host-10-10-10-1', 'svc-10-10-10-1-ldap', {
      type: 'RUNS',
      discovered_at: new Date().toISOString(),
      discovered_by: 'test',
      confidence: 0.6,
    });
    engine.addEdge('host-10-10-10-2', 'svc-10-10-10-2-smb', {
      type: 'RUNS',
      discovered_at: new Date().toISOString(),
      discovered_by: 'test',
      confidence: 0.6,
    });

    const result = await handlers.dispatch_agents({
      count: 4,
      strategy: 'by_type',
      types: ['incomplete_node', 'inferred_edge'],
      hops: 1,
    });
    const payload = JSON.parse(result.content[0].text);

    expect(payload.dispatched).toHaveLength(4);
    expect(payload.dispatched.map((task: { frontier_type: string }) => task.frontier_type)).toEqual([
      'incomplete_node',
      'inferred_edge',
      'incomplete_node',
      'inferred_edge',
    ]);
  });
});
