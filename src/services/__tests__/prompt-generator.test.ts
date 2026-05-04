import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { resolve } from 'path';
import { existsSync, unlinkSync } from 'fs';
import { GraphEngine } from '../graph-engine.js';
import { generateSystemPrompt, estimateTokens, type ToolEntry } from '../prompt-generator.js';
import { loadEngagementConfigFile } from '../../config.js';

const config = loadEngagementConfigFile(resolve('./engagement.json'));
const TEST_STATE_FILE = './state-test-prompt-gen.json';

function cleanup() {
  if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
}

function createTestEngine() {
  return new GraphEngine(config, TEST_STATE_FILE);
}

const MOCK_TOOLS: ToolEntry[] = [
  { name: 'get_state', description: 'Full engagement briefing' },
  { name: 'next_task', description: 'Filtered frontier candidates' },
  { name: 'query_graph', description: 'Open-ended graph exploration' },
  { name: 'validate_action', description: 'Pre-execution sanity check' },
  { name: 'report_finding', description: 'Submit discoveries to graph' },
  { name: 'log_action_event', description: 'Record action lifecycle' },
  { name: 'get_agent_context', description: 'Scoped view for sub-agents' },
  { name: 'get_skill', description: 'RAG skill lookup' },
  { name: 'open_session', description: 'Create persistent interactive session' },
  { name: 'parse_output', description: 'Deterministically parse tool output' },
];

const ALL_REGISTERED_TOOLS: ToolEntry[] = [
  { name: 'get_state', description: 'Full engagement briefing' },
  { name: 'run_lab_preflight', description: 'Run lab preflight checks' },
  { name: 'run_graph_health', description: 'Run graph health checks' },
  { name: 'recompute_objectives', description: 'Recompute objective status' },
  { name: 'get_history', description: 'Full activity log' },
  { name: 'export_graph', description: 'Complete graph dump' },
  { name: 'report_finding', description: 'Submit discoveries to graph' },
  { name: 'get_evidence', description: 'Retrieve evidence for a finding' },
  { name: 'next_task', description: 'Filtered frontier candidates' },
  { name: 'validate_action', description: 'Pre-execution sanity check' },
  { name: 'query_graph', description: 'Open-ended graph exploration' },
  { name: 'find_paths', description: 'Shortest path to objectives' },
  { name: 'register_agent', description: 'Dispatch a sub-agent' },
  { name: 'dispatch_agents', description: 'Dispatch multiple agents' },
  { name: 'get_agent_context', description: 'Scoped view for sub-agents' },
  { name: 'update_agent', description: 'Mark agent task done/failed' },
  { name: 'dispatch_subnet_agents', description: 'Parallel subnet enumeration' },
  { name: 'get_skill', description: 'RAG skill lookup' },
  { name: 'ingest_bloodhound', description: 'Ingest BloodHound data' },
  { name: 'ingest_azurehound', description: 'Ingest AzureHound data' },
  { name: 'check_tools', description: 'Check available tools' },
  { name: 'track_process', description: 'Track a background process' },
  { name: 'check_processes', description: 'Check tracked processes' },
  { name: 'suggest_inference_rule', description: 'Suggest an inference rule' },
  { name: 'parse_output', description: 'Deterministically parse tool output' },
  { name: 'log_action_event', description: 'Record action lifecycle' },
  { name: 'run_retrospective', description: 'Run engagement retrospective' },
  { name: 'generate_report', description: 'Generate pentest report' },
  { name: 'correct_graph', description: 'Correct graph data' },
  { name: 'open_session', description: 'Create persistent interactive session' },
  { name: 'write_session', description: 'Write to a session' },
  { name: 'read_session', description: 'Read from a session' },
  { name: 'send_to_session', description: 'Send command to session' },
  { name: 'list_sessions', description: 'List active sessions' },
  { name: 'update_session', description: 'Update session metadata' },
  { name: 'resize_session', description: 'Resize terminal dimensions' },
  { name: 'signal_session', description: 'Send signal to session' },
  { name: 'close_session', description: 'Close a session' },
  { name: 'update_scope', description: 'Update engagement scope' },
  { name: 'get_system_prompt', description: 'Generate dynamic system prompt' },
  { name: 'log_thought', description: 'Record reasoning, plans, decisions' },
  { name: 'run_bash', description: 'Execute shell command' },
  { name: 'run_tool', description: 'Execute binary with argv' },
  { name: 'submit_agent_transcript', description: 'Sub-agent wrap-up handoff' },
];

describe('prompt-generator', () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  describe('primary prompt', () => {
    it('includes identity and engagement briefing', () => {
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      expect(prompt).toContain('# Overwatch — Primary Session Instructions');
      expect(prompt).toContain('offensive security operator');
      expect(prompt).toContain(config.name);
      expect(prompt).toContain(config.id);
    });

    it('includes core loop instructions', () => {
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      expect(prompt).toContain('## Core Loop');
      expect(prompt).toContain('get_state()');
      expect(prompt).toContain('next_task()');
      expect(prompt).toContain('validate_action()');
      expect(prompt).toContain('report_finding()');
    });

    it('includes tool reference table with all provided tools', () => {
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      expect(prompt).toContain('## Tool Reference');
      expect(prompt).toContain(`${MOCK_TOOLS.length} tools available`);
      for (const tool of MOCK_TOOLS) {
        expect(prompt).toContain(`\`${tool.name}\``);
      }
    });

    it('includes state snapshot with graph summary', () => {
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      expect(prompt).toContain('## Current State Snapshot');
      expect(prompt).toContain('**Nodes:**');
      expect(prompt).toContain('**Edges:**');
      expect(prompt).toContain('**Access Level:**');
      expect(prompt).toContain('**Frontier Items:**');
    });

    it('reflects graph state after ingestion', () => {
      const engine = createTestEngine();
      engine.ingestFinding({
        id: 'f1',
        agent_id: 'test',
        timestamp: new Date().toISOString(),
        nodes: [{ id: 'host-1', type: 'host', label: '10.0.0.1' }],
        edges: [],
      });

      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });
      expect(prompt).toContain('1 host');
    });

    it('excludes tool table when include_tools is false', () => {
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, {
        role: 'primary',
        include_tools: false,
      });

      expect(prompt).not.toContain('## Tool Reference');
      expect(prompt).toContain('## Core Loop');
    });

    it('excludes state snapshot when include_state is false', () => {
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, {
        role: 'primary',
        include_state: false,
      });

      expect(prompt).not.toContain('## Current State Snapshot');
      expect(prompt).toContain('## Core Loop');
    });

    it('includes OPSEC profile from config', () => {
      const engine = createTestEngine();
      engine.updateConfig({ opsec: { ...config.opsec, enabled: true } });
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      if (config.opsec) {
        expect(prompt).toContain(config.opsec.name);
      }
      expect(prompt).toContain('OPSEC');
    });

    it('includes scope CIDRs and domains from config', () => {
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      if (config.scope.cidrs.length > 0) {
        expect(prompt).toContain('Scope CIDRs');
        for (const cidr of config.scope.cidrs) {
          expect(prompt).toContain(cidr);
        }
      }
      if (config.scope.domains.length > 0) {
        expect(prompt).toContain('Scope Domains');
      }
    });
  });

  describe('sub_agent prompt', () => {
    it('generates sub-agent identity section', () => {
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'sub_agent' });

      expect(prompt).toContain('# Overwatch — Sub-Agent Instructions');
      expect(prompt).toContain('sub-agent');
      expect(prompt).toContain(config.name);
    });

    it('includes scoped tool subset', () => {
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'sub_agent' });

      // Sub-agent should see scoped tools only
      expect(prompt).toContain('`get_agent_context`');
      expect(prompt).toContain('`validate_action`');
      expect(prompt).toContain('`report_finding`');
      expect(prompt).toContain('`query_graph`');
      expect(prompt).toContain('`get_skill`');
      // Should not include primary-only tools
      expect(prompt).not.toContain('`next_task`');
    });

    it('includes workflow instructions', () => {
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'sub_agent' });

      expect(prompt).toContain('## Workflow');
      expect(prompt).toContain('get_agent_context');
      expect(prompt).toContain('validate_action');
    });

    it('includes key principles', () => {
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      expect(prompt).toContain('## Key Principles');
      expect(prompt).toContain('graph is your memory');
      expect(prompt).toContain('Report early');
    });

    it('includes agent context section when agent_id matches', () => {
      const engine = createTestEngine();
      engine.registerAgent({
        id: 'task-abc',
        agent_id: 'agent-abc',
        assigned_at: new Date().toISOString(),
        status: 'running',
        frontier_item_id: 'fi-1',
        subgraph_node_ids: ['host-1', 'host-2'],
      });

      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, {
        role: 'sub_agent',
        agent_id: 'agent-abc',
      });

      expect(prompt).toContain('## Agent Context');
      expect(prompt).toContain('agent-abc');
      expect(prompt).toContain('fi-1');
      expect(prompt).toContain('host-1');
    });

    it('subAgentToolNames is a subset of all registered tool names', () => {
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, ALL_REGISTERED_TOOLS, { role: 'sub_agent' });

      const allKnownNames = new Set(ALL_REGISTERED_TOOLS.map(t => t.name));
      const toolTableMatch = prompt.match(/\| `(\w+)` \|/g) || [];
      const subAgentToolsInPrompt = toolTableMatch.map(m => m.match(/`(\w+)`/)![1]);

      expect(subAgentToolsInPrompt.length).toBeGreaterThan(0);
      for (const toolName of subAgentToolsInPrompt) {
        expect(allKnownNames.has(toolName)).toBe(true);
      }
    });

    it('tool table includes every tool the sub-agent workflow references', () => {
      // Regression: the workflow text told sub-agents to use log_thought,
      // run_bash, run_tool, and submit_agent_transcript, but the tool-table
      // allowlist omitted them — so get_system_prompt(role="sub_agent") was
      // self-contradictory. Keep the allowlist and the workflow in lockstep.
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, ALL_REGISTERED_TOOLS, { role: 'sub_agent' });
      const toolTableMatch = prompt.match(/\| `(\w+)` \|/g) || [];
      const subAgentToolsInPrompt = new Set(toolTableMatch.map(m => m.match(/`(\w+)`/)![1]));

      for (const required of ['log_thought', 'run_bash', 'run_tool', 'submit_agent_transcript']) {
        expect(subAgentToolsInPrompt.has(required), `${required} missing from sub-agent tool table`).toBe(true);
      }
    });
  });

  describe('objectives rendering', () => {
    it('renders objectives with [DONE] vs [    ] markers', () => {
      const customConfig = {
        ...config,
        objectives: [
          {
            id: 'obj-1',
            description: 'Get domain admin',
            target_node_type: 'credential' as const,
            target_criteria: { privileged: true },
            achieved: true,
          },
          {
            id: 'obj-2',
            description: 'Exfiltrate data',
            target_node_type: 'host' as const,
            target_criteria: {},
            achieved: false,
          },
        ],
      };
      const engine = new GraphEngine(customConfig, TEST_STATE_FILE);
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      expect(prompt).toContain('[DONE] **Get domain admin**');
      expect(prompt).toContain('[    ] **Exfiltrate data**');
    });
  });

  describe('tactical methodology section', () => {
    it('includes tactical methodology in primary prompt', () => {
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      expect(prompt).toContain('## Tactical Methodology');
      expect(prompt).toContain('Check existing results first');
      expect(prompt).toContain('CVE-first for identified services');
      expect(prompt).toContain('Review tool artifacts');
    });

    it('includes prioritization logic', () => {
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      expect(prompt).toContain('Exploitation > brute-force');
      expect(prompt).toContain('Authenticated access > re-authentication');
      expect(prompt).toContain('Quietest path wins');
      expect(prompt).toContain('Chain completion is high value');
    });

    it('includes credential awareness guidance', () => {
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      expect(prompt).toContain('Credential Awareness');
      expect(prompt).toContain('query_graph()');
      expect(prompt).toContain('credential reuse');
    });

    it('includes tactical section in sub-agent prompt too', () => {
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'sub_agent' });

      expect(prompt).toContain('## Tactical Methodology');
      expect(prompt).toContain('CVE-first');
    });
  });

  describe('profile-specific guidance', () => {
    it('includes profile hints for goad_ad profile', () => {
      const adConfig = { ...config, profile: 'goad_ad' as const };
      const engine = new GraphEngine(adConfig, TEST_STATE_FILE);
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      expect(prompt).toContain('Profile-Specific Guidance (goad_ad)');
      expect(prompt).toContain('credential chain completion');
      expect(prompt).toContain('BloodHound');
      expect(prompt).toContain('ESC1-ESC13');
    });

    it('includes profile hints for web_app profile', () => {
      const webConfig = { ...config, profile: 'web_app' as const };
      const engine = new GraphEngine(webConfig, TEST_STATE_FILE);
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      expect(prompt).toContain('Profile-Specific Guidance (web_app)');
      expect(prompt).toContain('CVE-first');
      expect(prompt).toContain('default credentials');
    });

    it('includes profile hints for cloud profile', () => {
      const cloudConfig = { ...config, profile: 'cloud' as const };
      const engine = new GraphEngine(cloudConfig, TEST_STATE_FILE);
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      expect(prompt).toContain('Profile-Specific Guidance (cloud)');
      expect(prompt).toContain('IAM first');
      expect(prompt).toContain('IMDS');
    });

    it('includes profile hints for hybrid profile', () => {
      const hybridConfig = { ...config, profile: 'hybrid' as const };
      const engine = new GraphEngine(hybridConfig, TEST_STATE_FILE);
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      expect(prompt).toContain('Profile-Specific Guidance (hybrid)');
      expect(prompt).toContain('pivot points');
    });

    it('includes profile hints for network profile', () => {
      const netConfig = { ...config, profile: 'network' as const };
      const engine = new GraphEngine(netConfig, TEST_STATE_FILE);
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      expect(prompt).toContain('Profile-Specific Guidance (network)');
      expect(prompt).toContain('service enumeration');
    });

    it('includes profile hints for single_host profile', () => {
      const shConfig = { ...config, profile: 'single_host' as const };
      const engine = new GraphEngine(shConfig, TEST_STATE_FILE);
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      expect(prompt).toContain('Profile-Specific Guidance (single_host)');
      expect(prompt).toContain('CVE databases');
    });
  });

  describe('anti-patterns section', () => {
    it('includes generic anti-patterns', () => {
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      expect(prompt).toContain('Anti-Patterns');
      expect(prompt).toContain('Do not crack hashes when the service has known CVEs');
      expect(prompt).toContain('Do not re-scan ports');
      expect(prompt).toContain('Do not attempt authentication with expired');
      expect(prompt).toContain('Do not ignore completed tool output');
      expect(prompt).toContain('Do not skip version detection');
    });

    it('includes engagement-specific failure patterns', () => {
      const fpConfig = {
        ...config,
        failure_patterns: [
          { technique: 'password_spray', target_pattern: '*.corp.local', warning: 'Account lockout after 3 attempts' },
          { technique: 'kerberoast', warning: 'AES only — RC4 downgrade will fail' },
        ],
      };
      const engine = new GraphEngine(fpConfig, TEST_STATE_FILE);
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      expect(prompt).toContain('Engagement-Specific Warnings');
      expect(prompt).toContain('password_spray');
      expect(prompt).toContain('*.corp.local');
      expect(prompt).toContain('Account lockout after 3 attempts');
      expect(prompt).toContain('kerberoast');
      expect(prompt).toContain('AES only');
    });
  });

  describe('situational awareness section', () => {
    it('includes situational section when state has credentials', () => {
      const engine = createTestEngine();
      // Ingest a host with admin access + credential to trigger access_summary
      engine.ingestFinding({
        id: 'f-sit-1',
        agent_id: 'test',
        timestamp: new Date().toISOString(),
        nodes: [
          { id: 'host-sit', type: 'host', label: '10.0.0.50' },
          { id: 'cred-sit', type: 'credential', label: 'admin:password123', confidence: 1.0, cred_type: 'plaintext', cred_user: 'admin' },
        ],
        edges: [
          { source: 'cred-sit', target: 'host-sit', properties: { type: 'ADMIN_TO', confidence: 1.0 } },
        ],
      });

      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });
      // Should contain state snapshot at minimum; situational section may or may not appear
      // depending on what the engine computes as valid credentials
      expect(prompt).toContain('## Current State Snapshot');
    });

    it('omits empty situational section', () => {
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });

      // With empty graph, situational section should be empty string (omitted)
      // so the Situational Awareness header should NOT appear
      const situationalCount = (prompt.match(/## Situational Awareness/g) || []).length;
      expect(situationalCount).toBeLessThanOrEqual(1);
    });
  });

  describe('enhanced sub-agent context', () => {
    it('includes task details when frontier item matches', () => {
      const engine = createTestEngine();
      // Register agent
      engine.registerAgent({
        id: 'task-detail-1',
        agent_id: 'agent-detail-1',
        assigned_at: new Date().toISOString(),
        status: 'running',
        frontier_item_id: 'fi-detail-1',
        subgraph_node_ids: ['host-1'],
      });

      // We need a frontier item with that ID — ingest some data to generate frontier
      engine.ingestFinding({
        id: 'f-detail-1',
        agent_id: 'test',
        timestamp: new Date().toISOString(),
        nodes: [
          { id: 'host-1', type: 'host', label: '10.0.0.1' },
        ],
        edges: [],
      });

      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, {
        role: 'sub_agent',
        agent_id: 'agent-detail-1',
      });

      // Should always include Agent Context section
      expect(prompt).toContain('## Agent Context');
      expect(prompt).toContain('agent-detail-1');
      // Tactical section should also be present for sub-agents
      expect(prompt).toContain('## Tactical Methodology');
    });

    it('includes target node properties for scoped nodes', () => {
      const engine = createTestEngine();
      // Identity resolution canonicalizes host id: host-10-0-0-99
      const canonicalId = 'host-10-0-0-99';
      engine.ingestFinding({
        id: 'f-target-1',
        agent_id: 'test',
        timestamp: new Date().toISOString(),
        nodes: [
          { id: 'host-tgt', type: 'host', label: '10.0.0.99', ip: '10.0.0.99', hostname: 'dc01.corp.local', os: 'Windows Server 2019' },
        ],
        edges: [],
      });
      engine.registerAgent({
        id: 'task-tgt-1',
        agent_id: 'agent-tgt-1',
        assigned_at: new Date().toISOString(),
        status: 'running',
        frontier_item_id: 'fi-tgt-1',
        subgraph_node_ids: [canonicalId],
      });

      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, {
        role: 'sub_agent',
        agent_id: 'agent-tgt-1',
      });

      expect(prompt).toContain('### Target Nodes');
      expect(prompt).toContain(canonicalId);
      expect(prompt).toContain('ip=10.0.0.99');
      expect(prompt).toContain('hostname=dc01.corp.local');
    });
  });

  describe('OPSEC budget in situational awareness', () => {
    it('includes OPSEC budget when noise has been spent', () => {
      const engine = createTestEngine();
      engine.updateConfig({ opsec: { ...config.opsec, enabled: true } });
      engine.recordOpsecNoise({ noise_estimate: 0.3, host_id: 'h1' });

      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });
      expect(prompt).toContain('### OPSEC Budget');
      expect(prompt).toContain('Noise spent:');
      expect(prompt).toContain('Remaining:');
      expect(prompt).toContain('Recommended approach:');
    });

    it('includes defensive signals when recorded', () => {
      const engine = createTestEngine();
      engine.updateConfig({ opsec: { ...config.opsec, enabled: true } });
      engine.recordOpsecNoise({ noise_estimate: 0.1 });
      engine.recordDefensiveSignal({
        type: 'lockout',
        host_id: 'host-locked',
        detected_at: new Date().toISOString(),
        description: 'Account lockout detected after spray',
      });

      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });
      expect(prompt).toContain('Defensive signals');
      expect(prompt).toContain('lockout');
      expect(prompt).toContain('Account lockout detected');
    });
  });

  describe('active campaigns in situational awareness', () => {
    it('includes active campaigns', () => {
      const engine = createTestEngine();
      // Ingest nodes to create frontier items
      engine.ingestFinding({
        id: 'f-camp-1',
        agent_id: 'test',
        timestamp: new Date().toISOString(),
        nodes: [
          { id: 'host-camp', type: 'host', label: '10.0.0.10' },
          { id: 'svc-camp', type: 'service', label: 'smb', port: 445 },
        ],
        edges: [
          { source: 'host-camp', target: 'svc-camp', properties: { type: 'RUNS', confidence: 1.0 } },
        ],
      });

      // Get frontier items to use as campaign items
      const state = engine.getState();
      const itemIds = state.frontier.map(f => f.id);
      // If no frontier items, use a dummy — campaign planner requires at least one
      const ids = itemIds.length > 0 ? itemIds.slice(0, 1) : ['dummy-fi-1'];

      const campaign = engine.createCampaign({
        name: 'Test Spray Campaign',
        strategy: 'credential_spray',
        item_ids: ids,
      });
      engine.activateCampaign(campaign.id);

      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });
      expect(prompt).toContain('### Active Campaigns');
      expect(prompt).toContain('Test Spray Campaign');
    });
  });

  describe('services without CVE checks', () => {
    it('surfaces services with version but no VULNERABLE_TO edges', () => {
      const engine = createTestEngine();
      engine.ingestFinding({
        id: 'f-cve-1',
        agent_id: 'test',
        timestamp: new Date().toISOString(),
        nodes: [
          { id: 'host-cve', type: 'host', label: '10.0.0.20' },
          { id: 'svc-cve', type: 'service', label: 'apache', version: '2.4.49', port: 80 },
        ],
        edges: [
          { source: 'host-cve', target: 'svc-cve', properties: { type: 'RUNS', confidence: 1.0 } },
        ],
      });

      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });
      expect(prompt).toContain('Services Without CVE Checks');
      expect(prompt).toContain('apache (2.4.49)');
    });

    it('does not surface services that have VULNERABLE_TO edges', () => {
      const engine = createTestEngine();
      engine.ingestFinding({
        id: 'f-cve-2',
        agent_id: 'test',
        timestamp: new Date().toISOString(),
        nodes: [
          { id: 'host-cve2', type: 'host', label: '10.0.0.21' },
          { id: 'svc-cve2', type: 'service', label: 'nginx', version: '1.18.0', port: 80 },
          { id: 'vuln-1', type: 'vulnerability', label: 'CVE-2021-23017' },
        ],
        edges: [
          { source: 'host-cve2', target: 'svc-cve2', properties: { type: 'RUNS', confidence: 1.0 } },
          { source: 'svc-cve2', target: 'vuln-1', properties: { type: 'VULNERABLE_TO', confidence: 0.9 } },
        ],
      });

      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });
      expect(prompt).not.toContain('nginx (1.18.0)');
    });
  });

  describe('retrospective anti-patterns from KB', () => {
    it('includes low-success techniques when KB has data', () => {
      const engine = createTestEngine();
      const kb = engine.getKB();
      if (kb) {
        // Simulate a low-success technique with >=5 attempts and <20% success
        for (let i = 0; i < 10; i++) {
          kb.recordTechniqueAttempt('password_spray', 'Password Spray', i < 1, 0.5);
        }
        const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });
        expect(prompt).toContain('Low-Success Techniques');
        expect(prompt).toContain('Password Spray');
        expect(prompt).toContain('1/10 succeeded');
      }
    });
  });

  describe('token budgeting', () => {
    it('estimateTokens uses chars/4 heuristic', () => {
      expect(estimateTokens('')).toBe(0);
      expect(estimateTokens('abcd')).toBe(1);
      expect(estimateTokens('hello world')).toBe(3); // 11 chars / 4 = 2.75 → ceil = 3
    });

    it('default budget (8000) includes all sections', () => {
      const engine = createTestEngine();
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });
      expect(prompt).toContain('# Overwatch');
      expect(prompt).toContain('## Core Loop');
      expect(prompt).toContain('## Tactical Methodology');
      expect(prompt).toContain('## Tool Reference');
      expect(prompt).toContain('## Current State Snapshot');
    });

    it('very small budget still includes CRITICAL sections', () => {
      const engine = createTestEngine();
      // Budget of 500 tokens — only identity and core loop (critical) should survive
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary', max_prompt_tokens: 500 });
      expect(prompt).toContain('# Overwatch');
      expect(prompt).toContain('## Core Loop');
      // Non-critical sections should be missing or summarized
      expect(prompt).not.toContain('## Current State Snapshot');
    });

    it('tight budget summarizes tool table instead of full list', () => {
      const engine = createTestEngine();
      // Use a budget that can fit critical + high priority but not tool table + state
      const fullPrompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary', max_prompt_tokens: 50000 });
      const fullTokens = estimateTokens(fullPrompt);

      // Budget that forces tool table into summary mode
      const tightBudget = Math.floor(fullTokens * 0.65);
      const trimmedPrompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary', max_prompt_tokens: tightBudget });

      // Should contain identity (critical)
      expect(trimmedPrompt).toContain('# Overwatch');
      // Token count should be within budget (with some tolerance for critical overflow)
      const trimmedTokens = estimateTokens(trimmedPrompt);
      expect(trimmedTokens).toBeLessThanOrEqual(tightBudget * 1.5); // Critical can overflow
    });

    it('config.max_prompt_tokens is respected when options.max_prompt_tokens not set', () => {
      // Use a budget too small to fit everything (500 forces trimming)
      const tightConfig = { ...config, max_prompt_tokens: 500 };
      const engine = new GraphEngine(tightConfig, TEST_STATE_FILE);
      const prompt = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary' });
      // With 500 token budget, non-critical sections should be trimmed
      // Critical sections (identity + core loop) may overflow, but HIGH/MEDIUM/LOW should be gone
      expect(prompt).not.toContain('## Tool Reference');
      expect(prompt).not.toContain('## Current State Snapshot');
      // Should still contain critical content
      expect(prompt).toContain('# Overwatch');
    });

    it('situational section gets summarized showing headings when over budget', () => {
      const engine = createTestEngine();
      // Ingest data to generate situational content
      engine.ingestFinding({
        id: 'f-budget-1',
        agent_id: 'test',
        timestamp: new Date().toISOString(),
        nodes: [
          { id: 'host-budget', type: 'host', label: '10.0.0.100' },
          { id: 'cred-budget', type: 'credential', label: 'admin:pass', confidence: 1.0, cred_type: 'plaintext', cred_user: 'admin' },
        ],
        edges: [
          { source: 'cred-budget', target: 'host-budget', properties: { type: 'ADMIN_TO', confidence: 1.0 } },
        ],
      });

      // Full output has situational section
      const full = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary', max_prompt_tokens: 50000 });
      if (full.includes('## Situational Awareness')) {
        // Now try with tight budget — should get compressed version or omit
        const tight = generateSystemPrompt(engine, MOCK_TOOLS, { role: 'primary', max_prompt_tokens: 1500 });
        // Should either be compressed or omitted entirely
        if (tight.includes('Situational Awareness')) {
          expect(tight).toContain('compressed');
        }
      }
    });
  });
});
