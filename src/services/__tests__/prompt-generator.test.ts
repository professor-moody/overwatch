import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { resolve } from 'path';
import { existsSync, unlinkSync } from 'fs';
import { GraphEngine } from '../graph-engine.js';
import { generateSystemPrompt, type ToolEntry } from '../prompt-generator.js';
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
});
