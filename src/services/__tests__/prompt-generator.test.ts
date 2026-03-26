import { describe, it, expect } from 'vitest';
import { resolve } from 'path';
import { GraphEngine } from '../graph-engine.js';
import { generateSystemPrompt, type ToolEntry } from '../prompt-generator.js';
import { loadEngagementConfigFile } from '../../config.js';

const config = loadEngagementConfigFile(resolve('./engagement.json'));

function createTestEngine() {
  return new GraphEngine(config);
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

describe('prompt-generator', () => {
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
  });
});
