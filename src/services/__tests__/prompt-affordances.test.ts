import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { resolve } from 'path';
import { existsSync, unlinkSync } from 'fs';
import { GraphEngine } from '../graph-engine.js';
import { generateSystemPrompt, estimateTokens, DEFAULT_MAX_PROMPT_TOKENS, type ToolEntry } from '../prompt-generator.js';
import { loadEngagementConfigFile } from '../../config.js';
import { checkPromptAffordances, REQUIRED_SUBAGENT_AFFORDANCES } from '../eval-rubric.js';
import { EVAL_SCENARIOS } from '../../test-support/eval-scenarios.js';
import type { AgentTask } from '../../types.js';

const config = loadEngagementConfigFile(resolve('./engagement.example.json'));
const STATE = './state-test-prompt-affordances.json';
const cleanup = () => { if (existsSync(STATE)) unlinkSync(STATE); };

const TOOLS: ToolEntry[] = [
  { name: 'get_agent_context', description: 'scoped view for sub-agents' },
  { name: 'validate_action', description: 'pre-execution sanity check' },
  { name: 'run_tool', description: 'execute binary with argv' },
  { name: 'run_bash', description: 'execute shell command' },
  { name: 'parse_output', description: 'deterministically parse tool output' },
  { name: 'report_finding', description: 'submit discoveries to graph' },
  { name: 'submit_agent_transcript', description: 'sub-agent wrap-up handoff' },
  { name: 'agent_heartbeat', description: 'refresh task heartbeat' },
  { name: 'query_graph', description: 'open-ended graph exploration' },
  { name: 'get_skill', description: 'RAG skill lookup' },
];

describe('sub_agent prompt affordances (Tier-1 structural guard)', () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  for (const scenario of EVAL_SCENARIOS) {
    it(`${scenario.id}: generated sub_agent prompt keeps the load-bearing affordances + fits budget`, () => {
      const engine = new GraphEngine(config, STATE);
      const agentId = `agent-${scenario.id}`;
      engine.registerAgent({
        id: `task-${scenario.id}`,
        agent_id: agentId,
        assigned_at: new Date().toISOString(),
        status: 'running',
        subgraph_node_ids: [],
        backend: 'headless_mcp',
        archetype: scenario.archetype,
      } as AgentTask);

      const prompt = generateSystemPrompt(engine, TOOLS, { role: 'sub_agent', agent_id: agentId });
      const { ok, missing } = checkPromptAffordances(prompt);
      expect(missing, `missing affordances for ${scenario.id}`).toEqual([]);
      expect(ok).toBe(true);
      expect(estimateTokens(prompt)).toBeLessThanOrEqual(DEFAULT_MAX_PROMPT_TOKENS);
    });
  }

  it('flags a prompt that dropped an affordance', () => {
    const { ok, missing } = checkPromptAffordances('uses get_agent_context and validate_action and submit_agent_transcript only');
    expect(ok).toBe(false);
    expect(missing).toContain('report_finding');
    expect(missing).toContain('parse_output');
  });

  it('exposes the required-affordance list for step (b) to reuse on its candidate', () => {
    expect(REQUIRED_SUBAGENT_AFFORDANCES.length).toBeGreaterThan(0);
  });
});

describe('lean variant (step b) — context-first restructure', () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  const genFor = (archetype: string, variant: 'control' | 'lean') => {
    const engine = new GraphEngine(config, STATE);
    const agentId = `agent-${archetype}`;
    engine.registerAgent({
      id: `task-${archetype}`, agent_id: agentId, assigned_at: new Date().toISOString(),
      status: 'running', subgraph_node_ids: [], backend: 'headless_mcp', archetype,
    } as AgentTask);
    return generateSystemPrompt(engine, TOOLS, { role: 'sub_agent', agent_id: agentId, variant });
  };

  for (const scenario of EVAL_SCENARIOS) {
    it(`${scenario.id}: lean prompt keeps affordances, fits budget, and is leaner than control`, () => {
      const control = genFor(scenario.archetype, 'control');
      const lean = genFor(scenario.archetype, 'lean');
      expect(checkPromptAffordances(lean).missing, `missing affordances in lean ${scenario.id}`).toEqual([]);
      expect(estimateTokens(lean)).toBeLessThanOrEqual(DEFAULT_MAX_PROMPT_TOKENS);
      expect(estimateTokens(lean)).toBeLessThan(estimateTokens(control));
    });
  }

  it('keeps the five affordance literals even for a read-only archetype (cve_researcher)', () => {
    expect(checkPromptAffordances(genFor('cve_researcher', 'lean')).ok).toBe(true);
  });

  it('leads with the Brief (objective/scope) before the Loop — not a persona paragraph', () => {
    const lean = genFor('recon_scanner', 'lean');
    expect(lean).toContain('## Brief');
    expect(lean.indexOf('## Brief')).toBeLessThan(lean.indexOf('## Loop'));
    expect(lean).not.toContain('You are an Overwatch sub-agent working a specific task'); // control's persona line
  });

  it('includes the credential playbook only for credential-class archetypes', () => {
    expect(genFor('cloud_cartographer', 'lean')).toContain('expand_aws_credential');
    expect(genFor('recon_scanner', 'lean')).not.toContain('expand_aws_credential');
  });
});
