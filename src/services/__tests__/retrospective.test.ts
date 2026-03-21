import { describe, it, expect } from 'vitest';
import {
  analyzeInferenceGaps,
  analyzeSkillGaps,
  analyzeScoring,
  generateReport,
  exportTrainingTraces,
  runRetrospective,
} from '../retrospective.js';
import type { RetrospectiveInput } from '../retrospective.js';
import type { EngagementConfig, NodeProperties, EdgeProperties, InferenceRule } from '../../types.js';

function makeInput(overrides?: Partial<RetrospectiveInput>): RetrospectiveInput {
  const config: EngagementConfig = {
    id: 'test-retro',
    name: 'Retro Test Engagement',
    created_at: '2026-01-01T00:00:00Z',
    scope: {
      cidrs: ['10.10.10.0/30'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [
      {
        id: 'obj-da',
        description: 'Get domain admin',
        target_node_type: 'credential',
        target_criteria: { privileged: true },
        achieved: true,
        achieved_at: '2026-01-01T12:00:00Z',
      },
      {
        id: 'obj-dc',
        description: 'Compromise DC',
        target_node_type: 'host',
        target_criteria: { hostname: 'dc01' },
        achieved: false,
      },
    ],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };

  const graph = {
    nodes: [
      { id: 'host-10-10-10-1', properties: { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', alive: true, discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
      { id: 'host-10-10-10-2', properties: { id: 'host-10-10-10-2', type: 'host', label: '10.10.10.2', ip: '10.10.10.2', alive: true, discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
      { id: 'svc-smb-1', properties: { id: 'svc-smb-1', type: 'service', label: 'SMB', port: 445, service_name: 'smb', discovered_at: '2026-01-01T01:00:00Z', confidence: 1.0 } as NodeProperties },
      { id: 'svc-smb-2', properties: { id: 'svc-smb-2', type: 'service', label: 'SMB', port: 445, service_name: 'smb', discovered_at: '2026-01-01T01:00:00Z', confidence: 1.0 } as NodeProperties },
      { id: 'user-jdoe', properties: { id: 'user-jdoe', type: 'user', label: 'jdoe', username: 'jdoe', discovered_at: '2026-01-01T02:00:00Z', confidence: 1.0 } as NodeProperties },
      { id: 'cred-da', properties: { id: 'cred-da', type: 'credential', label: 'DA cred', cred_type: 'ntlm', cred_user: 'admin', privileged: true, discovered_at: '2026-01-01T10:00:00Z', confidence: 1.0 } as NodeProperties },
      { id: 'domain-test-local', properties: { id: 'domain-test-local', type: 'domain', label: 'test.local', domain_name: 'test.local', discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties },
    ],
    edges: [
      { source: 'host-10-10-10-1', target: 'svc-smb-1', properties: { type: 'RUNS', confidence: 1.0, discovered_at: '2026-01-01T01:00:00Z' } as EdgeProperties },
      { source: 'host-10-10-10-2', target: 'svc-smb-2', properties: { type: 'RUNS', confidence: 1.0, discovered_at: '2026-01-01T01:00:00Z' } as EdgeProperties },
      { source: 'user-jdoe', target: 'host-10-10-10-1', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: '2026-01-01T05:00:00Z' } as EdgeProperties },
      { source: 'user-jdoe', target: 'host-10-10-10-2', properties: { type: 'ADMIN_TO', confidence: 1.0, discovered_at: '2026-01-01T06:00:00Z' } as EdgeProperties },
      { source: 'user-jdoe', target: 'cred-da', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: '2026-01-01T10:00:00Z' } as EdgeProperties },
      // Inferred edges (not confirmed)
      { source: 'cred-da', target: 'svc-smb-1', properties: { type: 'POTENTIAL_AUTH', confidence: 0.6, discovered_at: '2026-01-01T10:00:00Z' } as EdgeProperties },
      { source: 'cred-da', target: 'svc-smb-2', properties: { type: 'POTENTIAL_AUTH', confidence: 0.6, discovered_at: '2026-01-01T10:00:00Z' } as EdgeProperties },
    ],
  };

  const history = [
    { timestamp: '2026-01-01T00:00:00Z', description: 'Engagement initialized from config' },
    { timestamp: '2026-01-01T01:00:00Z', description: 'nmap scan completed on 10.10.10.0/30', agent_id: 'agent-1' },
    { timestamp: '2026-01-01T01:01:00Z', description: 'Finding ingested: 2 new nodes, 2 new edges' },
    { timestamp: '2026-01-01T02:00:00Z', description: 'smb enumeration with nxc on 10.10.10.1', agent_id: 'agent-1' },
    { timestamp: '2026-01-01T02:01:00Z', description: 'Finding ingested: 1 new node (user-jdoe)' },
    { timestamp: '2026-01-01T05:00:00Z', description: 'Credential testing - HAS_SESSION established', agent_id: 'agent-2' },
    { timestamp: '2026-01-01T06:00:00Z', description: 'Lateral movement - ADMIN_TO confirmed', agent_id: 'agent-2' },
    { timestamp: '2026-01-01T08:00:00Z', description: 'kerberoast attempt failed - access denied', agent_id: 'agent-3' },
    { timestamp: '2026-01-01T10:00:00Z', description: 'secretsdump - Finding ingested: credential discovered', agent_id: 'agent-2' },
    { timestamp: '2026-01-01T12:00:00Z', description: 'OBJECTIVE ACHIEVED: Get domain admin' },
  ];

  const inferenceRules: InferenceRule[] = [
    {
      id: 'rule-cred-fanout',
      name: 'Credential fan-out',
      description: 'New cred → POTENTIAL_AUTH to compatible services',
      trigger: { node_type: 'credential' },
      produces: [{ edge_type: 'POTENTIAL_AUTH', source_selector: 'trigger_node', target_selector: 'compatible_services', confidence: 0.6 }],
    },
  ];

  const agents = [
    { id: 'task-1', agent_id: 'agent-1', assigned_at: '2026-01-01T01:00:00Z', status: 'completed' as const, frontier_item_id: 'f1', subgraph_node_ids: ['host-10-10-10-1'], skill: 'network-recon', completed_at: '2026-01-01T02:30:00Z' },
    { id: 'task-2', agent_id: 'agent-2', assigned_at: '2026-01-01T05:00:00Z', status: 'completed' as const, frontier_item_id: 'f2', subgraph_node_ids: ['host-10-10-10-1', 'user-jdoe'], skill: 'lateral-movement', completed_at: '2026-01-01T10:30:00Z' },
    { id: 'task-3', agent_id: 'agent-3', assigned_at: '2026-01-01T08:00:00Z', status: 'failed' as const, frontier_item_id: 'f3', subgraph_node_ids: ['host-10-10-10-2'], skill: 'kerberoasting', completed_at: '2026-01-01T08:30:00Z' },
  ];

  const skillNames = [
    'network-recon', 'smb-enumeration', 'dns-enumeration', 'snmp-enumeration',
    'ad-discovery', 'kerberoasting', 'adcs-exploitation', 'smb-relay',
    'lateral-movement', 'privilege-escalation', 'credential-dumping',
    'password-spraying', 'ad-persistence', 'domain-trust-attacks',
    'pivoting', 'web-discovery', 'web-vuln-scanning', 'sql-injection',
    'web-app-attacks', 'cms-exploitation', 'linux-enumeration', 'linux-privesc',
    'aws-exploitation', 'azure-exploitation', 'gcp-exploitation',
    'data-exfiltration', 'persistence', 'sccm-attacks', 'exchange-attacks',
  ];

  return { config, graph, history, inferenceRules, agents, skillNames, ...overrides };
}

describe('Retrospective', () => {

  // =============================================
  // Inference Gap Analysis
  // =============================================
  describe('analyzeInferenceGaps', () => {
    it('suggests rules for repeated uncovered edge patterns', () => {
      const input = makeInput();
      // Add more RUNS edges to hit the 3+ threshold (already have 2, need 1 more)
      input.graph.nodes.push({
        id: 'host-10-10-10-3',
        properties: { id: 'host-10-10-10-3', type: 'host', label: '10.10.10.3', ip: '10.10.10.3', discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties,
      });
      input.graph.nodes.push({
        id: 'svc-smb-3',
        properties: { id: 'svc-smb-3', type: 'service', label: 'SMB', port: 445, service_name: 'smb', discovered_at: '2026-01-01T01:00:00Z', confidence: 1.0 } as NodeProperties,
      });
      input.graph.edges.push({
        source: 'host-10-10-10-3', target: 'svc-smb-3',
        properties: { type: 'RUNS', confidence: 1.0, discovered_at: '2026-01-01T01:00:00Z' } as EdgeProperties,
      });

      const suggestions = analyzeInferenceGaps(input);
      // RUNS (host→service) appears 3 times and no rule covers RUNS
      const runsSuggestion = suggestions.find(s => s.rule.id.includes('runs'));
      expect(runsSuggestion).toBeDefined();
      expect(runsSuggestion!.occurrences).toBeGreaterThanOrEqual(3);
      // Bug 3: source_selector and target_selector must differ to avoid self-loops
      const prod = runsSuggestion!.rule.produces[0];
      expect(prod.source_selector).not.toBe(prod.target_selector);
      expect(prod.source_selector).toBe('parent_host');
      expect(prod.target_selector).toBe('trigger_node');
    });

    it('skips same-type patterns that would produce self-loops (Bug 3)', () => {
      const input = makeInput();
      // Add 3+ host→host REACHABLE edges (same type on both sides)
      input.graph.nodes.push({
        id: 'host-10-10-10-3',
        properties: { id: 'host-10-10-10-3', type: 'host', label: '10.10.10.3', ip: '10.10.10.3', discovered_at: '2026-01-01T00:00:00Z', confidence: 1.0 } as NodeProperties,
      });
      input.graph.edges.push(
        { source: 'host-10-10-10-1', target: 'host-10-10-10-2', properties: { type: 'REACHABLE', confidence: 1.0, discovered_at: '2026-01-01T07:00:00Z' } as EdgeProperties },
        { source: 'host-10-10-10-2', target: 'host-10-10-10-1', properties: { type: 'REACHABLE', confidence: 1.0, discovered_at: '2026-01-01T07:01:00Z' } as EdgeProperties },
        { source: 'host-10-10-10-1', target: 'host-10-10-10-3', properties: { type: 'REACHABLE', confidence: 1.0, discovered_at: '2026-01-01T07:02:00Z' } as EdgeProperties },
      );
      const suggestions = analyzeInferenceGaps(input);
      // Same-type (host→host) patterns should be excluded to avoid self-loops
      const reachableSuggestion = suggestions.find(s => s.rule.id.includes('reachable'));
      expect(reachableSuggestion).toBeUndefined();
    });

    it('does not suggest rules for patterns covered by existing rules', () => {
      const input = makeInput();
      // POTENTIAL_AUTH is covered by the cred-fanout rule — should not be suggested
      const suggestions = analyzeInferenceGaps(input);
      const potAuthSuggestion = suggestions.find(s => s.rule.id.includes('potential_auth'));
      expect(potAuthSuggestion).toBeUndefined();
    });

    it('returns empty for small graphs', () => {
      const input = makeInput();
      input.graph.nodes = [];
      input.graph.edges = [];
      const suggestions = analyzeInferenceGaps(input);
      expect(suggestions).toEqual([]);
    });

    it('counts confirmed inferred edges using inferred_by_rule + confirmed_at', () => {
      const input = makeInput();
      // Replace edges with 6 inferred edges: 3 confirmed, 3 not
      input.graph.edges = [
        { source: 'cred-da', target: 'svc-smb-1', properties: { type: 'POTENTIAL_AUTH', confidence: 1.0, discovered_at: '2026-01-01T10:00:00Z', inferred_by_rule: 'rule-cred-fanout', inferred_at: '2026-01-01T10:00:00Z', confirmed_at: '2026-01-01T11:00:00Z' } as EdgeProperties },
        { source: 'cred-da', target: 'svc-smb-2', properties: { type: 'POTENTIAL_AUTH', confidence: 1.0, discovered_at: '2026-01-01T10:00:00Z', inferred_by_rule: 'rule-cred-fanout', inferred_at: '2026-01-01T10:00:00Z', confirmed_at: '2026-01-01T11:05:00Z' } as EdgeProperties },
        { source: 'user-jdoe', target: 'host-10-10-10-1', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: '2026-01-01T05:00:00Z', inferred_by_rule: 'rule-session', inferred_at: '2026-01-01T04:00:00Z', confirmed_at: '2026-01-01T05:00:00Z' } as EdgeProperties },
        // These 3 are inferred but NOT confirmed
        { source: 'user-jdoe', target: 'host-10-10-10-2', properties: { type: 'ADMIN_TO', confidence: 0.7, discovered_at: '2026-01-01T06:00:00Z', inferred_by_rule: 'rule-cred-fanout', inferred_at: '2026-01-01T06:00:00Z' } as EdgeProperties },
        { source: 'host-10-10-10-1', target: 'svc-smb-1', properties: { type: 'RUNS', confidence: 1.0, discovered_at: '2026-01-01T01:00:00Z' } as EdgeProperties },
        { source: 'host-10-10-10-2', target: 'svc-smb-2', properties: { type: 'RUNS', confidence: 1.0, discovered_at: '2026-01-01T01:00:00Z' } as EdgeProperties },
      ];

      const suggestions = analyzeInferenceGaps(input);
      // With 4 inferred edges (3 confirmed, 1 not), global rate is 75% — no low-confidence warning
      const lowConfSuggestion = suggestions.find(s => s.rule.id === 'suggested-review-low-confidence');
      expect(lowConfSuggestion).toBeUndefined();
    });

    it('flags low-performing rules by per-rule confirmation rate', () => {
      const input = makeInput();
      // 5 inferred edges from rule-bad, 0 confirmed
      input.graph.edges = [];
      for (let i = 0; i < 5; i++) {
        input.graph.edges.push({
          source: `cred-da`, target: `svc-smb-${i % 2 + 1}`,
          properties: { type: 'POTENTIAL_AUTH', confidence: 0.6, discovered_at: '2026-01-01T10:00:00Z', inferred_by_rule: 'rule-bad', inferred_at: '2026-01-01T10:00:00Z' } as EdgeProperties,
        });
      }

      const suggestions = analyzeInferenceGaps(input);
      // Should have a per-rule suggestion for rule-bad
      const ruleBadSuggestion = suggestions.find(s => s.rule.id === 'suggested-review-rule-bad');
      expect(ruleBadSuggestion).toBeDefined();
      expect(ruleBadSuggestion!.evidence).toContain('0/5');
      // Should also have the global low-confidence suggestion
      const globalSuggestion = suggestions.find(s => s.rule.id === 'suggested-review-low-confidence');
      expect(globalSuggestion).toBeDefined();
    });

    it('does not flag rules with insufficient data (<3 edges)', () => {
      const input = makeInput();
      input.graph.edges = [
        { source: 'cred-da', target: 'svc-smb-1', properties: { type: 'POTENTIAL_AUTH', confidence: 0.6, discovered_at: '2026-01-01T10:00:00Z', inferred_by_rule: 'rule-few', inferred_at: '2026-01-01T10:00:00Z' } as EdgeProperties },
        { source: 'cred-da', target: 'svc-smb-2', properties: { type: 'POTENTIAL_AUTH', confidence: 0.6, discovered_at: '2026-01-01T10:00:00Z', inferred_by_rule: 'rule-few', inferred_at: '2026-01-01T10:00:00Z' } as EdgeProperties },
      ];

      const suggestions = analyzeInferenceGaps(input);
      const ruleFewSuggestion = suggestions.find(s => s.rule.id.includes('rule-few'));
      expect(ruleFewSuggestion).toBeUndefined();
    });
  });

  // =============================================
  // Skill Gap Analysis
  // =============================================
  describe('analyzeSkillGaps', () => {
    it('identifies unused skills', () => {
      const input = makeInput();
      const gaps = analyzeSkillGaps(input);
      // Many skills were never referenced in history or agents
      expect(gaps.unused_skills.length).toBeGreaterThan(0);
      // network-recon and lateral-movement are used (agent skills)
      expect(gaps.unused_skills).not.toContain('network-recon');
      expect(gaps.unused_skills).not.toContain('lateral-movement');
    });

    it('identifies techniques mentioned but without skills', () => {
      const input = makeInput();
      const gaps = analyzeSkillGaps(input);
      // secretsdump is mentioned in history but isn't a skill name
      expect(gaps.missing_skills).toContain('secretsdump');
    });

    it('identifies failed techniques', () => {
      const input = makeInput();
      const gaps = analyzeSkillGaps(input);
      // kerberoast attempt failed
      expect(gaps.failed_techniques).toContain('kerberoast');
    });

    it('tracks skill usage from agents', () => {
      const input = makeInput();
      const gaps = analyzeSkillGaps(input);
      expect(gaps.skill_usage_counts['network-recon']).toBe(1);
      expect(gaps.skill_usage_counts['lateral-movement']).toBe(1);
      expect(gaps.skill_usage_counts['kerberoasting']).toBe(1);
    });
  });

  // =============================================
  // Scoring Analysis
  // =============================================
  describe('analyzeScoring', () => {
    it('returns current and suggested weights', () => {
      const input = makeInput();
      const scoring = analyzeScoring(input);
      expect(scoring.current_weights).toBeDefined();
      expect(scoring.suggested_weights).toBeDefined();
      expect(scoring.rationale.length).toBeGreaterThan(0);
    });

    it('tracks success by frontier type', () => {
      const input = makeInput();
      const scoring = analyzeScoring(input);
      expect(scoring.success_by_frontier_type).toHaveProperty('incomplete_node');
      expect(scoring.success_by_frontier_type).toHaveProperty('untested_edge');
      expect(scoring.success_by_frontier_type).toHaveProperty('inferred_edge');
    });

    it('suggests increased hops_to_objective weight when objectives unachieved', () => {
      const input = makeInput();
      // obj-dc is not achieved
      const scoring = analyzeScoring(input);
      expect(scoring.suggested_weights.hops_to_objective).toBeGreaterThanOrEqual(scoring.current_weights.hops_to_objective);
      const objRationale = scoring.rationale.find(r => r.includes('objective'));
      expect(objRationale).toBeDefined();
    });
  });

  describe('generateReport', () => {
    it('lists only reusable credentials in the executive summary', () => {
      const input = makeInput({
        graph: {
          nodes: [
            ...makeInput().graph.nodes,
            {
              id: 'cred-passive',
              properties: {
                id: 'cred-passive',
                type: 'credential',
                label: 'NTLMv2:jdoe',
                cred_material_kind: 'ntlmv2_challenge',
                cred_usable_for_auth: false,
                cred_user: 'jdoe',
                discovered_at: '2026-01-01T11:00:00Z',
                confidence: 1.0,
              } as NodeProperties,
            },
          ],
          edges: makeInput().graph.edges,
        },
      });

      const report = generateReport(input);
      expect(report).toContain('obtaining 1 reusable credential(s)');
      expect(report).not.toContain('ntlmv2_challenge: jdoe');
    });
  });

  // =============================================
  // Report Generation
  // =============================================
  describe('generateReport', () => {
    it('produces valid markdown with expected sections', () => {
      const input = makeInput();
      const report = generateReport(input);
      expect(report).toContain('# Engagement Report');
      expect(report).toContain('## Executive Summary');
      expect(report).toContain('## Scope');
      expect(report).toContain('## Objectives');
      expect(report).toContain('## Discovery Summary');
      expect(report).toContain('## Compromised Assets');
      expect(report).toContain('## Activity Timeline');
      expect(report).toContain('## Recommendations');
    });

    it('includes engagement name and config details', () => {
      const input = makeInput();
      const report = generateReport(input);
      expect(report).toContain('Retro Test Engagement');
      expect(report).toContain('10.10.10.0/30');
      expect(report).toContain('test.local');
    });

    it('shows objective status correctly', () => {
      const input = makeInput();
      const report = generateReport(input);
      expect(report).toContain('✅ Achieved');
      expect(report).toContain('❌ Pending');
    });

    it('lists compromised hosts and credentials', () => {
      const input = makeInput();
      const report = generateReport(input);
      expect(report).toContain('ntlm');
      expect(report).toContain('admin');
    });

    it('includes recommendations for untested edges', () => {
      const input = makeInput();
      const report = generateReport(input);
      expect(report).toContain('inferred edge');
    });
  });

  // =============================================
  // RLVR Training Traces
  // =============================================
  describe('exportTrainingTraces', () => {
    it('produces traces from activity log', () => {
      const input = makeInput();
      const traces = exportTrainingTraces(input);
      expect(traces.length).toBe(input.history.length);
    });

    it('each trace has required fields', () => {
      const input = makeInput();
      const traces = exportTrainingTraces(input);
      for (const t of traces) {
        expect(t).toHaveProperty('step');
        expect(t).toHaveProperty('timestamp');
        expect(t).toHaveProperty('state_summary');
        expect(t).toHaveProperty('action');
        expect(t).toHaveProperty('outcome');
        expect(t).toHaveProperty('reward');
        expect(t.state_summary).toHaveProperty('nodes');
        expect(t.state_summary).toHaveProperty('edges');
        expect(t.state_summary).toHaveProperty('access_level');
        expect(t.state_summary).toHaveProperty('objectives_achieved');
      }
    });

    it('assigns positive reward for findings', () => {
      const input = makeInput();
      const traces = exportTrainingTraces(input);
      // The "Finding ingested: 2 new nodes" entry should have positive reward
      const findingTrace = traces.find(t => t.action.type === 'report_finding');
      expect(findingTrace).toBeDefined();
    });

    it('assigns high reward for objective achievement', () => {
      const input = makeInput();
      const traces = exportTrainingTraces(input);
      const objTrace = traces.find(t => t.action.type === 'objective_achieved');
      expect(objTrace).toBeDefined();
    });

    it('returns empty traces for empty history', () => {
      const input = makeInput();
      input.history = [];
      const traces = exportTrainingTraces(input);
      expect(traces).toEqual([]);
    });
  });

  // =============================================
  // Full Retrospective
  // =============================================
  describe('runRetrospective', () => {
    it('produces all five outputs', () => {
      const input = makeInput();
      const result = runRetrospective(input);
      expect(result.inference_suggestions).toBeInstanceOf(Array);
      expect(result.skill_gaps).toBeDefined();
      expect(result.skill_gaps.unused_skills).toBeInstanceOf(Array);
      expect(result.scoring).toBeDefined();
      expect(result.scoring.rationale).toBeInstanceOf(Array);
      expect(result.report_markdown).toContain('# Engagement Report');
      expect(result.training_traces).toBeInstanceOf(Array);
      expect(result.summary).toContain('Retro Test Engagement');
    });

    it('summary includes key metrics', () => {
      const input = makeInput();
      const result = runRetrospective(input);
      expect(result.summary).toContain('nodes');
      expect(result.summary).toContain('edges');
      expect(result.summary).toContain('Objectives');
      expect(result.summary).toContain('Agents');
    });

    it('handles empty engagement gracefully', () => {
      const input = makeInput();
      input.graph = { nodes: [], edges: [] };
      input.history = [];
      input.agents = [];
      const result = runRetrospective(input);
      expect(result.inference_suggestions).toEqual([]);
      expect(result.training_traces).toEqual([]);
      expect(result.report_markdown).toContain('# Engagement Report');
      expect(result.summary).toContain('0 nodes');
    });
  });
});
