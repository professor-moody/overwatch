import { describe, it, expect } from 'vitest';
import type { InferenceRuleSuggestion, InferenceRule, RLVRTrace } from '../../types.js';
import { applyInferenceSuggestions, updateSkillAnnotations, type SkillAnnotations } from '../retrospective-hooks.js';
import { computeTechniquePriors, getTechniquePrior } from '../technique-priors.js';

function makeRule(id: string): InferenceRule {
  return {
    id,
    name: `Rule ${id}`,
    description: `Test rule ${id}`,
    trigger: { node_type: 'credential' as any },
    produces: [{ edge_type: 'VALID_ON' as any, source_selector: 'trigger_node', target_selector: 'domain_nodes', confidence: 0.7 }],
  };
}

function makeSuggestion(id: string, occurrences: number): InferenceRuleSuggestion {
  return { rule: makeRule(id), evidence: `Seen ${occurrences} times`, occurrences };
}

describe('Retrospective Hooks', () => {
  describe('applyInferenceSuggestions', () => {
    it('applies suggestions meeting occurrence threshold', () => {
      const suggestions = [makeSuggestion('r1', 10), makeSuggestion('r2', 3)];
      const applied: InferenceRule[] = [];
      const result = applyInferenceSuggestions(suggestions, (rule) => applied.push(rule), { minOccurrences: 5 });

      expect(result.applied).toHaveLength(1);
      expect(result.applied[0].rule.id).toBe('r1');
      expect(result.skipped).toHaveLength(1);
      expect(result.skipped[0].rule.id).toBe('r2');
      expect(applied).toHaveLength(1);
    });

    it('uses default minOccurrences of 5', () => {
      const suggestions = [makeSuggestion('r1', 5), makeSuggestion('r2', 4)];
      const applied: InferenceRule[] = [];
      const result = applyInferenceSuggestions(suggestions, (rule) => applied.push(rule));

      expect(result.applied).toHaveLength(1);
      expect(result.skipped).toHaveLength(1);
    });

    it('captures errors from addRule callback', () => {
      const suggestions = [makeSuggestion('r1', 10)];
      const result = applyInferenceSuggestions(suggestions, () => { throw new Error('duplicate rule'); });

      expect(result.applied).toHaveLength(0);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toContain('duplicate rule');
    });

    it('handles empty suggestions', () => {
      const result = applyInferenceSuggestions([], () => {});
      expect(result.applied).toHaveLength(0);
      expect(result.skipped).toHaveLength(0);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('updateSkillAnnotations', () => {
    it('creates new annotations from scratch', () => {
      const results = [
        { skill_name: 'nmap-scan', outcome: 'success' as const },
        { skill_name: 'nmap-scan', outcome: 'failure' as const },
        { skill_name: 'kerberoast', outcome: 'success' as const },
      ];
      const annotations = updateSkillAnnotations(null, results);

      expect(annotations.version).toBe(1);
      expect(annotations.annotations['nmap-scan'].use_count).toBe(2);
      expect(annotations.annotations['nmap-scan'].success_count).toBe(1);
      expect(annotations.annotations['nmap-scan'].failure_count).toBe(1);
      expect(annotations.annotations['nmap-scan'].success_rate).toBe(0.5);
      expect(annotations.annotations['kerberoast'].success_rate).toBe(1.0);
    });

    it('updates existing annotations', () => {
      const existing: SkillAnnotations = {
        version: 1,
        updated_at: '2026-01-01T00:00:00Z',
        annotations: {
          'nmap-scan': { skill_name: 'nmap-scan', use_count: 5, success_count: 4, failure_count: 1, success_rate: 0.8 },
        },
      };
      const results = [{ skill_name: 'nmap-scan', outcome: 'success' as const }];
      const updated = updateSkillAnnotations(existing, results);

      expect(updated.version).toBe(2);
      expect(updated.annotations['nmap-scan'].use_count).toBe(6);
      expect(updated.annotations['nmap-scan'].success_count).toBe(5);
    });

    it('tracks partial outcomes', () => {
      const results = [{ skill_name: 'spray', outcome: 'partial' as const }];
      const annotations = updateSkillAnnotations(null, results);
      expect(annotations.annotations['spray'].use_count).toBe(1);
      expect(annotations.annotations['spray'].success_count).toBe(0);
      expect(annotations.annotations['spray'].failure_count).toBe(0);
      expect(annotations.annotations['spray'].last_outcome).toBe('partial');
    });
  });
});

describe('Technique Priors', () => {
  function makeTrace(overrides: Partial<RLVRTrace> = {}): RLVRTrace {
    return {
      step: 1,
      timestamp: '2026-06-15T10:00:00Z',
      state_summary: { nodes: 10, edges: 20, access_level: 'user', objectives_achieved: 0 },
      action: { type: 'scan', tool: 'nmap' },
      outcome: { new_nodes: 2, new_edges: 3, objective_achieved: false },
      reward: 0.5,
      confidence: 'high',
      derived_from: 'structured',
      ...overrides,
    };
  }

  describe('computeTechniquePriors', () => {
    it('computes success rates from traces', () => {
      const traces = [
        makeTrace({ action: { type: 'scan', tool: 'nmap' }, reward: 1.0 }),
        makeTrace({ action: { type: 'scan', tool: 'nmap' }, reward: 0.5 }),
        makeTrace({ action: { type: 'scan', tool: 'nmap' }, reward: -0.5 }),
        makeTrace({ action: { type: 'exploit', tool: 'secretsdump' }, reward: 1.0 }),
      ];

      const priors = computeTechniquePriors(traces);
      expect(priors.size).toBe(2);

      const nmapPrior = priors.get('nmap')!;
      expect(nmapPrior.total_attempts).toBe(3);
      expect(nmapPrior.successful_attempts).toBe(2);
      expect(nmapPrior.success_rate).toBeCloseTo(2 / 3);

      const sdPrior = priors.get('secretsdump')!;
      expect(sdPrior.total_attempts).toBe(1);
      expect(sdPrior.success_rate).toBe(1.0);
    });

    it('uses technique when tool is absent', () => {
      const traces = [
        makeTrace({ action: { type: 'exploit', technique: 'kerberoast' }, reward: 1.0 }),
      ];
      const priors = computeTechniquePriors(traces);
      expect(priors.has('kerberoast')).toBe(true);
    });

    it('falls back to action type', () => {
      const traces = [
        makeTrace({ action: { type: 'lateral_move' }, reward: 0.5 }),
      ];
      const priors = computeTechniquePriors(traces);
      expect(priors.has('lateral_move')).toBe(true);
    });

    it('handles empty traces', () => {
      const priors = computeTechniquePriors([]);
      expect(priors.size).toBe(0);
    });

    it('computes running average reward', () => {
      const traces = [
        makeTrace({ action: { type: 'scan', tool: 'nmap' }, reward: 1.0 }),
        makeTrace({ action: { type: 'scan', tool: 'nmap' }, reward: 0.0 }),
      ];
      const priors = computeTechniquePriors(traces);
      expect(priors.get('nmap')!.avg_reward).toBeCloseTo(0.5);
    });
  });

  describe('getTechniquePrior', () => {
    it('returns matching prior', () => {
      const priors = new Map([['nmap', { technique: 'nmap', total_attempts: 5, successful_attempts: 3, success_rate: 0.6, avg_reward: 0.4 }]]);
      const result = getTechniquePrior('nmap', priors);
      expect(result).toBeDefined();
      expect(result!.success_rate).toBe(0.6);
    });

    it('returns null for unknown technique', () => {
      const priors = new Map();
      expect(getTechniquePrior('unknown', priors)).toBeNull();
    });

    it('is case-insensitive', () => {
      const priors = new Map([['nmap', { technique: 'nmap', total_attempts: 5, successful_attempts: 3, success_rate: 0.6, avg_reward: 0.4 }]]);
      expect(getTechniquePrior('NMAP', priors)).toBeDefined();
    });
  });
});
