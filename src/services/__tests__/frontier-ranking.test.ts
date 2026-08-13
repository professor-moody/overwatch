import { describe, expect, it } from 'vitest';
import { rankFrontier, selectFrontierTasks, annotateFrontierRanks, scoreItem } from '../frontier-ranking.js';
import type { FrontierItem } from '../../types.js';

function item(over: Partial<FrontierItem> & { id: string; type: FrontierItem['type'] }): FrontierItem {
  return {
    description: over.id,
    graph_metrics: { hops_to_objective: null, fan_out_estimate: 1, node_degree: 1, confidence: 1, ...(over.graph_metrics || {}) },
    opsec_noise: 0.2,
    ...over,
  } as FrontierItem;
}

describe('frontier ranking', () => {
  it('does not let a burst of enrichment tasks crowd out a high-value credential test', () => {
    // 40 metadata-enrichment items (surfaced FIRST in construction order) + one credential
    // test one hop from the objective. The old positional slice(0,20) would drop the cred.
    const items: FrontierItem[] = [];
    for (let i = 0; i < 40; i++) {
      items.push(item({ id: `enrich-${i}`, type: 'incomplete_node', graph_metrics: { hops_to_objective: null, fan_out_estimate: 1, node_degree: 1, confidence: 1 } }));
    }
    items.push(item({ id: 'cred-1', type: 'credential_test', opsec_noise: 0.1, graph_metrics: { hops_to_objective: 1, fan_out_estimate: 3, node_degree: 2, confidence: 0.9 } }));

    const surfaced = selectFrontierTasks(items, 20);
    expect(surfaced.map(s => s.id)).toContain('cred-1');
    expect(surfaced[0].id).toBe('cred-1');                 // and it ranks first
    expect(surfaced[0].rank_reason).toMatch(/1 hop to objective/);
  });

  it('ranks an item closer to the objective above a farther one of the same type', () => {
    const near = item({ id: 'near', type: 'network_pivot', graph_metrics: { hops_to_objective: 1, fan_out_estimate: 2, node_degree: 2, confidence: 1 } });
    const far = item({ id: 'far', type: 'network_pivot', graph_metrics: { hops_to_objective: 6, fan_out_estimate: 2, node_degree: 2, confidence: 1 } });
    const [first] = rankFrontier([far, near]);
    expect(first.id).toBe('near');
  });

  it('penalizes noisy items relative to a quiet equivalent', () => {
    const quiet = item({ id: 'quiet', type: 'network_discovery', opsec_noise: 0.05 });
    const loud = item({ id: 'loud', type: 'network_discovery', opsec_noise: 0.9 });
    const [first] = rankFrontier([loud, quiet]);
    expect(first.id).toBe('quiet');
  });

  it('applies a per-type diversity cap so one type cannot monopolize the window', () => {
    const items: FrontierItem[] = [];
    for (let i = 0; i < 30; i++) items.push(item({ id: `disc-${i}`, type: 'network_discovery' }));
    for (let i = 0; i < 30; i++) items.push(item({ id: `enrich-${i}`, type: 'incomplete_node' }));
    items.push(item({ id: 'pivot-1', type: 'network_pivot', graph_metrics: { hops_to_objective: 1, fan_out_estimate: 2, node_degree: 2, confidence: 1 } }));

    const surfaced = selectFrontierTasks(items, 10);
    const types = new Set(surfaced.map(s => s.type));
    expect(types.size).toBeGreaterThan(1);                 // not monopolized by one type
    expect(surfaced.map(s => s.id)).toContain('pivot-1');  // the lone high-value item survives
    // No type exceeds the diversity cap in the primary pass (ceil(10*0.4)=4) before backfill.
    const enrichCount = surfaced.filter(s => s.type === 'incomplete_node').length;
    expect(enrichCount).toBeLessThanOrEqual(6);            // capped + limited backfill, never all 10
  });

  it('backfills to fill the window rather than under-surfacing when types are scarce', () => {
    // Only one type available, more than the cap — must still return maxItems, not typeCap.
    const items = Array.from({ length: 15 }, (_, i) => item({ id: `n-${i}`, type: 'incomplete_node' }));
    expect(selectFrontierTasks(items, 10)).toHaveLength(10);
  });

  it('does NOT clamp the KB/chain confidence boost — a boosted lead outranks a plain one', () => {
    // graph_metrics.confidence is a multiplier that legitimately exceeds 1 when knowledge-base
    // hit-rates / attack-chain heuristics promote an item. The old ranker clamped it to 1, so
    // a boosted lead (1.4) and a plain one (1.0) tied. They must not tie now.
    const boosted = item({ id: 'boosted', type: 'inferred_edge', graph_metrics: { hops_to_objective: null, fan_out_estimate: 1, node_degree: 1, confidence: 1.4 } });
    const plain = item({ id: 'plain', type: 'inferred_edge', graph_metrics: { hops_to_objective: null, fan_out_estimate: 1, node_degree: 1, confidence: 1.0 } });
    const [first] = rankFrontier([plain, boosted]);
    expect(first.id).toBe('boosted');
    expect(scoreItem(boosted).priority_score).toBeGreaterThan(scoreItem(plain).priority_score);
    expect(scoreItem(boosted).evidence_confidence).toBeGreaterThan(1); // preserved, not clamped to 1
  });

  it('folds attack-chain strength (chain_score) into expected value — previously ignored', () => {
    const inChain = item({ id: 'in-chain', type: 'untested_edge', chain_score: 8 });
    const isolated = item({ id: 'isolated', type: 'untested_edge', chain_score: 0 });
    const [first] = rankFrontier([isolated, inChain]);
    expect(first.id).toBe('in-chain');
    expect(scoreItem(inChain).expected_value).toBeGreaterThan(scoreItem(isolated).expected_value);
    expect(scoreItem(inChain).explanation).toMatch(/chain value 8/);
  });

  it('annotateFrontierRanks is the canonical projection — annotates rank + sorts in place', () => {
    const enrich = item({ id: 'enrich', type: 'incomplete_node' });
    const cred = item({ id: 'cred', type: 'credential_test', opsec_noise: 0.1, graph_metrics: { hops_to_objective: 1, fan_out_estimate: 3, node_degree: 2, confidence: 1 } });
    const items: FrontierItem[] = [enrich, cred];
    const ranked = annotateFrontierRanks(items);
    // Sorted highest-priority first, in place (same array reference).
    expect(ranked).toBe(items);
    expect(ranked[0].id).toBe('cred');
    // Every item carries the split-axis rank.
    for (const it of ranked) {
      expect(it.rank).toBeDefined();
      expect(typeof it.rank!.priority_score).toBe('number');
      expect(typeof it.rank!.evidence_confidence).toBe('number');
      expect(typeof it.rank!.expected_value).toBe('number');
      expect(typeof it.rank!.expected_noise).toBe('number');
      expect(typeof it.rank!.explanation).toBe('string');
    }
    expect(ranked[0].rank!.priority_score).toBeGreaterThan(ranked[1].rank!.priority_score);
  });
});
