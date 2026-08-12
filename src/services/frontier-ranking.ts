// ============================================================
// Frontier ranking + diversity-aware selection.
//
// computeFrontier() emits items in construction order (every incomplete node first,
// credential/pivot items last), and next_task historically surfaced the first N with a
// positional slice. On a real engagement that buried valuable credential, pivot, and
// exploitation opportunities behind a wall of low-value metadata-enrichment tasks, all
// showing an indistinguishable score.
//
// This module ranks items by offensive value and selects the surfaced window with a
// per-type diversity cap, so a burst of near-identical enrichment can never crowd out the
// handful of high-value moves the model would otherwise never see. Every surfaced item
// carries an explicit `frontier_priority` and a short `rank_reason`.
// ============================================================

import type { FrontierItem } from '../types.js';

/**
 * Offensive value of each frontier item type. Access / pivot / credential work that moves
 * toward an objective outranks passive discovery, which outranks metadata enrichment
 * ("completeness" work that rarely changes a decision).
 */
const TYPE_WEIGHT: Record<FrontierItem['type'], number> = {
  credential_test: 1.0,
  mfa_bypass_candidate: 1.0,
  network_pivot: 0.95,
  cross_tier_pivot: 0.95,
  untested_edge: 0.85,
  inferred_edge: 0.8,
  cve_research: 0.6,
  idp_enumeration: 0.6,
  network_discovery: 0.55,
  domain_enumeration: 0.5,
  incomplete_node: 0.3,
};

export interface FrontierTaskSelection extends FrontierItem {
  /** Composed priority — higher is more valuable. NOT a probability; a ranking value. */
  frontier_priority: number;
  /** Short human-readable "why it's ranked here". */
  rank_reason: string;
}

function scoreItem(item: FrontierItem): { priority: number; reason: string } {
  const typeWeight = TYPE_WEIGHT[item.type] ?? 0.5;
  const hops = item.graph_metrics?.hops_to_objective;
  // Objective proximity: an item on a path to an objective is boosted the closer it is
  // (0 hops → +1.0, 1 hop → +0.5, …). An item not on any known path (null) gets no boost
  // but is not zeroed — discovery still has value.
  const objectiveBoost = typeof hops === 'number' ? 1 / (1 + Math.max(hops, 0)) : 0;
  const noise = typeof item.opsec_noise === 'number' ? item.opsec_noise : 0.3;
  const noiseFactor = 1 / (1 + 2 * noise); // penalize cost/noise
  const confidence = typeof item.graph_metrics?.confidence === 'number'
    ? Math.min(Math.max(item.graph_metrics.confidence, 0), 1)
    : 0.6;
  const fanOut = typeof item.graph_metrics?.fan_out_estimate === 'number' ? item.graph_metrics.fan_out_estimate : 0;
  const fanOutBonus = 1 + Math.min(Math.max(fanOut, 0), 20) / 40; // up to +0.5 for optionality

  const priority = typeWeight * (1 + objectiveBoost) * (0.4 + 0.6 * confidence) * noiseFactor * fanOutBonus;

  const bits: string[] = [item.type.replace(/_/g, ' ')];
  if (typeof hops === 'number') bits.push(hops <= 0 ? 'at objective' : `${hops} hop${hops === 1 ? '' : 's'} to objective`);
  if (noise >= 0.6) bits.push('noisy');
  else if (noise === 0) bits.push('silent');
  if (item.type === 'incomplete_node') bits.push('enrichment — deprioritized');
  return { priority, reason: bits.join(', ') };
}

/** Score every item and return them sorted by priority (highest first), each annotated. */
export function rankFrontier(items: FrontierItem[]): FrontierTaskSelection[] {
  return items
    .map(item => {
      const { priority, reason } = scoreItem(item);
      return { ...item, frontier_priority: Number(priority.toFixed(4)), rank_reason: reason };
    })
    .sort((a, b) => b.frontier_priority - a.frontier_priority || a.id.localeCompare(b.id));
}

/**
 * Rank by value, then select the surfaced window with a per-type diversity cap so a burst
 * of near-identical low-value items (metadata enrichment, one CIDR's hosts) cannot crowd
 * out pivots, credential tests, or exploitation. Diversity is a cap, not a hard quota — if
 * the cap leaves the window unfilled, the remaining slots are backfilled by priority, so
 * we never surface fewer tasks than available.
 */
export function selectFrontierTasks(items: FrontierItem[], maxItems: number): FrontierTaskSelection[] {
  if (maxItems <= 0) return [];
  const ranked = rankFrontier(items);
  const typeCap = Math.max(2, Math.ceil(maxItems * 0.4));
  const perType = new Map<string, number>();
  const chosen: FrontierTaskSelection[] = [];
  const deferred: FrontierTaskSelection[] = [];

  for (const r of ranked) {
    if (chosen.length >= maxItems) break;
    const used = perType.get(r.type) ?? 0;
    if (used < typeCap) {
      chosen.push(r);
      perType.set(r.type, used + 1);
    } else {
      deferred.push(r);
    }
  }
  for (const r of deferred) {
    if (chosen.length >= maxItems) break;
    chosen.push(r);
  }
  return chosen;
}
