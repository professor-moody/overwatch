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

import type { FrontierItem, FrontierRank } from '../types.js';

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
  /** Composed priority — higher is more valuable. NOT a probability; a ranking value.
   *  Mirror of `rank.priority_score`, kept for back-compat with existing consumers. */
  frontier_priority: number;
  /** Short human-readable "why it's ranked here". Mirror of `rank.explanation`. */
  rank_reason: string;
}

/**
 * The ONE scoring function for a frontier item — the canonical projection every consumer
 * shares. Splits the ranking into legible axes (evidence_confidence / expected_value /
 * expected_noise) plus the composed priority_score and a human explanation.
 */
export function scoreItem(item: FrontierItem): FrontierRank {
  const typeWeight = TYPE_WEIGHT[item.type] ?? 0.5;
  const hops = item.graph_metrics?.hops_to_objective;
  // Objective proximity: an item on a path to an objective is boosted the closer it is
  // (0 hops → +1.0, 1 hop → +0.5, …). An item not on any known path (null) gets no boost
  // but is not zeroed — discovery still has value.
  const objectiveBoost = typeof hops === 'number' ? 1 / (1 + Math.max(hops, 0)) : 0;
  const noise = typeof item.opsec_noise === 'number' ? item.opsec_noise : 0.3;
  const noiseFactor = 1 / (1 + 2 * noise); // penalize cost/noise

  // Evidence confidence is the item's composite confidence multiplier (edge confidence ×
  // credential weight × KB success-rate boost × chain boost). It is deliberately NOT clamped
  // to 1: those boosts push a well-supported lead above 1.0, and the old clamp erased the
  // signal so a KB/chain-boosted lead and a plain one ranked identically. Guard only against
  // negative / pathological values.
  const evidence_confidence = typeof item.graph_metrics?.confidence === 'number'
    ? Math.min(Math.max(item.graph_metrics.confidence, 0), 3)
    : 0.6;
  const confidenceFactor = 0.4 + 0.6 * evidence_confidence;

  const fanOut = typeof item.graph_metrics?.fan_out_estimate === 'number' ? item.graph_metrics.fan_out_estimate : 0;
  const fanOutBonus = 1 + Math.min(Math.max(fanOut, 0), 20) / 40; // up to +0.5 for optionality

  // Attack-chain strength (ChainScorer's composite, ~0..9) was previously ignored entirely
  // by the ranker. Fold it into expected value so an item advancing a strong, nearly-complete
  // attack chain outranks an isolated one of the same type.
  const chainScore = typeof item.chain_score === 'number' ? item.chain_score : 0;
  const chainBonus = 1 + (Math.min(Math.max(chainScore, 0), 9) / 9) * 0.6; // up to +0.6

  const expected_value = typeWeight * (1 + objectiveBoost) * fanOutBonus * chainBonus;
  const priority_score = expected_value * confidenceFactor * noiseFactor;

  const bits: string[] = [item.type.replace(/_/g, ' ')];
  if (typeof hops === 'number') bits.push(hops <= 0 ? 'at objective' : `${hops} hop${hops === 1 ? '' : 's'} to objective`);
  if (chainScore > 0) bits.push(`chain value ${chainScore.toFixed(1)}`);
  if (evidence_confidence > 1) bits.push('boosted lead');
  if (noise >= 0.6) bits.push('noisy');
  else if (noise === 0) bits.push('silent');
  if (item.type === 'incomplete_node') bits.push('enrichment — deprioritized');

  return {
    priority_score: Number(priority_score.toFixed(4)),
    evidence_confidence: Number(evidence_confidence.toFixed(4)),
    expected_value: Number(expected_value.toFixed(4)),
    expected_noise: Number(noise.toFixed(4)),
    explanation: bits.join(', '),
  };
}

/** Score every item and return them sorted by priority (highest first), each annotated with
 *  its canonical `rank` (and the back-compat `frontier_priority` / `rank_reason` mirrors). */
export function rankFrontier(items: FrontierItem[]): FrontierTaskSelection[] {
  return items
    .map(item => {
      const rank = scoreItem(item);
      item.rank = rank;
      return { ...item, rank, frontier_priority: rank.priority_score, rank_reason: rank.explanation };
    })
    .sort((a, b) => b.frontier_priority - a.frontier_priority || a.id.localeCompare(b.id));
}

/**
 * Canonical ranking projection for the whole product: annotate every item with its `rank`
 * and sort by priority (highest first), IN PLACE. The engine calls this exactly once when it
 * builds the frontier, so every downstream consumer — next_task, get_state, the dashboard,
 * campaigns, and dispatch — reads the same ordered, explained frontier and never re-sorts.
 */
export function annotateFrontierRanks(items: FrontierItem[]): FrontierItem[] {
  for (const item of items) item.rank = scoreItem(item);
  items.sort((a, b) => (b.rank!.priority_score - a.rank!.priority_score) || a.id.localeCompare(b.id));
  return items;
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
