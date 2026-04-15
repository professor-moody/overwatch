// ============================================================
// Overwatch — Technique Priors
// Per-technique success rates derived from RLVR training traces.
// Used to enrich validate_action() with historical success data.
// ============================================================

import type { RLVRTrace } from '../types.js';

export interface TechniquePrior {
  technique: string;
  total_attempts: number;
  successful_attempts: number;
  success_rate: number;
  avg_reward: number;
  last_seen?: string;
}

/**
 * Compute per-technique success rates from training traces.
 * Techniques are extracted from trace action descriptions and tool names.
 */
export function computeTechniquePriors(traces: RLVRTrace[]): Map<string, TechniquePrior> {
  const priors = new Map<string, TechniquePrior>();

  for (const trace of traces) {
    // Extract technique identifier from the trace
    const technique = extractTechnique(trace);
    if (!technique) continue;

    const existing = priors.get(technique) || {
      technique,
      total_attempts: 0,
      successful_attempts: 0,
      success_rate: 0,
      avg_reward: 0,
    };

    existing.total_attempts++;
    if (trace.reward > 0) existing.successful_attempts++;
    existing.avg_reward = (existing.avg_reward * (existing.total_attempts - 1) + trace.reward) / existing.total_attempts;
    existing.success_rate = existing.total_attempts > 0 ? existing.successful_attempts / existing.total_attempts : 0;
    existing.last_seen = trace.timestamp;

    priors.set(technique, existing);
  }

  return priors;
}

/**
 * Extract a technique identifier from a training trace.
 */
function extractTechnique(trace: RLVRTrace): string | undefined {
  // Try action.tool first
  if (trace.action?.tool) return trace.action.tool.toLowerCase();

  // Try action.technique
  if (trace.action?.technique) return trace.action.technique.toLowerCase();

  // Try action.type
  if (trace.action?.type) return trace.action.type.toLowerCase();

  return undefined;
}

/**
 * Look up the success prior for a technique.
 * Returns the prior if available, or a default unknown prior.
 */
export function getTechniquePrior(
  technique: string,
  priors: Map<string, TechniquePrior>,
): TechniquePrior | null {
  return priors.get(technique.toLowerCase()) || null;
}
