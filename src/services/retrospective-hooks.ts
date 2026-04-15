// ============================================================
// Overwatch — Retrospective Hooks
// Auto-apply inference rule suggestions from retrospective
// analysis and annotate skills with historical outcomes.
// ============================================================

import type { InferenceRuleSuggestion, InferenceRule } from '../types.js';

export interface AutoApplyResult {
  applied: InferenceRuleSuggestion[];
  skipped: InferenceRuleSuggestion[];
  errors: Array<{ suggestion: InferenceRuleSuggestion; error: string }>;
}

/**
 * Review inference suggestions and auto-apply those that meet quality thresholds.
 * - Requires occurrences >= minOccurrences (default 5)
 */
export function applyInferenceSuggestions(
  suggestions: InferenceRuleSuggestion[],
  addRule: (rule: InferenceRule) => void,
  options: { minOccurrences?: number } = {},
): AutoApplyResult {
  const minOccurrences = options.minOccurrences ?? 5;

  const applied: InferenceRuleSuggestion[] = [];
  const skipped: InferenceRuleSuggestion[] = [];
  const errors: AutoApplyResult['errors'] = [];

  for (const suggestion of suggestions) {
    // Check quality thresholds
    if ((suggestion.occurrences ?? 0) < minOccurrences) {
      skipped.push(suggestion);
      continue;
    }

    // Apply the suggested rule directly
    try {
      addRule(suggestion.rule);
      applied.push(suggestion);
    } catch (err) {
      errors.push({
        suggestion,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return { applied, skipped, errors };
}

export interface SkillAnnotation {
  skill_name: string;
  last_used?: string;           // ISO timestamp
  use_count: number;
  success_count: number;
  failure_count: number;
  success_rate: number;
  last_outcome?: 'success' | 'failure' | 'partial';
  notes?: string;
}

export interface SkillAnnotations {
  version: number;
  updated_at: string;
  annotations: Record<string, SkillAnnotation>;
}

/**
 * Update skill annotations based on retrospective analysis.
 */
export function updateSkillAnnotations(
  existing: SkillAnnotations | null,
  skillResults: Array<{ skill_name: string; outcome: 'success' | 'failure' | 'partial'; timestamp?: string }>,
): SkillAnnotations {
  const annotations = existing?.annotations ? { ...existing.annotations } : {};
  const now = new Date().toISOString();

  for (const result of skillResults) {
    const current = annotations[result.skill_name] || {
      skill_name: result.skill_name,
      use_count: 0,
      success_count: 0,
      failure_count: 0,
      success_rate: 0,
    };

    current.use_count++;
    if (result.outcome === 'success') current.success_count++;
    else if (result.outcome === 'failure') current.failure_count++;
    current.success_rate = current.use_count > 0 ? current.success_count / current.use_count : 0;
    current.last_used = result.timestamp || now;
    current.last_outcome = result.outcome;

    annotations[result.skill_name] = current;
  }

  return {
    version: (existing?.version ?? 0) + 1,
    updated_at: now,
    annotations,
  };
}
