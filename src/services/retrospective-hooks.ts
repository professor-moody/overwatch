// ============================================================
// Overwatch — Retrospective Hooks
// Auto-apply inference rule suggestions from retrospective
// analysis and annotate skills with historical outcomes.
// ============================================================

import type { InferenceRuleSuggestion, InferenceRule, ExportedGraph, NodeProperties } from '../types.js';
import { KnowledgeBase } from './knowledge-base.js';
import { EDGE_TO_ATTACK } from './finding-classifier.js';

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

// ============================================================
// Knowledge Base Import from Engagement
// ============================================================

export interface KBImportResult {
  techniques_imported: number;
  credentials_imported: number;
  defenses_imported: number;
}

/**
 * Extract technique, credential, and defense stats from an engagement graph
 * and import them into the knowledge base.
 */
export function importEngagementToKB(
  graph: ExportedGraph,
  kb: KnowledgeBase,
): KBImportResult {
  const techniques: Array<{ id: string; name: string; success: boolean; noise: number }> = [];
  const credentials: Array<{ service: string; isDefault: boolean; isWeak: boolean; username?: string }> = [];
  const defenses: Array<{ defense: string; techniquesBlocked: string[]; wasBypassed: boolean }> = [];

  // Extract technique stats from edges
  const seenTechniques = new Set<string>();
  for (const edge of graph.edges) {
    const tech = EDGE_TO_ATTACK[edge.properties.type];
    if (!tech) continue;
    const key = `${tech.id}-${edge.properties.test_result || 'untested'}`;
    if (seenTechniques.has(key)) continue;
    seenTechniques.add(key);
    techniques.push({
      id: tech.id,
      name: tech.name,
      success: edge.properties.test_result === 'success' || edge.properties.confidence >= 0.9,
      noise: typeof edge.properties.opsec_noise === 'number' ? edge.properties.opsec_noise : 0.3,
    });
  }

  // Extract credential patterns from credential nodes
  for (const node of graph.nodes) {
    const props = node.properties as NodeProperties;
    if (props.type !== 'credential') continue;
    const service = props.cred_type || 'unknown';
    credentials.push({
      service,
      isDefault: !!props.cred_is_default_guess,
      isWeak: props.cred_material_kind === 'plaintext_password',
      username: props.cred_user,
    });
  }

  // Extract defense info from host EDR/defense properties
  const seenDefenses = new Set<string>();
  for (const node of graph.nodes) {
    const props = node.properties as NodeProperties;
    if (props.type !== 'host' || !props.edr) continue;
    if (seenDefenses.has(props.edr)) continue;
    seenDefenses.add(props.edr);
    // Check if any edge from this host was successfully tested (defense bypassed)
    const wasBypassed = graph.edges.some(
      e => (e.source === node.id || e.target === node.id) && e.properties.test_result === 'success',
    );
    defenses.push({
      defense: props.edr,
      techniquesBlocked: [], // would need deeper analysis
      wasBypassed,
    });
  }

  kb.importFromEngagement({ techniques, credentials, defenses });
  kb.save();

  return {
    techniques_imported: techniques.length,
    credentials_imported: credentials.length,
    defenses_imported: defenses.length,
  };
}
