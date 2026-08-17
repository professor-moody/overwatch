// ============================================================
// Engagement quality — live scorecard for an engine
// ============================================================
// Computes the same ground-truth-free scorecard the report renders, directly from an engine and
// without building a full report document. Kept in its own module (not report-assembler) so the
// report pipeline's "one prepared document model" architecture invariant holds — this is a
// lightweight, on-demand path (findings are rebuilt per call, like the dashboard's findings view).

import type { GraphEngine } from './graph-engine.js';
import { buildFindings } from './report-generator.js';
import { computeEngagementScorecard, type EngagementScorecard } from './engagement-scorecard.js';
import { objectiveProofBacked } from './report-assembler.js';

export function computeEngagementScorecardForEngine(engine: GraphEngine): EngagementScorecard {
  const config = engine.getConfig();
  // sourceTrust attaches claim_state, which the verification / attack-path dimensions need.
  const graph = engine.exportGraph({ sourceTrust: true });
  const history = engine.getFullHistory();
  const evidenceLoader = (id: string): string | null => {
    try { return engine.getEvidenceStore().getRawOutputHead(id, 256 * 1024)?.text ?? null; } catch { return null; }
  };
  const findings = buildFindings(graph, history, config, { evidenceLoader });
  const scorecardObjectives = (config.objectives ?? []).map(obj => ({
    achieved: obj.achieved,
    currently_satisfied: obj.currently_satisfied ?? obj.achieved,
    proof_ready: objectiveProofBacked(engine, graph, obj),
  }));
  return computeEngagementScorecard(graph, findings, scorecardObjectives);
}
