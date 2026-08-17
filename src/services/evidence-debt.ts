// ============================================================
// Evidence Debt Queue
// ============================================================
// Ranks the engagement's open "evidence debt" — the specific quality problems an operator should
// act on — into one prioritized, drill-downable list, so the scorecard becomes an operating loop
// rather than a passive readout. Each item names a target (node / edge / objective / finding) so
// the UI can jump straight to inspect its evidence or correct the judgment.
//
// Categories (highest-severity first):
//   - contradiction        — a durable promotion conflicts with its own evidence (actively wrong)
//   - lapsed_objective     — a reached milestone whose supporting access has decayed
//   - unsupported_critical — a high/critical finding with no captured proof
//   - expiring_validation  — a positive promotion whose validity window is about to elapse

import type { GraphEngine } from './graph-engine.js';
import { buildFindings } from './report-generator.js';
import { hasCapturedProof } from './evidence-proof.js';
import { claimContradiction, type ClaimContradiction } from './source-trust.js';

export type EvidenceDebtKind =
  | 'contradiction'
  | 'lapsed_objective'
  | 'unsupported_critical'
  | 'expiring_validation';

export interface EvidenceDebtItem {
  kind: EvidenceDebtKind;
  /** Higher = more urgent; the queue is returned sorted by this descending. */
  severity: number;
  /** One-line, operator-facing description of the debt. */
  summary: string;
  /** Drill-down target — exactly the identifiers relevant to this item's kind. */
  node_id?: string;
  edge_id?: string;
  objective_id?: string;
  finding_id?: string;
}

/** Positive promotions carry a validity window worth watching as it approaches; negative/terminal
 *  ones (`refuted`) do not expire and `stale` is already decayed. */
const POSITIVE_PROMOTION_STATES = new Set(['observed', 'validated', 'exploited']);
/** Warn about a positive promotion whose window elapses within this horizon. */
const EXPIRY_HORIZON_MS = 7 * 24 * 60 * 60 * 1000;

function describeContradiction(kind: ClaimContradiction): string {
  return kind === 'refuted_but_evidence_positive'
    ? 'promoted refuted, but its evidence is positive'
    : 'promoted positive, but a test of it failed';
}

/**
 * Compute the ranked evidence-debt queue for an engagement, from the live graph. Findings are
 * rebuilt per call (as in the scorecard / findings view); the whole thing is an on-demand read.
 */
export function computeEvidenceDebt(engine: GraphEngine): EvidenceDebtItem[] {
  const config = engine.getConfig();
  const graph = engine.exportGraph({ sourceTrust: true });
  const history = engine.getFullHistory();
  const evidenceLoader = (id: string): string | null => {
    try { return engine.getEvidenceStore().getRawOutputHead(id, 256 * 1024)?.text ?? null; } catch { return null; }
  };
  const findings = buildFindings(graph, history, config, { evidenceLoader });
  const nowMs = Date.parse(engine.now());
  const items: EvidenceDebtItem[] = [];

  // 1. Contradictions — a durable promotion at odds with its own evidence. Both node and edge
  //    elements; exportGraph stamps the real engine edge id, so drill-down targets it directly.
  for (const n of graph.nodes) {
    const kind = claimContradiction(n.properties);
    if (kind) items.push({ kind: 'contradiction', severity: 100, summary: `${n.id}: ${describeContradiction(kind)}`, node_id: n.id });
  }
  for (const e of graph.edges) {
    const kind = claimContradiction(e.properties);
    if (kind) {
      const ref = `${String(e.properties.type ?? 'edge')} ${e.source}→${e.target}`;
      // node_id = source so the UI can focus the graph there (edges have no direct navigation).
      items.push({ kind: 'contradiction', severity: 100, summary: `${ref}: ${describeContradiction(kind)}`, node_id: e.source, ...(e.id ? { edge_id: e.id } : {}) });
    }
  }

  // 2. Lapsed objectives — reached (settled milestone) but no longer currently satisfied (support
  //    decayed). Uses the live, clock-evaluated check so a time-decayed claim counts immediately.
  //    Carry the matching target node so a validation agent can be dispatched against it.
  for (const obj of config.objectives ?? []) {
    if (obj.achieved && !engine.isObjectiveCurrentlySatisfied(obj)) {
      const target = obj.target_criteria
        ? engine.queryGraph({ node_type: obj.target_node_type, node_filter: obj.target_criteria }).nodes[0]?.id
        : undefined;
      items.push({
        kind: 'lapsed_objective', severity: 90,
        summary: `Objective "${obj.description}" was reached, but its supporting access has decayed — re-validate`,
        objective_id: obj.id, ...(target ? { node_id: target } : {}),
      });
    }
  }

  // 3. Unsupported critical findings — high/critical claims with no captured proof.
  for (const f of findings) {
    if ((f.severity === 'critical' || f.severity === 'high') && !hasCapturedProof(f)) {
      items.push({
        kind: 'unsupported_critical',
        severity: f.severity === 'critical' ? 85 : 70,
        summary: `${f.severity} finding without captured proof: ${f.title}`,
        finding_id: f.id,
      });
    }
  }

  // 4. Expiring validations — positive promotions whose validity window elapses soon.
  const scanExpiring = (props: Record<string, unknown>, ref: { node_id?: string; edge_id?: string }, label: string): void => {
    const promo = (props as { claim_promotion?: { state?: string; valid_until?: string } }).claim_promotion;
    if (!promo?.valid_until || !POSITIVE_PROMOTION_STATES.has(String(promo.state))) return;
    const until = Date.parse(promo.valid_until);
    if (!Number.isFinite(until) || !Number.isFinite(nowMs)) return;
    if (until > nowMs && until - nowMs <= EXPIRY_HORIZON_MS) {
      items.push({ kind: 'expiring_validation', severity: 40, summary: `${label} validation expires ${promo.valid_until} — re-validate before it decays to stale`, ...ref });
    }
  };
  for (const n of graph.nodes) scanExpiring(n.properties, { node_id: n.id }, n.id);
  for (const e of graph.edges) scanExpiring(e.properties, { node_id: e.source, ...(e.id ? { edge_id: e.id } : {}) }, `${String(e.properties.type ?? 'edge')} ${e.source}→${e.target}`);

  return items.sort((a, b) => b.severity - a.severity);
}
