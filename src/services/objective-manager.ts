// ============================================================
// Objective Manager
// Objective CRUD, achievement evaluation, phase tracking
// extracted from GraphEngine.
// ============================================================

import { v4 as uuidv4 } from 'uuid';
import type { EngineContext, ActivityLogEntry } from './engine-context.js';
import { isCredentialUsableForAuth } from './credential-utils.js';
import { isLiveSessionEdge } from './session-edge-utils.js';
import { claimState, isMatureClaim, type ClaimStateInput } from './source-trust.js';
import { OBJECTIVE_ACCESS_EDGE_TYPES } from './edge-semantics.js';
import type {
  NodeProperties, NodeType, EdgeType,
  EngagementConfig, EngagementState,
  GraphQuery, GraphQueryResult, PhaseStatus, PhaseCriterion,
} from '../types.js';

export interface ObjectiveManagerHost {
  ctx: EngineContext;
  getNode(id: string): NodeProperties | null;
  addNode(props: NodeProperties): string;
  getNodesByType(type: NodeType): NodeProperties[];
  queryGraph(query: GraphQuery): GraphQueryResult;
  persist(detail?: Record<string, unknown>): void;
  log(message: string, agentId?: string, extra?: Partial<ActivityLogEntry>): void;
  commitObjectives(objectives: EngagementConfig['objectives'], source: string): void;
  nowIso(): string;
}

// =============================================
// Objective CRUD
// =============================================

export function addObjective(
  host: ObjectiveManagerHost,
  obj: { description: string; target_node_type?: string; target_criteria?: Record<string, unknown>; achievement_edge_types?: string[] },
): EngagementConfig['objectives'][0] {
  const objective = {
    id: uuidv4(),
    description: obj.description,
    target_node_type: obj.target_node_type as NodeType | undefined,
    target_criteria: obj.target_criteria,
    achievement_edge_types: obj.achievement_edge_types as EdgeType[] | undefined,
    achieved: false,
  };
  host.commitObjectives([...host.ctx.config.objectives, objective], 'objective.add');
  return objective;
}

export function updateObjective(
  host: ObjectiveManagerHost,
  id: string,
  updates: Record<string, unknown>,
): boolean {
  const objectives = structuredClone(host.ctx.config.objectives);
  const obj = objectives.find(o => o.id === id);
  if (!obj) return false;
  if (typeof updates.description === 'string') obj.description = updates.description;
  if (typeof updates.target_node_type === 'string') obj.target_node_type = updates.target_node_type as NodeType;
  if (typeof updates.achieved === 'boolean') {
    obj.achieved = updates.achieved;
    obj.achieved_at = updates.achieved ? host.nowIso() : undefined;
  }
  if (updates.target_criteria !== undefined) obj.target_criteria = updates.target_criteria as Record<string, unknown>;
  if (Array.isArray(updates.achievement_edge_types)) obj.achievement_edge_types = updates.achievement_edge_types as EdgeType[];
  host.commitObjectives(objectives, 'objective.update');
  return true;
}

export function removeObjective(
  host: ObjectiveManagerHost,
  id: string,
): boolean {
  const objectives = host.ctx.config.objectives.filter(o => o.id !== id);
  const idx = host.ctx.config.objectives.findIndex(o => o.id === id);
  if (idx === -1) return false;
  host.commitObjectives(objectives, 'objective.remove');
  return true;
}

// =============================================
// Objective Evaluation
// =============================================

export function evaluateObjectives(host: ObjectiveManagerHost, opts?: { reconcile?: boolean }): void {
  const objectives = structuredClone(host.ctx.config.objectives);
  const changed = evaluateObjectiveDraft(host, objectives, opts);
  if (changed) host.commitObjectives(objectives, 'objective.evaluate');
  syncObjectiveNodes(host);
}

/** Whether an objective's target is currently obtained: a matching node reached via a MATURE
 *  access edge, an explicit `obtained` flag, or (for shares) readable/writable access. Pure
 *  read over the live graph (evaluated against `now`) — the single check achievement,
 *  reconciliation, AND the live scorecard's `currently_satisfied` all use, so a claim decaying by
 *  time is reflected on read without a mutating re-evaluation. */
export function isObjectiveObtained(
  host: ObjectiveManagerHost,
  obj: EngagementConfig['objectives'][number],
): boolean {
  if (!obj.target_criteria) return false;
  const matching = host.queryGraph({
    node_type: obj.target_node_type,
    node_filter: obj.target_criteria,
  });
  const accessEdgeTypes = obj.achievement_edge_types
    ? new Set<string>(obj.achievement_edge_types)
    : OBJECTIVE_ACCESS_EDGE_TYPES;
  return matching.nodes.some(n => {
    const nodeProps = n.properties;
    // A target whose OWN claim has been refuted or staled (an operator disproved the
    // credential, or it rotated) no longer counts as obtained, even if a mature access edge
    // still points at it — refuting/staling the target node propagates to the objective.
    const nodeState = claimState(nodeProps as ClaimStateInput, host.nowIso());
    if (nodeState === 'refuted' || nodeState === 'stale') return false;
    if (nodeProps.type === 'credential' && !isCredentialUsableForAuth(nodeProps)) {
      return false;
    }
    if (n.properties.obtained === true) return true;
    // Shares with readable/writable access count as obtained
    if (nodeProps.type === 'share' && (nodeProps.readable === true || nodeProps.writable === true)) {
      return true;
    }
    return host.ctx.graph.inEdges(n.id).some((e: string) => {
      const ep = host.ctx.graph.getEdgeAttributes(e);
      // F1: a HAS_SESSION edge that's been marked dead does NOT count
      // as obtaining the objective. Other access edges (ADMIN_TO,
      // OWNS_CRED, custom achievement_edge_types) are unaffected.
      if (ep.type === 'HAS_SESSION' && !isLiveSessionEdge(ep)) return false;
      if (ep.type !== 'OWNS_CRED') {
        return accessEdgeTypes.has(ep.type) && isMatureClaim(ep, host.nowIso());
      }
      return nodeProps.type === 'credential' && isCredentialUsableForAuth(nodeProps) && isMatureClaim(ep, host.nowIso());
    });
  });
}

/** Whether an objective's supporting access has been affirmatively DISPROVEN — a `refuted`
 *  promotion on a matching target node, or on an access edge into one. This (and only this) REVOKES
 *  the settled milestone: a refutation says the access was never truly established, so an objective
 *  it completed was never really achieved. Decay (`stale`) or mere absence does NOT revoke it —
 *  those lapse the live `currently_satisfied` while the milestone stays recorded. Deterministic over
 *  the live graph, so the milestone is un-achieved consistently on EVERY evaluation (self-healing at
 *  startup / on the next mutation), never dependent on a post-transaction reconcile call that a
 *  crash could skip. */
function isObjectiveSupportRefuted(
  host: ObjectiveManagerHost,
  obj: EngagementConfig['objectives'][number],
): boolean {
  if (!obj.target_criteria) return false;
  const now = host.nowIso();
  const matching = host.queryGraph({ node_type: obj.target_node_type, node_filter: obj.target_criteria });
  const accessEdgeTypes = obj.achievement_edge_types
    ? new Set<string>(obj.achievement_edge_types)
    : OBJECTIVE_ACCESS_EDGE_TYPES;
  return matching.nodes.some(n => {
    if (claimState(n.properties as ClaimStateInput, now) === 'refuted') return true;
    return host.ctx.graph.inEdges(n.id).some((e: string) => {
      const ep = host.ctx.graph.getEdgeAttributes(e);
      return accessEdgeTypes.has(ep.type) && claimState(ep as ClaimStateInput, now) === 'refuted';
    });
  });
}

export interface ObjectiveSupportRef {
  id: string;
  description: string;
  achieved: boolean;
  currently_satisfied: boolean;
}

/** Which objectives an element (a node or an edge) is part of the support chain for — i.e. the
 *  objectives that a refutation/staling of this element could lapse. A node supports an objective
 *  when it IS a matching target, or when it is the source of an access edge into one; an edge
 *  supports when it is an access edge (of the objective's achievement types) into a matching target.
 *  Pure read over the live graph — powers the claim editor's impact preview. */
export function objectivesSupportedByElement(
  host: ObjectiveManagerHost,
  target: { node_id?: string; edge_id?: string },
): ObjectiveSupportRef[] {
  const supported: ObjectiveSupportRef[] = [];
  let edge: { target: string; type: string } | undefined;
  if (target.edge_id && host.ctx.graph.hasEdge(target.edge_id)) {
    edge = { target: host.ctx.graph.target(target.edge_id), type: String(host.ctx.graph.getEdgeAttributes(target.edge_id).type) };
  }
  for (const obj of host.ctx.config.objectives) {
    if (!obj.target_criteria) continue;
    const matching = new Set(
      host.queryGraph({ node_type: obj.target_node_type, node_filter: obj.target_criteria }).nodes.map(n => n.id),
    );
    if (matching.size === 0) continue;
    const accessEdgeTypes = obj.achievement_edge_types
      ? new Set<string>(obj.achievement_edge_types)
      : OBJECTIVE_ACCESS_EDGE_TYPES;
    let supports = false;
    if (target.node_id) {
      supports = matching.has(target.node_id)
        || host.ctx.graph.outEdges(target.node_id).some((e: string) => {
          const ep = host.ctx.graph.getEdgeAttributes(e);
          return accessEdgeTypes.has(ep.type) && matching.has(host.ctx.graph.target(e));
        });
    } else if (edge) {
      supports = accessEdgeTypes.has(edge.type) && matching.has(edge.target);
    }
    if (supports) {
      supported.push({
        id: obj.id,
        description: obj.description,
        achieved: !!obj.achieved,
        currently_satisfied: obj.currently_satisfied ?? !!obj.achieved,
      });
    }
  }
  return supported;
}

function evaluateObjectiveDraft(
  host: ObjectiveManagerHost,
  objectives: EngagementConfig['objectives'],
  opts?: { reconcile?: boolean },
): boolean {
  let changed = false;
  for (const obj of objectives) {
    // Only target-criteria objectives are (un)obtained via the graph here; criterion-based
    // ones (e.g. access_level) have their own evaluation path.
    if (!obj.target_criteria) continue;

    const obtained = isObjectiveObtained(host, obj);

    // LIVE satisfaction — recomputed on EVERY evaluation (not gated by the milestone), so passive
    // decay is reflected without any promotion: a credential whose validity window elapsed, or a
    // rotated credential, reads as no longer satisfied on the next evaluation. `lost_at` stamps a
    // genuine OBSERVED true→false transition (an objective that was actually satisfied and then
    // lapsed) — NOT a milestone that an operator marked done but the graph never supported — and
    // clears when it is satisfied again.
    const wasSatisfied = obj.currently_satisfied === true;
    if (obj.currently_satisfied !== obtained) {
      obj.currently_satisfied = obtained;
      changed = true;
    }
    if (!obtained && wasSatisfied) {
      if (!obj.lost_at) { obj.lost_at = host.nowIso(); changed = true; }
    } else if (obtained && obj.lost_at) {
      obj.lost_at = undefined;
      changed = true;
    }

    // SETTLED MILESTONE — first obtainment latches `achieved`. It is revoked when the supporting
    // access is affirmatively DISPROVEN (`refuted`), evaluated deterministically here on EVERY pass
    // so that revocation SELF-HEALS — a refuting promotion whose post-transaction reconcile is lost
    // to a crash is repaired on the next evaluation (startup or any later mutation), not left
    // dependent on a single reconcile call. A decayed (`stale`) claim leaves the milestone recorded.
    // `opts.reconcile` additionally allows an EXPLICIT operator action (a withdrawal) to un-achieve
    // when the support reverts to any un-obtained state — e.g. retracting the sole validation that
    // completed the objective drops it back to an unproven candidate.
    if (obtained && !obj.achieved) {
      obj.achieved = true;
      obj.achieved_at = host.nowIso();
      changed = true;
    } else if (!obtained && obj.achieved && (isObjectiveSupportRefuted(host, obj) || opts?.reconcile)) {
      obj.achieved = false;
      obj.achieved_at = undefined;
      changed = true;
    }
  }
  return changed;
}

export function recomputeObjectives(
  host: ObjectiveManagerHost,
): { before: Array<{ id: string; achieved: boolean; achieved_at?: string }>; after: Array<{ id: string; achieved: boolean; achieved_at?: string }> } {
  const before = host.ctx.config.objectives.map(obj => ({
    id: obj.id,
    achieved: obj.achieved,
    achieved_at: obj.achieved_at,
  }));

  const objectives = structuredClone(host.ctx.config.objectives);
  for (const obj of objectives) {
    obj.achieved = false;
    delete obj.achieved_at;
    delete obj.currently_satisfied;
    delete obj.lost_at;
  }
  evaluateObjectiveDraft(host, objectives);
  host.commitObjectives(objectives, 'objective.recompute');
  syncObjectiveNodes(host);
  const after = objectives.map(obj => ({
    id: obj.id,
    achieved: obj.achieved,
    achieved_at: obj.achieved_at,
  }));
  return { before, after };
}

export function syncObjectiveNodes(host: ObjectiveManagerHost): void {
  const now = host.nowIso();
  for (const objective of host.ctx.config.objectives) {
    const nodeId = `obj-${objective.id}`;
    const existing = host.getNode(nodeId);
    if (!existing) continue;
    host.addNode({
      ...existing,
      objective_description: objective.description,
      objective_achieved: objective.achieved,
      objective_achieved_at: objective.achieved_at,
      objective_currently_satisfied: objective.currently_satisfied,
      objective_lost_at: objective.lost_at,
      last_seen_at: now,
    });
  }
}

// =============================================
// Phase Tracking
// =============================================

export function getPhaseStatuses(host: ObjectiveManagerHost): EngagementState['phases'] {
  const phases = host.ctx.config.phases;
  if (!phases || phases.length === 0) return [];

  const sorted = [...phases].sort((a, b) => a.order - b.order);
  const completedPhases = new Set<string>();
  const result: EngagementState['phases'] = [];

  for (const phase of sorted) {
    const entryMet = evaluateCriteria(host, phase.entry_criteria, completedPhases);
    const exitMet = evaluateCriteria(host, phase.exit_criteria, completedPhases);

    let status: PhaseStatus;
    if (exitMet && entryMet) {
      status = 'completed';
      completedPhases.add(phase.id);
    } else if (entryMet) {
      status = 'active';
    } else {
      status = 'locked';
    }

    result.push({
      id: phase.id,
      name: phase.name,
      order: phase.order,
      status,
      strategies: phase.strategies,
      entry_criteria_met: entryMet,
      exit_criteria_met: exitMet,
    });
  }

  return result;
}

export function getCurrentPhaseId(host: ObjectiveManagerHost): string | undefined {
  const statuses = getPhaseStatuses(host);
  const active = statuses.find(p => p.status === 'active');
  return active?.id;
}

/**
 * P4.1: return the full EngagementPhase record for the currently-active
 * phase, or undefined when no phase is active. Used by validateAction
 * and the approval queue to pick up per-phase OPSEC/approval overrides.
 */
export function getCurrentPhase(host: ObjectiveManagerHost): import('../types.js').EngagementPhase | undefined {
  const id = getCurrentPhaseId(host);
  if (!id) return undefined;
  return host.ctx.config.phases?.find(p => p.id === id);
}

// =============================================
// Phase Criteria Evaluation
// =============================================

function evaluateCriteria(
  host: ObjectiveManagerHost,
  criteria: PhaseCriterion[],
  completedPhases: Set<string>,
): boolean {
  if (criteria.length === 0) return true;
  return criteria.every(c => evaluateSingleCriterion(host, c, completedPhases));
}

function evaluateSingleCriterion(
  host: ObjectiveManagerHost,
  criterion: PhaseCriterion,
  completedPhases: Set<string>,
): boolean {
  switch (criterion.type) {
    case 'always':
      return true;
    case 'phase_completed':
      return completedPhases.has(criterion.phase_id);
    case 'objective_achieved':
      return host.ctx.config.objectives.some(
        o => o.id === criterion.objective_id && o.achieved,
      );
    case 'node_count': {
      let count = 0;
      host.ctx.graph.forEachNode((_, attrs) => {
        if (attrs.type === criterion.node_type && !attrs.superseded_by) count++;
      });
      return count >= criterion.min;
    }
    case 'access_level': {
      const levels: Record<string, number> = { none: 0, user: 1, local_admin: 2, domain_admin: 3 };
      const compromised: string[] = [];
      host.ctx.graph.forEachNode((_, attrs) => {
        if (attrs.type !== 'host' || attrs.superseded_by) return;
        const hasAccess = host.ctx.graph.inEdges(attrs.id).some((e: string) => {
          const ep = host.ctx.graph.getEdgeAttributes(e);
          if (ep.type === 'ADMIN_TO' && isMatureClaim(ep, host.nowIso())) return true;
          if (ep.type === 'HAS_SESSION' && isMatureClaim(ep, host.nowIso()) && ep.session_live === true) return true;
          return false;
        });
        if (hasAccess) compromised.push(attrs.label);
      });
      const current = computeAccessLevel(host, compromised);
      return (levels[current] ?? 0) >= (levels[criterion.min_level] ?? 0);
    }
    default:
      return false;
  }
}

export function computeAccessLevel(host: ObjectiveManagerHost, compromised: string[]): string {
  if (compromised.length === 0) return 'none';
  const scopeDomains = host.ctx.config.scope.domains.map(d => d.toLowerCase());
  // Check for DA — credential must be actually obtained, not just discovered,
  // AND must be a domain credential matching a scope domain.
  const hasDa = host.getNodesByType('credential').some(c => {
    if (c.privileged !== true || c.confidence < 0.9 || !isCredentialUsableForAuth(c)) return false;
    // Must be a domain credential matching a scope domain
    if (!c.cred_domain || !scopeDomains.includes(c.cred_domain.toLowerCase())) return false;
    // Must have an OWNS_CRED inbound edge or explicit obtained flag
    if (c.obtained === true) return true;
    return host.ctx.graph.inEdges(c.id).some((e: string) => {
      const ep = host.ctx.graph.getEdgeAttributes(e);
      return ep.type === 'OWNS_CRED' && isMatureClaim(ep, host.nowIso());
    });
  });
  if (hasDa) return 'domain_admin';
  // Check for local admin
  const hasAdmin = !!host.ctx.graph.findEdge((_, attrs) =>
    attrs.type === 'ADMIN_TO' && isMatureClaim(attrs, host.nowIso())
  );
  if (hasAdmin) return 'local_admin';
  return 'user';
}
