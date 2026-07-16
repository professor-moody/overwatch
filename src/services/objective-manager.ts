// ============================================================
// Objective Manager
// Objective CRUD, achievement evaluation, phase tracking
// extracted from GraphEngine.
// ============================================================

import { v4 as uuidv4 } from 'uuid';
import type { EngineContext, ActivityLogEntry } from './engine-context.js';
import { isCredentialUsableForAuth } from './credential-utils.js';
import { isLiveSessionEdge } from './session-edge-utils.js';
import type {
  NodeProperties, NodeType, EdgeType,
  EngagementConfig, EngagementState,
  GraphQuery, GraphQueryResult, PhaseStatus, PhaseCriterion,
} from '../types.js';

export interface ObjectiveManagerHost {
  ctx: EngineContext;
  getNode(id: string): NodeProperties | null;
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

const DEFAULT_ACCESS_EDGE_TYPES = new Set(['HAS_SESSION', 'ADMIN_TO', 'OWNS_CRED']);

export function evaluateObjectives(host: ObjectiveManagerHost): void {
  const objectives = structuredClone(host.ctx.config.objectives);
  const changed = evaluateObjectiveDraft(host, objectives);
  if (changed) host.commitObjectives(objectives, 'objective.evaluate');
  syncObjectiveNodes(host);
}

function evaluateObjectiveDraft(
  host: ObjectiveManagerHost,
  objectives: EngagementConfig['objectives'],
): boolean {
  let changed = false;
  for (const obj of objectives) {
    if (obj.achieved) continue;
    // Check if objective criteria are met in the graph
    if (obj.target_criteria) {
      const matching = host.queryGraph({
        node_type: obj.target_node_type,
        node_filter: obj.target_criteria
      });
      const accessEdgeTypes = obj.achievement_edge_types
        ? new Set(obj.achievement_edge_types)
        : DEFAULT_ACCESS_EDGE_TYPES;
      // A matching node must also be obtained — via an access edge, an explicit
      // obtained flag, or (for shares) readable/writable properties.
      const obtained = matching.nodes.some(n => {
        const nodeProps = n.properties;
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
            return accessEdgeTypes.has(ep.type) && ep.confidence >= 0.9;
          }
          return nodeProps.type === 'credential' && isCredentialUsableForAuth(nodeProps) && ep.confidence >= 0.9;
        });
      });
      if (obtained) {
        obj.achieved = true;
        obj.achieved_at = host.nowIso();
        changed = true;
      }
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
    host.ctx.graph.mergeNodeAttributes(nodeId, {
      objective_description: objective.description,
      objective_achieved: objective.achieved,
      objective_achieved_at: objective.achieved_at,
      last_seen_at: now,
    } as Partial<NodeProperties>);
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
          if (ep.type === 'ADMIN_TO' && ep.confidence >= 0.9) return true;
          if (ep.type === 'HAS_SESSION' && ep.confidence >= 0.9 && ep.session_live === true) return true;
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
      return ep.type === 'OWNS_CRED' && ep.confidence >= 0.9;
    });
  });
  if (hasDa) return 'domain_admin';
  // Check for local admin
  const hasAdmin = !!host.ctx.graph.findEdge((_, attrs) =>
    attrs.type === 'ADMIN_TO' && attrs.confidence >= 0.9
  );
  if (hasAdmin) return 'local_admin';
  return 'user';
}
