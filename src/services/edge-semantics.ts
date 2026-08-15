// ============================================================
// Canonical edge-type semantics registry
// ============================================================
// ONE source of truth for "what does this edge type MEAN" — is it material access we
// gained, a declared topology linkage, an exploited weakness, a credential relationship?
//
// Before this, four consumers each hand-maintained their own edge-type allowlist:
//   - objective-manager  (DEFAULT_ACCESS_EDGE_TYPES: what counts as "obtained")
//   - eval-run           (ORCH_ACCESS_EDGE_TYPES:    what counts as material offensive progress)
//   - engagement-scorecard (ATTACK_PATH_EDGE_TYPES:  what's an attack-path edge)
//   - path-analyzer      (inline HAS_SESSION / ADMIN_TO: what roots an attack path)
// They drifted — the orchestration set had already accreted topology edges (BACKED_BY /
// FEDERATES_WITH) and a non-edge (CROSS_TIER_PIVOT), which overstated progress (fixed in the
// edge-ID-delta change). Deriving every consumer from this registry retires that drift class.
//
// Roles are additive: an edge can be both material_access AND credential_access. The named
// sets below are pure projections of the roles, so a consumer never re-lists edge types.

import type { EdgeType } from '../types.js';

export type EdgeRole =
  /** Access / escalation / control gained over an asset — a shell, admin rights, a captured
   *  or validated credential, a directory-replication right, a role assumption. The material
   *  offensive progress an engagement is trying to make. */
  | 'material_access'
  /** An exploited weakness (a demonstrated exploit / auth bypass), distinct from the access
   *  it yields. */
  | 'exploitation'
  /** A credential relationship (a principal owns / a credential is valid on / was tested). */
  | 'credential_access'
  /** Counts as "obtained" for the DEFAULT objective-achievement check (a narrow, high-signal
   *  subset — a live session, local-admin rights, or an owned credential). */
  | 'objective_default'
  /** Qualifies a host as a live attack-path START (a current beachhead: session or admin). */
  | 'host_access'
  /** A declared / structural linkage that grants NO access on its own (backend wiring, SSO
   *  federation, DNS hierarchy, membership). Deliberately excluded from progress + attack-path
   *  metrics. */
  | 'topology'
  /** An inferred / weaker reachability lead (a hypothesis, e.g. SSRF-reaching or a potential
   *  auth), not yet a demonstrated capability. */
  | 'hypothesis';

/**
 * The registry. Only edge types with a meaningful role are listed; anything absent has no
 * special semantics (plain discovery / metadata). Keys are typed as EdgeType, so a typo or a
 * renamed edge type fails to compile — the drift can't silently reappear.
 */
const EDGE_ROLES: Partial<Record<EdgeType, readonly EdgeRole[]>> = {
  // Direct access / control.
  HAS_SESSION: ['material_access', 'objective_default', 'host_access'],
  ADMIN_TO: ['material_access', 'objective_default', 'host_access'],
  OWNS_CRED: ['material_access', 'objective_default', 'credential_access'],
  CAN_RDPINTO: ['material_access'],
  CAN_PSREMOTE: ['material_access'],
  // Credential validation / reuse.
  VALID_ON: ['material_access', 'credential_access'],
  TESTED_CRED: ['material_access', 'credential_access'],
  // AD directory-control / replication rights that yield material access.
  CAN_DCSYNC: ['material_access'],
  CAN_GET_CHANGES: ['material_access'],
  CAN_GET_CHANGES_ALL: ['material_access'],
  GENERIC_ALL: ['material_access'],
  // Cloud role assumption.
  ASSUMES_ROLE: ['material_access'],
  // Exploited weaknesses.
  EXPLOITS: ['exploitation'],
  AUTH_BYPASS: ['exploitation'],
  // Declared topology / structural linkages — grant no access on their own.
  BACKED_BY: ['topology'],
  FEDERATES_WITH: ['topology'],
  AUTHENTICATES_VIA: ['topology'],
  // Inferred / weaker reachability leads.
  POTENTIAL_AUTH: ['hypothesis'],
  CAN_REACH: ['hypothesis'],
};

function typesWithRole(role: EdgeRole): ReadonlySet<string> {
  return new Set(
    (Object.entries(EDGE_ROLES) as Array<[EdgeType, readonly EdgeRole[]]>)
      .filter(([, roles]) => roles.includes(role))
      .map(([type]) => type),
  );
}

function hasRole(type: string | undefined, role: EdgeRole): boolean {
  if (!type) return false;
  const roles = EDGE_ROLES[type as EdgeType];
  return !!roles && roles.includes(role);
}

// ---- Canonical named sets: pure projections of the roles above. ----

/** Material offensive access/escalation edges. (eval-run's material-progress set.) */
export const MATERIAL_ACCESS_EDGE_TYPES: ReadonlySet<string> = typesWithRole('material_access');

/** Attack-path edges: material access plus exploited weaknesses. (scorecard's set.) */
export const ATTACK_PATH_EDGE_TYPES: ReadonlySet<string> = new Set([
  ...typesWithRole('material_access'),
  ...typesWithRole('exploitation'),
]);

/** Edges that count as "obtained" for the default objective-achievement check. */
export const OBJECTIVE_ACCESS_EDGE_TYPES: ReadonlySet<string> = typesWithRole('objective_default');

/** Edges that root a live attack-path start (a current beachhead). */
export const HOST_ACCESS_EDGE_TYPES: ReadonlySet<string> = typesWithRole('host_access');

// ---- Predicates for single-type checks. ----

export const isMaterialAccessEdge = (type?: string): boolean => hasRole(type, 'material_access');
export const isAttackPathEdge = (type?: string): boolean => hasRole(type, 'material_access') || hasRole(type, 'exploitation');
export const isObjectiveAccessEdge = (type?: string): boolean => hasRole(type, 'objective_default');
export const isHostAccessEdge = (type?: string): boolean => hasRole(type, 'host_access');
export const isCredentialAccessEdge = (type?: string): boolean => hasRole(type, 'credential_access');
export const isTopologyEdge = (type?: string): boolean => hasRole(type, 'topology');
