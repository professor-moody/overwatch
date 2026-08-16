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
  MEMBER_OF: ['topology'],
  MEMBER_OF_DOMAIN: ['topology'],
  HOSTS: ['topology'],
  RUNS: ['topology'],
  RUNS_ON: ['topology'],
  REACHABLE: ['topology'],
  MANAGED_BY: ['topology'],
  TRUSTS: ['topology'],
  SAME_DOMAIN: ['topology'],
  HAS_ENDPOINT: ['topology'],
  HAS_POLICY: ['topology'],
  POLICY_ALLOWS: ['topology'],
  EXPOSED_TO: ['topology'],
  SERVICE_PRINCIPAL_FOR: ['topology'],
  ASSIGNED_TO_APP: ['topology'],
  MFA_REQUIRED_FOR: ['topology'],
  ISSUES_TOKENS_FOR: ['topology'],
  ISSUED_BY: ['topology'],
  SUBDOMAIN_OF: ['topology'],
  RESOLVES_TO: ['topology'],
  IN_NETBLOCK: ['topology'],
  OWNS_ASSET: ['topology'],
  AFFILIATED_WITH: ['topology'],
  // Inferred / weaker reachability leads + attack-surface opportunities (a principal is
  // roastable, a host is vulnerable, a relay/null-session is possible) — a lead, not access.
  POTENTIAL_AUTH: ['hypothesis'],
  CAN_REACH: ['hypothesis'],
  AS_REP_ROASTABLE: ['hypothesis'],
  KERBEROASTABLE: ['hypothesis'],
  VULNERABLE_TO: ['hypothesis'],
  RELAY_TARGET: ['hypothesis'],
  NULL_SESSION: ['hypothesis'],
  CAN_ENROLL: ['hypothesis'],
};

/**
 * Edge types intentionally left WITHOUT a role — reviewed and decided, not forgotten. Together
 * with EDGE_ROLES's keys this covers EVERY EdgeType (enforced by an exhaustiveness test), so a
 * newly-added edge type can't silently escape classification — the test fails until it is placed
 * in one list or the other. Grouped by why:
 *  - AD ACL / control edges (OWNS, GENERIC_WRITE, WRITE_DACL, ADD_MEMBER, FORCE_CHANGE_PASSWORD,
 *    ESC1-15, CAN_READ_LAPS/GMSA, RBCD_TARGET, …): genuine control-granting edges that are strong
 *    CANDIDATES for `material_access` — but adding them would change the orchestration-progress
 *    and attack-path counts, so that reclassification is a tracked behavior change, not silent.
 *  - credential provenance / app-scoped validity (DERIVED_FROM, DUMPED_FROM, SHARED_CREDENTIAL,
 *    VALID_FOR_APP, VALID_FOR_IDP_PRINCIPAL, AUTHENTICATED_AS): credential relationships, not
 *    access on their own.
 *  - operator-controlled decoy infra (OPERATED_BY, BAITED, RELAYED_VIA): not offensive progress.
 *  - synthetic bookkeeping (PATH_TO_OBJECTIVE, RELATED): not epistemic claims about the target.
 */
export const INTENTIONALLY_UNROLED_EDGE_TYPES: readonly EdgeType[] = [
  'DERIVED_FROM', 'DUMPED_FROM', 'DELEGATES_TO', 'WRITEABLE_BY', 'OWNS', 'GENERIC_WRITE',
  'WRITE_OWNER', 'WRITE_DACL', 'ADD_MEMBER', 'FORCE_CHANGE_PASSWORD', 'ALLOWED_TO_ACT',
  'MANAGE_CA', 'MANAGE_CERTIFICATES', 'OPERATES_CA',
  'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC7', 'ESC8', 'ESC9', 'ESC10', 'ESC11', 'ESC12', 'ESC13', 'ESC15',
  'CAN_DELEGATE_TO', 'CAN_CAPTURE_TGT_FROM', 'CAN_READ_LAPS', 'CAN_READ_GMSA', 'RBCD_TARGET',
  'SHARED_CREDENTIAL', 'AUTHENTICATED_AS', 'VALID_FOR_APP', 'VALID_FOR_IDP_PRINCIPAL',
  'OPERATED_BY', 'BAITED', 'RELAYED_VIA',
  'PATH_TO_OBJECTIVE', 'RELATED',
];

/** Edge types that carry a role — for the exhaustiveness guard. */
export const ROLED_EDGE_TYPES: readonly EdgeType[] = Object.keys(EDGE_ROLES) as EdgeType[];

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
