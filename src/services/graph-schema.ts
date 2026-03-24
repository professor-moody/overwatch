import type { EdgeType, NodeType } from '../types.js';

export type EdgeConstraint = {
  source: NodeType[];
  target: NodeType[];
};

export type EdgeConstraintViolation = {
  source_id: string;
  target_id: string;
  edge_type: EdgeType;
  source_type: NodeType;
  target_type: NodeType;
  expected_source_types: NodeType[];
  expected_target_types: NodeType[];
  edge_id?: string;
};

export type EdgeFixSuggestion =
  | { kind: 'replace_edge_type'; edge_type: EdgeType; message: string }
  | { kind: 'retarget_required'; message: string }
  | { kind: 'recreate_edge'; message: string };

export const EDGE_CONSTRAINTS: Partial<Record<EdgeType, EdgeConstraint>> = {
  // Network
  REACHABLE: { source: ['host'], target: ['host'] },
  RUNS: { source: ['host'], target: ['service'] },
  // Domain membership
  MEMBER_OF: { source: ['user', 'group'], target: ['group'] },
  MEMBER_OF_DOMAIN: { source: ['host', 'user', 'group'], target: ['domain'] },
  // Access
  ADMIN_TO: { source: ['user', 'group', 'credential'], target: ['host'] },
  HAS_SESSION: { source: ['user', 'group', 'credential'], target: ['host'] },
  CAN_RDPINTO: { source: ['user', 'group', 'credential'], target: ['host'] },
  CAN_PSREMOTE: { source: ['user', 'group', 'credential'], target: ['host'] },
  // Credential relationships
  VALID_ON: { source: ['user', 'group', 'credential'], target: ['host'] },
  OWNS_CRED: { source: ['user'], target: ['credential'] },
  DERIVED_FROM: { source: ['credential'], target: ['credential'] },
  // AD attack paths
  CAN_DCSYNC: { source: ['user', 'group'], target: ['domain'] },
  DELEGATES_TO: { source: ['user', 'host'], target: ['host', 'service'] },
  WRITEABLE_BY: { source: ['user', 'group'], target: ['user', 'group', 'host', 'gpo', 'ou', 'cert_template', 'ca'] },
  GENERIC_ALL: { source: ['user', 'group'], target: ['user', 'group', 'host', 'domain', 'gpo', 'ou', 'cert_template', 'ca'] },
  GENERIC_WRITE: { source: ['user', 'group'], target: ['user', 'group', 'host', 'gpo', 'ou', 'cert_template'] },
  WRITE_OWNER: { source: ['user', 'group'], target: ['user', 'group', 'host', 'domain', 'gpo', 'ou', 'cert_template', 'ca'] },
  WRITE_DACL: { source: ['user', 'group'], target: ['user', 'group', 'host', 'domain', 'gpo', 'ou', 'cert_template', 'ca'] },
  ADD_MEMBER: { source: ['user', 'group'], target: ['group'] },
  FORCE_CHANGE_PASSWORD: { source: ['user', 'group'], target: ['user'] },
  ALLOWED_TO_ACT: { source: ['host', 'user'], target: ['host'] },
  // ADCS
  CAN_ENROLL: { source: ['user', 'group'], target: ['cert_template', 'ca'] },
  ESC1: { source: ['user', 'group'], target: ['cert_template'] },
  ESC2: { source: ['user', 'group'], target: ['cert_template'] },
  ESC3: { source: ['user', 'group'], target: ['cert_template'] },
  ESC4: { source: ['user', 'group'], target: ['cert_template'] },
  ESC6: { source: ['user', 'group'], target: ['ca'] },
  ESC8: { source: ['user', 'group'], target: ['ca'] },
  // Trust
  TRUSTS: { source: ['domain'], target: ['domain'] },
  SAME_DOMAIN: { source: ['host', 'user', 'group'], target: ['host', 'user', 'group'] },
  // Roasting
  AS_REP_ROASTABLE: { source: ['user'], target: ['domain'] },
  KERBEROASTABLE: { source: ['user'], target: ['domain'] },
  // Delegation
  CAN_DELEGATE_TO: { source: ['host', 'user'], target: ['host', 'service'] },
  // ACL-derived
  CAN_READ_LAPS: { source: ['user', 'group'], target: ['host'] },
  CAN_READ_GMSA: { source: ['user', 'group'], target: ['user'] },
  RBCD_TARGET: { source: ['host', 'user'], target: ['host'] },
  // Credential provenance
  DUMPED_FROM: { source: ['credential'], target: ['host'] },
  // Lateral movement
  RELAY_TARGET: { source: ['host', 'user', 'credential'], target: ['host'] },
  NULL_SESSION: { source: ['host'], target: ['host', 'service'] },
  POTENTIAL_AUTH: { source: ['credential', 'user'], target: ['service', 'host'] },
  // Objective
  PATH_TO_OBJECTIVE: { source: ['host', 'user', 'credential', 'service', 'group'], target: ['objective'] },
  // RELATED is intentionally unconstrained
};

export function getEdgeConstraint(edgeType: EdgeType): EdgeConstraint | undefined {
  return EDGE_CONSTRAINTS[edgeType];
}

export function validateEdgeEndpoints(
  edgeType: EdgeType,
  sourceType: NodeType,
  targetType: NodeType,
  refs: Pick<EdgeConstraintViolation, 'source_id' | 'target_id'> & { edge_id?: string },
): { valid: true } | { valid: false; violation: EdgeConstraintViolation; suggested_fix?: EdgeFixSuggestion } {
  const constraint = getEdgeConstraint(edgeType);
  if (!constraint) {
    return { valid: true };
  }

  if (constraint.source.includes(sourceType) && constraint.target.includes(targetType)) {
    return { valid: true };
  }

  const violation: EdgeConstraintViolation = {
    source_id: refs.source_id,
    target_id: refs.target_id,
    edge_type: edgeType,
    source_type: sourceType,
    target_type: targetType,
    expected_source_types: constraint.source,
    expected_target_types: constraint.target,
    edge_id: refs.edge_id,
  };

  return {
    valid: false,
    violation,
    suggested_fix: getSuggestedEdgeFix(violation),
  };
}

export function getSuggestedEdgeFix(violation: EdgeConstraintViolation): EdgeFixSuggestion | undefined {
  if (violation.edge_type === 'RUNS' && violation.source_type === 'host' && violation.target_type === 'share') {
    return {
      kind: 'replace_edge_type',
      edge_type: 'RELATED',
      message: 'Shares should be linked from hosts with RELATED, not RUNS.',
    };
  }

  if (violation.edge_type === 'VALID_ON' && violation.target_type === 'domain') {
    return {
      kind: 'retarget_required',
      message: 'VALID_ON must target a host node, such as the domain controller where the credential is valid.',
    };
  }

  return {
    kind: 'recreate_edge',
    message: `Edge ${violation.edge_type} must connect ${violation.expected_source_types.join('/')} to ${violation.expected_target_types.join('/')}.`,
  };
}
