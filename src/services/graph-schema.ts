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
  RUNS: { source: ['host'], target: ['service'] },
  MEMBER_OF: { source: ['user', 'group'], target: ['group'] },
  MEMBER_OF_DOMAIN: { source: ['host', 'user', 'group'], target: ['domain'] },
  OWNS_CRED: { source: ['user'], target: ['credential'] },
  VALID_ON: { source: ['user', 'group', 'credential'], target: ['host'] },
  ADMIN_TO: { source: ['user', 'group', 'credential'], target: ['host'] },
  HAS_SESSION: { source: ['user', 'group', 'credential'], target: ['host'] },
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
