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
  REACHABLE: { source: ['host', 'cloud_identity', 'cloud_resource'], target: ['host', 'cloud_identity', 'cloud_resource'] },
  RUNS: { source: ['host'], target: ['service'] },
  // Domain membership
  MEMBER_OF: { source: ['user', 'group', 'cloud_identity'], target: ['group'] },
  MEMBER_OF_DOMAIN: { source: ['host', 'user', 'group'], target: ['domain'] },
  // Access
  ADMIN_TO: { source: ['user', 'group', 'credential'], target: ['host'] },
  HAS_SESSION: { source: ['user', 'group', 'credential'], target: ['host'] },
  CAN_RDPINTO: { source: ['user', 'group', 'credential'], target: ['host'] },
  CAN_PSREMOTE: { source: ['user', 'group', 'credential'], target: ['host'] },
  // Credential relationships
  VALID_ON: { source: ['user', 'group', 'credential'], target: ['host', 'service'] },
  TESTED_CRED: { source: ['user', 'group', 'credential'], target: ['host', 'service'] },
  OWNS_CRED: { source: ['user'], target: ['credential'] },
  DERIVED_FROM: { source: ['credential'], target: ['credential'] },
  // AD attack paths
  CAN_DCSYNC: { source: ['user', 'group'], target: ['domain'] },
  CAN_GET_CHANGES: { source: ['user', 'group'], target: ['domain'] },
  CAN_GET_CHANGES_ALL: { source: ['user', 'group'], target: ['domain'] },
  DELEGATES_TO: { source: ['user', 'host'], target: ['host', 'service'] },
  WRITEABLE_BY: { source: ['user', 'group'], target: ['user', 'group', 'host', 'gpo', 'ou', 'cert_template', 'ca'] },
  GENERIC_ALL: { source: ['user', 'group'], target: ['user', 'group', 'host', 'domain', 'gpo', 'ou', 'cert_template', 'ca'] },
  OWNS: { source: ['user', 'group'], target: ['user', 'group', 'host', 'domain', 'gpo', 'ou', 'cert_template', 'ca'] },
  GENERIC_WRITE: { source: ['user', 'group'], target: ['user', 'group', 'host', 'gpo', 'ou', 'cert_template'] },
  WRITE_OWNER: { source: ['user', 'group'], target: ['user', 'group', 'host', 'domain', 'gpo', 'ou', 'cert_template', 'ca'] },
  WRITE_DACL: { source: ['user', 'group'], target: ['user', 'group', 'host', 'domain', 'gpo', 'ou', 'cert_template', 'ca'] },
  ADD_MEMBER: { source: ['user', 'group'], target: ['group'] },
  FORCE_CHANGE_PASSWORD: { source: ['user', 'group'], target: ['user'] },
  ALLOWED_TO_ACT: { source: ['host', 'user', 'group'], target: ['host'] },
  // ADCS
  CAN_ENROLL: { source: ['user', 'group'], target: ['cert_template', 'ca'] },
  ISSUED_BY: { source: ['cert_template'], target: ['ca'] },
  OPERATES_CA: { source: ['domain'], target: ['ca'] },
  MANAGE_CA: { source: ['user', 'group'], target: ['ca'] },
  MANAGE_CERTIFICATES: { source: ['user', 'group'], target: ['ca'] },
  ESC1: { source: ['user', 'group'], target: ['cert_template'] },
  ESC2: { source: ['user', 'group'], target: ['cert_template'] },
  ESC3: { source: ['user', 'group'], target: ['cert_template'] },
  ESC4: { source: ['user', 'group'], target: ['cert_template'] },
  ESC5: { source: ['user', 'group'], target: ['cert_template', 'ca'] },
  ESC6: { source: ['user', 'group'], target: ['ca'] },
  ESC7: { source: ['user', 'group'], target: ['ca'] },
  ESC8: { source: ['user', 'group'], target: ['ca'] },
  ESC9: { source: ['user', 'group'], target: ['cert_template'] },
  ESC10: { source: ['user', 'group'], target: ['cert_template'] },
  ESC11: { source: ['user', 'group'], target: ['ca'] },
  ESC12: { source: ['user', 'group'], target: ['ca'] },
  ESC13: { source: ['user', 'group'], target: ['cert_template'] },
  // S3-A3: ESC15 (CVE-2024-49019) — enrollee-supplies-subject + schema v1.
  ESC15: { source: ['user', 'group'], target: ['cert_template'] },
  // Trust
  TRUSTS: { source: ['domain'], target: ['domain'] },
  SAME_DOMAIN: { source: ['host', 'user', 'group'], target: ['host', 'user', 'group'] },
  // Roasting
  AS_REP_ROASTABLE: { source: ['user'], target: ['domain'] },
  KERBEROASTABLE: { source: ['user'], target: ['domain'] },
  // Delegation
  CAN_DELEGATE_TO: { source: ['host', 'user'], target: ['host', 'service'] },
  // S2-3: an unconstrained-delegation host captures the forwarded TGT of
  // any principal that authenticates to it. Direction is host -> principal
  // (the captured identity), opposite to CAN_DELEGATE_TO.
  CAN_CAPTURE_TGT_FROM: { source: ['host'], target: ['user', 'group', 'credential'] },
  // ACL-derived
  CAN_READ_LAPS: { source: ['user', 'group'], target: ['host'] },
  CAN_READ_GMSA: { source: ['user', 'group'], target: ['user'] },
  RBCD_TARGET: { source: ['host', 'user'], target: ['host'] },
  // Credential reuse
  SHARED_CREDENTIAL: { source: ['credential'], target: ['credential'] },
  // Credential provenance
  DUMPED_FROM: { source: ['credential'], target: ['host'] },
  // Lateral movement
  RELAY_TARGET: { source: ['host', 'user', 'credential'], target: ['host'] },
  NULL_SESSION: { source: ['host'], target: ['host', 'service'] },
  POTENTIAL_AUTH: { source: ['credential', 'user', 'cloud_resource'], target: ['service', 'host', 'webapp', 'cloud_identity'] },
  // Web application surface
  HOSTS: { source: ['service'], target: ['webapp'] },
  AUTHENTICATED_AS: { source: ['credential'], target: ['webapp', 'api_endpoint'] },
  VULNERABLE_TO: { source: ['webapp', 'service', 'cloud_resource', 'api_endpoint'], target: ['vulnerability'] },
  EXPLOITS: { source: ['vulnerability'], target: ['host', 'credential', 'webapp', 'api_endpoint'] },
  HAS_ENDPOINT: { source: ['webapp'], target: ['api_endpoint'] },
  AUTH_BYPASS: { source: ['vulnerability'], target: ['webapp', 'api_endpoint'] },
  // Cloud infrastructure
  ASSUMES_ROLE: { source: ['cloud_identity', 'cloud_resource'], target: ['cloud_identity'] },
  // Service principal → app registration directory binding (Azure AD).
  // Distinct from ASSUMES_ROLE which implies RBAC takeover semantics.
  SERVICE_PRINCIPAL_FOR: { source: ['cloud_identity'], target: ['cloud_identity'] },
  HAS_POLICY: { source: ['cloud_identity', 'group'], target: ['cloud_policy'] },
  POLICY_ALLOWS: { source: ['cloud_policy'], target: ['cloud_resource'] },
  EXPOSED_TO: { source: ['cloud_resource'], target: ['cloud_network', 'subnet'] },
  RUNS_ON: { source: ['service', 'host', 'mock_service'], target: ['cloud_resource', 'host'] },
  MANAGED_BY: { source: ['cloud_resource'], target: ['cloud_identity'] },
  // Operator-controlled infrastructure
  OPERATED_BY: { source: ['mock_service'], target: ['user'] },
  BAITED: { source: ['mock_service'], target: ['credential'] },
  RELAYED_VIA: { source: ['credential'], target: ['mock_service'] },
  // Identity tier (Phase 1 enterprise readiness)
  // FEDERATES_WITH is bidirectional in spirit; we model the canonical
  // direction as idp → on-prem domain, with the reverse handled at query
  // time via the bidirectional edge-type set in path-analyzer.
  FEDERATES_WITH: { source: ['idp', 'domain'], target: ['idp', 'domain'] },
  AUTHENTICATES_VIA: { source: ['webapp', 'cloud_resource', 'api_endpoint'], target: ['idp_application'] },
  ASSIGNED_TO_APP: { source: ['idp_principal', 'user', 'group'], target: ['idp_application'] },
  MFA_REQUIRED_FOR: { source: ['idp_principal', 'user', 'group', 'idp_application'], target: ['idp_application'] },
  ISSUES_TOKENS_FOR: { source: ['idp_application'], target: ['cloud_identity', 'cloud_resource'] },
  // Cross-tier app/backend correlation
  BACKED_BY: { source: ['webapp', 'api_endpoint'], target: ['cloud_resource', 'host'] },
  // Inferred reachability (e.g. SSRF reaching IMDS) — intentionally weaker than BACKED_BY.
  CAN_REACH: { source: ['webapp', 'api_endpoint', 'host'], target: ['cloud_resource', 'host'] },
  // Token / hybrid identity validity
  VALID_FOR_APP: { source: ['credential'], target: ['idp_application'] },
  VALID_FOR_IDP_PRINCIPAL: { source: ['credential'], target: ['idp_principal'] },
  // Objective
  PATH_TO_OBJECTIVE: { source: ['host', 'user', 'credential', 'service', 'group', 'cloud_identity', 'cloud_resource', 'webapp'], target: ['objective'] },
  // OSINT / external recon (Phase 2A)
  SUBDOMAIN_OF: { source: ['subdomain'], target: ['domain', 'subdomain'] },
  RESOLVES_TO: { source: ['subdomain'], target: ['host'] },
  IN_NETBLOCK: { source: ['host'], target: ['asn'] },
  OWNS_ASSET: { source: ['organization'], target: ['domain', 'asn'] },
  AFFILIATED_WITH: { source: ['email'], target: ['organization'] },
  // RELATED is intentionally unconstrained
};

export function getEdgeConstraint(edgeType: EdgeType): EdgeConstraint | undefined {
  return EDGE_CONSTRAINTS[edgeType];
}

const _warnedUnconstrainedTypes = new Set<string>();

export function validateEdgeEndpoints(
  edgeType: EdgeType,
  sourceType: NodeType,
  targetType: NodeType,
  refs: Pick<EdgeConstraintViolation, 'source_id' | 'target_id'> & { edge_id?: string },
): { valid: true; unconstrained?: boolean } | { valid: false; violation: EdgeConstraintViolation; suggested_fix?: EdgeFixSuggestion } {
  const constraint = getEdgeConstraint(edgeType);
  if (!constraint) {
    if (!_warnedUnconstrainedTypes.has(edgeType)) {
      _warnedUnconstrainedTypes.add(edgeType);
      console.error(`[graph-schema] Edge type "${edgeType}" has no constraint definition — validation bypassed. Add it to EDGE_CONSTRAINTS to enforce topology checks.`);
    }
    return { valid: true, unconstrained: true };
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
      message: 'VALID_ON must target a host or service node, such as the domain controller or the specific service where the credential is valid.',
    };
  }

  return {
    kind: 'recreate_edge',
    message: `Edge ${violation.edge_type} must connect ${violation.expected_source_types.join('/')} to ${violation.expected_target_types.join('/')}.`,
  };
}
