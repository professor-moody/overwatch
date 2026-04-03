import type { OverwatchGraph } from './engine-context.js';
import type { HealthIssue, HealthReport, HealthSeverity, HealthSummary, LabProfile, NodeProperties } from '../types.js';
import { normalizeKeyPart } from './parser-utils.js';
import { validateEdgeEndpoints } from './graph-schema.js';
import { getIdentityMarkers, isCanonicalIdentityNode, isIdentityType, isUnresolvedIdentityNode } from './identity-resolution.js';
import { isCredentialStaleOrExpired } from './credential-utils.js';

const SEVERITY_ORDER: Record<HealthSeverity, number> = {
  critical: 0,
  warning: 1,
};

export function runHealthChecks(graph: OverwatchGraph): HealthReport {
  const issues: HealthIssue[] = [];

  issues.push(...findSplitHostIdentities(graph));
  issues.push(...findDanglingEdgeIssues(graph));
  issues.push(...findUnresolvedIdentityIssues(graph));
  issues.push(...findCredentialIdentityAmbiguities(graph));
  issues.push(...findIdentityMarkerCollisions(graph));
  issues.push(...findSharedCredentialMaterialIssues(graph));
  issues.push(...findTypeConstraintViolations(graph));
  issues.push(...findStaleInferredEdges(graph));
  issues.push(...findExpiredCredentialAuthEdges(graph));
  issues.push(...findBrokenCredentialLineage(graph));
  issues.push(...findUnmarkedStaleCredentials(graph));

  const sortedIssues = issues.sort((left, right) => {
    const severityCompare = SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity];
    if (severityCompare !== 0) return severityCompare;
    return left.check.localeCompare(right.check);
  });

  const counts_by_severity = {
    warning: sortedIssues.filter(issue => issue.severity === 'warning').length,
    critical: sortedIssues.filter(issue => issue.severity === 'critical').length,
  } satisfies Record<HealthSeverity, number>;

  const status = counts_by_severity.critical > 0
    ? 'critical'
    : counts_by_severity.warning > 0
      ? 'warning'
      : 'healthy';

  return {
    status,
    counts_by_severity,
    issues: sortedIssues,
  };
}

export function summarizeHealthReport(report: HealthReport, maxIssues: number = 5): HealthSummary {
  return {
    status: report.status,
    counts_by_severity: report.counts_by_severity,
    top_issues: report.issues.slice(0, maxIssues),
  };
}

// Domain-dependent health check names that are expected noise in non-AD engagements
const AD_DEPENDENT_CHECKS = new Set([
  'credential_identity_ambiguity',
  'unresolved_identity',
]);

/**
 * Detect whether the graph contains any AD context — domain nodes,
 * domain-qualified users/groups, or kerberos/ldap services tied to domains.
 */
export function hasADContext(graph: OverwatchGraph): boolean {
  let found = false;
  graph.forEachNode((_id, attrs) => {
    if (found) return;
    if (attrs.type === 'domain') { found = true; return; }
    if ((attrs.type === 'user' || attrs.type === 'group') &&
        typeof attrs.domain_name === 'string' && attrs.domain_name.length > 0) {
      found = true; return;
    }
    if (attrs.type === 'service' &&
        (attrs.service_name === 'kerberos' || attrs.service_name === 'ldap')) {
      found = true; return;
    }
  });
  return found;
}

/**
 * Suppress domain-dependent credential/identity warnings from the health report
 * for non-goad_ad profiles when no AD context has been discovered yet.
 * Returns a new report; the original is not mutated.
 */
export function contextualFilterHealthReport(
  report: HealthReport,
  profile: LabProfile,
  adContextPresent: boolean,
): HealthReport {
  // No filtering needed for goad_ad or when AD context is present
  if (profile === 'goad_ad' || adContextPresent) return report;

  const filtered = report.issues.filter(issue => !AD_DEPENDENT_CHECKS.has(issue.check));
  if (filtered.length === report.issues.length) return report;

  const counts_by_severity = {
    warning: filtered.filter(issue => issue.severity === 'warning').length,
    critical: filtered.filter(issue => issue.severity === 'critical').length,
  } satisfies Record<HealthSeverity, number>;

  const status = counts_by_severity.critical > 0
    ? 'critical' as const
    : counts_by_severity.warning > 0
      ? 'warning' as const
      : 'healthy' as const;

  return { status, counts_by_severity, issues: filtered };
}

function findSplitHostIdentities(graph: OverwatchGraph): HealthIssue[] {
  const issues: HealthIssue[] = [];
  const hosts: Array<{ id: string; props: NodeProperties }> = [];

  graph.forEachNode((id, attrs) => {
    if (attrs.type === 'host') {
      hosts.push({ id, props: attrs });
    }
  });

  const hostIdsByIp = new Map<string, string[]>();
  const hostIdsByName = new Map<string, string[]>();

  for (const host of hosts) {
    if (typeof host.props.ip === 'string' && host.props.ip.length > 0) {
      const ids = hostIdsByIp.get(host.props.ip) || [];
      ids.push(host.id);
      hostIdsByIp.set(host.props.ip, ids);
    }

    for (const marker of getHostNameMarkers(host.props)) {
      const ids = hostIdsByName.get(marker) || [];
      ids.push(host.id);
      hostIdsByName.set(marker, ids);
    }
  }

  for (const [ip, ids] of hostIdsByIp) {
    const uniqueIds = [...new Set(ids)];
    if (uniqueIds.length > 1) {
      issues.push({
        severity: 'critical',
        check: 'split_host_identity_ip',
        message: `Multiple host nodes claim IP ${ip}`,
        node_ids: uniqueIds,
        details: { ip },
      });
    }
  }

  for (const [marker, ids] of hostIdsByName) {
    const uniqueIds = [...new Set(ids)];
    if (uniqueIds.length > 1) {
      issues.push({
        severity: 'critical',
        check: 'split_host_identity_hostname',
        message: `Multiple host nodes share hostname marker ${marker}`,
        node_ids: uniqueIds,
        details: { hostname_marker: marker },
      });
    }
  }

  return issues;
}

function findDanglingEdgeIssues(graph: OverwatchGraph): HealthIssue[] {
  const issues: HealthIssue[] = [];

  graph.forEachEdge((edgeId, _attrs, source, target) => {
    const missing: string[] = [];
    if (!graph.hasNode(source)) missing.push(`source:${source}`);
    if (!graph.hasNode(target)) missing.push(`target:${target}`);
    if (missing.length > 0) {
      issues.push({
        severity: 'critical',
        check: 'dangling_edge_reference',
        message: `Edge ${edgeId} references missing graph nodes`,
        edge_ids: [edgeId],
        details: { missing },
      });
    }
  });

  return issues;
}

function findUnresolvedIdentityIssues(graph: OverwatchGraph): HealthIssue[] {
  const issues: HealthIssue[] = [];

  graph.forEachNode((id, attrs) => {
    if (!isIdentityType(attrs.type) || !isUnresolvedIdentityNode({ ...attrs, id })) return;
    const severity = ['host', 'domain', 'ca', 'cert_template'].includes(attrs.type)
      ? 'critical'
      : 'warning';

    issues.push({
      severity,
      check: 'unresolved_identity',
      message: `Identity ${id} did not converge to a canonical ${attrs.type} node`,
      node_ids: [id],
      details: {
        bh_sid: attrs.bh_sid,
        type: attrs.type,
        identity_markers: getEffectiveIdentityMarkers(attrs),
        suggested_resolution: id.startsWith('bh-') ? 'auto_merge' : 'needs_operator_review',
      },
    });
  });

  return issues;
}

function findIdentityMarkerCollisions(graph: OverwatchGraph): HealthIssue[] {
  const issues: HealthIssue[] = [];
  const markerToNodes = new Map<string, Array<{ id: string; type: string }>>();

  graph.forEachNode((id, attrs) => {
    if (!isCanonicalIdentityNode({ ...attrs, id })) return;
    for (const marker of getEffectiveIdentityMarkers(attrs)) {
      const bucket = markerToNodes.get(marker) || [];
      bucket.push({ id, type: attrs.type });
      markerToNodes.set(marker, bucket);
    }
  });

  for (const [marker, nodes] of markerToNodes) {
    const uniqueIds = [...new Set(nodes.map((node) => node.id))];
    if (uniqueIds.length < 2) continue;
    const types = [...new Set(nodes.map((node) => node.type))];
    const isCredentialOnly = types.length === 1 && types[0] === 'credential';
    const severity: HealthSeverity = isCredentialOnly
      ? 'warning'
      : types.some((type) => ['host', 'domain', 'user', 'ca', 'cert_template'].includes(type))
        ? 'critical'
        : 'warning';
    const message = isCredentialOnly
      ? `Multiple credential nodes claim the same account-qualified identity marker ${marker}`
      : `Multiple canonical nodes claim identity marker ${marker}`;
    issues.push({
      severity,
      check: 'identity_marker_collision',
      message,
      node_ids: uniqueIds,
      details: {
        identity_marker: marker,
        node_types: types,
        suggested_resolution: isCredentialOnly ? 'needs_operator_review' : 'replace_id',
      },
    });
  }

  return issues;
}

function findCredentialIdentityAmbiguities(graph: OverwatchGraph): HealthIssue[] {
  const issues: HealthIssue[] = [];

  graph.forEachNode((id, attrs) => {
    if (attrs.type !== 'credential' || attrs.identity_status === 'superseded') return;
    if (typeof attrs.cred_user !== 'string' || attrs.cred_user.length === 0) return;
    if (typeof attrs.cred_domain === 'string' && attrs.cred_domain.length > 0) return;

    // Determine why inference didn't resolve this
    let hasOwner = false;
    const candidateDomains = new Set<string>();
    graph.forEachInEdge(id, (_edgeId, edgeAttrs, source) => {
      if (edgeAttrs.type !== 'OWNS_CRED') return;
      const sourceAttrs = graph.getNodeAttributes(source);
      if (sourceAttrs.type !== 'user') return;
      hasOwner = true;
      let foundEdgeDomain = false;
      graph.forEachOutEdge(source, (_eid, eAttrs, _src, target) => {
        if (eAttrs.type !== 'MEMBER_OF_DOMAIN') return;
        const tgtAttrs = graph.getNodeAttributes(target);
        if (tgtAttrs.type === 'domain') {
          const dn = tgtAttrs.domain_name || tgtAttrs.label;
          if (typeof dn === 'string' && dn.length > 0) {
            candidateDomains.add(dn.toLowerCase());
            foundEdgeDomain = true;
          }
        }
      });
      // Fallback: use owner's domain_name property if no MEMBER_OF_DOMAIN edges found
      if (!foundEdgeDomain) {
        const ownerDn = sourceAttrs.domain_name;
        if (typeof ownerDn === 'string' && ownerDn.length > 0) {
          candidateDomains.add(ownerDn.toLowerCase());
        }
      }
    });

    const suggestedResolution = !hasOwner
      ? 'no_owner'
      : candidateDomains.size === 0
        ? 'owner_has_no_domain'
        : 'multiple_domains';

    issues.push({
      severity: 'warning',
      check: 'credential_identity_ambiguity',
      message: `Credential ${id} is missing domain qualification for account ${attrs.cred_user}`,
      node_ids: [id],
      details: {
        cred_user: attrs.cred_user,
        suggested_resolution: suggestedResolution,
        candidate_domains: candidateDomains.size > 1 ? [...candidateDomains] : undefined,
      },
    });
  });

  return issues;
}

function findSharedCredentialMaterialIssues(graph: OverwatchGraph): HealthIssue[] {
  const issues: HealthIssue[] = [];
  const materialToNodes = new Map<string, Array<{ id: string; account: string; material_kind: string; fingerprint: string }>>();

  graph.forEachNode((id, attrs) => {
    if (attrs.type !== 'credential' || attrs.identity_status === 'superseded') return;
    const materialKind = typeof attrs.cred_material_kind === 'string'
      ? attrs.cred_material_kind
      : typeof attrs.cred_type === 'string'
        ? attrs.cred_type
        : undefined;
    const fingerprint = typeof attrs.cred_hash === 'string'
      ? attrs.cred_hash
      : typeof attrs.cred_value === 'string'
        ? attrs.cred_value
        : undefined;
    if (!materialKind || !fingerprint) return;

    const bucketKey = `${normalizeKeyPart(materialKind)}:${normalizeKeyPart(fingerprint)}`;
    const account = typeof attrs.cred_user === 'string'
      ? `${attrs.cred_domain || '<unknown>'}\\${attrs.cred_user}`
      : attrs.label || id;
    const bucket = materialToNodes.get(bucketKey) || [];
    bucket.push({ id, account, material_kind: materialKind, fingerprint });
    materialToNodes.set(bucketKey, bucket);
  });

  for (const [materialKey, nodes] of materialToNodes) {
    const uniqueIds = [...new Set(nodes.map((node) => node.id))];
    if (uniqueIds.length < 2) continue;
    const uniqueAccounts = [...new Set(nodes.map((node) => node.account))];
    if (uniqueAccounts.length < 2) continue;
    issues.push({
      severity: 'warning',
      check: 'shared_credential_material',
      message: `Multiple credential nodes share the same material fingerprint ${materialKey}`,
      node_ids: uniqueIds,
      details: {
        material_key: materialKey,
        accounts: uniqueAccounts,
        suggested_resolution: 'none',
      },
    });
  }

  return issues;
}

function findTypeConstraintViolations(graph: OverwatchGraph): HealthIssue[] {
  const issues: HealthIssue[] = [];

  graph.forEachEdge((edgeId, attrs, source, target) => {
    const sourceNode = graph.getNodeAttributes(source);
    const targetNode = graph.getNodeAttributes(target);
    const validation = validateEdgeEndpoints(attrs.type, sourceNode.type, targetNode.type, {
      edge_id: edgeId,
      source_id: source,
      target_id: target,
    });
    if (!validation.valid) {
      issues.push({
        severity: 'critical',
        check: 'edge_type_constraint',
        message: `Edge ${attrs.type} violates source/target type constraints`,
        edge_ids: [edgeId],
        node_ids: [source, target],
        details: {
          expected_source_types: validation.violation.expected_source_types,
          expected_target_types: validation.violation.expected_target_types,
          actual_source_type: sourceNode.type,
          actual_target_type: targetNode.type,
          violations: [{
            source_id: source,
            edge_type: attrs.type,
            target_id: target,
            source_type: sourceNode.type,
            target_type: targetNode.type,
          }],
          suggested_fix: validation.suggested_fix,
        },
      });
    }
  });

  return issues;
}

function findStaleInferredEdges(graph: OverwatchGraph): HealthIssue[] {
  const issues: HealthIssue[] = [];

  graph.forEachEdge((edgeId, attrs, source, target) => {
    if (!attrs.inferred_by_rule) return;

    if (attrs.inferred_by_rule === 'rule-smb-signing-relay' && attrs.type === 'RELAY_TARGET') {
      const supported = graph.outEdges(target).some((candidateEdgeId: string) => {
        const edgeAttrs = graph.getEdgeAttributes(candidateEdgeId);
        if (edgeAttrs.type !== 'RUNS') return false;
        const serviceNode = graph.getNodeAttributes(graph.target(candidateEdgeId));
        return serviceNode.type === 'service' && serviceNode.service_name === 'smb' && serviceNode.smb_signing === false;
      });

      if (!supported) {
        issues.push({
          severity: 'warning',
          check: 'stale_inferred_edge',
          message: `Inferred RELAY_TARGET edge ${edgeId} no longer has SMB-signing-disabled support`,
          edge_ids: [edgeId],
          node_ids: [source, target],
          details: { rule_id: attrs.inferred_by_rule },
        });
      }
    }
  });

  return issues;
}

function getHostNameMarkers(node: NodeProperties): string[] {
  const candidates = [
    typeof node.hostname === 'string' ? node.hostname : undefined,
    typeof node.dnshostname === 'string' ? node.dnshostname : undefined,
    typeof node.dNSHostName === 'string' ? node.dNSHostName : undefined,
    typeof node.label === 'string' && !isIpv4(node.label) ? node.label : undefined,
  ].filter((value): value is string => typeof value === 'string' && value.trim().length > 0);

  const markers = new Set(candidates.map(value => normalizeKeyPart(value)));
  // Also add short hostname for FQDNs so braavos.essos.local matches BRAAVOS
  for (const name of candidates) {
    const dotIdx = name.indexOf('.');
    if (dotIdx > 0) {
      markers.add(normalizeKeyPart(name.substring(0, dotIdx)));
    }
  }
  return [...markers];
}

function isIpv4(value: string): boolean {
  return /^\d+\.\d+\.\d+\.\d+$/.test(value.trim());
}

function getEffectiveIdentityMarkers(node: NodeProperties): string[] {
  // Always recompute from node properties so stale persisted markers
  // (e.g. old credential:material:* entries) don't cause false positives.
  return getIdentityMarkers(node);
}

function findExpiredCredentialAuthEdges(graph: OverwatchGraph): HealthIssue[] {
  const issues: HealthIssue[] = [];

  graph.forEachNode((id, attrs) => {
    if (attrs.type !== 'credential' || attrs.identity_status === 'superseded') return;
    if (!isCredentialStaleOrExpired(attrs)) return;

    const activeAuthEdges: string[] = [];
    for (const edgeId of graph.outEdges(id) as string[]) {
      const edgeAttrs = graph.getEdgeAttributes(edgeId);
      if (edgeAttrs.type === 'POTENTIAL_AUTH' && edgeAttrs.confidence >= 0.5) {
        activeAuthEdges.push(edgeId);
      }
    }

    if (activeAuthEdges.length > 0) {
      issues.push({
        severity: 'warning',
        check: 'expired_credential_auth_edges',
        message: `Expired/stale credential ${id} still has ${activeAuthEdges.length} active POTENTIAL_AUTH edge(s) with confidence >= 0.5`,
        node_ids: [id],
        edge_ids: activeAuthEdges,
        details: {
          credential_status: attrs.credential_status,
          valid_until: attrs.valid_until,
        },
      });
    }
  });

  return issues;
}

function findBrokenCredentialLineage(graph: OverwatchGraph): HealthIssue[] {
  const issues: HealthIssue[] = [];

  graph.forEachEdge((edgeId, attrs, source, target) => {
    if (attrs.type !== 'DERIVED_FROM') return;

    const missing: string[] = [];
    if (!graph.hasNode(source)) {
      missing.push(`source:${source}`);
    } else {
      const sourceAttrs = graph.getNodeAttributes(source);
      if (sourceAttrs.identity_status === 'superseded') {
        missing.push(`source:${source} (superseded)`);
      }
    }
    if (!graph.hasNode(target)) {
      missing.push(`target:${target}`);
    } else {
      const targetAttrs = graph.getNodeAttributes(target);
      if (targetAttrs.identity_status === 'superseded') {
        missing.push(`target:${target} (superseded)`);
      }
    }

    if (missing.length > 0) {
      issues.push({
        severity: 'critical',
        check: 'broken_credential_lineage',
        message: `DERIVED_FROM edge ${edgeId} references missing or superseded credential node(s)`,
        edge_ids: [edgeId],
        node_ids: [source, target],
        details: { missing },
      });
    }
  });

  return issues;
}

function findUnmarkedStaleCredentials(graph: OverwatchGraph): HealthIssue[] {
  const issues: HealthIssue[] = [];
  const now = Date.now();

  graph.forEachNode((id, attrs) => {
    if (attrs.type !== 'credential' || attrs.identity_status === 'superseded') return;

    if (typeof attrs.valid_until === 'string') {
      const expiry = new Date(attrs.valid_until).getTime();
      if (Number.isFinite(expiry) && expiry < now) {
        if (!attrs.credential_status || attrs.credential_status === 'active') {
          issues.push({
            severity: 'warning',
            check: 'unmarked_stale_credential',
            message: `Credential ${id} has valid_until in the past but credential_status is still '${attrs.credential_status || 'unset'}'`,
            node_ids: [id],
            details: {
              valid_until: attrs.valid_until,
              credential_status: attrs.credential_status,
            },
          });
        }
      }
    }
  });

  return issues;
}
