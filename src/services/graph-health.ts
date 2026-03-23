import type { OverwatchGraph } from './engine-context.js';
import type { EdgeType, HealthIssue, HealthReport, HealthSeverity, HealthSummary, NodeProperties } from '../types.js';
import { normalizeKeyPart } from './parser-utils.js';
import { validateEdgeEndpoints } from './graph-schema.js';
import { getIdentityMarkers, isCanonicalIdentityNode, isIdentityType, isUnresolvedIdentityNode } from './identity-resolution.js';

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

  graph.forEachEdge((edgeId, attrs, source, target) => {
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

    issues.push({
      severity: 'warning',
      check: 'credential_identity_ambiguity',
      message: `Credential ${id} is missing domain qualification for account ${attrs.cred_user}`,
      node_ids: [id],
      details: {
        cred_user: attrs.cred_user,
        suggested_resolution: 'needs_operator_review',
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
