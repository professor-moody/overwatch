import type { OverwatchGraph } from './engine-context.js';
import type { EdgeType, HealthIssue, HealthReport, HealthSeverity, HealthSummary, NodeProperties } from '../types.js';
import { normalizeKeyPart } from './parser-utils.js';

const SEVERITY_ORDER: Record<HealthSeverity, number> = {
  critical: 0,
  warning: 1,
};

type EdgeConstraint = {
  source: string[];
  target: string[];
};

const EDGE_CONSTRAINTS: Partial<Record<EdgeType, EdgeConstraint>> = {
  RUNS: { source: ['host'], target: ['service'] },
  MEMBER_OF: { source: ['user', 'group'], target: ['group'] },
  MEMBER_OF_DOMAIN: { source: ['host', 'user', 'group'], target: ['domain'] },
  OWNS_CRED: { source: ['user'], target: ['credential'] },
  VALID_ON: { source: ['user', 'group', 'credential'], target: ['host'] },
  ADMIN_TO: { source: ['user', 'group', 'credential'], target: ['host'] },
  HAS_SESSION: { source: ['user', 'group', 'credential'], target: ['host'] },
};

export function runHealthChecks(graph: OverwatchGraph): HealthReport {
  const issues: HealthIssue[] = [];

  issues.push(...findSplitHostIdentities(graph));
  issues.push(...findDanglingEdgeIssues(graph));
  issues.push(...findUnresolvedBloodHoundIdentities(graph));
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

function findUnresolvedBloodHoundIdentities(graph: OverwatchGraph): HealthIssue[] {
  const issues: HealthIssue[] = [];

  graph.forEachNode((id, attrs) => {
    if (!id.startsWith('bh-')) return;
    if (!attrs.bh_sid) return;
    if (!['host', 'user', 'domain'].includes(attrs.type)) return;

    issues.push({
      severity: 'warning',
      check: 'unresolved_bloodhound_identity',
      message: `BloodHound identity ${id} did not converge to a canonical ${attrs.type} node`,
      node_ids: [id],
      details: { bh_sid: attrs.bh_sid, type: attrs.type },
    });
  });

  return issues;
}

function findTypeConstraintViolations(graph: OverwatchGraph): HealthIssue[] {
  const issues: HealthIssue[] = [];

  graph.forEachEdge((edgeId, attrs, source, target) => {
    const constraint = EDGE_CONSTRAINTS[attrs.type];
    if (!constraint) return;

    const sourceNode = graph.getNodeAttributes(source);
    const targetNode = graph.getNodeAttributes(target);
    if (!constraint.source.includes(sourceNode.type) || !constraint.target.includes(targetNode.type)) {
      issues.push({
        severity: 'critical',
        check: 'edge_type_constraint',
        message: `Edge ${attrs.type} violates source/target type constraints`,
        edge_ids: [edgeId],
        node_ids: [source, target],
        details: {
          expected_source_types: constraint.source,
          expected_target_types: constraint.target,
          actual_source_type: sourceNode.type,
          actual_target_type: targetNode.type,
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

  return [...new Set(candidates.map(value => normalizeKeyPart(value)))];
}

function isIpv4(value: string): boolean {
  return /^\d+\.\d+\.\d+\.\d+$/.test(value.trim());
}
