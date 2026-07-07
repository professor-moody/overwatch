import type { Finding, NodeProperties } from '../types.js';
import { NODE_TYPES } from '../types.js';
import { getCredentialMaterialKind, isCredentialUsableForAuth } from './credential-utils.js';
import { validateEdgeEndpoints } from './graph-schema.js';

export type MutationValidationError = {
  code: 'missing_node_reference' | 'edge_type_constraint' | 'credential_material_missing';
  message: string;
  node_id?: string;
  source_id?: string;
  target_id?: string;
  edge_type?: string;
  suggestion?: Record<string, unknown>;
  details?: Record<string, unknown>;
};

export type PreparedFinding = {
  finding: Finding;
  errors: MutationValidationError[];
};

export function prepareFindingForIngest(
  finding: Finding,
  getExistingNode: (nodeId: string) => NodeProperties | null,
): PreparedFinding {
  const normalizedNodes = finding.nodes.map(node => normalizeFindingNode(node));
  const nodeMap = new Map<string, NodeProperties>();
  const errors: MutationValidationError[] = [];

  for (const node of normalizedNodes) {
    nodeMap.set(node.id, node as NodeProperties);
    errors.push(...validateFindingNode(node));
  }

  for (const edge of finding.edges) {
    const sourceNode = nodeMap.get(edge.source) || getExistingNode(edge.source);
    const targetNode = nodeMap.get(edge.target) || getExistingNode(edge.target);

    if (!sourceNode || !targetNode) {
      errors.push({
        code: 'missing_node_reference',
        message: `Edge ${edge.properties.type} references node(s) that are not present in the graph or the submitted finding.`,
        source_id: edge.source,
        target_id: edge.target,
        edge_type: edge.properties.type,
        details: {
          missing_source: !sourceNode,
          missing_target: !targetNode,
        },
      });
      continue;
    }

    const validation = validateEdgeEndpoints(edge.properties.type, sourceNode.type, targetNode.type, {
      source_id: edge.source,
      target_id: edge.target,
    });
    if (!validation.valid) {
      errors.push({
        code: 'edge_type_constraint',
        message: `Edge ${edge.properties.type} cannot connect ${sourceNode.type} to ${targetNode.type}.`,
        source_id: edge.source,
        target_id: edge.target,
        edge_type: edge.properties.type,
        suggestion: validation.suggested_fix,
        details: {
          expected_source_types: validation.violation.expected_source_types,
          expected_target_types: validation.violation.expected_target_types,
          actual_source_type: sourceNode.type,
          actual_target_type: targetNode.type,
        },
      });
    }
  }

  return {
    finding: {
      ...finding,
      nodes: normalizedNodes,
    },
    errors,
  };
}

// The node types the schema recognizes. Anything else from an agent or parser
// is a stray type — most often a vulnerability *subtype* (e.g. 'cors_misconfig')
// mistakenly used as a node type. Left alone it fails the VULNERABLE_TO target
// constraint and the whole finding is dropped, so we coerce stray vuln-looking
// nodes to a real `vulnerability` node (preserving the original token as
// vuln_type) before validation.
const NODE_TYPE_SET: ReadonlySet<string> = new Set<string>(NODE_TYPES);

const VULN_TYPE_HINT = /(vuln|misconfig|xss|sqli|ssrf|idor|lfi|rce|takeover|injection|traversal|bypass|security[_-]?header|hardcoded[_-]?secret|weak[_-]?crypto|cors|csrf|ssti|xxe|deserial|exposure|disclosure|cve)/i;

/** Coerce a stray-typed node to `vulnerability` when it clearly represents one.
 *  Conservative: only fires for unrecognized types that also look like a vuln
 *  (vuln fields present or a vuln-ish type token), so a genuine typo like
 *  'webserver' is left to fail loudly rather than be silently reshaped. */
function coerceStrayVulnerabilityNode<T extends Partial<NodeProperties> & { id: string; type: string }>(node: T): T {
  if (NODE_TYPE_SET.has(node.type)) return node;
  const n = node as T & Record<string, unknown>;
  const looksVuln =
    n.cvss != null || n.cve != null || n.cwe != null || n.severity != null ||
    (typeof n.vuln_type === 'string' && n.vuln_type.length > 0) ||
    VULN_TYPE_HINT.test(node.type);
  if (!looksVuln) return node;
  return {
    ...node,
    vuln_type: (typeof n.vuln_type === 'string' && n.vuln_type) || node.type,
    type: 'vulnerability',
  } as unknown as T;
}

export function normalizeFindingNode<T extends Partial<NodeProperties> & { id: string; type: string }>(node: T): T {
  const coerced = coerceStrayVulnerabilityNode(node);
  if (coerced.type !== 'credential') {
    return coerced;
  }

  const normalized = { ...coerced } as T & Record<string, unknown>;

  // Normalize non-standard aliases from parsers
  if (typeof normalized.cred_material_kind !== 'string' && typeof normalized.material_kind === 'string') {
    // Map raw parser values to canonical enum values
    const mkMap: Record<string, string> = { password: 'plaintext_password', hash: 'ntlm_hash' };
    normalized.cred_material_kind = (mkMap[normalized.material_kind as string] || normalized.material_kind) as NodeProperties['cred_material_kind'];
  }

  if (typeof normalized.cred_hash !== 'string' && typeof normalized.hash === 'string') {
    normalized.cred_hash = normalized.hash;
  }

  if (typeof normalized.cred_user !== 'string' && typeof normalized.username === 'string') {
    normalized.cred_user = normalized.username;
  }

  if (typeof normalized.cred_domain !== 'string' && typeof normalized.domain === 'string') {
    normalized.cred_domain = normalized.domain;
  }

  if (typeof normalized.cred_type !== 'string' && typeof normalized.credential_type === 'string') {
    normalized.cred_type = normalized.credential_type as NodeProperties['cred_type'];
  }

  if (typeof normalized.cred_hash !== 'string' && typeof normalized.nthash === 'string') {
    normalized.cred_hash = normalized.nthash;
  }

  if (typeof normalized.cred_value !== 'string' && typeof normalized.password === 'string') {
    normalized.cred_value = normalized.password;
  }

  if (typeof normalized.cred_value !== 'string' && typeof normalized.cred_hash === 'string') {
    normalized.cred_value = normalized.cred_hash;
  }

  if (typeof normalized.cred_type !== 'string' && typeof normalized.nthash === 'string') {
    normalized.cred_type = 'ntlm';
  }

  const materialKind = getCredentialMaterialKind(normalized as NodeProperties);
  if (typeof normalized.cred_material_kind !== 'string' && materialKind) {
    normalized.cred_material_kind = materialKind as NodeProperties['cred_material_kind'];
  }

  if (typeof normalized.cred_usable_for_auth !== 'boolean' && (normalized.cred_material_kind || normalized.cred_type)) {
    normalized.cred_usable_for_auth = isCredentialUsableForAuth(normalized as NodeProperties);
  }

  return normalized as T;
}

export function validateFindingNode(node: Partial<NodeProperties> & { id: string; type: string }): MutationValidationError[] {
  if (node.type !== 'credential') {
    return [];
  }

  const materialKind = getCredentialMaterialKind(node as NodeProperties);
  const claimsReusableAccess = node.privileged === true || node.cred_usable_for_auth === true;
  if (claimsReusableAccess && !materialKind) {
    return [{
      code: 'credential_material_missing',
      message: 'Credential claims reusable or privileged access but does not include normalized credential material.',
      node_id: node.id,
      suggestion: {
        required_fields: ['cred_type', 'cred_material_kind', 'cred_value or cred_hash', 'cred_user', 'cred_domain'],
      },
    }];
  }

  return [];
}
