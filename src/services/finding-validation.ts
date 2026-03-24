import type { Finding, NodeProperties } from '../types.js';
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

export function normalizeFindingNode<T extends Partial<NodeProperties> & { id: string; type: string }>(node: T): T {
  if (node.type !== 'credential') {
    return node;
  }

  const normalized = { ...node } as T & Record<string, unknown>;

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
