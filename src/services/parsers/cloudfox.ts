import type { Finding, ParseContext } from '../../types.js';
import { cloudIdentityId, cloudPolicyId, cloudResourceId } from '../parser-utils.js';

/**
 * Parse CloudFox JSON output (AWS privilege escalation / resource enumeration).
 *
 * CloudFox modules produce JSON arrays when invoked with `--output json`.
 * Supported modules: inventory, permissions, role-trusts, principals, loot.
 *
 * Format: Array of objects with fields like AWSService, Type, Name, Arn,
 * Principal, Action, Resource, AccountId, Region, etc.
 */
export function parseCloudFox(output: string, agentId: string = 'cloudfox-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const seenNodes = new Set<string>();

  let records: Record<string, unknown>[];
  try {
    const parsed = JSON.parse(output);
    records = Array.isArray(parsed) ? parsed : (Array.isArray(parsed.results) ? parsed.results : []);
  } catch {
    return { id: `cloudfox-${Date.now()}`, agent_id: agentId, timestamp: now, nodes: [], edges: [] };
  }

  if (records.length === 0) {
    return { id: `cloudfox-${Date.now()}`, agent_id: agentId, timestamp: now, nodes: [], edges: [] };
  }

  const accountId = String(context?.cloud_account || records[0]?.AccountId || '');

  function addNode(node: Finding['nodes'][0]): void {
    if (!seenNodes.has(node.id)) {
      seenNodes.add(node.id);
      nodes.push(node);
    }
  }

  for (const rec of records) {
    const arn = String(rec.Arn || rec.arn || rec.RoleArn || rec.PrincipalArn || '');
    const principal = String(rec.Principal || rec.principal || rec.Name || rec.name || '');
    const awsService = String(rec.AWSService || rec.Service || rec.service || '').toLowerCase();
    const recType = String(rec.Type || rec.type || '');
    const action = String(rec.Action || rec.action || '');
    const resource = String(rec.Resource || rec.resource || '');
    const region = String(rec.Region || rec.region || '');
    const recAccountId = String(rec.AccountId || rec.account_id || accountId);

    // --- Role trust entries → cloud_identity + ASSUMES_ROLE ---
    if (recType === 'RoleTrust' || recType === 'role-trust' || awsService === 'role-trusts') {
      const trustedPrincipal = String(rec.TrustedPrincipal || rec.trusted_principal || rec.Principal || '');
      const roleArn = String(rec.RoleArn || rec.Arn || arn);
      if (!roleArn || !trustedPrincipal) continue;

      const roleNodeId = cloudIdentityId(roleArn);
      addNode({
        id: roleNodeId, type: 'cloud_identity',
        label: roleArn.split('/').pop() || roleArn,
        discovered_at: now, discovered_by: agentId, confidence: 1.0,
        provider: 'aws', arn: roleArn, principal_type: 'role',
        cloud_account: (roleArn.match(/:(\d{12}):/)?.[1]) || recAccountId,
      } as Finding['nodes'][0]);

      if (trustedPrincipal !== '*') {
        const trustedId = cloudIdentityId(trustedPrincipal);
        addNode({
          id: trustedId, type: 'cloud_identity',
          label: trustedPrincipal.split('/').pop() || trustedPrincipal,
          discovered_at: now, discovered_by: agentId, confidence: 0.8,
          provider: 'aws', arn: trustedPrincipal,
          principal_type: trustedPrincipal.includes(':role/') ? 'role' : 'user',
          cloud_account: (trustedPrincipal.match(/:(\d{12}):/)?.[1]) || '',
        } as Finding['nodes'][0]);
        edges.push({
          source: trustedId, target: roleNodeId,
          properties: { type: 'ASSUMES_ROLE', confidence: 0.9, discovered_at: now, discovered_by: agentId },
        });
      }
      continue;
    }

    // --- Permission entries → cloud_identity + cloud_policy + POLICY_ALLOWS ---
    if (recType === 'Permission' || recType === 'permission' || awsService === 'permissions' || (action && resource)) {
      const principalArn = String(rec.PrincipalArn || rec.Principal || arn);
      if (!principalArn || !action) continue;

      const identityId = cloudIdentityId(principalArn);
      addNode({
        id: identityId, type: 'cloud_identity',
        label: principalArn.split('/').pop() || principalArn,
        discovered_at: now, discovered_by: agentId, confidence: 1.0,
        provider: 'aws', arn: principalArn,
        principal_type: principalArn.includes(':role/') ? 'role' : 'user',
        cloud_account: (principalArn.match(/:(\d{12}):/)?.[1]) || recAccountId,
      } as Finding['nodes'][0]);

      // Create a policy node capturing the allowed action
      const policyLabel = `${principalArn.split('/').pop() || 'unknown'}-${action}`;
      const polId = cloudPolicyId('aws', policyLabel);
      addNode({
        id: polId, type: 'cloud_policy',
        label: policyLabel,
        discovered_at: now, discovered_by: agentId, confidence: 0.9,
        provider: 'aws', policy_name: policyLabel,
        effect: 'allow',
        actions: [action],
        resources: resource ? [resource] : ['*'],
      } as Finding['nodes'][0]);

      edges.push({
        source: identityId, target: polId,
        properties: { type: 'HAS_POLICY', confidence: 0.9, discovered_at: now, discovered_by: agentId },
      });

      // If resource is a specific ARN, create a cloud_resource and POLICY_ALLOWS edge
      if (resource && resource !== '*') {
        const resId = cloudResourceId(resource);
        addNode({
          id: resId, type: 'cloud_resource',
          label: resource.split('/').pop() || resource.split(':').pop() || resource,
          discovered_at: now, discovered_by: agentId, confidence: 0.8,
          provider: 'aws', arn: resource, cloud_account: recAccountId,
        } as Finding['nodes'][0]);
        edges.push({
          source: polId, target: resId,
          properties: { type: 'POLICY_ALLOWS', confidence: 0.9, discovered_at: now, discovered_by: agentId },
        });
      }
      continue;
    }

    // --- Inventory / resource entries → cloud_resource ---
    if (arn || (principal && awsService)) {
      const resourceArn = arn || `${awsService}:${recAccountId}:${region}:${principal}`;
      const nodeId = awsService === 'iam' || recType === 'User' || recType === 'Role'
        ? cloudIdentityId(resourceArn)
        : cloudResourceId(resourceArn);
      const nodeType = awsService === 'iam' || recType === 'User' || recType === 'Role'
        ? 'cloud_identity' : 'cloud_resource';

      addNode({
        id: nodeId, type: nodeType,
        label: principal || arn.split('/').pop() || arn,
        discovered_at: now, discovered_by: agentId, confidence: 1.0,
        provider: 'aws', arn: arn || undefined,
        resource_type: nodeType === 'cloud_resource' ? (awsService || recType.toLowerCase()) : undefined,
        principal_type: nodeType === 'cloud_identity' ? (recType === 'Role' ? 'role' : 'user') : undefined,
        region: region || undefined, cloud_account: recAccountId,
      } as Finding['nodes'][0]);

      // Lambda/EC2 with attached role → MANAGED_BY
      const attachedRole = String(rec.Role || rec.role || rec.ExecutionRole || '');
      if (attachedRole && nodeType === 'cloud_resource') {
        const roleNodeId = cloudIdentityId(attachedRole);
        addNode({
          id: roleNodeId, type: 'cloud_identity',
          label: attachedRole.split('/').pop() || attachedRole,
          discovered_at: now, discovered_by: agentId, confidence: 0.9,
          provider: 'aws', arn: attachedRole, principal_type: 'role',
          cloud_account: (attachedRole.match(/:(\d{12}):/)?.[1]) || recAccountId,
        } as Finding['nodes'][0]);
        edges.push({
          source: nodeId, target: roleNodeId,
          properties: { type: 'MANAGED_BY', confidence: 1.0, discovered_at: now, discovered_by: agentId },
        });
      }
    }
  }

  return { id: `cloudfox-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
}
