// ============================================================
// AzureHound / ROADtools Ingest
// Parse AzureHound JSON output into structured Findings
// ============================================================

import type { Finding } from '../types.js';
import { cloudIdentityId, cloudPolicyId, groupId, normalizeKeyPart } from './parser-utils.js';

export interface AzureHoundIngestResult {
  findings: Finding[];
  files_processed: number;
  total_nodes: number;
  total_edges: number;
  errors: string[];
}

interface AzureHoundData {
  kind?: string;
  data?: any[];
  // ROADtools format
  value?: any[];
}

const AGENT_ID = 'azurehound-ingest';

export function parseAzureHoundFile(content: string, filename: string): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const seenNodes = new Set<string>();

  let data: AzureHoundData;
  try {
    data = JSON.parse(content);
  } catch {
    return { id: `azurehound-${Date.now()}`, agent_id: AGENT_ID, timestamp: now, nodes: [], edges: [] };
  }

  const items = data.data || data.value || (Array.isArray(data) ? data : []);
  const kind = (data.kind || inferKindFromFilename(filename)).toLowerCase();

  for (const item of items) {
    const props = item.Properties || item.properties || item;

    switch (kind) {
      case 'azusers':
      case 'users': {
        const objectId = props.id || props.objectId || item.ObjectIdentifier || '';
        if (!objectId) break;
        const upn = props.userPrincipalName || props.mail || '';
        const displayName = props.displayName || upn || objectId;
        const nodeId = cloudIdentityId(`azure:user:${objectId}`);
        if (seenNodes.has(nodeId)) break;
        seenNodes.add(nodeId);
        nodes.push({
          id: nodeId, type: 'cloud_identity',
          label: displayName,
          discovered_at: now, discovered_by: AGENT_ID, confidence: 1.0,
          provider: 'azure', principal_type: 'user',
          arn: objectId,
          username: upn,
          enabled: props.accountEnabled !== false,
          mfa_enabled: props.strongAuthenticationDetail?.methods?.length > 0 || undefined,
          cloud_account: props.tenantId || '',
        } as Finding['nodes'][0]);
        break;
      }

      case 'azgroups':
      case 'groups': {
        const objectId = props.id || props.objectId || item.ObjectIdentifier || '';
        if (!objectId) break;
        const displayName = props.displayName || objectId;
        const nodeId = groupId(displayName, 'azure');
        if (seenNodes.has(nodeId)) break;
        seenNodes.add(nodeId);
        nodes.push({
          id: nodeId, type: 'group',
          label: displayName,
          discovered_at: now, discovered_by: AGENT_ID, confidence: 1.0,
          provider: 'azure',
          sid: objectId,
        } as Finding['nodes'][0]);

        // Group members
        const members = item.Members || props.members || [];
        for (const member of Array.isArray(members) ? members : []) {
          const memberId = member.ObjectIdentifier || member.id || member.objectId || '';
          const memberType = (member.ObjectType || member['@odata.type'] || '').toLowerCase();
          if (!memberId) continue;

          let memberNodeId: string;
          if (memberType.includes('user')) {
            memberNodeId = cloudIdentityId(`azure:user:${memberId}`);
          } else if (memberType.includes('group')) {
            memberNodeId = groupId(member.displayName || memberId, 'azure');
          } else if (memberType.includes('serviceprincipal') || memberType.includes('app')) {
            memberNodeId = cloudIdentityId(`azure:sp:${memberId}`);
          } else {
            memberNodeId = cloudIdentityId(`azure:unknown:${memberId}`);
          }

          if (!seenNodes.has(memberNodeId)) {
            seenNodes.add(memberNodeId);
            nodes.push({
              id: memberNodeId,
              type: memberType.includes('group') ? 'group' : 'cloud_identity',
              label: member.displayName || memberId,
              discovered_at: now, discovered_by: AGENT_ID, confidence: 0.8,
              provider: 'azure',
              arn: memberId,
            } as Finding['nodes'][0]);
          }

          edges.push({
            source: memberNodeId, target: nodeId,
            properties: { type: 'MEMBER_OF', confidence: 1.0, discovered_at: now, discovered_by: AGENT_ID },
          });
        }
        break;
      }

      case 'azapps':
      case 'apps':
      case 'applications': {
        const appId = props.appId || props.id || item.ObjectIdentifier || '';
        if (!appId) break;
        const displayName = props.displayName || appId;
        const nodeId = cloudIdentityId(`azure:app:${appId}`);
        if (seenNodes.has(nodeId)) break;
        seenNodes.add(nodeId);
        nodes.push({
          id: nodeId, type: 'cloud_identity',
          label: displayName,
          discovered_at: now, discovered_by: AGENT_ID, confidence: 1.0,
          provider: 'azure', principal_type: 'app',
          arn: appId,
          cloud_account: props.tenantId || '',
        } as Finding['nodes'][0]);
        break;
      }

      case 'azserviceprincipals':
      case 'serviceprincipals': {
        const spId = props.id || props.objectId || item.ObjectIdentifier || '';
        if (!spId) break;
        const displayName = props.displayName || spId;
        const nodeId = cloudIdentityId(`azure:sp:${spId}`);
        if (seenNodes.has(nodeId)) break;
        seenNodes.add(nodeId);
        nodes.push({
          id: nodeId, type: 'cloud_identity',
          label: displayName,
          discovered_at: now, discovered_by: AGENT_ID, confidence: 1.0,
          provider: 'azure', principal_type: 'service_account',
          arn: spId,
          cloud_account: props.tenantId || '',
        } as Finding['nodes'][0]);

        // Link to app if appId is present
        const appId = props.appId;
        if (appId) {
          const appNodeId = cloudIdentityId(`azure:app:${appId}`);
          edges.push({
            source: nodeId, target: appNodeId,
            properties: { type: 'ASSUMES_ROLE', confidence: 1.0, discovered_at: now, discovered_by: AGENT_ID },
          });
        }
        break;
      }

      case 'azroleassignments':
      case 'roleassignments': {
        const roleDefId = props.roleDefinitionId || props.RoleDefinitionId || '';
        const principalId = props.principalId || props.PrincipalId || '';
        const roleName = props.roleDefinitionName || props.RoleDefinitionName || roleDefId;
        if (!principalId || !roleName) break;

        const policyNodeId = cloudPolicyId('azure', roleName);
        if (!seenNodes.has(policyNodeId)) {
          seenNodes.add(policyNodeId);
          nodes.push({
            id: policyNodeId, type: 'cloud_policy',
            label: roleName,
            discovered_at: now, discovered_by: AGENT_ID, confidence: 1.0,
            provider: 'azure', policy_name: roleName,
            effect: 'allow',
          } as Finding['nodes'][0]);
        }

        const principalNodeId = cloudIdentityId(`azure:principal:${principalId}`);
        if (!seenNodes.has(principalNodeId)) {
          seenNodes.add(principalNodeId);
          nodes.push({
            id: principalNodeId, type: 'cloud_identity',
            label: principalId,
            discovered_at: now, discovered_by: AGENT_ID, confidence: 0.8,
            provider: 'azure', arn: principalId,
          } as Finding['nodes'][0]);
        }

        edges.push({
          source: principalNodeId, target: policyNodeId,
          properties: { type: 'HAS_POLICY', confidence: 1.0, discovered_at: now, discovered_by: AGENT_ID },
        });
        break;
      }

      case 'azapproleassignments':
      case 'approleassignments': {
        const principalId = props.principalId || props.PrincipalId || '';
        const resourceId = props.resourceId || props.ResourceId || '';
        if (!principalId || !resourceId) break;

        const srcId = cloudIdentityId(`azure:principal:${principalId}`);
        const tgtId = cloudIdentityId(`azure:sp:${resourceId}`);

        if (!seenNodes.has(srcId)) {
          seenNodes.add(srcId);
          nodes.push({
            id: srcId, type: 'cloud_identity',
            label: principalId,
            discovered_at: now, discovered_by: AGENT_ID, confidence: 0.8,
            provider: 'azure', arn: principalId,
          } as Finding['nodes'][0]);
        }
        if (!seenNodes.has(tgtId)) {
          seenNodes.add(tgtId);
          nodes.push({
            id: tgtId, type: 'cloud_identity',
            label: resourceId,
            discovered_at: now, discovered_by: AGENT_ID, confidence: 0.8,
            provider: 'azure', arn: resourceId, principal_type: 'service_account',
          } as Finding['nodes'][0]);
        }

        edges.push({
          source: srcId, target: tgtId,
          properties: { type: 'ASSUMES_ROLE', confidence: 1.0, discovered_at: now, discovered_by: AGENT_ID },
        });
        break;
      }

      default:
        break;
    }
  }

  return {
    id: `azurehound-${normalizeKeyPart(filename)}-${Date.now()}`,
    agent_id: AGENT_ID,
    timestamp: now,
    nodes,
    edges,
  };
}

function inferKindFromFilename(filename: string): string {
  const lower = filename.toLowerCase();
  if (lower.includes('user')) return 'azusers';
  if (lower.includes('group')) return 'azgroups';
  if (lower.includes('serviceprincipal')) return 'azserviceprincipals';
  if (lower.includes('app') && !lower.includes('approle')) return 'azapps';
  if (lower.includes('approleassignment')) return 'azapproleassignments';
  if (lower.includes('roleassignment')) return 'azroleassignments';
  return 'unknown';
}
