// ============================================================
// AzureHound / ROADtools Ingest
// Parse AzureHound JSON output into structured Findings
// ============================================================

import type { Finding } from '../types.js';
import { cloudIdentityId, cloudPolicyId, cloudResourceId, normalizeKeyPart } from './parser-utils.js';
import { expandAzureRole } from './azure-roles.js';
import { createHash } from 'node:crypto';

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

// All Azure entities (users, SPs, groups) share a single ID namespace keyed
// by their Entra object ID (a UUID). This ensures that role assignments —
// which only carry a principalId — attach to the correct node regardless of
// whether the principal is a user, group, or service principal.
function azureObjectNodeId(objectId: string): string {
  return `azure-${normalizeKeyPart(objectId)}`;
}

export interface AzureHoundParseResult {
  finding: Finding;
  warnings: string[];
}

export function parseAzureHoundFile(content: string, filename: string): AzureHoundParseResult {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const warnings: string[] = [];
  const now = new Date().toISOString();
  const seenNodes = new Set<string>();

  let data: AzureHoundData;
  try {
    data = JSON.parse(content);
  } catch {
    return { finding: { id: `azurehound-${Date.now()}`, agent_id: AGENT_ID, timestamp: now, nodes: [], edges: [] }, warnings: [`${filename}: failed to parse JSON`] };
  }

  const items = data.data || data.value || (Array.isArray(data) ? data : []);
  const kind = (data.kind || inferKindFromFilename(filename)).toLowerCase();

  const SUPPORTED_KINDS = new Set([
    'azusers', 'users', 'azgroups', 'groups', 'azapps', 'apps', 'applications',
    'azserviceprincipals', 'serviceprincipals', 'azroleassignments', 'roleassignments',
    'azapproleassignments', 'approleassignments',
  ]);
  if (!SUPPORTED_KINDS.has(kind) && kind !== 'unknown') {
    warnings.push(`${filename}: unsupported AzureHound kind '${kind}', skipping ${items.length} item(s)`);
  }
  // Phase D: surface silent zero-result collapses when kind inference failed.
  if (kind === 'unknown' && items.length > 0) {
    warnings.push(`${filename}: could not infer AzureHound kind from filename or 'kind' field; skipping ${items.length} item(s)`);
  }

  for (const item of items) {
    const props = item.Properties || item.properties || item;

    switch (kind) {
      case 'azusers':
      case 'users': {
        const objectId = props.id || props.objectId || item.ObjectIdentifier || '';
        if (!objectId) break;
        const upn = props.userPrincipalName || props.mail || '';
        const displayName = props.displayName || upn || objectId;
        const nodeId = azureObjectNodeId(objectId);
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
        const nodeId = azureObjectNodeId(objectId);
        if (seenNodes.has(nodeId)) break;
        seenNodes.add(nodeId);
        nodes.push({
          id: nodeId, type: 'group',
          label: displayName,
          discovered_at: now, discovered_by: AGENT_ID, confidence: 1.0,
          provider: 'azure',
          sid: objectId,
        } as Finding['nodes'][0]);

        // Group members — keyed by object ID to align with entity nodes
        const members = item.Members || props.members || [];
        for (const member of Array.isArray(members) ? members : []) {
          const memberId = member.ObjectIdentifier || member.id || member.objectId || '';
          const memberType = (member.ObjectType || member['@odata.type'] || '').toLowerCase();
          if (!memberId) continue;

          const memberNodeId = azureObjectNodeId(memberId);

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
        // Apps use appId (different from SP objectId), so keep a separate namespace
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
        const nodeId = azureObjectNodeId(spId);
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

        // Link to app if appId is present (apps use a separate namespace)
        const appId = props.appId;
        if (appId) {
          const appNodeId = cloudIdentityId(`azure:app:${appId}`);
          // Emit stub app node if not already seen so the edge target is valid
          if (!seenNodes.has(appNodeId)) {
            seenNodes.add(appNodeId);
            nodes.push({
              id: appNodeId, type: 'cloud_identity',
              label: props.displayName ? `${props.displayName} (App)` : String(appId),
              discovered_at: now, discovered_by: AGENT_ID, confidence: 0.8,
              provider: 'azure', principal_type: 'app',
              arn: String(appId),
              cloud_account: props.tenantId || '',
            } as Finding['nodes'][0]);
          }
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
        // Scope of the assignment (subscription / RG / single resource path).
        // Without this, Reader-on-one-RG looks identical to Owner-on-tenant.
        const scope = (props.scope || props.Scope || '') as string;
        if (!principalId || !roleName) break;

        // Per-assignment policy node: (principal, role, scope) is the natural
        // identity of an Azure RBAC assignment. Without this, two distinct
        // Reader assignments at different scopes would collapse into one
        // node, losing the scope distinction entirely.
        const scopeKey = scope || 'tenant-root';
        const scopeHash = createHash('sha1').update(scopeKey).digest('hex').slice(0, 10);
        const policyDiscriminator = `${roleName}--${normalizeKeyPart(principalId)}--${scopeHash}`;
        const policyNodeId = cloudPolicyId('azure', policyDiscriminator);
        if (!seenNodes.has(policyNodeId)) {
          seenNodes.add(policyNodeId);
          const expansion = expandAzureRole(roleName);
          const policyNode: Record<string, unknown> = {
            id: policyNodeId, type: 'cloud_policy',
            label: scope ? `${roleName} @ ${scope.split('/').pop() || scope}` : roleName,
            discovered_at: now, discovered_by: AGENT_ID, confidence: 1.0,
            provider: 'azure', policy_name: roleName,
            effect: 'allow',
            role_definition_name: roleName,
            role_definition_id: roleDefId || undefined,
            assignment_scope: scope || undefined,
          };
          if (expansion.expanded) {
            policyNode.actions = expansion.actions;
            policyNode.resources = scope ? [scope] : ['*'];
            if (expansion.not_actions.length > 0) policyNode.not_actions = expansion.not_actions;
            policyNode.permission_expansion = 'expanded';
          } else {
            // Unknown role — record what we know so the simulator can flag
            // results as "enumerated only, not permission-expanded" instead
            // of silently treating the assignment as no-op.
            policyNode.permission_expansion = 'enumerated_only';
            policyNode.resources = scope ? [scope] : ['*'];
          }
          nodes.push(policyNode as Finding['nodes'][0]);
        }

        // Resolve principal: try azure-{id} first, fall back to azure:app:{id} if
        // the principalId matches an App Registration (which uses cloudIdentityId)
        const appNodeId = cloudIdentityId(`azure:app:${principalId}`);
        const principalNodeId = seenNodes.has(appNodeId) ? appNodeId : azureObjectNodeId(principalId);
        if (!seenNodes.has(principalNodeId)) {
          seenNodes.add(principalNodeId);
          nodes.push({
            id: principalNodeId, type: 'cloud_identity',
            label: principalId,
            discovered_at: now, discovered_by: AGENT_ID, confidence: 0.8,
            provider: 'azure', arn: principalId,
          } as Finding['nodes'][0]);
        }

        // Phase C: when the assignment scope is known, materialize a stub
        // cloud_resource for it and link the role to that scope so distinct
        // scopes produce distinct edges (no more Reader vs Owner collapse).
        if (scope) {
          const resNodeId = cloudResourceId(scope);
          if (!seenNodes.has(resNodeId)) {
            seenNodes.add(resNodeId);
            const label = scope.split('/').filter(Boolean).pop() || scope;
            nodes.push({
              id: resNodeId, type: 'cloud_resource',
              label,
              discovered_at: now, discovered_by: AGENT_ID, confidence: 0.9,
              provider: 'azure', arn: scope,
            } as Finding['nodes'][0]);
          }
          // role definition applies to this scope
          edges.push({
            source: policyNodeId, target: resNodeId,
            properties: { type: 'POLICY_ALLOWS', confidence: 1.0, discovered_at: now, discovered_by: AGENT_ID, scope },
          });
          // principal holds this role at this scope (scope on edge for retros)
          edges.push({
            source: principalNodeId, target: policyNodeId,
            properties: {
              type: 'HAS_POLICY', confidence: 1.0,
              discovered_at: now, discovered_by: AGENT_ID,
              scope, role_definition_name: roleName,
            },
          });
        } else {
          // Backwards compatible: no scope known → keep the legacy edge shape
          edges.push({
            source: principalNodeId, target: policyNodeId,
            properties: { type: 'HAS_POLICY', confidence: 1.0, discovered_at: now, discovered_by: AGENT_ID },
          });
        }
        break;
      }

      case 'azapproleassignments':
      case 'approleassignments': {
        const principalId = props.principalId || props.PrincipalId || '';
        const resourceId = props.resourceId || props.ResourceId || '';
        if (!principalId || !resourceId) break;

        const srcId = azureObjectNodeId(principalId);
        const tgtId = azureObjectNodeId(resourceId);

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
    finding: {
      id: `azurehound-${normalizeKeyPart(filename)}-${Date.now()}`,
      agent_id: AGENT_ID,
      timestamp: now,
      nodes,
      edges,
    },
    warnings,
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
