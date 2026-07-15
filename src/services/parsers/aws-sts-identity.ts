// ============================================================
// Parser: aws sts get-caller-identity (--output json)
//
// Single-object response: { UserId, Account, Arn }. Emits / updates a
// `cloud_identity` node for the principal and links the source
// credential via OWNS_CRED. The Account is captured separately so
// downstream cross-tier-correlator entries that key on aws_account
// match cleanly.
// ============================================================

import type { Finding, ParseContext } from '../../types.js';
import { cloudIdentityId } from '../parser-utils.js';

interface CallerIdentity {
  UserId?: string;
  Account?: string;
  Arn?: string;
}

interface PlaybookContext extends ParseContext {
  source_credential_id?: string;
  credential_execution_binding?: string;
  credential_execution_binding_identity?: string;
}

export function parseAwsStsIdentity(
  output: string,
  agentId: string = 'aws-sts-identity-parser',
  context?: ParseContext,
): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const ctx = (context ?? {}) as PlaybookContext;

  let identity: CallerIdentity;
  try {
    identity = JSON.parse(output) as CallerIdentity;
  } catch {
    return { id: `aws-sts-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const arnAccount = identity.Arn?.match(/^arn:aws[a-zA-Z-]*:(?:iam|sts)::(\d{12}):/)?.[1];
  if (!identity.Arn || !identity.Account || !/^\d{12}$/.test(identity.Account)
      || !arnAccount || arnAccount !== identity.Account) {
    return { id: `aws-sts-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  // Preserve AWS's caller shape while exposing a normalized enumeration kind.
  const arnSuffix = identity.Arn.split(':').pop() ?? '';
  let principalType: 'user' | 'role' | 'federated' = 'federated';
  let callerKind: 'user' | 'role' | 'role_session' | 'root' | 'federated' | 'unknown' = 'unknown';
  let enumerationPrincipalKind: 'user' | 'role' | 'root' | 'federated' | 'unknown' = 'unknown';
  let principalName: string | undefined;
  if (arnSuffix.startsWith('assumed-role/')) {
    principalType = 'federated';
    callerKind = 'role_session';
    enumerationPrincipalKind = 'role';
    principalName = arnSuffix.split('/')[1];
  } else if (arnSuffix.startsWith('role/')) {
    principalType = 'role';
    callerKind = 'role';
    enumerationPrincipalKind = 'role';
    principalName = arnSuffix.slice('role/'.length).split('/').pop();
  } else if (arnSuffix.startsWith('user/')) {
    principalType = 'user';
    callerKind = 'user';
    enumerationPrincipalKind = 'user';
    principalName = arnSuffix.slice('user/'.length).split('/').pop();
  } else if (arnSuffix === 'root') {
    principalType = 'user';
    callerKind = 'root';
    enumerationPrincipalKind = 'root';
  } else if (arnSuffix.startsWith('federated-user/')) {
    principalType = 'federated';
    callerKind = 'federated';
    enumerationPrincipalKind = 'federated';
    principalName = arnSuffix.slice('federated-user/'.length);
  }

  const cloudId = cloudIdentityId(identity.Arn);
  nodes.push({
    id: cloudId,
    type: 'cloud_identity',
    label: identity.Arn,
    provider: 'aws',
    cloud_provider: 'aws',
    cloud_account: identity.Account,
    account_id: identity.Account,
    arn: identity.Arn,
    caller_arn: identity.Arn,
    principal_type: principalType,
    principal_kind: 'aws',
    caller_kind: callerKind,
    enumeration_principal_kind: enumerationPrincipalKind,
    principal_name: principalName,
    user_id: identity.UserId,
    discovered_at: now,
    confidence: 1.0,
  });

  if (ctx.source_credential_id) {
    edges.push({
      source: cloudId,
      target: ctx.source_credential_id,
      properties: {
        type: 'OWNS_CRED',
        confidence: 1.0,
        discovered_at: now,
        discovered_by: agentId,
        binding_source: 'aws_sts_get_caller_identity',
        credential_execution_binding: ctx.credential_execution_binding_identity
          ?? ctx.credential_execution_binding,
        notes: 'AWS STS get-caller-identity confirmed credential maps to this principal',
      },
    });
  }

  return { id: `aws-sts-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
}
