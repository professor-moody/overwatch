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

  if (!identity.Arn || !identity.Account) {
    return { id: `aws-sts-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  // Determine principal type from ARN. The third colon-separated chunk
  // after `arn:aws:iam::<account>:` tells us role/user/role-session.
  const arnSuffix = identity.Arn.split(':').pop() ?? '';
  let principalType: 'user' | 'role' | 'federated' = 'user';
  // assumed-role sessions are *federated* in the principal_type union;
  // we keep the raw caller_kind separately for the report.
  let callerKind: 'user' | 'role' | 'role_session' = 'user';
  if (arnSuffix.startsWith('assumed-role/')) { principalType = 'federated'; callerKind = 'role_session'; }
  else if (arnSuffix.startsWith('role/')) { principalType = 'role'; callerKind = 'role'; }

  const cloudId = cloudIdentityId(identity.Arn);
  nodes.push({
    id: cloudId,
    type: 'cloud_identity',
    label: identity.Arn,
    cloud_provider: 'aws',
    cloud_account: identity.Account,
    arn: identity.Arn,
    principal_type: principalType,
    caller_kind: callerKind,
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
        notes: 'AWS STS get-caller-identity confirmed credential maps to this principal',
      },
    });
  }

  return { id: `aws-sts-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
}
