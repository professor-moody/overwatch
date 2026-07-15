// AWS IAM list-attached-{user,role}-policies JSON.

import type { Finding, ParseContext } from '../../types.js';
import { cloudPolicyId } from '../parser-utils.js';

interface AttachedPolicy {
  PolicyName?: string;
  PolicyArn?: string;
}

interface AttachedPoliciesPayload {
  AttachedPolicies?: AttachedPolicy[];
  IsTruncated?: boolean;
  Marker?: string;
  NextToken?: string;
}

export function parseAwsIamAttachedPolicies(
  output: string,
  agentId: string = 'aws-iam-attached-policies-parser',
  context?: ParseContext,
): Finding {
  const now = new Date().toISOString();
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  let payload: AttachedPoliciesPayload;
  try {
    payload = JSON.parse(output) as AttachedPoliciesPayload;
  } catch {
    return { id: `aws-attached-policies-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const targetId = context?.target_cloud_identity_id;
  if (!targetId || !Array.isArray(payload.AttachedPolicies)) {
    return { id: `aws-attached-policies-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  for (const policy of payload.AttachedPolicies) {
    if (!policy.PolicyName || !policy.PolicyArn) continue;
    // Policy names are only account-local. ARN identity prevents same-name
    // customer policies in different accounts from collapsing together.
    const policyId = cloudPolicyId('aws', policy.PolicyArn);
    nodes.push({
      id: policyId,
      type: 'cloud_policy',
      label: policy.PolicyName,
      provider: 'aws',
      policy_name: policy.PolicyName,
      arn: policy.PolicyArn,
      policy_arn: policy.PolicyArn,
      // list-attached-* proves attachment, not the policy document. The IAM
      // simulator must not turn that missing expansion into a definitive deny.
      permission_expansion: 'unevaluable',
      cloud_account: context?.cloud_account ?? context?.aws_account ?? context?.account_id,
      discovered_at: now,
      confidence: 1.0,
    });
    edges.push({
      source: targetId,
      target: policyId,
      properties: {
        type: 'HAS_POLICY',
        confidence: 1.0,
        discovered_at: now,
        discovered_by: agentId,
      },
    });
  }

  const partial = payload.IsTruncated === true || !!payload.Marker || !!payload.NextToken;
  return {
    id: `aws-attached-policies-${Date.now()}`,
    agent_id: agentId,
    timestamp: now,
    nodes,
    edges,
    partial: partial || undefined,
    partial_reason: partial ? 'aws_pagination_incomplete' : undefined,
  };
}
