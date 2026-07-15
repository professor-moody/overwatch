// ============================================================
// Parser: aws iam get-account-summary (--output json)
//
// Response shape: { SummaryMap: { Users: 12, Groups: 4, Roles: 30, ... } }
// We don't model these as separate nodes — they're an aggregate snapshot
// of the AWS account. Stamp the summary on the cloud_identity node that
// matches the credential's account, or on a synthesized "account
// summary" placeholder when no caller identity has been ingested yet.
// ============================================================

import type { Finding, NodeProperties, ParseContext } from '../../types.js';
import { cloudIdentityId } from '../parser-utils.js';

interface AccountSummary {
  SummaryMap?: Record<string, number>;
}

interface PlaybookContext extends ParseContext {
  source_credential_id?: string;
  /** When provided, stamp the summary on this specific cloud_identity node id. Otherwise the parser uses the credential's `cred_aws_account` (if present) to construct one. */
  target_cloud_identity_id?: string;
  /** AWS account id when the source credential or target identity isn't in the graph yet. */
  aws_account?: string;
  caller_arn?: string;
}

export function parseAwsIamSummary(
  output: string,
  agentId: string = 'aws-iam-summary-parser',
  context?: ParseContext,
): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const ctx = (context ?? {}) as PlaybookContext;

  let payload: AccountSummary;
  try {
    payload = JSON.parse(output) as AccountSummary;
  } catch {
    return { id: `aws-iam-summary-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const summary = payload.SummaryMap;
  if (!summary || Object.keys(summary).length === 0) {
    return { id: `aws-iam-summary-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  // An account summary does not prove that the root principal was observed.
  // Require the caller identity that the STS step explicitly bound.
  const targetId = ctx.target_cloud_identity_id;
  let nodeProps: Partial<NodeProperties> = {};
  if (!targetId || !ctx.caller_arn) {
    return { id: `aws-iam-summary-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }
  const account = ctx.aws_account ?? ctx.cloud_account ?? ctx.account_id;
  const arnAccount = ctx.caller_arn.match(/^arn:aws[a-zA-Z-]*:(?:iam|sts)::(\d{12}):/)?.[1];
  if (!account || arnAccount !== account || targetId !== cloudIdentityId(ctx.caller_arn)) {
    return { id: `aws-iam-summary-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }
  nodeProps = {
    provider: 'aws',
    cloud_account: account,
    arn: ctx.caller_arn,
  };

  const node: NodeProperties = {
    id: targetId,
    type: 'cloud_identity',
    label: typeof nodeProps.arn === 'string' ? nodeProps.arn : targetId,
    preserve_existing_label: true,
    discovered_at: now,
    confidence: 1.0,
    ...nodeProps,
    account_summary: summary,
    account_summary_observed_at: now,
  } as NodeProperties;
  nodes.push(node);

  return { id: `aws-iam-summary-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
}
