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

  // Pick a target node: explicit context override > synthesized account placeholder.
  let targetId = ctx.target_cloud_identity_id;
  let nodeProps: Partial<NodeProperties> = {};
  if (!targetId) {
    const account = ctx.aws_account;
    if (!account) {
      // No way to anchor the summary — emit it as a free-floating
      // observation under a placeholder that downstream correlators
      // can merge if a real cloud_identity lands later.
      targetId = cloudIdentityId('aws-account-unknown');
    } else {
      targetId = cloudIdentityId(`arn:aws:iam::${account}:root`);
      nodeProps = {
        cloud_provider: 'aws',
        cloud_account: account,
        // 'user' is the closest principal_type for an account-root proxy.
        principal_type: 'user',
        caller_kind: 'account_root',
        arn: `arn:aws:iam::${account}:root`,
      };
    }
  }

  const node: NodeProperties = {
    id: targetId!,
    type: 'cloud_identity',
    label: targetId!.replace(/^cloud-identity-/, ''),
    discovered_at: now,
    confidence: 1.0,
    ...nodeProps,
    account_summary: summary,
    account_summary_observed_at: now,
  } as NodeProperties;
  nodes.push(node);

  return { id: `aws-iam-summary-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
}
