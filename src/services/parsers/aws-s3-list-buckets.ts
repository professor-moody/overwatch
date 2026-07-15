// AWS S3 ListBuckets JSON.

import type { Finding, ParseContext } from '../../types.js';
import { cloudResourceId } from '../parser-utils.js';

interface BucketRecord {
  Name?: string;
  CreationDate?: string;
  BucketArn?: string;
  BucketRegion?: string;
}

interface ListBucketsPayload {
  Buckets?: BucketRecord[];
  ContinuationToken?: string;
  NextToken?: string;
  IsTruncated?: boolean;
}

export function parseAwsS3ListBuckets(
  output: string,
  agentId: string = 'aws-s3-list-buckets-parser',
  context?: ParseContext,
): Finding {
  const now = new Date().toISOString();
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  let payload: ListBucketsPayload;
  try {
    payload = JSON.parse(output) as ListBucketsPayload;
  } catch {
    return { id: `aws-s3-buckets-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }
  if (!Array.isArray(payload.Buckets)) {
    return { id: `aws-s3-buckets-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const account = context?.cloud_account ?? context?.aws_account ?? context?.account_id;
  const callerPartition = typeof context?.caller_arn === 'string'
    ? context.caller_arn.match(/^arn:([^:]+):/)?.[1]
    : undefined;
  const partition = callerPartition && ['aws', 'aws-us-gov', 'aws-cn'].includes(callerPartition)
    ? callerPartition
    : 'aws';
  for (const bucket of payload.Buckets) {
    if (!bucket.Name) continue;
    const arn = bucket.BucketArn || `arn:${partition}:s3:::${bucket.Name}`;
    nodes.push({
      id: cloudResourceId(arn),
      type: 'cloud_resource',
      label: bucket.Name,
      provider: 'aws',
      arn,
      resource_type: 's3_bucket',
      cloud_account: account,
      region: bucket.BucketRegion ?? context?.cloud_region,
      created_at: bucket.CreationDate,
      discovered_at: now,
      confidence: 1.0,
    });
  }

  const partial = payload.IsTruncated === true || !!payload.ContinuationToken || !!payload.NextToken;
  return {
    id: `aws-s3-buckets-${Date.now()}`,
    agent_id: agentId,
    timestamp: now,
    nodes,
    edges,
    partial: partial || undefined,
    partial_reason: partial ? 'aws_pagination_incomplete' : undefined,
  };
}
