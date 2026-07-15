// AWS Lambda ListFunctions JSON.

import type { Finding, ParseContext } from '../../types.js';
import { cloudIdentityId, cloudResourceId } from '../parser-utils.js';

interface LambdaFunctionRecord {
  FunctionName?: string;
  FunctionArn?: string;
  Runtime?: string;
  Role?: string;
  Handler?: string;
  CodeSize?: number;
  Description?: string;
  Timeout?: number;
  MemorySize?: number;
  LastModified?: string;
  PackageType?: string;
  Architectures?: string[];
}

interface ListFunctionsPayload {
  Functions?: LambdaFunctionRecord[];
  NextMarker?: string;
}

export function parseAwsLambdaListFunctions(
  output: string,
  agentId: string = 'aws-lambda-list-functions-parser',
  context?: ParseContext,
): Finding {
  const now = new Date().toISOString();
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  let payload: ListFunctionsPayload;
  try {
    payload = JSON.parse(output) as ListFunctionsPayload;
  } catch {
    return { id: `aws-lambda-functions-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }
  if (!Array.isArray(payload.Functions)) {
    return { id: `aws-lambda-functions-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const addNode = (node: Finding['nodes'][number]) => {
    if (seenNodes.has(node.id)) return;
    seenNodes.add(node.id);
    nodes.push(node);
  };

  for (const fn of payload.Functions) {
    if (!fn.FunctionArn) continue;
    const arnParts = fn.FunctionArn.split(':');
    const region = arnParts[3] || context?.cloud_region;
    const account = arnParts[4] || context?.cloud_account || context?.aws_account || context?.account_id;
    const functionId = cloudResourceId(fn.FunctionArn);
    addNode({
      id: functionId,
      type: 'cloud_resource',
      label: fn.FunctionName || fn.FunctionArn.split(':').pop() || fn.FunctionArn,
      provider: 'aws',
      arn: fn.FunctionArn,
      resource_type: 'lambda',
      region,
      cloud_account: account,
      runtime: fn.Runtime,
      handler: fn.Handler,
      code_size: fn.CodeSize,
      description: fn.Description,
      timeout_seconds: fn.Timeout,
      memory_size_mb: fn.MemorySize,
      last_modified: fn.LastModified,
      package_type: fn.PackageType,
      architectures: fn.Architectures,
      discovered_at: now,
      confidence: 1.0,
    });

    if (fn.Role) {
      const roleId = cloudIdentityId(fn.Role);
      addNode({
        id: roleId,
        type: 'cloud_identity',
        label: fn.Role.split('/').pop() || fn.Role,
        provider: 'aws',
        arn: fn.Role,
        principal_type: 'role',
        cloud_account: fn.Role.match(/:(\d{12}):/)?.[1] || account,
        discovered_at: now,
        confidence: 1.0,
      });
      edges.push({
        source: functionId,
        target: roleId,
        properties: {
          type: 'MANAGED_BY',
          confidence: 1.0,
          discovered_at: now,
          discovered_by: agentId,
        },
      });
    }
  }

  return {
    id: `aws-lambda-functions-${Date.now()}`,
    agent_id: agentId,
    timestamp: now,
    nodes,
    edges,
    partial: !!payload.NextMarker || undefined,
    partial_reason: payload.NextMarker ? 'aws_pagination_incomplete' : undefined,
  };
}
