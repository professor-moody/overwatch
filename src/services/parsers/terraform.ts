import type { Finding, ParseContext } from '../../types.js';
import { cloudIdentityId, cloudNetworkId, cloudPolicyId, cloudResourceId, hostId } from '../parser-utils.js';

/**
 * Parse Terraform state JSON (`terraform show -json` or raw `.tfstate`).
 *
 * Terraform state structure:
 *   { version, terraform_version?, resources: [{ mode, type, name, provider, instances: [{ attributes }] }] }
 *
 * We also accept `terraform show -json` output which wraps resources under
 * `values.root_module.resources[]` with `{ type, name, values: { ...attributes } }`.
 */
export function parseTerraformState(output: string, agentId: string = 'terraform-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const seenNodes = new Set<string>();

  let data: Record<string, unknown>;
  try {
    data = JSON.parse(output) as Record<string, unknown>;
  } catch {
    return { id: `terraform-${Date.now()}`, agent_id: agentId, timestamp: now, nodes: [], edges: [] };
  }

  const accountId = String(context?.cloud_account || '');

  function addNode(node: Finding['nodes'][0]): void {
    if (!seenNodes.has(node.id)) {
      seenNodes.add(node.id);
      nodes.push(node);
    }
  }

  // Collect resources from either raw state or `terraform show -json` format
  interface TfResource {
    type: string;
    name: string;
    provider?: string;
    attrs: Record<string, unknown>;
  }

  const resources: TfResource[] = [];

  // Raw .tfstate format
  if (Array.isArray(data.resources)) {
    for (const res of data.resources) {
      const r = res as Record<string, unknown>;
      const resType = String(r.type || '');
      const resName = String(r.name || '');
      const provider = String(r.provider || '');
      const instances = Array.isArray(r.instances) ? r.instances as Record<string, unknown>[] : [];
      for (const inst of instances) {
        const attrs = (inst.attributes || {}) as Record<string, unknown>;
        resources.push({ type: resType, name: resName, provider, attrs });
      }
    }
  }

  // `terraform show -json` format
  const values = data.values as Record<string, unknown> | undefined;
  const rootModule = values?.root_module as Record<string, unknown> | undefined;
  if (rootModule && Array.isArray(rootModule.resources)) {
    for (const res of rootModule.resources) {
      const r = res as Record<string, unknown>;
      resources.push({
        type: String(r.type || ''),
        name: String(r.name || ''),
        provider: String(r.provider_name || ''),
        attrs: (r.values || {}) as Record<string, unknown>,
      });
    }
    // Also handle child modules
    const childModules = Array.isArray(rootModule.child_modules) ? rootModule.child_modules as Record<string, unknown>[] : [];
    for (const mod of childModules) {
      const modResources = Array.isArray(mod.resources) ? mod.resources as Record<string, unknown>[] : [];
      for (const res of modResources) {
        resources.push({
          type: String(res.type || ''),
          name: String(res.name || ''),
          provider: String(res.provider_name || ''),
          attrs: (res.values || {}) as Record<string, unknown>,
        });
      }
    }
  }

  if (resources.length === 0) {
    return { id: `terraform-${Date.now()}`, agent_id: agentId, timestamp: now, nodes: [], edges: [] };
  }

  // Detect provider from resource type prefix
  function detectProvider(resType: string, provider?: string): 'aws' | 'azure' | 'gcp' {
    if (resType.startsWith('aws_') || provider?.includes('aws')) return 'aws';
    if (resType.startsWith('azurerm_') || provider?.includes('azure')) return 'azure';
    if (resType.startsWith('google_') || provider?.includes('google')) return 'gcp';
    return 'aws';
  }

  function arnOrUndefined(value: unknown): string | undefined {
    const str = String(value || '');
    return str.startsWith('arn:') ? str : undefined;
  }

  function ec2RegionFromAz(value: unknown): string {
    const az = String(value || '');
    return az ? az.replace(/[a-z]$/, '') : 'unknown';
  }

  for (const res of resources) {
    const provider = detectProvider(res.type, res.provider);
    const arn = arnOrUndefined(res.attrs.arn);
    const providerResourceId = String(res.attrs.id || '');

    // --- AWS EC2 instances ---
    if (res.type === 'aws_instance') {
      const instanceId = String(res.attrs.id || '');
      const region = ec2RegionFromAz(res.attrs.availability_zone);
      const instArn = arn || `arn:aws:ec2:${region}:${accountId}:instance/${instanceId}`;
      const nodeId = cloudResourceId(instArn);
      addNode({
        id: nodeId, type: 'cloud_resource',
        label: String((res.attrs.tags as Record<string, unknown>)?.Name || res.name || instanceId),
        discovered_at: now, discovered_by: agentId, confidence: 1.0,
        provider, arn: instArn, resource_type: 'ec2',
        region,
        cloud_account: accountId,
        provider_resource_id: instanceId || providerResourceId || undefined,
        public: !!(res.attrs.public_ip || res.attrs.associate_public_ip_address),
        imdsv2_required: (res.attrs.metadata_options as Record<string, unknown>[] | undefined)?.[0]?.http_tokens === 'required',
      } as Finding['nodes'][0]);

      // Link to host node if IP known
      const ip = String(res.attrs.private_ip || res.attrs.public_ip || '');
      if (ip) {
        const hId = hostId(ip);
        addNode({
          id: hId, type: 'host', label: ip,
          discovered_at: now, discovered_by: agentId, confidence: 0.9,
          ip, alive: true,
        } as Finding['nodes'][0]);
        edges.push({
          source: hId, target: nodeId,
          properties: { type: 'RUNS_ON', confidence: 1.0, discovered_at: now, discovered_by: agentId },
        });
      }

      // IAM instance profile → MANAGED_BY
      const iamProfile = String(res.attrs.iam_instance_profile || '');
      if (iamProfile) {
        const profileArn = iamProfile.startsWith('arn:') ? iamProfile : `arn:aws:iam::${accountId}:instance-profile/${iamProfile}`;
        const profileNodeId = cloudIdentityId(profileArn);
        addNode({
          id: profileNodeId, type: 'cloud_identity',
          label: iamProfile.split('/').pop() || iamProfile,
          discovered_at: now, discovered_by: agentId, confidence: 0.9,
          provider, arn: profileArn, principal_type: 'role',
          cloud_account: accountId,
        } as Finding['nodes'][0]);
        edges.push({
          source: nodeId, target: profileNodeId,
          properties: { type: 'MANAGED_BY', confidence: 1.0, discovered_at: now, discovered_by: agentId },
        });
      }
      continue;
    }

    // --- AWS IAM roles ---
    if (res.type === 'aws_iam_role') {
      const roleArn = arn || `arn:aws:iam::${accountId}:role/${res.name}`;
      const nodeId = cloudIdentityId(roleArn);
      addNode({
        id: nodeId, type: 'cloud_identity',
        label: String(res.attrs.name || res.name),
        discovered_at: now, discovered_by: agentId, confidence: 1.0,
        provider, arn: roleArn, principal_type: 'role',
        cloud_account: accountId,
      } as Finding['nodes'][0]);

      // Trust policy
      const trustPolicy = res.attrs.assume_role_policy;
      if (typeof trustPolicy === 'string') {
        try {
          const doc = JSON.parse(trustPolicy) as Record<string, unknown>;
          const stmts = Array.isArray(doc.Statement) ? doc.Statement : [];
          for (const stmt of stmts) {
            if ((stmt as Record<string, unknown>).Effect !== 'Allow') continue;
            const principals = ((stmt as Record<string, unknown>).Principal as Record<string, unknown>)?.AWS;
            const arnList = Array.isArray(principals) ? principals : (principals ? [principals] : []);
            for (const trustedArn of arnList) {
              if (typeof trustedArn !== 'string' || trustedArn === '*') continue;
              const trustedId = cloudIdentityId(trustedArn);
              addNode({
                id: trustedId, type: 'cloud_identity',
                label: trustedArn.split('/').pop() || trustedArn,
                discovered_at: now, discovered_by: agentId, confidence: 0.8,
                provider, arn: trustedArn,
                principal_type: trustedArn.includes(':role/') ? 'role' : 'user',
                cloud_account: (trustedArn.match(/:(\d{12}):/)?.[1]) || '',
              } as Finding['nodes'][0]);
              edges.push({
                source: trustedId, target: nodeId,
                properties: {
                  type: 'ASSUMES_ROLE',
                  confidence: 0.9,
                  discovered_at: now,
                  discovered_by: agentId,
                  assumption_confirmed: false,
                  assumption_basis: 'trust_policy',
                },
              });
            }
          }
        } catch { /* ignore malformed policy */ }
      }
      continue;
    }

    // --- AWS IAM users ---
    if (res.type === 'aws_iam_user') {
      const userArn = arn || `arn:aws:iam::${accountId}:user/${res.attrs.name || res.name}`;
      const nodeId = cloudIdentityId(userArn);
      addNode({
        id: nodeId, type: 'cloud_identity',
        label: String(res.attrs.name || res.name),
        discovered_at: now, discovered_by: agentId, confidence: 1.0,
        provider, arn: userArn, principal_type: 'user',
        cloud_account: accountId,
      } as Finding['nodes'][0]);
      continue;
    }

    // --- AWS IAM policy attachment ---
    if (res.type === 'aws_iam_role_policy_attachment' || res.type === 'aws_iam_user_policy_attachment') {
      const policyArn = String(res.attrs.policy_arn || '');
      const targetArn = String(res.attrs.role || res.attrs.user || '');
      if (!policyArn || !targetArn) continue;

      const fullTargetArn = targetArn.startsWith('arn:') ? targetArn :
        `arn:aws:iam::${accountId}:${res.type.includes('role') ? 'role' : 'user'}/${targetArn}`;
      const identityId = cloudIdentityId(fullTargetArn);
      const polId = cloudPolicyId('aws', policyArn);

      addNode({
        id: identityId, type: 'cloud_identity',
        label: targetArn.split('/').pop() || targetArn,
        discovered_at: now, discovered_by: agentId, confidence: 0.9,
        provider, arn: fullTargetArn, cloud_account: accountId,
      } as Finding['nodes'][0]);
      addNode({
        id: polId, type: 'cloud_policy',
        label: policyArn.split('/').pop() || policyArn,
        discovered_at: now, discovered_by: agentId, confidence: 1.0,
        provider, arn: policyArn, policy_name: policyArn.split('/').pop() || policyArn,
      } as Finding['nodes'][0]);
      edges.push({
        source: identityId, target: polId,
        properties: { type: 'HAS_POLICY', confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
      continue;
    }

    // --- AWS S3 buckets ---
    if (res.type === 'aws_s3_bucket') {
      const bucketName = String(res.attrs.bucket || res.attrs.id || res.name);
      const bucketArn = arn || `arn:aws:s3:::${bucketName}`;
      const nodeId = cloudResourceId(bucketArn);
      addNode({
        id: nodeId, type: 'cloud_resource',
        label: bucketName,
        discovered_at: now, discovered_by: agentId, confidence: 1.0,
        provider, arn: bucketArn, resource_type: 's3_bucket',
        region: String(res.attrs.region || ''), cloud_account: accountId,
        provider_resource_id: providerResourceId || bucketName,
      } as Finding['nodes'][0]);
      continue;
    }

    // --- AWS Lambda functions ---
    if (res.type === 'aws_lambda_function') {
      const fnName = String(res.attrs.function_name || res.name);
      const fnArn = arn || `arn:aws:lambda:unknown:${accountId}:function:${fnName}`;
      const nodeId = cloudResourceId(fnArn);
      addNode({
        id: nodeId, type: 'cloud_resource',
        label: fnName,
        discovered_at: now, discovered_by: agentId, confidence: 1.0,
        provider, arn: fnArn, resource_type: 'lambda',
        cloud_account: accountId,
        provider_resource_id: providerResourceId || fnName,
      } as Finding['nodes'][0]);

      const roleArn = String(res.attrs.role || '');
      if (roleArn) {
        const roleNodeId = cloudIdentityId(roleArn);
        addNode({
          id: roleNodeId, type: 'cloud_identity',
          label: roleArn.split('/').pop() || roleArn,
          discovered_at: now, discovered_by: agentId, confidence: 0.9,
          provider, arn: roleArn, principal_type: 'role',
          cloud_account: accountId,
        } as Finding['nodes'][0]);
        edges.push({
          source: nodeId, target: roleNodeId,
          properties: { type: 'MANAGED_BY', confidence: 1.0, discovered_at: now, discovered_by: agentId },
        });
      }
      continue;
    }

    // --- AWS Security Groups ---
    if (res.type === 'aws_security_group') {
      const sgId = String(res.attrs.id || res.name);
      const sgArn = arn || `arn:aws:ec2:unknown:${accountId}:security-group/${sgId}`;
      const nodeId = cloudNetworkId(sgArn);

      const ingress: string[] = [];
      const ingressRules = Array.isArray(res.attrs.ingress) ? res.attrs.ingress as Record<string, unknown>[] : [];
      for (const rule of ingressRules) {
        const fromPort = String(rule.from_port ?? '*');
        const toPort = String(rule.to_port ?? '*');
        const proto = String(rule.protocol || 'tcp');
        const cidrs = Array.isArray(rule.cidr_blocks) ? rule.cidr_blocks as string[] : [];
        for (const cidr of cidrs) {
          ingress.push(`${proto}:${fromPort}-${toPort}:${cidr}`);
        }
      }

      addNode({
        id: nodeId, type: 'cloud_network',
        label: String(res.attrs.name || sgId),
        discovered_at: now, discovered_by: agentId, confidence: 1.0,
        network_type: 'security_group', ingress_rules: ingress,
        provider_resource_id: providerResourceId || sgId,
      } as Finding['nodes'][0]);
      continue;
    }

    // --- Generic fallback: create a cloud_resource for any unhandled type ---
    if (arn && res.type) {
      const nodeId = cloudResourceId(arn);
      addNode({
        id: nodeId, type: 'cloud_resource',
        label: String(res.attrs.name || res.name || arn),
        discovered_at: now, discovered_by: agentId, confidence: 0.8,
        provider, arn, resource_type: res.type.replace(/^aws_|^azurerm_|^google_/, ''),
        cloud_account: accountId,
      } as Finding['nodes'][0]);
    }
  }

  return { id: `terraform-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
}
