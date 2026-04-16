import type { Finding, ParseContext } from '../../types.js';
import { cloudIdentityId, cloudPolicyId, cloudResourceId, hostId, vulnerabilityId } from '../parser-utils.js';

export function parsePacu(output: string, agentId: string = 'pacu-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const seenNodes = new Set<string>();

  let data: Record<string, unknown>;
  try {
    data = JSON.parse(output) as Record<string, unknown>;
  } catch {
    return { id: `pacu-${Date.now()}`, agent_id: agentId, timestamp: now, nodes: [], edges: [] };
  }

  const accountId = (context?.cloud_account || data.AccountId || data.account_id || '') as string;

  // IAM Users
  if (Array.isArray(data.IAMUsers)) {
    for (const user of data.IAMUsers) {
      const arn = user.Arn || user.arn || '';
      if (!arn) continue;
      const nodeId = cloudIdentityId(arn);
      if (seenNodes.has(nodeId)) continue;
      seenNodes.add(nodeId);
      nodes.push({
        id: nodeId, type: 'cloud_identity',
        label: user.UserName || user.user_name || arn,
        discovered_at: now, discovered_by: agentId, confidence: 1.0,
        provider: 'aws', arn, principal_type: 'user',
        cloud_account: accountId || (arn.match(/:(\d{12}):/)?.[1]) || '',
        mfa_enabled: Array.isArray(user.MFADevices) ? user.MFADevices.length > 0 : undefined,
      } as Finding['nodes'][0]);
    }
  }

  // IAM Roles
  if (Array.isArray(data.IAMRoles)) {
    for (const role of data.IAMRoles) {
      const arn = role.Arn || role.arn || '';
      if (!arn) continue;
      const nodeId = cloudIdentityId(arn);
      if (seenNodes.has(nodeId)) continue;
      seenNodes.add(nodeId);
      nodes.push({
        id: nodeId, type: 'cloud_identity',
        label: role.RoleName || role.role_name || arn,
        discovered_at: now, discovered_by: agentId, confidence: 1.0,
        provider: 'aws', arn, principal_type: 'role',
        cloud_account: accountId || (arn.match(/:(\d{12}):/)?.[1]) || '',
      } as Finding['nodes'][0]);

      // Trust policy — ASSUMES_ROLE edges from trusted principals
      const trustPolicy = role.AssumeRolePolicyDocument || role.assume_role_policy_document;
      if (trustPolicy) {
        let doc: Record<string, unknown> | null = null;
        try {
          doc = typeof trustPolicy === 'string' ? JSON.parse(trustPolicy) : trustPolicy;
        } catch {
          // Malformed trust policy document — skip this role's trust edges, continue processing
        }
        if (doc) {
          const statements = Array.isArray(doc?.Statement) ? doc.Statement : [];
          for (const stmt of statements) {
            if (stmt.Effect !== 'Allow') continue;
            const principals = stmt.Principal?.AWS;
            const arnList = Array.isArray(principals) ? principals : (principals ? [principals] : []);
            for (const trustedArn of arnList) {
              if (typeof trustedArn !== 'string' || trustedArn === '*') continue;
              const trustedId = cloudIdentityId(trustedArn);
              if (!seenNodes.has(trustedId)) {
                seenNodes.add(trustedId);
                nodes.push({
                  id: trustedId, type: 'cloud_identity',
                  label: trustedArn.split('/').pop() || trustedArn,
                  discovered_at: now, discovered_by: agentId, confidence: 0.8,
                  provider: 'aws', arn: trustedArn,
                  principal_type: trustedArn.includes(':role/') ? 'role' : 'user',
                  cloud_account: (trustedArn.match(/:(\d{12}):/)?.[1]) || '',
                } as Finding['nodes'][0]);
              }
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
        }
      }
    }
  }

  // IAM Policies
  if (Array.isArray(data.IAMPolicies)) {
    for (const policy of data.IAMPolicies) {
      const arn = policy.Arn || policy.arn || '';
      const policyName = policy.PolicyName || policy.policy_name || '';
      if (!policyName) continue;
      const nodeId = cloudPolicyId('aws', arn || policyName);
      if (seenNodes.has(nodeId)) continue;
      seenNodes.add(nodeId);

      // Extract statement-level actions so explicit denies survive ingestion.
      const policyDoc = policy.PolicyDocument || policy.document;
      const doc = typeof policyDoc === 'string' ? (() => { try { return JSON.parse(policyDoc); } catch { return null; } })() : policyDoc;
      const policyNodes: string[] = [];
      const statements = doc?.Statement ? (Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement]) : [];
      if (doc?.Statement) {
        for (const [index, stmt] of statements.entries()) {
          const effect = String(stmt.Effect || 'Allow').toLowerCase();
          if (effect !== 'allow' && effect !== 'deny') continue;
          const actions = Array.isArray(stmt.Action) ? stmt.Action : (stmt.Action ? [stmt.Action] : []);
          const resources = Array.isArray(stmt.Resource) ? stmt.Resource : (stmt.Resource ? [stmt.Resource] : ['*']);
          const conditions = stmt.Condition ? [JSON.stringify(stmt.Condition)] : undefined;
          const stmtId = statements.length === 1 ? nodeId : cloudPolicyId('aws', `${arn || policyName}:statement:${index}:${effect}`);
          policyNodes.push(stmtId);
          nodes.push({
            id: stmtId, type: 'cloud_policy',
            label: statements.length === 1 ? policyName : `${policyName} (${effect} statement ${index + 1})`,
            discovered_at: now, discovered_by: agentId, confidence: 1.0,
            provider: 'aws', policy_name: policyName, arn,
            effect, actions, resources,
            ...(conditions ? { conditions } : {}),
          } as Finding['nodes'][0]);
        }
      }

      if (policyNodes.length === 0) {
        policyNodes.push(nodeId);
        nodes.push({
          id: nodeId, type: 'cloud_policy',
          label: policyName,
          discovered_at: now, discovered_by: agentId, confidence: 1.0,
          provider: 'aws', policy_name: policyName, arn,
          effect: 'allow', actions: [], resources: [],
        } as Finding['nodes'][0]);
      }

      // HAS_POLICY edges from attached entities
      const attached = policy.AttachedEntities || policy.attached_entities || [];
      for (const entity of Array.isArray(attached) ? attached : []) {
        const entityArn = entity.Arn || entity.arn || entity;
        if (typeof entityArn !== 'string') continue;
        const entityId = cloudIdentityId(entityArn);
        if (!seenNodes.has(entityId)) {
          seenNodes.add(entityId);
          nodes.push({
            id: entityId, type: 'cloud_identity',
            label: entityArn.split('/').pop() || entityArn,
            discovered_at: now, discovered_by: agentId, confidence: 0.8,
            provider: 'aws', arn: entityArn,
            cloud_account: (entityArn.match(/:(\d{12}):/)?.[1]) || '',
          } as Finding['nodes'][0]);
        }
        for (const policyNodeId of policyNodes) {
          edges.push({
            source: entityId, target: policyNodeId,
            properties: { type: 'HAS_POLICY', confidence: 1.0, discovered_at: now, discovered_by: agentId },
          });
        }
      }
    }
  }

  // S3 Buckets
  if (Array.isArray(data.S3Buckets)) {
    for (const bucket of data.S3Buckets) {
      const bucketName = bucket.Name || bucket.name || '';
      if (!bucketName) continue;
      const bucketArn = `arn:aws:s3:::${bucketName}`;
      const nodeId = cloudResourceId(bucketArn);
      if (seenNodes.has(nodeId)) continue;
      seenNodes.add(nodeId);

      const pab = bucket.PublicAccessBlockConfiguration;
      const explicitPublic = bucket.Public === true || bucket.public === true
        || bucket.IsPublic === true || bucket.is_public === true
        || bucket.AclPublic === true || bucket.acl_public === true
        || bucket.PolicyPublic === true || bucket.policy_public === true;
      const hasIncompleteBpa = pab
        ? !(pab.BlockPublicAcls && pab.BlockPublicPolicy && pab.IgnorePublicAcls && pab.RestrictPublicBuckets)
        : undefined;

      nodes.push({
        id: nodeId, type: 'cloud_resource',
        label: bucketName,
        discovered_at: now, discovered_by: agentId, confidence: 1.0,
        provider: 'aws', arn: bucketArn,
        resource_type: 's3_bucket', region: bucket.Region || bucket.region,
        ...(explicitPublic ? { public: true } : {}),
        ...(hasIncompleteBpa !== undefined ? { public_access_block_incomplete: hasIncompleteBpa } : {}),
        cloud_account: accountId,
      } as Finding['nodes'][0]);
    }
  }

  // EC2 Instances
  if (Array.isArray(data.EC2Instances)) {
    for (const inst of data.EC2Instances) {
      const instanceId = inst.InstanceId || inst.instance_id || '';
      if (!instanceId) continue;
      const instArn = inst.Arn || inst.arn || `arn:aws:ec2:${inst.Region || inst.region || 'unknown'}:${accountId}:instance/${instanceId}`;
      const nodeId = cloudResourceId(instArn);
      if (seenNodes.has(nodeId)) continue;
      seenNodes.add(nodeId);

      const imdsv2 = inst.MetadataOptions?.HttpTokens === 'required';

      nodes.push({
        id: nodeId, type: 'cloud_resource',
        label: instanceId,
        discovered_at: now, discovered_by: agentId, confidence: 1.0,
        provider: 'aws', arn: instArn,
        resource_type: 'ec2', region: inst.Region || inst.region,
        cloud_account: accountId, imdsv2_required: imdsv2,
        public: !!(inst.PublicIpAddress || inst.public_ip),
      } as Finding['nodes'][0]);

      // If instance has a public/private IP, link to host node
      const ip = inst.PrivateIpAddress || inst.private_ip || inst.PublicIpAddress || inst.public_ip;
      if (ip) {
        const hId = hostId(ip);
        if (!seenNodes.has(hId)) {
          seenNodes.add(hId);
          nodes.push({
            id: hId, type: 'host', label: ip,
            discovered_at: now, discovered_by: agentId, confidence: 0.9,
            ip, alive: true,
          } as Finding['nodes'][0]);
        }
        edges.push({
          source: hId, target: nodeId,
          properties: { type: 'RUNS_ON', confidence: 1.0, discovered_at: now, discovered_by: agentId },
        });
      }

      // If instance has an IAM role (instance profile), resolve the actual role ARN
      // AWS instance profiles contain a Roles array; use the role ARN when available
      // to avoid creating false pivot paths through the profile ARN.
      const profile = inst.IamInstanceProfile || inst.iam_instance_profile;
      if (profile) {
        const profileArn = profile.Arn || profile.arn || '';
        const roles = Array.isArray(profile.Roles) ? profile.Roles : (Array.isArray(profile.roles) ? profile.roles : []);
        const roleArn = roles.length > 0 ? (roles[0].Arn || roles[0].arn || '') : '';
        const resolvedArn = roleArn || profileArn;
        if (resolvedArn) {
          const principalType = roleArn ? 'role' : 'instance_profile';
          const roleNodeId = cloudIdentityId(resolvedArn);
          if (!seenNodes.has(roleNodeId)) {
            seenNodes.add(roleNodeId);
            nodes.push({
              id: roleNodeId, type: 'cloud_identity',
              label: resolvedArn.split('/').pop() || resolvedArn,
              discovered_at: now, discovered_by: agentId, confidence: 0.9,
              provider: 'aws', arn: resolvedArn, principal_type: principalType,
              cloud_account: accountId,
            } as Finding['nodes'][0]);
          }
          edges.push({
            source: nodeId, target: roleNodeId,
            properties: { type: 'MANAGED_BY', confidence: 1.0, discovered_at: now, discovered_by: agentId },
          });
        }
      }
    }
  }

  return { id: `pacu-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
}

// --- Prowler / ScoutSuite Parser ---

export function parseProwler(output: string, agentId: string = 'prowler-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const seenNodes = new Set<string>();

  // Prowler OCSF JSON output — one JSON object per line
  const lines = output.split('\n').filter(l => l.trim());

  for (const line of lines) {
    let finding: Record<string, unknown>;
    try {
      finding = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue;
    }

    // Extract nested structures for safe access
    const resources = Array.isArray(finding.resources) ? finding.resources as Record<string, unknown>[] : [];
    const resource0 = resources[0] as Record<string, unknown> | undefined;
    const cloud = finding.cloud as Record<string, unknown> | undefined;
    const cloudAccount = cloud?.account as Record<string, unknown> | undefined;
    const findingInfo = finding.finding_info as Record<string, unknown> | undefined;

    // Extract resource info
    const resourceArn = (finding.ResourceArn || finding.resource_arn
      || resource0?.uid || resource0?.arn || '') as string;
    const resourceId = (finding.ResourceId || finding.resource_id
      || resource0?.name || '') as string;
    const accountIdVal = (finding.AccountId || finding.account_id
      || cloudAccount?.uid || context?.cloud_account || '') as string;
    const regionVal = (finding.Region || finding.region
      || cloud?.region || context?.cloud_region || '') as string;
    const provider = String(finding.Provider || finding.provider || 'aws').toLowerCase() as 'aws' | 'azure' | 'gcp';

    if (!resourceArn && !resourceId) continue;

    const arnForId = resourceArn || `${provider}:${accountIdVal}:${resourceId}`;
    const crNodeId = cloudResourceId(arnForId);

    // Determine resource_type from service or check_type
    const serviceName = String(finding.ServiceName || finding.service_name || resource0?.type || '').toLowerCase();
    const resourceType = serviceName.replace(/^aws\./, '').replace(/\./g, '_') || 'unknown';

    if (!seenNodes.has(crNodeId)) {
      seenNodes.add(crNodeId);
      nodes.push({
        id: crNodeId, type: 'cloud_resource',
        label: resourceId || resourceArn,
        discovered_at: now, discovered_by: agentId, confidence: 1.0,
        provider, arn: resourceArn, resource_type: resourceType,
        region: regionVal, cloud_account: accountIdVal,
      } as Finding['nodes'][0]);
    }

    // Map all failed checks to vulnerability nodes regardless of severity.
    // Severity is carried on the node so reporting/filtering can decide emphasis.
    const status = String(finding.Status || finding.status_code || finding.status || '').toUpperCase();
    const severity = String(finding.Severity || finding.severity || findingInfo?.severity || '').toUpperCase();

    const PROWLER_SEVERITY_CVSS: Record<string, number> = {
      CRITICAL: 9.0,
      HIGH: 7.5,
      MEDIUM: 5.0,
      LOW: 2.5,
      INFORMATIONAL: 0,
    };

    if (status === 'FAIL') {
      const checkId = (finding.CheckID || finding.check_id || findingInfo?.uid || `prowler-${Date.now()}`) as string;
      const vulnNodeId = vulnerabilityId(checkId, crNodeId);
      if (!seenNodes.has(vulnNodeId)) {
        seenNodes.add(vulnNodeId);
        const description = (finding.StatusExtended || finding.status_extended
          || findingInfo?.desc || finding.Description || '') as string;
        nodes.push({
          id: vulnNodeId, type: 'vulnerability',
          label: `${checkId}: ${description}`.slice(0, 120),
          discovered_at: now, discovered_by: agentId,
          confidence: 1.0,
          vuln_type: 'cloud_misconfiguration',
          cvss: PROWLER_SEVERITY_CVSS[severity] ?? 5.0,
          exploitable: severity === 'CRITICAL' || severity === 'HIGH',
          affected_component: resourceType,
          prowler_severity: severity.toLowerCase(),
        } as Finding['nodes'][0]);
        edges.push({
          source: crNodeId, target: vulnNodeId,
          properties: { type: 'VULNERABLE_TO', confidence: 1.0, discovered_at: now, discovered_by: agentId },
        });
      }
    }
  }

  return { id: `prowler-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
}

/**
 * Parse enumerate-iam text output.
 *
 * enumerate-iam probes every AWS API action and reports which succeed.
 * Output lines look like:
 *   [INFO] -- Account ID: 123456789012
 *   [INFO] -- ARN: arn:aws:iam::123456789012:user/testuser
 *   [INFO] iam.list_users() worked!
 *   [INFO] s3.list_buckets() worked!
 */
function botoMethodToIamAction(service: string, method: string): string {
  const action = method
    .split('_')
    .filter(Boolean)
    .map(part => part.charAt(0).toUpperCase() + part.slice(1))
    .join('');
  return `${service}:${action}`;
}

export function parseEnumerateIam(output: string, agentId: string = 'enumerate-iam-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();

  const lines = output.split('\n');

  let accountIdVal = context?.cloud_account || '';
  let arnVal = '';
  const confirmed: string[] = [];

  for (const line of lines) {
    // Account ID
    const accMatch = line.match(/Account\s+ID:\s*(\d{12})/i);
    if (accMatch) { accountIdVal = accMatch[1]; continue; }

    // ARN
    const arnMatch = line.match(/ARN:\s*(arn:[^\s]+)/i);
    if (arnMatch) { arnVal = arnMatch[1]; continue; }

    // Confirmed API call
    const apiMatch = line.match(/(\w+\.\w+)\(\)\s+worked/i);
    if (apiMatch) {
      // Convert "iam.list_users" to "iam:ListUsers" style
      const [service, action] = apiMatch[1].split('.');
      const normalised = botoMethodToIamAction(service, action);
      confirmed.push(normalised);
    }
  }

  if (confirmed.length === 0) {
    return { id: `enumerate-iam-${Date.now()}`, agent_id: agentId, timestamp: now, nodes: [], edges: [] };
  }

  // Create cloud_identity for the enumerated principal
  const identityArn = arnVal || `arn:aws:iam::${accountIdVal}:user/enumerated`;
  const identityNodeId = cloudIdentityId(identityArn);
  nodes.push({
    id: identityNodeId, type: 'cloud_identity',
    label: arnVal ? arnVal.split('/').pop() || arnVal : 'enumerated-principal',
    discovered_at: now, discovered_by: agentId, confidence: 1.0,
    provider: 'aws', arn: arnVal || undefined,
    principal_type: arnVal.includes(':role/') ? 'role' : 'user',
    cloud_account: accountIdVal,
    policies_enumerated: true,
  } as Finding['nodes'][0]);

  // Create a cloud_policy with the confirmed actions
  const policyId = cloudPolicyId('aws', `enumerated-${identityArn}`);
  nodes.push({
    id: policyId, type: 'cloud_policy',
    label: `Enumerated permissions (${confirmed.length} actions)`,
    discovered_at: now, discovered_by: agentId, confidence: 0.9,
    provider: 'aws', policy_name: 'enumerated-permissions',
    effect: 'allow', actions: confirmed, resources: ['*'],
  } as Finding['nodes'][0]);

  edges.push({
    source: identityNodeId, target: policyId,
    properties: { type: 'HAS_POLICY', confidence: 0.9, discovered_at: now, discovered_by: agentId },
  });

  return { id: `enumerate-iam-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
}
