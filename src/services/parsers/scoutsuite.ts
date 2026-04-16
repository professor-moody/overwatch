import type { Finding, ParseContext } from '../../types.js';
import { cloudIdentityId, cloudNetworkId, cloudPolicyId, cloudResourceId, vulnerabilityId } from '../parser-utils.js';

/**
 * Parse ScoutSuite JSON results (multi-cloud: AWS, Azure, GCP).
 *
 * ScoutSuite produces a JS file (`scoutsuite_results.js`) with
 * `scoutsuite_results = { ... }`.  We accept either the raw JS
 * (stripping the assignment prefix) or plain JSON.
 *
 * Output structure:
 *   { provider_code, account_id, services: { <svc>: { findings, <resource_group>: { items } } } }
 */
export function parseScoutSuite(output: string, agentId: string = 'scoutsuite-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const seenNodes = new Set<string>();

  // Strip JS assignment wrapper if present
  let jsonStr = output.trim();
  const assignMatch = jsonStr.match(/^\s*(?:var\s+)?scoutsuite_results\s*=\s*/);
  if (assignMatch) {
    jsonStr = jsonStr.slice(assignMatch[0].length);
    // Remove trailing semicolon
    if (jsonStr.endsWith(';')) jsonStr = jsonStr.slice(0, -1);
  }

  let data: Record<string, unknown>;
  try {
    data = JSON.parse(jsonStr) as Record<string, unknown>;
  } catch {
    return { id: `scoutsuite-${Date.now()}`, agent_id: agentId, timestamp: now, nodes: [], edges: [] };
  }

  const providerCode = String(data.provider_code || data.provider || context?.cloud_provider || 'aws').toLowerCase() as 'aws' | 'azure' | 'gcp';
  const accountId = String(data.account_id || context?.cloud_account || '');
  const services = data.services as Record<string, Record<string, unknown>> | undefined;
  if (!services) {
    return { id: `scoutsuite-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
  }

  const SEVERITY_CVSS: Record<string, number> = {
    danger: 8.0,
    warning: 5.0,
    good: 0,
  };

  function addNode(node: Finding['nodes'][0]): void {
    if (!seenNodes.has(node.id)) {
      seenNodes.add(node.id);
      nodes.push(node);
    }
  }

  for (const [serviceName, serviceData] of Object.entries(services)) {
    // --- Process findings (flagged security checks) ---
    const findings = serviceData.findings as Record<string, Record<string, unknown>> | undefined;
    if (findings) {
      for (const [findingKey, finding] of Object.entries(findings)) {
        const flagged = Number(finding.flagged_items ?? 0);
        if (flagged === 0) continue;
        const level = String(finding.level || 'warning');
        if (level === 'good') continue;

        // Flagged items list may contain dot-paths to resources
        const items = Array.isArray(finding.items) ? finding.items as string[] : [];
        for (const itemPath of items) {
          // Build a resource reference from the flagged item path
          const resArn = `${providerCode}:${accountId}:${serviceName}:${itemPath}`;
          const crNodeId = cloudResourceId(resArn);
          addNode({
            id: crNodeId, type: 'cloud_resource',
            label: itemPath.split('.').pop() || itemPath,
            discovered_at: now, discovered_by: agentId, confidence: 0.9,
            provider: providerCode, resource_type: serviceName,
            cloud_account: accountId,
          } as Finding['nodes'][0]);

          const vulnId = vulnerabilityId(findingKey, crNodeId);
          addNode({
            id: vulnId, type: 'vulnerability',
            label: `${findingKey}: ${String(finding.description || '').slice(0, 100)}`,
            discovered_at: now, discovered_by: agentId, confidence: 1.0,
            vuln_type: 'cloud_misconfiguration',
            cvss: SEVERITY_CVSS[level] ?? 5.0,
            exploitable: level === 'danger',
            affected_component: serviceName,
            scoutsuite_level: level,
          } as Finding['nodes'][0]);

          edges.push({
            source: crNodeId, target: vulnId,
            properties: { type: 'VULNERABLE_TO', confidence: 1.0, discovered_at: now, discovered_by: agentId },
          });
        }
      }
    }

    // --- Process IAM resources ---
    if (serviceName === 'iam') {
      const users = (serviceData.users as Record<string, Record<string, unknown>> | undefined)?.items as Record<string, Record<string, unknown>> | undefined;
      if (users) {
        for (const user of Object.values(users)) {
          const arn = String(user.arn || '');
          if (!arn) continue;
          const nodeId = cloudIdentityId(arn);
          addNode({
            id: nodeId, type: 'cloud_identity',
            label: String(user.name || arn),
            discovered_at: now, discovered_by: agentId, confidence: 1.0,
            provider: providerCode, arn, principal_type: 'user',
            cloud_account: accountId,
            mfa_enabled: user.mfa_enabled === true || (Array.isArray(user.mfa_devices) && user.mfa_devices.length > 0),
          } as Finding['nodes'][0]);

          // User policies
          const userPolicies = Array.isArray(user.policies) ? user.policies : [];
          for (const pol of userPolicies) {
            const pArn = String((pol as Record<string, unknown>).arn || (pol as Record<string, unknown>).PolicyArn || '');
            const pName = String((pol as Record<string, unknown>).name || (pol as Record<string, unknown>).PolicyName || pArn);
            if (!pName) continue;
            const polId = cloudPolicyId(providerCode, pArn || pName);
            addNode({
              id: polId, type: 'cloud_policy',
              label: pName,
              discovered_at: now, discovered_by: agentId, confidence: 1.0,
              provider: providerCode, policy_name: pName, arn: pArn,
            } as Finding['nodes'][0]);
            edges.push({
              source: nodeId, target: polId,
              properties: { type: 'HAS_POLICY', confidence: 1.0, discovered_at: now, discovered_by: agentId },
            });
          }
        }
      }

      const roles = (serviceData.roles as Record<string, Record<string, unknown>> | undefined)?.items as Record<string, Record<string, unknown>> | undefined;
      if (roles) {
        for (const role of Object.values(roles)) {
          const arn = String(role.arn || '');
          if (!arn) continue;
          const nodeId = cloudIdentityId(arn);
          addNode({
            id: nodeId, type: 'cloud_identity',
            label: String(role.name || arn),
            discovered_at: now, discovered_by: agentId, confidence: 1.0,
            provider: providerCode, arn, principal_type: 'role',
            cloud_account: accountId,
          } as Finding['nodes'][0]);

          // Trust policy → ASSUMES_ROLE edges
          const trustPolicy = role.assume_role_policy_document ?? role.AssumeRolePolicyDocument;
          if (trustPolicy) {
            let doc: Record<string, unknown> | null = null;
            try { doc = typeof trustPolicy === 'string' ? JSON.parse(trustPolicy) : trustPolicy as Record<string, unknown>; } catch { /* skip */ }
            if (doc) {
              const stmts = Array.isArray(doc.Statement) ? doc.Statement : [];
              for (const stmt of stmts) {
                if (stmt.Effect !== 'Allow') continue;
                const principals = (stmt as Record<string, unknown>).Principal as Record<string, unknown> | undefined;
                const awsPrincipals = principals?.AWS;
                const arnList = Array.isArray(awsPrincipals) ? awsPrincipals : (awsPrincipals ? [awsPrincipals] : []);
                for (const trustedArn of arnList) {
                  if (typeof trustedArn !== 'string' || trustedArn === '*') continue;
                  const trustedId = cloudIdentityId(trustedArn);
                  addNode({
                    id: trustedId, type: 'cloud_identity',
                    label: trustedArn.split('/').pop() || trustedArn,
                    discovered_at: now, discovered_by: agentId, confidence: 0.8,
                    provider: providerCode, arn: trustedArn,
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
            }
          }
        }
      }
    }

    // --- Process EC2 instances ---
    if (serviceName === 'ec2') {
      const instances = (serviceData.instances as Record<string, Record<string, unknown>> | undefined)?.items as Record<string, Record<string, unknown>> | undefined;
      if (instances) {
        for (const inst of Object.values(instances)) {
          const instId = String(inst.instance_id || inst.id || '');
          if (!instId) continue;
          const arn = String(inst.arn || `arn:aws:ec2:${inst.region || 'unknown'}:${accountId}:instance/${instId}`);
          const nodeId = cloudResourceId(arn);
          addNode({
            id: nodeId, type: 'cloud_resource',
            label: String(inst.name || instId),
            discovered_at: now, discovered_by: agentId, confidence: 1.0,
            provider: providerCode, arn, resource_type: 'ec2',
            region: String(inst.region || ''), cloud_account: accountId,
            public: !!(inst.public_ip || inst.PublicIpAddress),
            imdsv2_required: (inst.metadata_options as Record<string, unknown> | undefined)?.http_tokens === 'required'
              || (inst.MetadataOptions as Record<string, unknown> | undefined)?.HttpTokens === 'required',
          } as Finding['nodes'][0]);
        }
      }

      // --- Security groups → cloud_network ---
      const sgs = (serviceData.security_groups as Record<string, Record<string, unknown>> | undefined)?.items as Record<string, Record<string, unknown>> | undefined;
      if (sgs) {
        for (const sg of Object.values(sgs)) {
          const sgId = String(sg.id || sg.GroupId || '');
          if (!sgId) continue;
          const arn = String(sg.arn || `arn:aws:ec2:${sg.region || 'unknown'}:${accountId}:security-group/${sgId}`);
          const nodeId = cloudNetworkId(arn);

          const ingress: string[] = [];
          const rules = Array.isArray(sg.rules) ? sg.rules : (Array.isArray(sg.IpPermissions) ? sg.IpPermissions : []);
          for (const rule of rules) {
            const proto = String((rule as Record<string, unknown>).protocol || (rule as Record<string, unknown>).IpProtocol || 'tcp');
            const port = String((rule as Record<string, unknown>).port || (rule as Record<string, unknown>).FromPort || '*');
            const grants = Array.isArray((rule as Record<string, unknown>).grants || (rule as Record<string, unknown>).IpRanges) ?
              ((rule as Record<string, unknown>).grants || (rule as Record<string, unknown>).IpRanges) as Record<string, unknown>[] : [];
            for (const grant of grants) {
              const cidr = String(grant.value || grant.CidrIp || '*');
              ingress.push(`${proto}:${port}:${cidr}`);
            }
          }

          addNode({
            id: nodeId, type: 'cloud_network',
            label: String(sg.name || sgId),
            discovered_at: now, discovered_by: agentId, confidence: 1.0,
            network_type: 'security_group', ingress_rules: ingress,
          } as Finding['nodes'][0]);
        }
      }
    }

    // --- Process S3 buckets ---
    if (serviceName === 's3') {
      const buckets = (serviceData.buckets as Record<string, Record<string, unknown>> | undefined)?.items as Record<string, Record<string, unknown>> | undefined;
      if (buckets) {
        for (const bucket of Object.values(buckets)) {
          const name = String(bucket.name || '');
          if (!name) continue;
          const arn = String(bucket.arn || `arn:aws:s3:::${name}`);
          const nodeId = cloudResourceId(arn);
          addNode({
            id: nodeId, type: 'cloud_resource',
            label: name,
            discovered_at: now, discovered_by: agentId, confidence: 1.0,
            provider: providerCode, arn, resource_type: 's3_bucket',
            cloud_account: accountId,
            public: bucket.acls_public === true || bucket.policy_public === true,
            encrypted: bucket.default_encryption === true || bucket.encryption_enabled === true,
          } as Finding['nodes'][0]);
        }
      }
    }

    // --- Process Lambda functions ---
    if (serviceName === 'awslambda' || serviceName === 'lambda') {
      const functions = (serviceData.functions as Record<string, Record<string, unknown>> | undefined)?.items as Record<string, Record<string, unknown>> | undefined;
      if (functions) {
        for (const fn of Object.values(functions)) {
          const fnName = String(fn.name || fn.FunctionName || '');
          const arn = String(fn.arn || '');
          if (!fnName && !arn) continue;
          const nodeId = cloudResourceId(arn || `${providerCode}:lambda:${fnName}`);
          addNode({
            id: nodeId, type: 'cloud_resource',
            label: fnName || arn,
            discovered_at: now, discovered_by: agentId, confidence: 1.0,
            provider: providerCode, arn, resource_type: 'lambda',
            region: String(fn.region || ''), cloud_account: accountId,
          } as Finding['nodes'][0]);

          // Lambda execution role → MANAGED_BY
          const roleArn = fn.role || fn.Role;
          if (typeof roleArn === 'string' && roleArn) {
            const roleNodeId = cloudIdentityId(roleArn);
            addNode({
              id: roleNodeId, type: 'cloud_identity',
              label: roleArn.split('/').pop() || roleArn,
              discovered_at: now, discovered_by: agentId, confidence: 0.9,
              provider: providerCode, arn: roleArn, principal_type: 'role',
              cloud_account: (roleArn.match(/:(\d{12}):/)?.[1]) || accountId,
            } as Finding['nodes'][0]);
            edges.push({
              source: nodeId, target: roleNodeId,
              properties: { type: 'MANAGED_BY', confidence: 1.0, discovered_at: now, discovered_by: agentId },
            });
          }
        }
      }
    }
  }

  return { id: `scoutsuite-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
}
