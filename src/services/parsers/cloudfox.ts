import type { Finding, ParseContext } from '../../types.js';
import { cloudIdentityId, cloudPolicyId, cloudPolicyStatementId, cloudResourceId } from '../parser-utils.js';

/**
 * Parse CloudFox JSON output (AWS privilege escalation / resource enumeration).
 *
 * CloudFox writes per-module JSON arrays beneath its --outdir. The AWS
 * playbook emits a normalized envelope containing those real records; legacy
 * bare arrays / `{results: [...]}` remain accepted for compatibility.
 *
 * Format: Array of objects with fields like AWSService, Type, Name, Arn,
 * Principal, Action, Resource, AccountId, Region, etc.
 */
export function parseCloudFox(output: string, agentId: string = 'cloudfox-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const nodeIndex = new Map<string, Finding['nodes'][0]>();
  const edgeIndex = new Map<string, Finding['edges'][0]>();

  let records: Record<string, unknown>[];
  try {
    const parsed = JSON.parse(output);
    if (parsed?.format === 'cloudfox-json-files-v1' && Array.isArray(parsed.records)) {
      records = parsed.records.flatMap((entry: unknown) => {
        if (!entry || typeof entry !== 'object') return [];
        const wrapped = entry as { module?: unknown; record?: unknown };
        if (!wrapped.record || typeof wrapped.record !== 'object' || Array.isArray(wrapped.record)) return [];
        return [{ ...(wrapped.record as Record<string, unknown>), _cloudfox_module: String(wrapped.module ?? '') }];
      });
    } else {
      records = Array.isArray(parsed) ? parsed : (Array.isArray(parsed.results) ? parsed.results : []);
    }
  } catch {
    return { id: `cloudfox-${Date.now()}`, agent_id: agentId, timestamp: now, nodes: [], edges: [] };
  }

  if (records.length === 0) {
    return { id: `cloudfox-${Date.now()}`, agent_id: agentId, timestamp: now, nodes: [], edges: [] };
  }

  const field = (rec: Record<string, unknown>, ...keys: string[]): string => {
    for (const key of keys) {
      const value = rec[key];
      if (value !== undefined && value !== null && String(value).length > 0) return String(value);
    }
    return '';
  };
  const yesNo = (value: string): boolean | undefined => {
    if (/^(yes|true)$/i.test(value)) return true;
    if (/^(no|false)$/i.test(value)) return false;
    return undefined;
  };
  const accountId = String(context?.cloud_account || field(records[0], 'AccountId', 'Account ID', 'Account') || '');
  const callerPartition = typeof context?.caller_arn === 'string'
    ? context.caller_arn.match(/^arn:([^:]+):/)?.[1]
    : undefined;
  const partition = callerPartition && ['aws', 'aws-us-gov', 'aws-cn'].includes(callerPartition)
    ? callerPartition
    : 'aws';

  function addNode(node: Finding['nodes'][0]): void {
    const existing = nodeIndex.get(node.id);
    if (!existing) {
      nodeIndex.set(node.id, node);
      nodes.push(node);
      return;
    }
    for (const [key, value] of Object.entries(node)) {
      if (value !== undefined && (existing[key] === undefined || existing[key] === '')) existing[key] = value;
    }
    if (typeof node.confidence === 'number') {
      existing.confidence = Math.max(typeof existing.confidence === 'number' ? existing.confidence : 0, node.confidence);
    }
    for (const key of ['is_admin', 'privileged', 'can_priv_esc_to_admin', 'public'] as const) {
      const oldValue = existing[key];
      const newValue = node[key];
      if (oldValue === true || newValue === true) existing[key] = true;
      else if (oldValue === false || newValue === false) existing[key] = false;
    }
    // CloudFox permissions are row-oriented. Preserve every observed action,
    // resource, and condition when several rows describe the same policy.
    for (const key of ['actions', 'not_actions', 'resources', 'conditions'] as const) {
      const oldValues = Array.isArray(existing[key]) ? (existing[key] as unknown[]).map(String) : [];
      const newValues = Array.isArray(node[key]) ? (node[key] as unknown[]).map(String) : [];
      if (newValues.length > 0) existing[key] = [...new Set([...oldValues, ...newValues])];
    }
  }

  function addEdge(edge: Finding['edges'][0]): void {
    const key = `${edge.source}\0${edge.target}\0${edge.properties.type}`;
    const existing = edgeIndex.get(key);
    if (!existing) {
      edgeIndex.set(key, edge);
      edges.push(edge);
      return;
    }
    for (const prop of ['trusted_subjects', 'external_ids', 'trust_conditions'] as const) {
      const prior = Array.isArray(existing.properties[prop]) ? (existing.properties[prop] as unknown[]).map(String) : [];
      const incoming = Array.isArray(edge.properties[prop]) ? (edge.properties[prop] as unknown[]).map(String) : [];
      if (incoming.length > 0) existing.properties[prop] = [...new Set([...prior, ...incoming])];
    }
    if (edge.properties.type === 'ASSUMES_ROLE') {
      // Duplicate trust rows are alternatives. One unconditional alternative
      // is enough to make the merged reachability unconditional.
      existing.properties.condition_present = existing.properties.condition_present === true
        && edge.properties.condition_present === true;
      existing.properties.confidence = existing.properties.condition_present === true ? 0.6 : 0.9;
    } else if (typeof edge.properties.confidence === 'number') {
      existing.properties.confidence = Math.max(
        typeof existing.properties.confidence === 'number' ? existing.properties.confidence : 0,
        edge.properties.confidence,
      );
    }
  }

  for (const rec of records) {
    const module = field(rec, '_cloudfox_module', 'module').toLowerCase();
    let arn = field(rec, 'Arn', 'ARN', 'arn', 'RoleArn', 'Role Arn', 'Role ARN', 'PrincipalArn', 'Principal Arn', 'Principal ARN', 'FunctionArn', 'Function ARN');
    let principal = field(rec, 'Principal', 'principal', 'Name', 'name', 'Role Name', 'User Name', 'Function Name', 'Instance Name', 'Instance ID', 'ID');
    let awsService = field(rec, 'AWSService', 'Service', 'service').toLowerCase();
    let recType = field(rec, 'Type', 'type', 'Principal Type');
    const rawAction = field(rec, 'Action', 'action', 'Actions', 'Permission');
    const notAction = /^\[NotAction\]\s*/i.test(rawAction);
    const action = rawAction.replace(/^\[NotAction\]\s*/i, '');
    const resource = field(rec, 'Resource', 'resource', 'Resources');
    let region = field(rec, 'Region', 'region');
    const recAccountId = field(rec, 'AccountId', 'Account ID', 'Account', 'account_id') || accountId;

    if (module.includes('bucket')) {
      awsService ||= 's3';
      recType ||= 'Bucket';
      if (!arn && principal) arn = `arn:${partition}:s3:::${principal}`;
    } else if (module.includes('lambda')) {
      awsService ||= 'lambda';
      recType ||= 'Lambda';
    } else if (module.includes('instance')) {
      awsService ||= 'ec2';
      recType ||= 'Instance';
      const instanceId = field(rec, 'Instance ID', 'InstanceId', 'ID');
      const zone = field(rec, 'Zone', 'Availability Zone', 'AvailabilityZone');
      if (!region && zone) region = zone.match(/^([a-z]{2}(?:-gov)?-[a-z]+-\d+)/)?.[1] ?? '';
      if (!arn && instanceId && region && recAccountId) arn = `arn:${partition}:ec2:${region}:${recAccountId}:instance/${instanceId}`;
    } else if (module.includes('principal')) {
      awsService ||= 'iam';
      recType ||= arn.includes(':role/') ? 'Role' : 'User';
    }

    // --- Role trust entries → cloud_identity + ASSUMES_ROLE ---
    if (recType === 'RoleTrust' || recType === 'role-trust' || awsService === 'role-trusts' || module.includes('role-trust')) {
      const trustedPrincipal = field(rec, 'TrustedPrincipal', 'Trusted Principal', 'trusted_principal', 'Principal');
      const trustedService = field(rec, 'Trusted Service', 'TrustedService', 'trusted_service');
      const trustedProvider = field(rec, 'Trusted Provider', 'TrustedProvider', 'trusted_provider');
      const trustedValue = trustedPrincipal || trustedService || trustedProvider;
      const roleArn = field(rec, 'RoleArn', 'Role Arn', 'Role ARN', 'Arn', 'ARN') || arn;
      if (!roleArn || !trustedValue) continue;

      const roleNodeId = cloudIdentityId(roleArn);
      const roleIsAdmin = yesNo(field(rec, 'IsAdmin?', 'IsAdminRole?'));
      addNode({
        id: roleNodeId, type: 'cloud_identity',
        label: roleArn.split('/').pop() || roleArn,
        discovered_at: now, discovered_by: agentId, confidence: 1.0,
        provider: 'aws', arn: roleArn, principal_type: 'role',
        cloud_account: (roleArn.match(/:(\d{12}):/)?.[1]) || recAccountId,
        is_admin: roleIsAdmin,
        privileged: roleIsAdmin === undefined ? undefined : roleIsAdmin,
        can_priv_esc_to_admin: yesNo(field(rec, 'CanPrivEscToAdmin?')),
      } as Finding['nodes'][0]);

      // Preserve every supported trust principal using the same stable-id
      // convention as the generic AWS parser.
      const conditionsRaw = rec.Conditions ?? rec.Condition ?? rec.conditions ?? rec['Condition Keys'];
      const externalId = field(rec, 'ExternalID', 'External ID', 'ExternalId');
      const trustedSubject = field(rec, 'Trusted Subject', 'TrustedSubject', 'trusted_subject');
      const hasConditions = (conditionsRaw !== undefined && conditionsRaw !== null && String(conditionsRaw).length > 0)
        || !!externalId || !!trustedSubject;
      const decoratedArn = trustedValue.match(/^(arn:[^\s]+)(?:\s+\(([^)]+)\))?$/);
      const canonicalTrustedValue = decoratedArn?.[1] ?? trustedValue;
      const trustedVendor = decoratedArn?.[2];
      const principalKind = trustedValue === '*' ? 'wildcard' : trustedService ? 'service' : trustedProvider ? 'federated' : 'aws';
      const principalType = principalKind === 'wildcard' ? 'wildcard'
        : principalKind === 'service' ? 'service'
          : principalKind === 'federated' ? 'federated'
            : canonicalTrustedValue.includes(':role/') ? 'role'
              : canonicalTrustedValue.includes(':user/') ? 'user' : 'canonical';
      const trustedId = principalKind === 'aws'
        ? cloudIdentityId(canonicalTrustedValue)
        : cloudIdentityId(`aws:${principalKind}:${canonicalTrustedValue}`);
      addNode({
        id: trustedId, type: 'cloud_identity',
        label: principalKind === 'aws'
          ? canonicalTrustedValue.split('/').pop() || canonicalTrustedValue
          : `${principalKind}:${canonicalTrustedValue}`,
        discovered_at: now, discovered_by: agentId, confidence: 0.8,
        provider: 'aws', arn: principalKind === 'aws' && canonicalTrustedValue.startsWith('arn:') ? canonicalTrustedValue : undefined,
        principal_value: canonicalTrustedValue,
        principal_display_suffix: trustedVendor,
        principal_type: principalType,
        principal_kind: principalKind,
        cloud_account: (canonicalTrustedValue.match(/:(\d{12}):/)?.[1]) || '',
      } as Finding['nodes'][0]);
      const roleNode = nodeIndex.get(roleNodeId);
      if (roleNode && principalKind === 'wildcard') roleNode.wildcard_trust = true;
      addEdge({
        source: trustedId, target: roleNodeId,
        properties: {
          type: 'ASSUMES_ROLE',
          confidence: hasConditions ? 0.6 : 0.9,
          discovered_at: now,
          discovered_by: agentId,
          assumption_confirmed: false,
          assumption_basis: 'trust_policy',
          condition_present: hasConditions,
          ...(conditionsRaw !== undefined ? {
            trust_conditions_json: JSON.stringify(conditionsRaw),
            trust_conditions: [String(conditionsRaw)],
          } : {}),
          ...(externalId ? { external_id: externalId, external_ids: [externalId] } : {}),
          ...(trustedSubject ? { trusted_subject: trustedSubject, trusted_subjects: [trustedSubject] } : {}),
          principal_kind: principalKind,
          trust_principal_kind: principalType,
        },
      });
      continue;
    }

    // --- Permission entries → cloud_identity + cloud_policy + POLICY_ALLOWS ---
    if (recType === 'Permission' || recType === 'permission' || awsService === 'permissions' || module.includes('permission') || (action && resource)) {
      const principalArn = field(rec, 'PrincipalArn', 'Principal Arn', 'Principal ARN', 'Principal', 'Arn', 'ARN') || arn;
      if (!principalArn || !action) continue;

      const rawPolicyArn = field(rec, 'Policy Arn', 'Policy ARN', 'PolicyArn');
      const policyArn = /^arn:/i.test(rawPolicyArn) ? rawPolicyArn : '';
      const policyName = field(rec, 'Policy Name', 'PolicyName') || (!policyArn ? rawPolicyArn : '');
      const policyType = field(rec, 'Policy', 'Policy Type', 'PolicyType') || 'unknown';
      const effect = (field(rec, 'Effect', 'effect') || 'Allow').toLowerCase();
      const conditionFlag = field(rec, 'Condition', 'Conditions', 'condition');
      const conditionPresent = yesNo(conditionFlag);

      const identityId = cloudIdentityId(principalArn);
      addNode({
        id: identityId, type: 'cloud_identity',
        label: principalArn.split('/').pop() || principalArn,
        discovered_at: now, discovered_by: agentId, confidence: 1.0,
        provider: 'aws', arn: principalArn,
        principal_type: principalArn.includes(':role/') ? 'role' : 'user',
        cloud_account: (principalArn.match(/:(\d{12}):/)?.[1]) || recAccountId,
      } as Finding['nodes'][0]);

      const policyBaseIdentity = policyArn || `${principalArn}:${policyType}:${policyName || 'unnamed'}`;
      // CloudFox is row-oriented; use a stable statement identity so action /
      // resource / condition pairs never become an overclaiming Cartesian set.
      const policyIdentity = `${policyBaseIdentity}:effect:${effect}:action:${notAction ? 'not-' : ''}${action}:resource:${resource || '*'}:condition:${conditionFlag || 'unknown'}`;
      const policyLabel = policyName || policyArn.split('/').pop() || `${principalArn.split('/').pop() || 'unknown'}-${policyType}`;
      if (policyArn) {
        const parentPolicyId = cloudPolicyId('aws', policyArn);
        addNode({
          id: parentPolicyId, type: 'cloud_policy', label: policyLabel,
          discovered_at: now, discovered_by: agentId, confidence: 0.9,
          provider: 'aws', policy_name: policyLabel, policy_arn: policyArn, arn: policyArn,
          permission_expansion: 'expanded', policy_expanded_by: 'cloudfox',
        } as Finding['nodes'][0]);
        addEdge({
          source: identityId, target: parentPolicyId,
          properties: { type: 'HAS_POLICY', confidence: 0.9, discovered_at: now, discovered_by: agentId },
        });
      }
      // Keep readable exact identity as metadata, but key the statement by a
      // hash. cloudPolicyId's legacy slug normalization can collapse distinct
      // case-sensitive AWS actions/resources containing '.', '/', or '*'.
      const polId = cloudPolicyStatementId('aws', policyIdentity);
      addNode({
        id: polId, type: 'cloud_policy',
        label: policyLabel,
        discovered_at: now, discovered_by: agentId, confidence: 0.9,
        provider: 'aws', policy_name: policyLabel,
        policy_arn: policyArn || undefined,
        policy_parent_identity: policyBaseIdentity,
        policy_identity: policyIdentity,
        policy_statement: true,
        arn: policyArn || undefined,
        policy_type: policyType,
        effect,
        actions: notAction ? [] : [action],
        not_actions: notAction ? [action] : [],
        resources: resource ? [resource] : ['*'],
        condition_present: conditionPresent,
        condition_flag: conditionFlag || undefined,
      } as Finding['nodes'][0]);

      addEdge({
        source: identityId, target: polId,
        properties: { type: 'HAS_POLICY', confidence: 0.9, discovered_at: now, discovered_by: agentId },
      });

      // If resource is a specific ARN, create a cloud_resource and POLICY_ALLOWS edge
      if (effect === 'allow' && !notAction && conditionPresent !== true && resource && resource !== '*') {
        const resId = cloudResourceId(resource);
        addNode({
          id: resId, type: 'cloud_resource',
          label: resource.split('/').pop() || resource.split(':').pop() || resource,
          discovered_at: now, discovered_by: agentId, confidence: 0.8,
          provider: 'aws', arn: resource, cloud_account: recAccountId,
        } as Finding['nodes'][0]);
        addEdge({
          source: polId, target: resId,
          properties: { type: 'POLICY_ALLOWS', confidence: 0.9, discovered_at: now, discovered_by: agentId },
        });
      }
      continue;
    }

    // --- Inventory / resource entries → cloud_resource ---
    if (arn || (principal && awsService)) {
      const resourceArn = arn || `${awsService}:${recAccountId}:${region}:${principal}`;
      const nodeId = awsService === 'iam' || recType === 'User' || recType === 'Role'
        ? cloudIdentityId(resourceArn)
        : cloudResourceId(resourceArn);
      const nodeType = awsService === 'iam' || recType === 'User' || recType === 'Role'
        ? 'cloud_identity' : 'cloud_resource';

      const recordIsAdmin = yesNo(field(rec, 'IsAdmin?', 'IsAdminRole?'));
      addNode({
        id: nodeId, type: nodeType,
        label: principal || arn.split('/').pop() || arn,
        discovered_at: now, discovered_by: agentId, confidence: 1.0,
        provider: 'aws', arn: arn || undefined,
        resource_type: nodeType === 'cloud_resource'
          ? (awsService === 's3' && recType.toLowerCase() === 'bucket' ? 's3_bucket' : awsService || recType.toLowerCase())
          : undefined,
        principal_type: nodeType === 'cloud_identity' ? (recType === 'Role' ? 'role' : 'user') : undefined,
        region: region || undefined, cloud_account: recAccountId,
        public: yesNo(field(rec, 'Public?', 'Public', 'public')),
        is_admin: recordIsAdmin,
        privileged: nodeType === 'cloud_identity' && recordIsAdmin !== undefined ? recordIsAdmin : undefined,
        can_priv_esc_to_admin: yesNo(field(rec, 'CanPrivEscToAdmin?')),
      } as Finding['nodes'][0]);

      // Lambda/EC2 with attached role → MANAGED_BY
      const attachedRole = field(rec, 'Role', 'role', 'Role Arn', 'Role ARN', 'ExecutionRole', 'Execution Role');
      if (attachedRole && nodeType === 'cloud_resource') {
        const roleNodeId = cloudIdentityId(attachedRole);
        const attachedRoleIsAdmin = yesNo(field(rec, 'IsAdminRole?', 'IsAdmin?'));
        addNode({
          id: roleNodeId, type: 'cloud_identity',
          label: attachedRole.split('/').pop() || attachedRole,
          discovered_at: now, discovered_by: agentId, confidence: 0.9,
          provider: 'aws', arn: attachedRole, principal_type: 'role',
          cloud_account: (attachedRole.match(/:(\d{12}):/)?.[1]) || recAccountId,
          is_admin: attachedRoleIsAdmin,
          privileged: attachedRoleIsAdmin === undefined ? undefined : attachedRoleIsAdmin,
          can_priv_esc_to_admin: yesNo(field(rec, 'CanPrivEscToAdmin?')),
        } as Finding['nodes'][0]);
        addEdge({
          source: nodeId, target: roleNodeId,
          properties: { type: 'MANAGED_BY', confidence: 1.0, discovered_at: now, discovered_by: agentId },
        });
      }
    }
  }

  return { id: `cloudfox-${Date.now()}`, agent_id: agentId, timestamp: now, nodes, edges };
}
