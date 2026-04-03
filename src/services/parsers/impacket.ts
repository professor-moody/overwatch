import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { credentialId, domainId, hostId, resolveDomainName, splitQualifiedAccount, userId } from '../parser-utils.js';

// --- Secretsdump Parser (impacket-secretsdump) ---

// Matches: username:rid:lmhash:nthash:::
const SECRETSDUMP_LINE = /^([^:*\s][^:]*):(\d+):([a-f0-9]{32}):([a-f0-9]{32}):::$/i;
const PRIVILEGED_ACCOUNTS = new Set(['krbtgt', 'administrator']);

export function parseSecretsdump(output: string, agentId: string = 'secretsdump-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();
  const contextDomain = context?.domain;
  const sourceHost = context?.source_host;

  // Resolve source host node ID and create host node if context provides it
  let sourceHostId: string | undefined;
  if (sourceHost) {
    sourceHostId = hostId(sourceHost);
    if (!seenNodes.has(sourceHostId)) {
      const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(sourceHost);
      nodes.push({
        id: sourceHostId, type: 'host', label: sourceHost,
        ...(isIp ? { ip: sourceHost } : { hostname: sourceHost }),
      });
      seenNodes.add(sourceHostId);
    }
  }

  // Resolve domain node if context provides it
  let contextDomainNodeId: string | undefined;
  if (contextDomain) {
    contextDomainNodeId = domainId(contextDomain);
    if (!seenNodes.has(contextDomainNodeId)) {
      nodes.push({ id: contextDomainNodeId, type: 'domain', label: contextDomain, domain_name: contextDomain });
      seenNodes.add(contextDomainNodeId);
    }
  }

  for (const line of output.split('\n')) {
    const m = line.trim().match(SECRETSDUMP_LINE);
    if (!m) continue;

    const [, rawUser, , , nthash] = m;

    // Parse DOMAIN\user or plain user
    // IMPORTANT: context.domain is only a soft hint for credential display.
    // We must NOT use it for user identity or MEMBER_OF_DOMAIN edges because
    // SAM dumps produce unqualified local accounts (Administrator:500) that
    // would be falsely merged with domain accounts if context.domain is applied.
    const parsed = splitQualifiedAccount(rawUser);
    const explicitDomain = parsed.domain ? resolveDomainName(parsed.domain, context?.domain_aliases) : undefined;
    const username = parsed.username;

    // Skip machine accounts
    if (username.endsWith('$')) continue;

    const userLower = username.toLowerCase();
    const resolvedCredId = credentialId('ntlm_hash', nthash, username, explicitDomain);
    const resolvedUserId = userId(username, explicitDomain);
    const isPrivileged = PRIVILEGED_ACCOUNTS.has(userLower);
    const domainFromContext = !explicitDomain && !!contextDomain;

    if (!seenNodes.has(resolvedCredId)) {
      nodes.push({
        id: resolvedCredId,
        type: 'credential',
        label: `NTLM:${username}`,
        cred_type: 'ntlm',
        cred_material_kind: 'ntlm_hash',
        cred_usable_for_auth: true,
        cred_evidence_kind: 'dump',
        cred_value: nthash,
        cred_user: username,
        cred_domain: explicitDomain || contextDomain,
        cred_domain_source: domainFromContext ? 'parser_context' : explicitDomain ? 'explicit' : undefined,
        dump_source_host: sourceHost,
        privileged: isPrivileged || undefined,
      });
      seenNodes.add(resolvedCredId);
    }

    if (!seenNodes.has(resolvedUserId)) {
      nodes.push({
        id: resolvedUserId,
        type: 'user',
        label: explicitDomain ? `${explicitDomain}\\${username}` : username,
        username,
        domain_name: explicitDomain,
        privileged: isPrivileged || undefined,
      });
      seenNodes.add(resolvedUserId);
    }

    edges.push({
      source: resolvedUserId,
      target: resolvedCredId,
      properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: now, discovered_by: agentId },
    });

    // MEMBER_OF_DOMAIN edge only when domain is explicitly present in the dump line
    // (DOMAIN\user format). Never from context.domain — that would falsely qualify local SAM accounts.
    const effectiveDomainNodeId = explicitDomain ? domainId(explicitDomain) : undefined;
    if (effectiveDomainNodeId) {
      if (!seenNodes.has(effectiveDomainNodeId)) {
        nodes.push({ id: effectiveDomainNodeId, type: 'domain', label: explicitDomain!, domain_name: explicitDomain });
        seenNodes.add(effectiveDomainNodeId);
      }
      edges.push({
        source: resolvedUserId,
        target: effectiveDomainNodeId,
        properties: { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
    }

    // DUMPED_FROM edge when source host is known
    if (sourceHostId) {
      edges.push({
        source: resolvedCredId,
        target: sourceHostId,
        properties: { type: 'DUMPED_FROM', confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
