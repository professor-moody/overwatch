import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { credentialId, userId } from '../parser-utils.js';

// --- Hashcat Parser (--show / potfile) ---

function looksLikeHashcatOutput(output: string): boolean {
  const lines = output.split('\n');
  const preamble = lines.slice(0, 30);
  // Hashcat --show, potfile, or session output markers
  const markers = [
    /^Session\.*:/i, /^Status\.*:/i, /^Hash\.Mode\.*:/i, /^Hash\.Target/i,
    /^\$krb5tgs\$/, /^\$krb5asrep\$/, /^\$HEX\[/,
    /^[a-f0-9]{32}:.+$/i,
  ];
  // Short input (potfile snippet) is always accepted
  if (lines.filter(l => l.trim()).length <= 20) return true;
  return preamble.some(line => markers.some(m => m.test(line.trim())));
}

export function parseHashcat(output: string, agentId: string = 'hashcat-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();
  const contextDomain = context?.domain;

  if (!looksLikeHashcatOutput(output)) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  for (const rawLine of output.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    let username: string | undefined;
    let domain: string | undefined;
    let plaintext: string | undefined;
    let hashValue: string | undefined;

    // Kerberoast: $krb5tgs$23$*user$REALM$spn*$...:plaintext
    const krbMatch = line.match(/^(\$krb5tgs\$\d+\$\*([^$*]+)\$([^$*]+)\$[^:]+):(.+)$/);
    if (krbMatch) {
      hashValue = krbMatch[1];
      username = krbMatch[2];
      domain = krbMatch[3];
      plaintext = krbMatch[4];
    }

    // AS-REP: $krb5asrep$23$user@REALM:...:plaintext
    if (!plaintext) {
      const asrepMatch = line.match(/^(\$krb5asrep\$\d+\$([^@:]+)@([^:]+)[^:]*):(.+)$/);
      if (asrepMatch) {
        hashValue = asrepMatch[1];
        username = asrepMatch[2];
        domain = asrepMatch[3];
        plaintext = asrepMatch[4];
      }
    }

    // NTLMv2: user::DOMAIN:challenge:response:blob:plaintext
    if (!plaintext) {
      const v2Match = line.match(/^([^:]+)::([^:]+):([^:]+):([^:]+):([^:]+):(.+)$/);
      if (v2Match) {
        username = v2Match[1];
        domain = v2Match[2];
        hashValue = `${v2Match[1]}::${v2Match[2]}:${v2Match[3]}:${v2Match[4]}:${v2Match[5]}`;
        plaintext = v2Match[6];
      }
    }

    // Plain NTLM (32 hex chars): hash:plaintext
    if (!plaintext) {
      const ntlmMatch = line.match(/^([a-f0-9]{32}):(.+)$/i);
      if (ntlmMatch) {
        hashValue = ntlmMatch[1];
        plaintext = ntlmMatch[2];
      }
    }

    if (!plaintext || plaintext.trim().length === 0) continue;

    // Fall back to context domain when hash format doesn't include domain
    const hadExplicitDomain = !!domain;
    if (!domain && contextDomain) {
      domain = contextDomain;
    }

    const resolvedCredId = credentialId(
      'plaintext_password',
      hashValue || plaintext,
      username,
      domain,
    );
    if (seenNodes.has(resolvedCredId)) continue;

    nodes.push({
      id: resolvedCredId,
      type: 'credential',
      label: username ? `${username}:${plaintext}` : `cracked:${plaintext}`,
      cred_type: 'plaintext',
      cred_material_kind: 'plaintext_password',
      cred_usable_for_auth: true,
      cred_evidence_kind: 'crack',
      cred_value: plaintext,
      cred_user: username,
      cred_domain: domain,
      cred_domain_source: !hadExplicitDomain && contextDomain ? 'parser_context' : domain ? 'explicit' : undefined,
      cred_hash: hashValue,
    });
    seenNodes.add(resolvedCredId);

    if (username) {
      const resolvedUserId = userId(username, domain);

      if (!seenNodes.has(resolvedUserId)) {
        nodes.push({
          id: resolvedUserId,
          type: 'user',
          label: domain ? `${domain}\\${username}` : username,
          username,
          domain_name: domain,
        });
        seenNodes.add(resolvedUserId);
      }

      edges.push({
        source: resolvedUserId,
        target: resolvedCredId,
        properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
