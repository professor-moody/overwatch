// ============================================================
// Overwatch — Impacket Suite Parser
// Parsers for GetNPUsers, GetUserSPNs, getTGT, getST,
// smbclient, wmiexec, and psexec output.
// ============================================================

import type { Finding, EdgeType, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { credentialId, domainId, hostId, resolveDomainName, userId } from '../parser-utils.js';

// --- GetNPUsers (AS-REP Roasting) ---
// Output lines like: $krb5asrep$23$user@DOMAIN:hash...
// The etype digit (23 / 17 / 18) is captured so we don't silently rewrite
// non-23 hashes as 23 when reconstructing cred_value for handoff.
const ASREP_HASH = /^\$krb5asrep\$(\d+)\$([^@]+)@([^:]+):(.+)$/i;

export function parseGetNPUsers(output: string, agentId: string = 'getnpusers-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  for (const line of output.split('\n')) {
    const m = line.trim().match(ASREP_HASH);
    if (!m) continue;

    const [, etype, username, rawDomain, hashValue] = m;
    const domain = resolveDomainName(rawDomain, context?.domain_aliases);

    const resolvedUserId = userId(username, domain);
    if (!seenNodes.has(resolvedUserId)) {
      nodes.push({
        id: resolvedUserId,
        type: 'user',
        label: domain ? `${domain}\\${username}` : username,
        username,
        domain_name: domain,
        asrep_roastable: true,
      });
      seenNodes.add(resolvedUserId);
    }

    // AS-REP roast hash. F6: this is NOT a TGS — it's an offline-crackable
    // AS-REP material with different cracking semantics. Tag it distinctly so
    // reporting, expiry, and downstream handoff don't conflate it with
    // captured TGS tickets.
    const credNodeId = credentialId('kerberos_asrep', hashValue.substring(0, 32), username, domain);
    if (!seenNodes.has(credNodeId)) {
      // 1.1: persist the full AS-REP hash on the credential node so it can
      // be exported to a hashcat input (mode 18200/19600/19700) without
      // re-running the tool. Etype is preserved from the source — non-23
      // hashes (17, 18) used to be silently rewritten as 23, breaking
      // crack handoff and reporting fidelity.
      const fullHash = `$krb5asrep$${etype}$${username}@${rawDomain}:${hashValue}`;
      nodes.push({
        id: credNodeId,
        type: 'credential',
        label: `AS-REP:${username}`,
        cred_type: 'kerberos_asrep',
        cred_material_kind: 'kerberos_asrep',
        cred_value: fullHash,
        cred_hash: fullHash,
        cred_usable_for_auth: false,
        cred_evidence_kind: 'capture',
        cred_user: username,
        cred_domain: domain,
      });
      seenNodes.add(credNodeId);
    }

    edges.push({
      source: resolvedUserId,
      target: credNodeId,
      properties: { type: 'OWNS_CRED' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId },
    });

    // Domain node + roasting edge
    if (domain) {
      const domId = domainId(domain);
      if (!seenNodes.has(domId)) {
        nodes.push({ id: domId, type: 'domain', label: domain, domain_name: domain });
        seenNodes.add(domId);
      }
      edges.push({
        source: resolvedUserId,
        target: domId,
        properties: { type: 'AS_REP_ROASTABLE' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- GetUserSPNs (Kerberoasting) ---
// Output: $krb5tgs$23$*user$DOMAIN$spn*$hash...
// Etype (23 / 17 / 18) captured so we don't silently rewrite non-23
// material when reconstructing cred_value for handoff.
const KERBEROAST_HASH = /^\$krb5tgs\$(\d+)\$\*([^$]+)\$([^$]+)\$([^*]+)\*\$(.+)$/i;
// Also handles tabular output: user  SPN  ...
const SPN_TABLE = /^(\S+)\s+(\S+\/\S+)\s/;

export function parseGetUserSPNs(output: string, agentId: string = 'getuserspns-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  for (const line of output.split('\n')) {
    // Hash line
    const hashMatch = line.trim().match(KERBEROAST_HASH);
    if (hashMatch) {
      const [, etype, username, rawDomain, _spn, hashValue] = hashMatch;
      const domain = resolveDomainName(rawDomain, context?.domain_aliases);

      const resolvedUserId = userId(username, domain);
      if (!seenNodes.has(resolvedUserId)) {
        nodes.push({
          id: resolvedUserId,
          type: 'user',
          label: domain ? `${domain}\\${username}` : username,
          username,
          domain_name: domain,
          has_spn: true,
        });
        seenNodes.add(resolvedUserId);
      }

      const credNodeId = credentialId('kerberos_tgs', hashValue.substring(0, 32), username, domain);
      if (!seenNodes.has(credNodeId)) {
        // 1.1: persist the full Kerberoast hash so it can be cracked
        // (hashcat mode 13100/19600/19700) without re-running GetUserSPNs.
        // Etype preserved from the source.
        const fullHash = `$krb5tgs$${etype}$*${username}$${rawDomain}$${_spn}*$${hashValue}`;
        nodes.push({
          id: credNodeId,
          type: 'credential',
          label: `TGS:${username}`,
          cred_type: 'kerberos_tgs',
          cred_material_kind: 'kerberos_tgs',
          cred_value: fullHash,
          cred_hash: fullHash,
          cred_usable_for_auth: false,
          cred_evidence_kind: 'capture',
          cred_user: username,
          cred_domain: domain,
        });
        seenNodes.add(credNodeId);
      }

      edges.push({
        source: resolvedUserId,
        target: credNodeId,
        properties: { type: 'OWNS_CRED' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });

      if (domain) {
        const domId = domainId(domain);
        if (!seenNodes.has(domId)) {
          nodes.push({ id: domId, type: 'domain', label: domain, domain_name: domain });
          seenNodes.add(domId);
        }
        edges.push({
          source: resolvedUserId,
          target: domId,
          properties: { type: 'KERBEROASTABLE' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId },
        });
      }
      continue;
    }

    // Table row: user SPN
    const tableMatch = line.trim().match(SPN_TABLE);
    if (tableMatch && !line.includes('ServicePrincipalName')) {
      const [, username] = tableMatch;
      const domain = context?.domain;
      const resolvedUserId = userId(username, domain);
      if (!seenNodes.has(resolvedUserId)) {
        nodes.push({
          id: resolvedUserId,
          type: 'user',
          label: domain ? `${domain}\\${username}` : username,
          username,
          domain_name: domain,
          has_spn: true,
        });
        seenNodes.add(resolvedUserId);
      }
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- getTGT ---
// Success: [*] Saving ticket in user.ccache
// Failure: [-] Kerberos SessionError: ...
const TGT_SUCCESS = /Saving ticket in (\S+)/i;
export function parseGetTGT(output: string, agentId: string = 'gettgt-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  const success = TGT_SUCCESS.test(output);
  if (!success) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  // Extract user from ccache filename or context
  const ccacheMatch = output.match(/Saving ticket in (\S+)/i);
  const ccacheName = ccacheMatch ? ccacheMatch[1] : '';
  // Filename format: user.ccache or domain/user.ccache. The previous
  // pattern `([^.]+)\.ccache$` only captured the substring after the LAST
  // dot, so dotted usernames like `john.smith.ccache` resolved as `smith`
  // and the TGT was attributed to the wrong principal. `(.+?)\.ccache$`
  // (non-greedy) keeps the full username, including dots.
  const nameMatch = ccacheName.match(/(?:([^/]+)\/)?(.+?)\.ccache$/);
  // F10: do NOT fall back to context.domain.split('.')[0] — that fabricates
  // a fake user (e.g. "corp" for domain corp.local) and links a TGT to it.
  // If the ccache filename does not encode a username, leave it undefined
  // and skip the OWNS_CRED edge below.
  const username = nameMatch?.[2] || (typeof context?.username === 'string' ? context.username : undefined);
  const domain = nameMatch?.[1] ? resolveDomainName(nameMatch[1], context?.domain_aliases) : context?.domain;

  // TGT credential with ~10h lifetime
  const tgtExpiry = new Date(Date.now() + 10 * 60 * 60 * 1000).toISOString();
  const credNodeId = credentialId('kerberos_tgt', ccacheName || 'tgt', username || 'unknown', domain);

  if (!seenNodes.has(credNodeId)) {
    // 1.3: store the ccache filename as the credential's `cred_value`. With
    // the path on the node, downstream tooling (and operators) can re-use
    // the TGT directly via `KRB5CCNAME=<path>` without re-running getTGT.
    // Previously the node was marked usable_for_auth:true but carried no
    // material — a misleading combination.
    nodes.push({
      id: credNodeId,
      type: 'credential',
      label: username ? `TGT:${username}` : 'TGT:unknown-principal',
      cred_type: 'kerberos_tgt',
      cred_material_kind: 'kerberos_tgt',
      cred_value: ccacheName || undefined,
      cred_usable_for_auth: !!ccacheName,
      cred_evidence_kind: 'capture',
      cred_user: username,
      cred_domain: domain,
      valid_until: tgtExpiry,
    });
    seenNodes.add(credNodeId);
  }

  // F10: only emit a user node + OWNS_CRED edge when we actually know the
  // principal. Otherwise we'd fabricate (e.g.) corp.local\corp from the
  // domain prefix and falsely link a TGT to it.
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
      target: credNodeId,
      properties: { type: 'OWNS_CRED' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId },
    });
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- getST ---
// Success: [*] Saving ticket in user.ccache
const ST_SUCCESS = /Saving ticket in (\S+)/i;

/**
 * F11: Extract S4U2Self/S4U2Proxy / RBCD / cross-realm context from a raw
 * Impacket getST command line. Recognized flags (case-insensitive):
 *   -spn <SPN>
 *   -impersonate <user>
 *   -altservice <SPN>
 *   -u2u
 * Trailing positional argument has the form `[domain/]user[:password]@target`.
 */
function parseGetSTCommandLine(cmd: string): {
  target_spn?: string;
  alt_service?: string;
  impersonated_user?: string;
  caller_user?: string;
  caller_domain?: string;
  target_host?: string;
  u2u?: boolean;
} {
  const out: ReturnType<typeof parseGetSTCommandLine> = {};
  if (!cmd || typeof cmd !== 'string') return out;
  // Tokenize on whitespace; respect simple quoting.
  const tokens: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(cmd)) !== null) {
    tokens.push(m[1] ?? m[2] ?? m[3] ?? '');
  }
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i].toLowerCase();
    const next = tokens[i + 1];
    if (!next) continue;
    if (t === '-spn') { out.target_spn = next; i++; continue; }
    if (t === '-altservice') { out.alt_service = next; i++; continue; }
    if (t === '-impersonate') { out.impersonated_user = next; i++; continue; }
    if (t === '-u2u') { out.u2u = true; continue; }
  }
  // Last positional that looks like [domain/]user[:pw]@target
  for (let i = tokens.length - 1; i >= 0; i--) {
    const tok = tokens[i];
    if (tok.startsWith('-')) continue;
    const at = tok.indexOf('@');
    if (at <= 0) continue;
    const principal = tok.substring(0, at);
    const target = tok.substring(at + 1);
    if (!target) continue;
    let user = principal;
    let dom: string | undefined;
    const slash = principal.indexOf('/');
    if (slash > 0) {
      dom = principal.substring(0, slash);
      user = principal.substring(slash + 1);
    }
    const colon = user.indexOf(':');
    if (colon > 0) user = user.substring(0, colon);
    if (user) out.caller_user = user;
    if (dom) out.caller_domain = dom;
    out.target_host = target;
    break;
  }
  return out;
}

export function parseGetST(output: string, agentId: string = 'getst-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  const success = ST_SUCCESS.test(output);
  if (!success) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  const ccacheMatch = output.match(/Saving ticket in (\S+)/i);
  const ccacheName = ccacheMatch ? ccacheMatch[1] : 'st';

  // F11: lift context from the raw command line if available so getST output
  // doesn't fabricate `service-ticket` as a synthetic principal and does
  // populate target SPN / impersonated user / caller bindings.
  const cmdLine = typeof context?.command_line === 'string' ? context.command_line : '';
  const cli = parseGetSTCommandLine(cmdLine);
  const domain = resolveDomainName(cli.caller_domain || (typeof context?.domain === 'string' ? context.domain : '') || '', context?.domain_aliases) || cli.caller_domain || context?.domain;
  const callerUser = cli.caller_user || (typeof context?.username === 'string' ? context.username : undefined);
  const impersonated = cli.impersonated_user;
  const targetSpn = cli.alt_service || cli.target_spn;

  // Cred holder: in S4U flows the resulting ST is for the impersonated user.
  // Otherwise the caller owns the ST.
  const ticketUser = impersonated || callerUser;

  const credNodeId = credentialId('kerberos_tgs', ccacheName, ticketUser || 'service-ticket', domain);
  if (!seenNodes.has(credNodeId)) {
    // 1.3: store ccache filename on the ST node so it's reusable. Mirror of
    // the parseGetTGT change above.
    const haveTicketPath = !!ccacheName && ccacheName !== 'st';
    nodes.push({
      id: credNodeId,
      type: 'credential',
      label: ticketUser ? `ST:${ticketUser}` : `ST:${ccacheName}`,
      cred_type: 'kerberos_tgs',
      cred_material_kind: 'kerberos_tgs',
      cred_value: haveTicketPath ? ccacheName : undefined,
      cred_usable_for_auth: haveTicketPath,
      cred_evidence_kind: 'capture',
      cred_user: ticketUser,
      cred_domain: domain,
      target_spn: targetSpn,
      impersonated_user: impersonated,
      valid_until: new Date(Date.now() + 10 * 60 * 60 * 1000).toISOString(),
    });
    seenNodes.add(credNodeId);
  }

  // Owner edge: caller owns the credential; in S4U flows we still link the
  // caller as the operator who minted the ticket.
  if (callerUser) {
    const callerId = userId(callerUser, domain);
    if (!seenNodes.has(callerId)) {
      nodes.push({
        id: callerId,
        type: 'user',
        label: domain ? `${domain}\\${callerUser}` : callerUser,
        username: callerUser,
        domain_name: domain,
      });
      seenNodes.add(callerId);
    }
    edges.push({
      source: callerId,
      target: credNodeId,
      properties: { type: 'OWNS_CRED' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId },
    });
  }

  // Impersonated principal: surface the impersonated user as a node so the
  // graph records the S4U target. We don't add a dedicated impersonation
  // edge type here — `impersonated_user` on the credential node carries the
  // semantics; downstream inference can consume it without a schema change.
  if (impersonated) {
    const impId = userId(impersonated, domain);
    if (!seenNodes.has(impId)) {
      nodes.push({
        id: impId,
        type: 'user',
        label: domain ? `${domain}\\${impersonated}` : impersonated,
        username: impersonated,
        domain_name: domain,
      });
      seenNodes.add(impId);
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- smbclient ---
// Share listing: SHARENAME  Disk  Comment
const SMBCLIENT_SHARE = /^\s+(\S+)\s+(Disk|IPC|Printer)\s+(.*)/;

export function parseSmbclient(output: string, agentId: string = 'smbclient-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const seenEdges = new Set<string>();
  const now = new Date().toISOString();

  const targetHost = context?.source_host;
  let resolvedHostId: string | undefined;

  if (targetHost) {
    resolvedHostId = hostId(targetHost);
    if (!seenNodes.has(resolvedHostId)) {
      const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(targetHost);
      nodes.push({
        id: resolvedHostId,
        type: 'host',
        label: targetHost,
        ...(isIp ? { ip: targetHost } : { hostname: targetHost }),
      });
      seenNodes.add(resolvedHostId);
    }
  }

  function addEdgeOnce(source: string, target: string, type: EdgeType, confidence: number): void {
    const key = `${source}--${type}--${target}`;
    if (seenEdges.has(key)) return;
    edges.push({ source, target, properties: { type, confidence, discovered_at: now, discovered_by: agentId } });
    seenEdges.add(key);
  }

  for (const line of output.split('\n')) {
    const shareMatch = line.match(SMBCLIENT_SHARE);
    if (!shareMatch) continue;

    const [, shareName, shareType] = shareMatch;
    if (shareType === 'IPC' || shareName === 'IPC$') continue;

    const shareId = resolvedHostId
      ? `share-${resolvedHostId.replace(/^host-/, '')}-${shareName.toLowerCase()}`
      : `share-unknown-${shareName.toLowerCase()}`;

    if (!seenNodes.has(shareId)) {
      nodes.push({
        id: shareId,
        type: 'share',
        label: targetHost ? `\\\\${targetHost}\\${shareName}` : shareName,
        share_name: shareName,
      });
      seenNodes.add(shareId);
    }

    if (resolvedHostId) {
      addEdgeOnce(resolvedHostId, shareId, 'RELATED', 1.0);
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- wmiexec / psexec ---
// HAS_SESSION can only be claimed once the command has actually executed
// on the remote host. Pre-exec markers like `Opening SVCManager` are NOT
// proof of code execution — psexec can open SVCManager and still fail the
// service-creation step with STATUS_ACCESS_DENIED. We require:
//   1. A strong post-exec marker (process creation confirmed, interactive
//      shell launched, or a Windows shell prompt echoed back), AND
//   2. No known failure marker anywhere in the output (auth/permission
//      errors, Kerberos/SMB session errors, "Permission denied").
const EXEC_SUCCESS_STRONG = [
  /Launching semi-interactive shell/i,         // psexec interactive mode came up
  /Process .* (?:created|finished|started)/i,   // psexec/wmiexec process confirmation
  /Service .* successfully installed/i,         // psexec service-install path
  /C:\\Windows\\(?:system32|System32)>/i,       // shell prompt echoed back
  /Microsoft Windows \[Version/i,               // Windows shell banner
  /SMB Service.*Started/i,                      // wmiexec relay-style indicator
];
const EXEC_FAILURE = [
  /STATUS_ACCESS_DENIED/i,
  /STATUS_LOGON_FAILURE/i,
  /STATUS_LOGIN_FAILURE/i,
  /STATUS_NOT_SUPPORTED/i,
  /STATUS_OBJECT_NAME_NOT_FOUND/i,
  /STATUS_BAD_NETWORK_NAME/i,
  /STATUS_NO_LOGON_SERVERS/i,
  /STATUS_PASSWORD_EXPIRED/i,
  /Authentication failed/i,
  /Login failed/i,
  /Permission denied/i,
  /SMB SessionError/i,
  /Kerberos SessionError/i,
];
function looksLikeExecSuccess(output: string): boolean {
  if (EXEC_FAILURE.some(re => re.test(output))) return false;
  return EXEC_SUCCESS_STRONG.some(re => re.test(output));
}
const EXEC_TARGET = /Target\s*:\s*(\S+)|^Impacket.*@(\S+)/i;

export function parseWmiexec(output: string, agentId: string = 'wmiexec-parser', context?: ParseContext): Finding {
  return parseExecOutput(output, agentId, context, 'wmiexec');
}

export function parsePsexec(output: string, agentId: string = 'psexec-parser', context?: ParseContext): Finding {
  return parseExecOutput(output, agentId, context, 'psexec');
}

function parseExecOutput(output: string, agentId: string, context: ParseContext | undefined, tool: string): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  // Try to extract target
  let targetHost = context?.source_host;
  if (!targetHost) {
    const targetMatch = output.match(EXEC_TARGET);
    if (targetMatch) {
      targetHost = targetMatch[1] || targetMatch[2];
    }
  }

  if (!targetHost || !looksLikeExecSuccess(output)) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  const resolvedHostId = hostId(targetHost);
  if (!seenNodes.has(resolvedHostId)) {
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(targetHost);
    nodes.push({
      id: resolvedHostId,
      type: 'host',
      label: targetHost,
      ...(isIp ? { ip: targetHost } : { hostname: targetHost }),
    });
    seenNodes.add(resolvedHostId);
  }

  // If context provides domain/user, create HAS_SESSION edge
  if (context?.domain) {
    // Try to extract user from Impacket header: domain/user@target
    const headerMatch = output.match(/(?:Impacket|impacket).*?([^/\s]+)\/([^@\s]+)@/);
    if (headerMatch) {
      const [, rawDomain, username] = headerMatch;
      const domain = resolveDomainName(rawDomain, context?.domain_aliases);
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
        target: resolvedHostId,
        properties: {
          type: 'HAS_SESSION' as EdgeType,
          confidence: 1.0,
          discovered_at: now,
          discovered_by: agentId,
          notes: `${tool} execution confirmed`,
        },
      });
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
