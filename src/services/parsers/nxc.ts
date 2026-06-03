import type { Finding, EdgeType, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { credentialId, domainId, hostId, resolveDomainName, serviceId, userId } from '../parser-utils.js';

// --- NetExec (NXC) Parser ---

export function parseNxc(output: string, agentId: string = 'nxc-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const lines = output.split('\n');
  const seenNodes = new Set<string>();
  const seenEdges = new Set<string>();
  const now = new Date().toISOString();

  // Per-IP context accumulated from [*] info lines
  const hostMeta = new Map<string, { hostname?: string; domain?: string; os?: string; signing?: boolean; smbv1?: boolean; nullAuth?: boolean }>();
  // Track whether we're inside a user enumeration table for a given IP
  let userTableIp: string | undefined;

  function addEdgeOnce(source: string, target: string, type: EdgeType, confidence: number, extra?: Record<string, unknown>): void {
    const edgeKey = `${source}--${type}--${target}`;
    if (seenEdges.has(edgeKey)) return;
    edges.push({
      source,
      target,
      properties: { type, confidence, discovered_at: now, discovered_by: agentId, ...(extra ?? {}) },
    });
    seenEdges.add(edgeKey);
  }

  function ensureSmbContext(ip: string): { hostNodeId: string; serviceNodeId: string } {
    const resolvedHostId = hostId(ip);
    const serviceNodeId = serviceId(ip, 445);

    if (!seenNodes.has(resolvedHostId)) {
      const meta = hostMeta.get(ip);
      nodes.push({
        id: resolvedHostId,
        type: 'host',
        label: meta?.hostname || ip,
        ip,
        alive: true,
        hostname: meta?.hostname,
        domain_name: meta?.domain,
        os: meta?.os,
        null_session: meta?.nullAuth || undefined,
      });
      seenNodes.add(resolvedHostId);
    }

    if (!seenNodes.has(serviceNodeId)) {
      const meta = hostMeta.get(ip);
      nodes.push({
        id: serviceNodeId,
        type: 'service',
        label: 'smb/445',
        port: 445,
        protocol: 'tcp',
        service_name: 'smb',
        smb_signing: meta?.signing,
        smbv1: meta?.smbv1,
      });
      seenNodes.add(serviceNodeId);
    }

    addEdgeOnce(resolvedHostId, serviceNodeId, 'RUNS', 1.0);
    return { hostNodeId: resolvedHostId, serviceNodeId };
  }

  function ensureDomainContext(domain: string): string {
    const resolvedDomainId = domainId(domain);
    if (!seenNodes.has(resolvedDomainId)) {
      nodes.push({ id: resolvedDomainId, type: 'domain', label: domain, domain_name: domain });
      seenNodes.add(resolvedDomainId);
    }
    return resolvedDomainId;
  }

  function addUserNode(username: string, domain: string | undefined, description?: string): string {
    const resolvedUserId = userId(username, domain);
    if (!seenNodes.has(resolvedUserId)) {
      nodes.push({
        id: resolvedUserId,
        type: 'user',
        label: domain ? `${domain}\\${username}` : username,
        username,
        domain_name: domain,
        description: description || undefined,
      });
      seenNodes.add(resolvedUserId);
    }
    if (domain) {
      const resolvedDomainId = ensureDomainContext(domain);
      addEdgeOnce(resolvedUserId, resolvedDomainId, 'MEMBER_OF_DOMAIN', 1.0);
    }
    return resolvedUserId;
  }

  function parseDomainUserSecret(message: string): { rawDomain: string; username: string; secret?: string } | null {
    const match = message.match(/([^\\\s]+)\\([^:\s)]+)/);
    if (!match) return null;
    const afterUser = message.slice((match.index ?? 0) + match[0].length);
    let secret: string | undefined;
    if (afterUser.startsWith(':')) {
      secret = afterUser
        .slice(1)
        .replace(/\s+\([^)]*\)\s*$/, '')
        .trim();
    }
    return {
      rawDomain: match[1],
      username: match[2],
      secret: secret && secret.length > 0 ? secret : undefined,
    };
  }

  // Broad prefix regex for all SMB lines: SMB  IP/IPv6/hostname  PORT  HOSTNAME  <rest>
  const smbLineRe = /^SMB\s+((?:\d+\.){3}\d+|\[?[a-fA-F0-9:]+\]?|[\w.-]+)\s+(\d+)\s+(\S+)\s+(.*)/i;
  // S4-A1: multi-protocol dispatch. Same line shape as SMB; handles the
  // auth-success / auth-failure / lockout paths only — the SMB-specific
  // module behaviors (shares, spider, SAM/LSA dumps, NTDS, signing) are
  // not portable to non-SMB protocols and stay in the SMB block.
  const multiProtoLineRe = /^(WINRM|LDAP|RDP|SSH|FTP|VNC|MSSQL)\s+((?:\d+\.){3}\d+|\[?[a-fA-F0-9:]+\]?|[\w.-]+)\s+(\d+)\s+(\S+)\s+(.*)/i;

  function ensureServiceContext(ip: string, port: number, protocol: string): { hostNodeId: string; serviceNodeId: string } {
    const resolvedHostId = hostId(ip);
    const serviceNodeId = serviceId(ip, port);
    if (!seenNodes.has(resolvedHostId)) {
      const meta = hostMeta.get(ip);
      nodes.push({
        id: resolvedHostId,
        type: 'host',
        label: meta?.hostname || ip,
        ip,
        alive: true,
        hostname: meta?.hostname,
        domain_name: meta?.domain,
        os: meta?.os,
      });
      seenNodes.add(resolvedHostId);
    }
    if (!seenNodes.has(serviceNodeId)) {
      nodes.push({
        id: serviceNodeId,
        type: 'service',
        label: `${protocol}/${port}`,
        port,
        protocol: 'tcp',
        service_name: protocol,
      });
      seenNodes.add(serviceNodeId);
    }
    addEdgeOnce(resolvedHostId, serviceNodeId, 'RUNS', 1.0);
    return { hostNodeId: resolvedHostId, serviceNodeId };
  }

  /**
   * SSH and FTP often emit `user@host:pass` or `user:pass` without a
   * domain prefix. parseDomainUserSecret requires a backslash. This
   * helper accepts either shape and returns a normalized result.
   */
  function parseProtoUserSecret(message: string, protocol: string): { rawDomain: string | undefined; username: string; secret?: string } | null {
    const withDomain = parseDomainUserSecret(message);
    if (withDomain) return withDomain;
    if (protocol === 'ssh' || protocol === 'ftp' || protocol === 'vnc' || protocol === 'mssql') {
      // user@host:secret OR user:secret
      const atForm = message.match(/^\s*([^@\s:()]+)@[^\s:]+:([^\s)]+)/);
      if (atForm) return { rawDomain: undefined, username: atForm[1], secret: atForm[2] };
      const plain = message.match(/^\s*([^@\s:()\\]+):([^\s)]+)/);
      if (plain) return { rawDomain: undefined, username: plain[1], secret: plain[2] };
    }
    return null;
  }

  for (const line of lines) {
    // --- S4-A1: non-SMB protocol dispatch ---
    const protoLine = line.match(multiProtoLineRe);
    if (protoLine) {
      const [, rawProto, ip, portStr, _hostname, rest] = protoLine;
      const protocol = rawProto.toLowerCase();
      const port = parseInt(portStr, 10);
      // MSSQL has its own bespoke linked-server branch later in the file;
      // skip it here so we don't double-handle.
      if (protocol === 'mssql') {
        // Let the MSSQL-specific block below own this line.
      } else {
        const { hostNodeId } = ensureServiceContext(ip, port, protocol);

        // [*] info line — capture hostname/domain when present, same as SMB.
        const protoInfo = rest.match(/^\[\*\]\s*(.*)/);
        if (protoInfo) {
          const infoMsg = protoInfo[1];
          if (!hostMeta.has(ip)) hostMeta.set(ip, {});
          const meta = hostMeta.get(ip)!;
          const nameMatch = infoMsg.match(/\(name:([^)]+)\)/i);
          if (nameMatch) meta.hostname = nameMatch[1].trim();
          const domainMatch = infoMsg.match(/\(domain:([^)]+)\)/i);
          if (domainMatch) meta.domain = resolveDomainName(domainMatch[1].trim(), context?.domain_aliases);
          // Refresh node display from new metadata.
          const hostNode = nodes.find(n => n.id === hostNodeId);
          if (hostNode) {
            if (meta.hostname) { (hostNode as Record<string, unknown>).hostname = meta.hostname; hostNode.label = meta.hostname; }
            if (meta.domain) (hostNode as Record<string, unknown>).domain_name = meta.domain;
          }
          continue;
        }

        // [+] / [-] auth outcome lines.
        const status = rest.match(/^\[([+-])\]\s*(.*)/);
        if (status) {
          const [, sign, message] = status;
          if (sign === '+') {
            const parsed = parseProtoUserSecret(message, protocol);
            if (parsed) {
              const credDomain = parsed.rawDomain
                ? resolveDomainName(parsed.rawDomain, context?.domain_aliases)
                : hostMeta.get(ip)?.domain;
              const username = parsed.username;
              const secret = parsed.secret;
              const resolvedUserId = addUserNode(username, credDomain);

              addEdgeOnce(resolvedUserId, hostNodeId, 'VALID_ON', secret ? 1.0 : 0.7, { tested_service: protocol });

              // (Pwn3d!) marker — present on WINRM and RDP per NetExec; absent on SSH/FTP/LDAP.
              if (message.includes('Pwn3d!')) {
                const userNode = nodes.find(n => n.id === resolvedUserId);
                if (userNode) (userNode as Record<string, unknown>).privileged = true;
                addEdgeOnce(resolvedUserId, hostNodeId, 'ADMIN_TO', 1.0);
              }

              if (secret) {
                const isNtlm = /^[a-fA-F0-9]{32}$/.test(secret);
                const credKind = isNtlm ? 'ntlm_hash' : 'plaintext_password';
                const credNodeId = credentialId(credKind, secret, username, credDomain);
                if (!seenNodes.has(credNodeId)) {
                  nodes.push({
                    id: credNodeId,
                    type: 'credential',
                    label: isNtlm ? `NTLM:${username}` : `pw:${username}`,
                    cred_type: isNtlm ? 'ntlm' : 'plaintext',
                    cred_material_kind: credKind,
                    cred_usable_for_auth: true,
                    cred_evidence_kind: 'spray_success',
                    cred_value: secret,
                    cred_user: username,
                    cred_domain: credDomain,
                  });
                  seenNodes.add(credNodeId);
                }
                addEdgeOnce(resolvedUserId, credNodeId, 'OWNS_CRED', 1.0);
                addEdgeOnce(credNodeId, hostNodeId, 'VALID_ON', 1.0, { tested_service: protocol });
              }
            }
          } else {
            // [-] failure path — extend Sprint 1 F0-3 status-code differentiation
            // to all protocols, not just SMB.
            const credMatch = message.match(/([^\\]+)\\([^\s:]+)/) || message.match(/^([^\s@:]+)[@: ]/);
            if (credMatch) {
              const rawCredDomain = credMatch.length === 3 ? credMatch[1] : undefined;
              const username = credMatch.length === 3 ? credMatch[2] : credMatch[1];
              const credDomain = rawCredDomain
                ? resolveDomainName(rawCredDomain, context?.domain_aliases)
                : hostMeta.get(ip)?.domain;
              if (username && username !== '') {
                const resolvedUserId = addUserNode(username, credDomain);
                addEdgeOnce(resolvedUserId, hostNodeId, 'TESTED_CRED', 0.0, { tested_service: protocol });
                const userNode = nodes.find(n => n.id === resolvedUserId);

                if (/STATUS_ACCOUNT_LOCKED_OUT/i.test(message)) {
                  const hostNode = nodes.find(n => n.id === hostNodeId);
                  if (hostNode) {
                    (hostNode as Record<string, unknown>).lockout_observed = true;
                    const victims = ((hostNode as Record<string, unknown>).lockout_victims as string[] | undefined) || [];
                    if (!victims.includes(username)) victims.push(username);
                    (hostNode as Record<string, unknown>).lockout_victims = victims;
                  }
                  if (userNode) (userNode as Record<string, unknown>).locked_out = true;
                } else if (/STATUS_PASSWORD_EXPIRED/i.test(message)) {
                  if (userNode) (userNode as Record<string, unknown>).password_expired = true;
                } else if (/STATUS_ACCOUNT_RESTRICTION/i.test(message) || /STATUS_LOGON_TYPE_NOT_GRANTED/i.test(message)) {
                  if (userNode) (userNode as Record<string, unknown>).account_restricted = true;
                }
              }
            }
          }
          continue;
        }

        // Unrecognized non-SMB line under a recognized protocol; skip rather
        // than fall through into the SMB-specific code path below.
        continue;
      }
    }

    const smbLine = line.match(smbLineRe);
    if (!smbLine) {
      userTableIp = undefined;
      continue;
    }

    const [, ip, port, _hostname, rest] = smbLine;
    if (port !== '445') continue;

    // --- [*] Info line: extract host metadata ---
    const infoMatch = rest.match(/^\[\*\]\s*(.*)/);
    if (infoMatch) {
      const infoMsg = infoMatch[1];

      // "Enumerated N local users: DOMAIN" — end of user table
      if (/Enumerated\s+\d+/i.test(infoMsg)) {
        userTableIp = undefined;
        continue;
      }

      // --- spider_plus file listing ---
      // NXC spider_plus outputs: [*] \\IP\SHARE\path\to\file (size)
      const spiderMsgMatch = infoMsg.match(/^\\\\[^\\]+\\([^\\]+)\\(.+?)(?:\s+\(\d+[^)]*\))?$/);
      if (spiderMsgMatch) {
        const [, shareName, filePath] = spiderMsgMatch;
        const { hostNodeId: resolvedHostId } = ensureSmbContext(ip);
        const shareId = `share-${ip.replace(/\./g, '-')}-${shareName.toLowerCase()}`;

        if (!seenNodes.has(shareId)) {
          nodes.push({
            id: shareId,
            type: 'share',
            label: `\\\\${ip}\\${shareName}`,
            share_name: shareName,
            readable: true,
          });
          seenNodes.add(shareId);
          addEdgeOnce(resolvedHostId, shareId, 'RELATED', 1.0);
        }

        const shareNode = nodes.find(n => n.id === shareId);
        if (shareNode) {
          const files = (shareNode.spider_files as string[]) || [];
          files.push(filePath);
          shareNode.spider_files = files;
        }
        continue;
      }

      // Host info: Windows ... (name:X) (domain:X) (signing:X) (SMBv1:X) (Null Auth:X)
      if (!hostMeta.has(ip)) {
        hostMeta.set(ip, {});
      }
      const meta = hostMeta.get(ip)!;

      const nameMatch = infoMsg.match(/\(name:([^)]+)\)/i);
      if (nameMatch) meta.hostname = nameMatch[1].trim();

      const domainMatch = infoMsg.match(/\(domain:([^)]+)\)/i);
      if (domainMatch) meta.domain = resolveDomainName(domainMatch[1].trim(), context?.domain_aliases);

      const signingMatch = infoMsg.match(/\(signing:(True|False)\)/i);
      if (signingMatch) meta.signing = signingMatch[1].toLowerCase() === 'true';

      const smbv1Match = infoMsg.match(/\(SMBv1:(True|False)\)/i);
      if (smbv1Match) meta.smbv1 = smbv1Match[1].toLowerCase() === 'true';

      const nullAuthMatch = infoMsg.match(/\(Null Auth:(True|False)\)/i);
      if (nullAuthMatch) meta.nullAuth = nullAuthMatch[1].toLowerCase() === 'true';

      // Extract OS from the info text before first parenthetical.
      // Matches Windows, Linux, FreeBSD, and other OS strings.
      const osMatch = infoMsg.match(/^((?:Windows|Linux|FreeBSD|Ubuntu|Debian|CentOS|Red Hat|Samba)\s[^(]+)/i);
      if (osMatch) meta.os = osMatch[1].trim();

      continue;
    }

    // --- [+] or [-] Status lines: auth results ---
    const statusMatch = rest.match(/^\[([+-])\]\s*(.*)/);
    if (statusMatch) {
      userTableIp = undefined;
      const [, status, message] = statusMatch;
      const { hostNodeId: resolvedHostId } = ensureSmbContext(ip);

      // Check for Pwn3d! (admin access)
      if (message.includes('Pwn3d!')) {
        const parsedCred = parseDomainUserSecret(message);
        if (parsedCred) {
          const credDomain = resolveDomainName(parsedCred.rawDomain, context?.domain_aliases);
          const username = parsedCred.username;
          const resolvedUserId = addUserNode(username, credDomain);
          // Upgrade to privileged
          const userNode = nodes.find(n => n.id === resolvedUserId);
          if (userNode) userNode.privileged = true;
          addEdgeOnce(resolvedUserId, resolvedHostId, 'ADMIN_TO', 1.0);
        }
      }

      // F0-2: NTDS dump detection.
      //
      // NXC `--ntds` produces a notification line of the form
      //   [+] Dumped 7 NTDS hashes to /tmp/nxc/ntds.dump
      //   [+] Dumped 7000 NTDS hashes from the domain
      // Full NTDS extraction implies domain-level compromise of the DC. We
      // stamp the host node so downstream surfaces (dashboard, inference
      // rules, report generator) can treat the host as a domain-compromise
      // source. The individual hash rows are emitted by the SAM branch
      // below; this block surfaces the headline event the operator must
      // not miss.
      const ntdsMatch = message.match(/Dumped\s+(\d+)\s+NTDS\s+hashes?(?:\s+to\s+(\S+))?/i);
      if (ntdsMatch) {
        const hashCount = parseInt(ntdsMatch[1], 10);
        const dumpPath = ntdsMatch[2];
        const hostNode = nodes.find(n => n.id === resolvedHostId);
        if (hostNode) {
          (hostNode as Record<string, unknown>).ntds_dumped = true;
          (hostNode as Record<string, unknown>).ntds_hash_count = hashCount;
          if (dumpPath) (hostNode as Record<string, unknown>).ntds_dump_path = dumpPath;
          // Mark the DC as a domain-compromise pivot — downstream inference
          // rules can chain this to PATH_TO_OBJECTIVE on the domain.
          (hostNode as Record<string, unknown>).dc_compromised = true;
        }
      }

      // Valid auth (+ status) with domain\user pattern.
      // 1.2: also capture the credential material when it's printed alongside.
      // NXC commonly emits `DOMAIN\user:password` or `DOMAIN\user:NTHASH` on
      // a successful login; previously we extracted only the user and dropped
      // the secret on the floor, leaving the operator unable to reuse the
      // credential without re-running the tool. We now create a credential
      // node and an OWNS_CRED edge whenever the secret is captured, and
      // emit a redacted (cred_usable_for_auth=false) placeholder node when
      // only the success banner is visible — preserving the access claim
      // without lying about reusability.
      if (status === '+') {
        // Capture optional secret after the user (`user:secret`). The secret
        // may contain shell-unfriendly chars and spaces; we stop only before
        // a trailing status parenthetical (e.g. " (Pwn3d!)").
        const parsedCred = parseDomainUserSecret(message);
        if (parsedCred) {
          const { username, secret } = parsedCred;
          const credDomain = resolveDomainName(parsedCred.rawDomain, context?.domain_aliases);
          if (username && username !== '') {
            addUserNode(username, credDomain);
            const resolvedUserId = userId(username, credDomain);
            addEdgeOnce(resolvedUserId, resolvedHostId, 'VALID_ON', 0.9, { tested_service: 'smb' });

            // Determine credential material. NTLM hashes are exactly 32 hex
            // chars; anything else captured here is treated as plaintext.
            const isNtlm = !!secret && /^[a-fA-F0-9]{32}$/.test(secret);
            const credKind: 'ntlm_hash' | 'plaintext_password' | undefined = secret
              ? (isNtlm ? 'ntlm_hash' : 'plaintext_password')
              : undefined;
            const credIdKey = secret ?? 'redacted';
            const credNodeId = credentialId(credKind ?? 'plaintext_password', credIdKey, username, credDomain);
            if (!seenNodes.has(credNodeId)) {
              nodes.push({
                id: credNodeId,
                type: 'credential',
                label: isNtlm ? `NTLM:${username}` : `pw:${username}`,
                cred_type: isNtlm ? 'ntlm' : 'plaintext',
                cred_material_kind: credKind,
                cred_usable_for_auth: !!secret,
                cred_evidence_kind: 'spray_success',
                cred_value: secret,
                cred_user: username,
                cred_domain: credDomain,
              });
              seenNodes.add(credNodeId);
            }
            addEdgeOnce(resolvedUserId, credNodeId, 'OWNS_CRED', secret ? 1.0 : 0.6);
            addEdgeOnce(credNodeId, resolvedHostId, 'VALID_ON', secret ? 1.0 : 0.7, { tested_service: 'smb' });
          }
        }
      }

      // Failed auth (- status) — record for spray coverage and lockout
      // tracking. F2: stamp `tested_service` on the edge so credential
      // coverage can attribute the test to the SMB service rather than
      // marking the entire host covered for SSH/RDP/WinRM/etc.
      //
      // F0-3: differentiate NT status codes — STATUS_ACCOUNT_LOCKED_OUT,
      // STATUS_PASSWORD_EXPIRED, STATUS_ACCOUNT_RESTRICTION must surface as
      // distinct operator signals so the LLM does not keep spraying into a
      // lockout or treat an expired-but-real account as unknown.
      if (status === '-') {
        const credMatch = message.match(/([^\\]+)\\([^\s:]+)/);
        if (credMatch) {
          const [, rawCredDomain, username] = credMatch;
          const credDomain = resolveDomainName(rawCredDomain, context?.domain_aliases);
          if (username && username !== '') {
            const resolvedUserId = addUserNode(username, credDomain);
            addEdgeOnce(resolvedUserId, resolvedHostId, 'TESTED_CRED', 0.0, { tested_service: 'smb' });
            const userNode = nodes.find(n => n.id === resolvedUserId);

            if (/STATUS_ACCOUNT_LOCKED_OUT/i.test(message)) {
              // Spray hit lockout — stamp the host so downstream rules can
              // halt further auth attempts against this target, and the user
              // so the operator knows which account triggered it.
              const hostNode = nodes.find(n => n.id === resolvedHostId);
              if (hostNode) {
                (hostNode as Record<string, unknown>).lockout_observed = true;
                const victims = ((hostNode as Record<string, unknown>).lockout_victims as string[] | undefined) || [];
                if (!victims.includes(username)) victims.push(username);
                (hostNode as Record<string, unknown>).lockout_victims = victims;
              }
              if (userNode) (userNode as Record<string, unknown>).locked_out = true;
            } else if (/STATUS_PASSWORD_EXPIRED/i.test(message)) {
              if (userNode) (userNode as Record<string, unknown>).password_expired = true;
            } else if (/STATUS_ACCOUNT_RESTRICTION/i.test(message) || /STATUS_LOGON_TYPE_NOT_GRANTED/i.test(message)) {
              if (userNode) (userNode as Record<string, unknown>).account_restricted = true;
            }
          }
        }
      }

      continue;
    }

    // --- SAM dump lines: hash format within NXC output ---
    // NXC --sam outputs: SMB  IP  445  HOST  username:rid:lmhash:nthash:::
    {
      const samMatch = rest.match(/^([^:*\s][^:]*):(\d+):([a-f0-9]{32}):([a-f0-9]{32}):::$/i);
      if (samMatch) {
        const [, rawUser, , , nthash] = samMatch;
        const username = rawUser.replace(/^.*\\/, '');
        if (!username.endsWith('$')) {
          const { hostNodeId: resolvedHostId } = ensureSmbContext(ip);
          const domain = hostMeta.get(ip)?.domain;
          const credNodeId = credentialId('ntlm_hash', nthash, username, domain);

          if (!seenNodes.has(credNodeId)) {
            nodes.push({
              id: credNodeId,
              type: 'credential',
              label: `NTLM:${username}`,
              cred_type: 'ntlm',
              cred_material_kind: 'ntlm_hash',
              cred_usable_for_auth: true,
              cred_evidence_kind: 'dump',
              cred_value: nthash,
              cred_user: username,
              cred_domain: domain,
              dump_source_host: ip,
            });
            seenNodes.add(credNodeId);
          }

          const resolvedUserId = addUserNode(username, domain);
          addEdgeOnce(resolvedUserId, credNodeId, 'OWNS_CRED', 1.0);
          edges.push({
            source: credNodeId,
            target: resolvedHostId,
            properties: { type: 'DUMPED_FROM', confidence: 1.0, discovered_at: now, discovered_by: agentId },
          });
        }
        continue;
      }
    }

    // --- LSA secrets lines ---
    // NXC --lsa outputs: SMB  IP  445  HOST  domain\account:plaintext_password
    // Also: DPAPI secrets, NL$KM, DefaultPassword
    {
      const lsaMatch = rest.match(/^([^:]+):(.*)/);
      if (lsaMatch && !rest.includes('-Username-') && !rest.startsWith('[') && userTableIp !== ip) {
        const [, rawAccount, secret] = lsaMatch;
        // Skip known non-credential lines
        if (secret && secret.length > 0 && !rawAccount.startsWith('NL$KM') && !rawAccount.startsWith('dpapi_')) {
          // DefaultPassword or cleartext password
          const isDefault = rawAccount.toLowerCase().includes('defaultpassword');
          const parts = rawAccount.split('\\');
          const username = parts.length > 1 ? parts[1] : parts[0];
          const domain = parts.length > 1 ? resolveDomainName(parts[0], context?.domain_aliases) : hostMeta.get(ip)?.domain;

          if (username && secret.trim().length > 0) {
            const { hostNodeId: resolvedHostId } = ensureSmbContext(ip);
            const credNodeId = credentialId('plaintext_password', secret.trim(), username, domain);

            if (!seenNodes.has(credNodeId)) {
              nodes.push({
                id: credNodeId,
                type: 'credential',
                label: `${username} LSA secret`,
                cred_type: 'plaintext',
                cred_material_kind: 'plaintext_password',
                cred_usable_for_auth: true,
                cred_evidence_kind: 'dump',
                cred_value: secret.trim(),
                cred_user: username,
                cred_domain: domain,
                cred_is_default_guess: isDefault || undefined,
                dump_source_host: ip,
              });
              seenNodes.add(credNodeId);
            }

            const resolvedUserId = addUserNode(username, domain);
            addEdgeOnce(resolvedUserId, credNodeId, 'OWNS_CRED', 1.0);
            edges.push({
              source: credNodeId,
              target: resolvedHostId,
              properties: { type: 'DUMPED_FROM', confidence: 1.0, discovered_at: now, discovered_by: agentId },
            });
            continue;
          }
        }
      }
    }

    // --- User enumeration table header ---
    if (rest.includes('-Username-') && rest.includes('-Description-')) {
      userTableIp = ip;
      ensureSmbContext(ip);
      continue;
    }

    // --- User enumeration table rows ---
    if (userTableIp === ip) {
      // Table row format: username  date  badpw  description
      // Fields are separated by variable whitespace. Username is first non-empty field.
      const trimmedRest = rest.trim();
      if (!trimmedRest || trimmedRest.startsWith('[')) {
        userTableIp = undefined;
        continue;
      }

      // Parse: username  YYYY-MM-DD HH:MM:SS  badpw  description
      // Or:   username  <never>  badpw  description
      const userRowMatch = trimmedRest.match(
        /^(\S+)\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}|<never>)\s+(\d+)\s+(.*)/
      );
      if (userRowMatch) {
        const [, username, , , description] = userRowMatch;
        if (username.toLowerCase() === 'guest') continue;

        const domain = hostMeta.get(ip)?.domain;
        const resolvedUserId = addUserNode(username, domain, description);

        // Check for password in description: (Password : value) or (Password: value)
        const pwMatch = description.match(/\(Password\s*:\s*(.+?)\)/i);
        if (pwMatch) {
          const password = pwMatch[1].trim();
          const credNodeId = credentialId('plaintext_password', password, username, domain);
          if (!seenNodes.has(credNodeId)) {
            nodes.push({
              id: credNodeId,
              type: 'credential',
              label: `${username} cleartext password`,
              cred_user: username,
              cred_domain: domain,
              cred_type: 'plaintext',
              cred_value: password,
              cred_evidence_kind: 'manual',
            });
            seenNodes.add(credNodeId);
          }
          addEdgeOnce(resolvedUserId, credNodeId, 'OWNS_CRED', 1.0);
        }
      }
      continue;
    }

    // --- Share enumeration: HOSTNAME  sharename  READ/WRITE ---
    // NOTE: alternation order matters here. The combined `READ,\s*WRITE`
    // (and reverse) variants must match BEFORE the bare tokens, otherwise
    // "READ, WRITE" gets captured as "READ" only and writable shares are
    // misclassified as read-only — hiding escalation/exfil paths.
    const shareMatch = rest.match(/^(\S+)\s+(READ,\s*WRITE|WRITE,\s*READ|WRITE|READ)/i);
    if (shareMatch) {
      const [, shareName, perms] = shareMatch;
      if (shareName.startsWith('[') || shareName === '-Username-') continue;
      const { hostNodeId: resolvedHostId } = ensureSmbContext(ip);
      const shareId = `share-${ip.replace(/\./g, '-')}-${shareName.toLowerCase()}`;

      // Tokenize on commas to be robust to future NXC format tweaks
      // (e.g. extra whitespace, additional perm flags).
      const tokens = perms.split(/,\s*/).map(t => t.trim().toUpperCase());
      if (!seenNodes.has(shareId)) {
        nodes.push({
          id: shareId,
          type: 'share',
          label: `\\\\${ip}\\${shareName}`,
          share_name: shareName,
          readable: tokens.includes('READ'),
          writable: tokens.includes('WRITE'),
        });
        seenNodes.add(shareId);
      }
      addEdgeOnce(resolvedHostId, shareId, 'RELATED', 1.0);
    }
  }

  // --- MSSQL linked server detection ---
  // NXC mssql module: MSSQL  IP  PORT  HOST  [*] Linked SQL Servers: SERVER1, SERVER2
  const mssqlLineRe = /^MSSQL\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+(.*)/i;
  const mssqlLinkedServers = new Map<string, string[]>(); // ip -> linked server names
  for (const line of lines) {
    const mssqlLine = line.match(mssqlLineRe);
    if (!mssqlLine) continue;
    const [, mssqlIp, mssqlPort, mssqlHostname, mssqlRest] = mssqlLine;

    // Ensure MSSQL host + service nodes exist
    const mssqlHostId = hostId(mssqlIp);
    if (!seenNodes.has(mssqlHostId)) {
      nodes.push({
        id: mssqlHostId,
        type: 'host',
        label: mssqlHostname || mssqlIp,
        ip: mssqlIp,
        hostname: mssqlHostname,
        alive: true,
      });
      seenNodes.add(mssqlHostId);
    }
    const mssqlSvcId = serviceId(mssqlIp, mssqlPort);
    if (!seenNodes.has(mssqlSvcId)) {
      nodes.push({
        id: mssqlSvcId,
        type: 'service',
        label: `mssql/${mssqlPort}`,
        port: parseInt(mssqlPort, 10),
        protocol: 'tcp',
        service_name: 'mssql',
      });
      seenNodes.add(mssqlSvcId);
      addEdgeOnce(mssqlHostId, mssqlSvcId, 'RUNS', 1.0);
    }

    // Detect linked server lines
    const linkedMatch = mssqlRest.match(/\[\*\]\s*(?:Linked\s+(?:SQL\s+)?Servers?|Link):\s*(.*)/i);
    if (linkedMatch) {
      const serverNames = linkedMatch[1].split(/[,;]/).map(s => s.trim()).filter(Boolean);
      if (serverNames.length > 0) {
        const existing = mssqlLinkedServers.get(mssqlSvcId) || [];
        for (const name of serverNames) {
          if (!existing.includes(name)) existing.push(name);
        }
        mssqlLinkedServers.set(mssqlSvcId, existing);
      }
    }
  }
  // Apply linked_servers to MSSQL service nodes
  for (const [svcId, servers] of mssqlLinkedServers) {
    const svcNode = nodes.find(n => n.id === svcId);
    if (svcNode) {
      svcNode.linked_servers = servers;
    }
  }

  // Post-processing: ensure hosts from info-only lines are emitted
  for (const [ip] of hostMeta) {
    ensureSmbContext(ip);
  }

  // Post-processing: create NULL_SESSION edges for hosts with null auth
  for (const [ip, meta] of hostMeta) {
    if (!meta.nullAuth) continue;
    const resolvedHostId = hostId(ip);
    const serviceNodeId = serviceId(ip, 445);
    addEdgeOnce(resolvedHostId, serviceNodeId, 'NULL_SESSION', 1.0);
  }

  // Post-processing: update host nodes with metadata that arrived after node creation
  for (const node of nodes) {
    if (node.type === 'host' && typeof node.ip === 'string') {
      const meta = hostMeta.get(node.ip);
      if (meta) {
        if (meta.hostname && !node.hostname) node.hostname = meta.hostname;
        if (meta.domain && !node.domain_name) node.domain_name = meta.domain;
        if (meta.os && !node.os) node.os = meta.os;
        if (meta.nullAuth && !node.null_session) node.null_session = true;
        if (meta.hostname && node.label === node.ip) node.label = meta.hostname;
      }
    }
  }

  return {
    id: uuidv4(),
    agent_id: agentId,
    timestamp: new Date().toISOString(),
    nodes,
    edges,
  };
}
