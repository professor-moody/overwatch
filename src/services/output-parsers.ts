// ============================================================
// Output Parsers
// Parse common offensive tool outputs into structured Findings
// ============================================================

import type { Finding, NodeType, EdgeType, ParseContext } from '../types.js';
import { v4 as uuidv4 } from 'uuid';
import { XMLParser } from 'fast-xml-parser';
import { caId, certTemplateId, credentialId, domainId, groupId, hostId, normalizeKeyPart, resolveDomainName, splitQualifiedAccount, userId } from './parser-utils.js';
import { classifyPrincipalIdentity, getIdentityMarkers, resolveNodeIdentity } from './identity-resolution.js';

// Nmap uses verbose service names; normalize to short names matching inference rules
const NMAP_SERVICE_MAP: Record<string, string> = {
  'kerberos-sec': 'kerberos',
  'microsoft-ds': 'smb',
  'netbios-ssn': 'smb',
  'ms-wbt-server': 'rdp',
  'ms-sql-s': 'mssql',
  'ms-sql-m': 'mssql',
  'domain': 'dns',
  'msrpc': 'rpc',
  'http-proxy': 'http',
  'ssl/http': 'https',
  'ssl/https': 'https',
};

function normalizeServiceName(raw?: string): string | undefined {
  if (!raw) return raw;
  return NMAP_SERVICE_MAP[raw] ?? raw;
}

// --- Nmap XML Parser ---

interface NmapHost {
  ip: string;
  hostname?: string;
  os?: string;
  alive: boolean;
  ports: Array<{
    port: number;
    protocol: string;
    state: string;
    service?: string;
    version?: string;
    banner?: string;
  }>;
}

const OS_BANNER_PATTERNS: Array<{ pattern: RegExp; os: string }> = [
  { pattern: /Microsoft Windows/i, os: 'Windows' },
  { pattern: /Windows Server (\d+)/i, os: 'Windows Server' },
  { pattern: /OpenSSH.*Ubuntu/i, os: 'Linux/Ubuntu' },
  { pattern: /OpenSSH.*Debian/i, os: 'Linux/Debian' },
  { pattern: /OpenSSH.*el[789]/i, os: 'Linux/RHEL' },
  { pattern: /OpenSSH.*CentOS/i, os: 'Linux/CentOS' },
  { pattern: /Apache.*(?:Ubuntu|Debian)/i, os: 'Linux' },
  { pattern: /nginx/i, os: 'Linux' },
  { pattern: /Samba/i, os: 'Linux' },
  { pattern: /FreeBSD/i, os: 'FreeBSD' },
];

function inferOsFromBanners(ports: NmapHost['ports']): string | undefined {
  for (const port of ports) {
    const text = [port.version, port.banner].filter(Boolean).join(' ');
    if (!text) continue;
    for (const { pattern, os } of OS_BANNER_PATTERNS) {
      const m = text.match(pattern);
      if (m) {
        // For "Windows Server (\d+)", include the version number
        if (os === 'Windows Server' && m[1]) return `Windows Server ${m[1]}`;
        return os;
      }
    }
  }
  return undefined;
}

export function parseNmapXml(xml: string, agentId: string = 'nmap-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const hosts = extractNmapHosts(xml);

  for (const host of hosts) {
    const resolvedHostId = hostId(host.ip);

    // Infer OS from service banners when osmatch is absent
    let os = host.os;
    if (!os) {
      os = inferOsFromBanners(host.ports);
    }

    nodes.push({
      id: resolvedHostId,
      type: 'host',
      label: host.hostname || host.ip,
      ip: host.ip,
      hostname: host.hostname,
      os,
      alive: host.alive,
    });

    for (const port of host.ports) {
      if (port.state !== 'open') continue;

      const svcId = `svc-${host.ip.replace(/\./g, '-')}-${port.port}`;
      nodes.push({
        id: svcId,
        type: 'service',
        label: `${port.service || 'unknown'}/${port.port}`,
        port: port.port,
        protocol: port.protocol,
        service_name: normalizeServiceName(port.service),
        version: port.version,
        banner: port.banner,
      });

      edges.push({
        source: resolvedHostId,
        target: svcId,
        properties: {
          type: 'RUNS',
          confidence: 1.0,
          discovered_at: new Date().toISOString(),
          discovered_by: agentId,
        },
      });
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

const nmapXmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  allowBooleanAttributes: true,
  isArray: (name) => ['host', 'address', 'port', 'hostname', 'osmatch'].includes(name),
  commentPropName: false,
});

function extractNmapHosts(xml: string): NmapHost[] {
  const hosts: NmapHost[] = [];
  let parsed: any;
  try {
    parsed = nmapXmlParser.parse(xml);
  } catch {
    return hosts;
  }

  const nmaprun = parsed.nmaprun || parsed;
  const hostEntries: any[] = nmaprun?.host || [];

  for (const h of hostEntries) {
    // IP address — find the ipv4 address entry
    const addresses: any[] = Array.isArray(h.address) ? h.address : h.address ? [h.address] : [];
    const ipv4 = addresses.find((a: any) => a['@_addrtype'] === 'ipv4');
    if (!ipv4) continue;
    const ip = ipv4['@_addr'];

    // Status
    const alive = h.status ? h.status['@_state'] === 'up' : true;

    // Hostname
    const hostnames = h.hostnames?.hostname;
    const hostnameEntry = Array.isArray(hostnames) ? hostnames[0] : hostnames;
    const hostname = hostnameEntry?.['@_name'] || undefined;

    // OS
    const osmatches = h.os?.osmatch;
    const osEntry = Array.isArray(osmatches) ? osmatches[0] : osmatches;
    const os = osEntry?.['@_name'] || undefined;

    // Ports
    const ports: NmapHost['ports'] = [];
    const portEntries: any[] = h.ports?.port || [];
    const portList = Array.isArray(portEntries) ? portEntries : [portEntries];

    for (const p of portList) {
      if (!p['@_protocol'] || !p['@_portid']) continue;

      const svc = p.service;
      let service: string | undefined;
      let version: string | undefined;
      let banner: string | undefined;

      if (svc) {
        service = svc['@_name'] || undefined;
        version = [svc['@_product'], svc['@_version']].filter(Boolean).join(' ') || undefined;
        banner = svc['@_extrainfo'] || undefined;
      }

      ports.push({
        port: parseInt(p['@_portid']),
        protocol: p['@_protocol'],
        state: p.state?.['@_state'] || 'unknown',
        service,
        version,
        banner,
      });
    }

    hosts.push({ ip, hostname, os, alive, ports });
  }

  return hosts;
}

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

  function addEdgeOnce(source: string, target: string, type: EdgeType, confidence: number): void {
    const edgeKey = `${source}--${type}--${target}`;
    if (seenEdges.has(edgeKey)) return;
    edges.push({
      source,
      target,
      properties: { type, confidence, discovered_at: now, discovered_by: agentId },
    });
    seenEdges.add(edgeKey);
  }

  function ensureSmbContext(ip: string): { hostNodeId: string; serviceNodeId: string } {
    const resolvedHostId = hostId(ip);
    const serviceNodeId = `svc-${ip.replace(/\./g, '-')}-445`;

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

  // Broad prefix regex for all SMB lines: SMB  IP  PORT  HOSTNAME  <rest>
  const smbLineRe = /^SMB\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+(.*)/i;

  for (const line of lines) {
    const smbLine = line.match(smbLineRe);
    if (!smbLine) {
      userTableIp = undefined;
      continue;
    }

    const [, ip, port, hostname, rest] = smbLine;
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

      // Extract OS from the info text before first parenthetical
      const osMatch = infoMsg.match(/^(Windows\s[^(]+)/i);
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
        const credMatch = message.match(/([^\\]+)\\([^\s]+)/);
        if (credMatch) {
          const [, rawCredDomain, username] = credMatch;
          const credDomain = resolveDomainName(rawCredDomain, context?.domain_aliases);
          const resolvedUserId = addUserNode(username, credDomain);
          // Upgrade to privileged
          const userNode = nodes.find(n => n.id === resolvedUserId);
          if (userNode) userNode.privileged = true;
          addEdgeOnce(resolvedUserId, resolvedHostId, 'ADMIN_TO', 1.0);
        }
      }

      // Valid auth (+ status) with domain\user pattern
      if (status === '+') {
        const credMatch = message.match(/([^\\]+)\\([^\s:]+)/);
        if (credMatch) {
          const [, rawCredDomain, username] = credMatch;
          const credDomain = resolveDomainName(rawCredDomain, context?.domain_aliases);
          if (username && username !== '') {
            addUserNode(username, credDomain);
            addEdgeOnce(userId(username, credDomain), resolvedHostId, 'VALID_ON', 0.9);
          }
        }
      }

      continue;
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
    const shareMatch = rest.match(/^(\S+)\s+(READ|WRITE|READ,\s*WRITE)/i);
    if (shareMatch) {
      const [, shareName, perms] = shareMatch;
      if (shareName.startsWith('[') || shareName === '-Username-') continue;
      const { hostNodeId: resolvedHostId } = ensureSmbContext(ip);
      const shareId = `share-${ip.replace(/\./g, '-')}-${shareName.toLowerCase()}`;

      if (!seenNodes.has(shareId)) {
        nodes.push({
          id: shareId,
          type: 'share',
          label: `\\\\${ip}\\${shareName}`,
          share_name: shareName,
          readable: perms.includes('READ'),
          writable: perms.includes('WRITE'),
        });
        seenNodes.add(shareId);
      }
      addEdgeOnce(resolvedHostId, shareId, 'RELATED', 1.0);
    }
  }

  // Post-processing: create NULL_SESSION edges for hosts with null auth
  for (const [ip, meta] of hostMeta) {
    if (!meta.nullAuth) continue;
    const resolvedHostId = hostId(ip);
    const serviceNodeId = `svc-${ip.replace(/\./g, '-')}-445`;
    // Ensure context exists (may not have been created yet if only [*] lines were seen)
    ensureSmbContext(ip);
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

// --- Certipy Parser ---

export function parseCertipy(output: string, agentId: string = 'certipy-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();

  // Parse certipy find output (JSON format)
  try {
    const data = JSON.parse(output);

    // Certificate Authorities
    if (data['Certificate Authorities']) {
      for (const [caName, caData] of Object.entries(data['Certificate Authorities'] as Record<string, any>)) {
        const caNodeId = caId(caName);
        if (!seenNodes.has(caNodeId)) {
          nodes.push({
            id: caNodeId,
            type: 'ca',
            label: caName,
            ca_name: caName,
            ca_kind: 'enterprise_ca',
          });
          seenNodes.add(caNodeId);
        }
      }
    }

    // Certificate Templates
    if (data['Certificate Templates']) {
      for (const [templateName, templateData] of Object.entries(data['Certificate Templates'] as Record<string, any>)) {
        const tmplId = certTemplateId(templateName);
        const tmpl = templateData as Record<string, any>;

        if (!seenNodes.has(tmplId)) {
          nodes.push({
            id: tmplId,
            type: 'cert_template',
            label: templateName,
            template_name: templateName,
            enrollee_supplies_subject: tmpl['Enrollee Supplies Subject'] === true,
            eku: Array.isArray(tmpl['Extended Key Usage']) ? tmpl['Extended Key Usage'] : undefined,
          });
          seenNodes.add(tmplId);
        }

        // Check for ESC vulnerabilities
        if (tmpl['[!] Vulnerabilities']) {
          const vulns = tmpl['[!] Vulnerabilities'] as Record<string, any>;
          for (const [escName] of Object.entries(vulns)) {
            const escType = escName.toUpperCase().replace(/[^A-Z0-9]/g, '') as EdgeType;
            if (['ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC6', 'ESC8'].includes(escType)) {
              // Create ESC edge from enrollable entities to template
              if (tmpl['Enrollment Permissions'] && tmpl['Enrollment Permissions']['Enrollment Rights']) {
                for (const principal of tmpl['Enrollment Permissions']['Enrollment Rights'] as string[]) {
                  const principalIdentity = classifyPrincipalIdentity(principal);
                  const principalId = principalIdentity.id;
                  const resolution = resolveNodeIdentity({
                    id: principalId,
                    type: principalIdentity.nodeType,
                    label: principalIdentity.label,
                    username: principalIdentity.username,
                    domain_name: principalIdentity.domain_name,
                  });
                  const resolvedPrincipalId = resolution.id;
                  if (!seenNodes.has(resolvedPrincipalId)) {
                    nodes.push({
                      id: resolvedPrincipalId,
                      type: principalIdentity.nodeType,
                      label: principalIdentity.label,
                      username: principalIdentity.username,
                      domain_name: principalIdentity.domain_name,
                      identity_status: resolution.status,
                      identity_family: resolution.family,
                      canonical_id: resolution.status === 'canonical' ? resolvedPrincipalId : undefined,
                      identity_markers: resolution.markers,
                      principal_type_ambiguous: principalIdentity.ambiguous || undefined,
                    });
                    seenNodes.add(resolvedPrincipalId);
                  }
                  edges.push({
                    source: resolvedPrincipalId,
                    target: tmplId,
                    properties: {
                      type: escType as EdgeType,
                      confidence: 0.9,
                      discovered_at: new Date().toISOString(),
                      discovered_by: agentId,
                    },
                  });
                }
              }
            }
          }
        }
      }
    }
  } catch {
    // Not JSON — try line-based parsing for certipy text output
    const lines = output.split('\n');
    for (const line of lines) {
      const templateMatch = line.match(/Template Name\s*:\s*(.+)/i);
      if (templateMatch) {
        const templateName = templateMatch[1].trim();
        const tmplId = certTemplateId(templateName);
        if (!seenNodes.has(tmplId)) {
          nodes.push({
            id: tmplId,
            type: 'cert_template',
            label: templateName,
            template_name: templateName,
          });
          seenNodes.add(tmplId);
        }
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

// --- Kerbrute Parser ---

export function parseKerbrute(output: string, agentId: string = 'kerbrute-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  for (const line of output.split('\n')) {
    // Valid username: [+] VALID USERNAME:\tuser@domain
    const enumMatch = line.match(/\[\+\]\s*VALID USERNAME:\s*(\S+)/i);
    if (enumMatch) {
      const upn = parseUpn(enumMatch[1]);
      if (!upn) continue;
      const { username, domain } = upn;
      const resolvedUserId = userId(username, domain);
      const resolvedDomainId = domainId(domain);

      if (!seenNodes.has(resolvedUserId)) {
        nodes.push({ id: resolvedUserId, type: 'user', label: `${username}@${domain}`, username, domain_name: domain });
        seenNodes.add(resolvedUserId);
      }
      if (!seenNodes.has(resolvedDomainId)) {
        nodes.push({ id: resolvedDomainId, type: 'domain', label: domain, domain_name: domain });
        seenNodes.add(resolvedDomainId);
      }
      edges.push({
        source: resolvedUserId,
        target: resolvedDomainId,
        properties: { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
      continue;
    }

    // Password spray: [+] VALID LOGIN:\tuser@domain:password
    const sprayPayloadMatch = line.match(/\[\+\]\s*VALID LOGIN:\s*(.+)$/i);
    if (sprayPayloadMatch) {
      const parsed = parseKerbruteLogin(sprayPayloadMatch[1]);
      if (!parsed) continue;
      const { username, domain, password } = parsed;
      const resolvedUserId = userId(username, domain);
      const resolvedDomainId = domainId(domain);
      const resolvedCredId = credentialId('plaintext_password', password, username, domain);

      if (!seenNodes.has(resolvedUserId)) {
        nodes.push({ id: resolvedUserId, type: 'user', label: `${username}@${domain}`, username, domain_name: domain });
        seenNodes.add(resolvedUserId);
      }
      if (!seenNodes.has(resolvedDomainId)) {
        nodes.push({ id: resolvedDomainId, type: 'domain', label: domain, domain_name: domain });
        seenNodes.add(resolvedDomainId);
      }
      if (!seenNodes.has(resolvedCredId)) {
        nodes.push({
          id: resolvedCredId,
          type: 'credential',
          label: `${username}:***`,
          cred_type: 'plaintext',
          cred_material_kind: 'plaintext_password',
          cred_usable_for_auth: true,
          cred_evidence_kind: 'spray_success',
          cred_value: password,
          cred_user: username,
          cred_domain: domain,
        });
        seenNodes.add(resolvedCredId);
      }

      edges.push({
        source: resolvedUserId,
        target: resolvedDomainId,
        properties: { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
      edges.push({
        source: resolvedUserId,
        target: resolvedCredId,
        properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- Hashcat Parser (--show / potfile) ---

export function parseHashcat(output: string, agentId: string = 'hashcat-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();
  const contextDomain = context?.domain;

  for (const rawLine of output.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    let username: string | undefined;
    let domain: string | undefined;
    let plaintext: string | undefined;
    let hashValue: string | undefined;
    let hashType: string = 'unknown';

    // Kerberoast: $krb5tgs$23$*user$REALM$spn*$...:plaintext
    const krbMatch = line.match(/^(\$krb5tgs\$\d+\$\*([^$*]+)\$([^$*]+)\$[^:]+):(.+)$/);
    if (krbMatch) {
      hashValue = krbMatch[1];
      username = krbMatch[2];
      domain = krbMatch[3];
      plaintext = krbMatch[4];
      hashType = 'kerberoast';
    }

    // AS-REP: $krb5asrep$23$user@REALM:...:plaintext
    if (!plaintext) {
      const asrepMatch = line.match(/^(\$krb5asrep\$\d+\$([^@:]+)@([^:]+)[^:]*):(.+)$/);
      if (asrepMatch) {
        hashValue = asrepMatch[1];
        username = asrepMatch[2];
        domain = asrepMatch[3];
        plaintext = asrepMatch[4];
        hashType = 'asrep';
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
        hashType = 'ntlmv2';
      }
    }

    // Plain NTLM (32 hex chars): hash:plaintext
    if (!plaintext) {
      const ntlmMatch = line.match(/^([a-f0-9]{32}):(.+)$/i);
      if (ntlmMatch) {
        hashValue = ntlmMatch[1];
        plaintext = ntlmMatch[2];
        hashType = 'ntlm';
      }
    }

    if (!plaintext || plaintext.length === 0) continue;

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

// --- Responder Parser ---

export function parseResponder(output: string, agentId: string = 'responder-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  const lines = output.split('\n');

  for (let i = 0; i < lines.length; i++) {
    // Look for NTLMv2-SSP Client line as stanza start
    const clientMatch = lines[i].match(/NTLMv2-SSP Client\s*:\s*(\d+\.\d+\.\d+\.\d+)/);
    if (!clientMatch) continue;
    const clientIp = clientMatch[1];

    // Next line should be Username
    const userLine = lines[i + 1] || '';
    const userMatch = userLine.match(/NTLMv2-SSP Username\s*:\s*([^\\]+)\\(.+)/);
    if (!userMatch) continue;
    const domain = userMatch[1].trim();
    const username = userMatch[2].trim();

    // Next line should be Hash
    const hashLine = lines[i + 2] || '';
    const hashMatch = hashLine.match(/NTLMv2-SSP Hash\s*:\s*(.+)/);
    if (!hashMatch) continue;
    const hash = hashMatch[1].trim();

    const resolvedHostId = hostId(clientIp);
    const resolvedUserId = userId(username, domain);
    const resolvedCredId = credentialId('ntlmv2_challenge', hash, username, domain);

    if (!seenNodes.has(resolvedHostId)) {
      nodes.push({ id: resolvedHostId, type: 'host', label: clientIp, ip: clientIp, alive: true });
      seenNodes.add(resolvedHostId);
    }
    if (!seenNodes.has(resolvedUserId)) {
      nodes.push({ id: resolvedUserId, type: 'user', label: `${domain}\\${username}`, username, domain_name: domain });
      seenNodes.add(resolvedUserId);
    }
    if (!seenNodes.has(resolvedCredId)) {
      nodes.push({
        id: resolvedCredId,
        type: 'credential',
        label: `NTLMv2:${username}`,
        cred_type: 'ntlmv2_challenge',
        cred_material_kind: 'ntlmv2_challenge',
        cred_usable_for_auth: false,
        cred_evidence_kind: 'capture',
        cred_value: hash,
        cred_user: username,
        cred_domain: domain,
        observed_from_ip: clientIp,
      });
      seenNodes.add(resolvedCredId);
    }

    edges.push({
      source: resolvedUserId,
      target: resolvedCredId,
      properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: now, discovered_by: agentId },
    });

    // Skip past the stanza we just consumed
    i += 2;
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- ldapsearch / ldapdomaindump Parser ---

// UAC bit for "Do not require Kerberos preauthentication"
const UAC_DONT_REQUIRE_PREAUTH = 0x400000;
// UAC bit for disabled account
const UAC_ACCOUNTDISABLE = 0x0002;

function domainFromDn(dn: string): string | undefined {
  const dcParts: string[] = [];
  for (const part of dn.split(',')) {
    const m = part.trim().match(/^DC=(.+)$/i);
    if (m) dcParts.push(m[1]);
  }
  return dcParts.length > 0 ? dcParts.join('.') : undefined;
}

function parseLdifStanzas(raw: string): Array<Record<string, string[]>> {
  // Handle line continuations (leading space = continuation of previous line)
  const unfolded = raw.replace(/\r?\n /g, '');
  const stanzas: Array<Record<string, string[]>> = [];
  let current: Record<string, string[]> = {};
  let hasContent = false;

  for (const line of unfolded.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) {
      if (hasContent) {
        stanzas.push(current);
        current = {};
        hasContent = false;
      }
      continue;
    }
    // base64-encoded: attr:: base64value
    const b64Match = trimmed.match(/^([^:]+)::\s*(.*)$/);
    if (b64Match) {
      const [, attr, b64val] = b64Match;
      const key = attr.toLowerCase();
      let decoded: string;
      try {
        decoded = Buffer.from(b64val, 'base64').toString('utf-8');
      } catch {
        decoded = b64val;
      }
      (current[key] ??= []).push(decoded);
      hasContent = true;
      continue;
    }
    // Normal: attr: value
    const normalMatch = trimmed.match(/^([^:]+):\s*(.*)$/);
    if (normalMatch) {
      const [, attr, val] = normalMatch;
      (current[attr.toLowerCase()] ??= []).push(val);
      hasContent = true;
    }
  }
  if (hasContent) stanzas.push(current);
  return stanzas;
}

export function parseLdapsearch(output: string, agentId: string = 'ldapsearch-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  function addEdgeOnce(source: string, target: string, type: EdgeType, confidence: number): void {
    const key = `${source}--${type}--${target}`;
    if (seenNodes.has(key)) return;
    edges.push({ source, target, properties: { type, confidence, discovered_at: now, discovered_by: agentId } });
    seenNodes.add(key);
  }

  // Try ldapdomaindump JSON first
  try {
    const data = JSON.parse(output);
    if (Array.isArray(data) && data.length > 0 && data[0].attributes) {
      return parseLdapdomaindumpJson(data, agentId);
    }
  } catch {
    // Not JSON — parse as LDIF
  }

  const stanzas = parseLdifStanzas(output);
  for (const entry of stanzas) {
    const objectClass = (entry['objectclass'] || []).map(c => c.toLowerCase());
    const dn = (entry['dn'] || [''])[0];
    const domain = domainFromDn(dn);
    const sam = (entry['samaccountname'] || [''])[0];

    if (!sam) continue;

    // User objects
    if (objectClass.includes('person') || objectClass.includes('user')) {
      const resolvedUserId = userId(sam, domain);
      if (seenNodes.has(resolvedUserId)) continue;

      const uacRaw = parseInt((entry['useraccountcontrol'] || ['0'])[0], 10) || 0;
      const spns = entry['serviceprincipalname'] || [];
      const adminCount = (entry['admincount'] || ['0'])[0];
      const displayName = (entry['displayname'] || [''])[0] || undefined;
      const sidVal = (entry['objectsid'] || [''])[0] || undefined;
      const enabled = !(uacRaw & UAC_ACCOUNTDISABLE);

      nodes.push({
        id: resolvedUserId,
        type: 'user',
        label: domain ? `${domain}\\${sam}` : sam,
        username: sam,
        domain_name: domain,
        display_name: displayName,
        enabled,
        has_spn: spns.length > 0 || undefined,
        asrep_roastable: !!(uacRaw & UAC_DONT_REQUIRE_PREAUTH) || undefined,
        privileged: adminCount === '1' || undefined,
        sid: sidVal,
      });
      seenNodes.add(resolvedUserId);

      // Domain membership
      if (domain) {
        const resolvedDomainId = domainId(domain);
        if (!seenNodes.has(resolvedDomainId)) {
          nodes.push({ id: resolvedDomainId, type: 'domain', label: domain, domain_name: domain });
          seenNodes.add(resolvedDomainId);
        }
        addEdgeOnce(resolvedUserId, resolvedDomainId, 'MEMBER_OF_DOMAIN', 1.0);
      }

      // Group memberships
      for (const memberOf of entry['memberof'] || []) {
        const groupCn = memberOf.match(/^CN=([^,]+)/i);
        if (groupCn) {
          const resolvedGroupId = groupId(groupCn[1], domain);
          if (!seenNodes.has(resolvedGroupId)) {
            nodes.push({ id: resolvedGroupId, type: 'group', label: groupCn[1], domain_name: domain });
            seenNodes.add(resolvedGroupId);
          }
          addEdgeOnce(resolvedUserId, resolvedGroupId, 'MEMBER_OF', 1.0);
        }
      }
      continue;
    }

    // Group objects
    if (objectClass.includes('group')) {
      const resolvedGroupId = groupId(sam, domain);
      if (seenNodes.has(resolvedGroupId)) continue;

      const sidVal = (entry['objectsid'] || [''])[0] || undefined;
      const adminCount = (entry['admincount'] || ['0'])[0];
      nodes.push({
        id: resolvedGroupId,
        type: 'group',
        label: sam,
        domain_name: domain,
        sid: sidVal,
        privileged: adminCount === '1' || undefined,
      });
      seenNodes.add(resolvedGroupId);
      continue;
    }

    // Computer objects
    if (objectClass.includes('computer')) {
      const dnsHostname = (entry['dnshostname'] || [''])[0];
      const osVal = (entry['operatingsystem'] || [''])[0] || undefined;
      const ip = dnsHostname || sam.replace(/\$$/, '');
      const resolvedHostId = dnsHostname ? `host-${normalizeKeyPart(dnsHostname)}` : hostId(ip);
      if (seenNodes.has(resolvedHostId)) continue;

      nodes.push({
        id: resolvedHostId,
        type: 'host',
        label: dnsHostname || sam,
        hostname: dnsHostname || undefined,
        os: osVal,
        domain_joined: true,
        alive: true,
      });
      seenNodes.add(resolvedHostId);

      if (domain) {
        const resolvedDomainId = domainId(domain);
        if (!seenNodes.has(resolvedDomainId)) {
          nodes.push({ id: resolvedDomainId, type: 'domain', label: domain, domain_name: domain });
          seenNodes.add(resolvedDomainId);
        }
        addEdgeOnce(resolvedHostId, resolvedDomainId, 'MEMBER_OF_DOMAIN', 1.0);
      }
      continue;
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

function parseLdapdomaindumpJson(data: any[], agentId: string): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  function addEdgeOnce(source: string, target: string, type: EdgeType, confidence: number): void {
    const key = `${source}--${type}--${target}`;
    if (seenNodes.has(key)) return;
    edges.push({ source, target, properties: { type, confidence, discovered_at: now, discovered_by: agentId } });
    seenNodes.add(key);
  }

  for (const entry of data) {
    const attrs = entry.attributes || entry;
    const objectClass = (attrs.objectClass || []).map((c: string) => c.toLowerCase());
    const sam = (Array.isArray(attrs.sAMAccountName) ? attrs.sAMAccountName[0] : attrs.sAMAccountName) || '';
    const dn = (Array.isArray(attrs.distinguishedName) ? attrs.distinguishedName[0] : attrs.distinguishedName) || '';
    const domain = domainFromDn(dn);

    if (!sam) continue;

    if (objectClass.includes('person') || objectClass.includes('user')) {
      const resolvedUserId = userId(sam, domain);
      if (seenNodes.has(resolvedUserId)) continue;

      const uac = parseInt(attrs.userAccountControl || '0', 10) || 0;
      const spns = attrs.servicePrincipalName || [];
      const adminCount = String(attrs.adminCount || '0');

      nodes.push({
        id: resolvedUserId,
        type: 'user',
        label: domain ? `${domain}\\${sam}` : sam,
        username: sam,
        domain_name: domain,
        display_name: attrs.displayName || undefined,
        enabled: !(uac & UAC_ACCOUNTDISABLE),
        has_spn: (Array.isArray(spns) ? spns.length > 0 : !!spns) || undefined,
        asrep_roastable: !!(uac & UAC_DONT_REQUIRE_PREAUTH) || undefined,
        privileged: adminCount === '1' || undefined,
        sid: attrs.objectSid || undefined,
      });
      seenNodes.add(resolvedUserId);

      if (domain) {
        const resolvedDomainId = domainId(domain);
        if (!seenNodes.has(resolvedDomainId)) {
          nodes.push({ id: resolvedDomainId, type: 'domain', label: domain, domain_name: domain });
          seenNodes.add(resolvedDomainId);
        }
        addEdgeOnce(resolvedUserId, resolvedDomainId, 'MEMBER_OF_DOMAIN', 1.0);
      }

      for (const memberOf of (attrs.memberOf || [])) {
        const groupCn = memberOf.match(/^CN=([^,]+)/i);
        if (groupCn) {
          const resolvedGroupId = groupId(groupCn[1], domain);
          if (!seenNodes.has(resolvedGroupId)) {
            nodes.push({ id: resolvedGroupId, type: 'group', label: groupCn[1], domain_name: domain });
            seenNodes.add(resolvedGroupId);
          }
          addEdgeOnce(resolvedUserId, resolvedGroupId, 'MEMBER_OF', 1.0);
        }
      }
      continue;
    }

    if (objectClass.includes('computer')) {
      const dnsHostname = attrs.dNSHostName || attrs.dnshostname || '';
      const osVal = attrs.operatingSystem || undefined;
      const resolvedHostId = dnsHostname ? `host-${normalizeKeyPart(dnsHostname)}` : `host-${normalizeKeyPart(sam)}`;
      if (seenNodes.has(resolvedHostId)) continue;

      nodes.push({
        id: resolvedHostId,
        type: 'host',
        label: dnsHostname || sam,
        hostname: dnsHostname || undefined,
        os: osVal,
        domain_joined: true,
        alive: true,
      });
      seenNodes.add(resolvedHostId);

      if (domain) {
        const resolvedDomainId = domainId(domain);
        if (!seenNodes.has(resolvedDomainId)) {
          nodes.push({ id: resolvedDomainId, type: 'domain', label: domain, domain_name: domain });
          seenNodes.add(resolvedDomainId);
        }
        addEdgeOnce(resolvedHostId, resolvedDomainId, 'MEMBER_OF_DOMAIN', 1.0);
      }
      continue;
    }

    if (objectClass.includes('group')) {
      const resolvedGroupId = groupId(sam, domain);
      if (seenNodes.has(resolvedGroupId)) continue;
      nodes.push({
        id: resolvedGroupId,
        type: 'group',
        label: sam,
        domain_name: domain,
        sid: attrs.objectSid || undefined,
        privileged: String(attrs.adminCount || '0') === '1' || undefined,
      });
      seenNodes.add(resolvedGroupId);
      continue;
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- enum4linux-ng Parser ---

export function parseEnum4linux(output: string, agentId: string = 'enum4linux-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  function addEdgeOnce(source: string, target: string, type: EdgeType, confidence: number): void {
    const key = `${source}--${type}--${target}`;
    if (seenNodes.has(key)) return;
    edges.push({ source, target, properties: { type, confidence, discovered_at: now, discovered_by: agentId } });
    seenNodes.add(key);
  }

  // Try JSON first (enum4linux-ng -oJ)
  try {
    const data = JSON.parse(output);
    return parseEnum4linuxJson(data, agentId, context);
  } catch {
    // Fall back to text parsing
  }

  // Text-mode parsing
  let targetIp: string | undefined;
  let domain: string | undefined;
  let nullSession = false;

  for (const line of output.split('\n')) {
    // Target IP
    const targetMatch = line.match(/Target:\s*(\d+\.\d+\.\d+\.\d+)/i) ||
                         line.match(/\|\s*Target\s*\|\s*(\d+\.\d+\.\d+\.\d+)/);
    if (targetMatch) { targetIp = targetMatch[1]; continue; }

    // Domain/Workgroup
    const domainMatch = line.match(/Domain:\s*(\S+)/i) ||
                         line.match(/\[\+\]\s*.*domain\s+name:\s*(\S+)/i);
    if (domainMatch && !domain) { domain = resolveDomainName(domainMatch[1], context?.domain_aliases); continue; }

    // Null session
    if (/null session/i.test(line) && /\[\+\]/.test(line)) {
      nullSession = true;
      continue;
    }

    // RID-cycled users: 500: ACME\Administrator or 1103: ACME\jdoe (SidTypeUser)
    const ridMatch = line.match(/(\d+):\s*([^\\]+)\\(\S+)\s*\(SidTypeUser\)/i);
    if (ridMatch) {
      const [, , ridDomain, username] = ridMatch;
      const resolvedDomain = ridDomain ? resolveDomainName(ridDomain, context?.domain_aliases) : domain;
      const resolvedUserId = userId(username, resolvedDomain);
      if (!seenNodes.has(resolvedUserId)) {
        nodes.push({
          id: resolvedUserId,
          type: 'user',
          label: resolvedDomain ? `${resolvedDomain}\\${username}` : username,
          username,
          domain_name: resolvedDomain,
        });
        seenNodes.add(resolvedUserId);
      }
      if (resolvedDomain) {
        const resolvedDomainId = domainId(resolvedDomain);
        if (!seenNodes.has(resolvedDomainId)) {
          nodes.push({ id: resolvedDomainId, type: 'domain', label: resolvedDomain, domain_name: resolvedDomain });
          seenNodes.add(resolvedDomainId);
        }
        addEdgeOnce(resolvedUserId, resolvedDomainId, 'MEMBER_OF_DOMAIN', 1.0);
      }
      continue;
    }

    // RID-cycled groups: 513: ACME\Domain Users (SidTypeGroup)
    const ridGroupMatch = line.match(/(\d+):\s*([^\\]+)\\(.+?)\s*\(SidTypeGroup\)/i);
    if (ridGroupMatch) {
      const [, , gDomain, gName] = ridGroupMatch;
      const resolvedGDomain = gDomain ? resolveDomainName(gDomain, context?.domain_aliases) : domain;
      const resolvedGroupId = groupId(gName, resolvedGDomain);
      if (!seenNodes.has(resolvedGroupId)) {
        nodes.push({ id: resolvedGroupId, type: 'group', label: gName, domain_name: resolvedGDomain });
        seenNodes.add(resolvedGroupId);
      }
      continue;
    }

    // Share enumeration: [+] sharename ... READ/WRITE or Mapping: OK, Listing: OK
    const shareMatch = line.match(/\[\+\]\s*(\S+)\s+.*(?:READ|WRITE|Mapping:\s*OK)/i);
    if (shareMatch && targetIp) {
      const shareName = shareMatch[1];
      if (shareName.startsWith('[') || shareName === 'Enumerating') continue;
      const shareNodeId = `share-${targetIp.replace(/\./g, '-')}-${normalizeKeyPart(shareName)}`;
      if (!seenNodes.has(shareNodeId)) {
        const readable = /READ/i.test(line) || /Listing:\s*OK/i.test(line);
        const writable = /WRITE/i.test(line);
        nodes.push({
          id: shareNodeId,
          type: 'share',
          label: `\\\\${targetIp}\\${shareName}`,
          share_name: shareName,
          readable: readable || undefined,
          writable: writable || undefined,
        });
        seenNodes.add(shareNodeId);
      }
    }
  }

  // Create host and SMB service context if we found a target
  if (targetIp) {
    const resolvedHostId = hostId(targetIp);
    const serviceNodeId = `svc-${targetIp.replace(/\./g, '-')}-445`;

    if (!seenNodes.has(resolvedHostId)) {
      nodes.push({
        id: resolvedHostId,
        type: 'host',
        label: targetIp,
        ip: targetIp,
        alive: true,
        domain_joined: domain ? true : undefined,
        null_session: nullSession || undefined,
      });
      seenNodes.add(resolvedHostId);
    }
    if (!seenNodes.has(serviceNodeId)) {
      nodes.push({
        id: serviceNodeId,
        type: 'service',
        label: 'smb/445',
        port: 445,
        protocol: 'tcp',
        service_name: 'smb',
      });
      seenNodes.add(serviceNodeId);
    }
    addEdgeOnce(resolvedHostId, serviceNodeId, 'RUNS', 1.0);

    if (nullSession) {
      addEdgeOnce(resolvedHostId, serviceNodeId, 'NULL_SESSION', 1.0);
    }

    // Attach shares to host
    for (const node of nodes) {
      if (node.type === 'share') {
        addEdgeOnce(resolvedHostId, node.id, 'RELATED', 1.0);
      }
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

function parseEnum4linuxJson(data: any, agentId: string, context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  function addEdgeOnce(source: string, target: string, type: EdgeType, confidence: number): void {
    const key = `${source}--${type}--${target}`;
    if (seenNodes.has(key)) return;
    edges.push({ source, target, properties: { type, confidence, discovered_at: now, discovered_by: agentId } });
    seenNodes.add(key);
  }

  const targetIp = data.target?.host || data.target?.ip || data.os_info?.target;
  const rawDomain = data.domain_info?.domain || data.target?.domain;
  const domain = rawDomain ? resolveDomainName(rawDomain, context?.domain_aliases) : undefined;
  const osInfo = data.os_info;
  const nullSession = data.session_check?.null_session_allowed === true ||
                       data.session_check?.null_session === true;
  const smbSigning = data.smb_info?.signing_required;

  // Host + service
  if (targetIp) {
    const resolvedHostId = hostId(targetIp);
    const serviceNodeId = `svc-${targetIp.replace(/\./g, '-')}-445`;

    nodes.push({
      id: resolvedHostId,
      type: 'host',
      label: targetIp,
      ip: targetIp,
      hostname: osInfo?.hostname || undefined,
      os: osInfo?.os || osInfo?.os_version || undefined,
      alive: true,
      domain_joined: domain ? true : undefined,
      null_session: nullSession || undefined,
    });
    seenNodes.add(resolvedHostId);

    nodes.push({
      id: serviceNodeId,
      type: 'service',
      label: 'smb/445',
      port: 445,
      protocol: 'tcp',
      service_name: 'smb',
      smb_signing: smbSigning,
    });
    seenNodes.add(serviceNodeId);
    addEdgeOnce(resolvedHostId, serviceNodeId, 'RUNS', 1.0);

    if (nullSession) {
      addEdgeOnce(resolvedHostId, serviceNodeId, 'NULL_SESSION', 1.0);
    }
  }

  // Users
  const users = data.users || {};
  for (const [rid, userObj] of Object.entries(users as Record<string, any>)) {
    const username = userObj.username || userObj.name;
    if (!username) continue;
    const resolvedUserId = userId(username, domain);
    if (seenNodes.has(resolvedUserId)) continue;

    nodes.push({
      id: resolvedUserId,
      type: 'user',
      label: domain ? `${domain}\\${username}` : username,
      username,
      domain_name: domain,
    });
    seenNodes.add(resolvedUserId);

    if (domain) {
      const resolvedDomainId = domainId(domain);
      if (!seenNodes.has(resolvedDomainId)) {
        nodes.push({ id: resolvedDomainId, type: 'domain', label: domain, domain_name: domain });
        seenNodes.add(resolvedDomainId);
      }
      addEdgeOnce(resolvedUserId, resolvedDomainId, 'MEMBER_OF_DOMAIN', 1.0);
    }
  }

  // Groups
  const groups = data.groups || {};
  for (const [rid, grpObj] of Object.entries(groups as Record<string, any>)) {
    const gName = grpObj.groupname || grpObj.name;
    if (!gName) continue;
    const resolvedGroupId = groupId(gName, domain);
    if (seenNodes.has(resolvedGroupId)) continue;

    nodes.push({
      id: resolvedGroupId,
      type: 'group',
      label: gName,
      domain_name: domain,
    });
    seenNodes.add(resolvedGroupId);

    // Members
    for (const member of (grpObj.members || [])) {
      const memberName = typeof member === 'string' ? member : member.name || member.username;
      if (!memberName) continue;
      const resolvedUserId = userId(memberName, domain);
      if (seenNodes.has(resolvedUserId)) {
        addEdgeOnce(resolvedUserId, resolvedGroupId, 'MEMBER_OF', 1.0);
      }
    }
  }

  // Shares
  const shares = data.shares || {};
  for (const [shareName, shareObj] of Object.entries(shares as Record<string, any>)) {
    if (!targetIp) continue;
    const shareNodeId = `share-${targetIp.replace(/\./g, '-')}-${normalizeKeyPart(shareName)}`;
    if (seenNodes.has(shareNodeId)) continue;

    const access = shareObj.access || {};
    nodes.push({
      id: shareNodeId,
      type: 'share',
      label: `\\\\${targetIp}\\${shareName}`,
      share_name: shareName,
      readable: access.mapping === 'OK' || access.readable === true || undefined,
      writable: access.writable === true || undefined,
    });
    seenNodes.add(shareNodeId);

    const resolvedHostId = hostId(targetIp);
    addEdgeOnce(resolvedHostId, shareNodeId, 'RELATED', 1.0);
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- Rubeus Parser (kerberoast, asreproast, monitor/triage) ---

export function parseRubeus(output: string, agentId: string = 'rubeus-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  if (!output.trim()) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  // Detect subcommand from content patterns
  const hasKerberoastHash = /\$krb5tgs\$/i.test(output);
  const hasAsrepHash = /\$krb5asrep\$/i.test(output);
  const hasBase64Ticket = /Base64EncodedTicket/i.test(output);

  // Parse stanza-based output: blocks delimited by [*] lines
  if (hasKerberoastHash) {
    parseRubeusKerberoast(output, nodes, edges, seenNodes, now, agentId);
  }
  if (hasAsrepHash) {
    parseRubeusAsreproast(output, nodes, edges, seenNodes, now, agentId);
  }
  if (hasBase64Ticket) {
    parseRubeusMonitor(output, nodes, edges, seenNodes, now, agentId);
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

function parseRubeusKerberoast(
  output: string, nodes: Finding['nodes'], edges: Finding['edges'],
  seenNodes: Set<string>, now: string, agentId: string,
): void {
  // Split into blocks per user — Rubeus outputs [*] SamAccountName : ... per entry
  const blocks = output.split(/(?=\[\*\]\s*SamAccountName\s*:)/i);

  for (const block of blocks) {
    const samMatch = block.match(/SamAccountName\s*:\s*(\S+)/i);
    const spnMatch = block.match(/ServicePrincipalName\s*:\s*(\S+)/i);
    const hashMatch = block.match(/Hash\s*:\s*(\$krb5tgs\$[^\s]+)/i);
    // Handle multi-line hashes (Rubeus wraps long hashes)
    const multiLineHash = block.match(/Hash\s*:\s*([\s\S]*?)(?=\n\s*\n|\[\*\]|$)/i);

    if (!samMatch) continue;
    const username = samMatch[1];
    let hash = hashMatch ? hashMatch[1] : undefined;

    // For multi-line hashes, join and clean
    if (!hash && multiLineHash) {
      hash = multiLineHash[1].replace(/\s+/g, '').trim();
      if (!hash.startsWith('$krb5tgs$')) hash = undefined;
    }

    // Extract domain from SPN or hash
    let domain: string | undefined;
    const domainFromHash = hash?.match(/\$krb5tgs\$\d+\$\*[^$]+\$([^$*]+)\$/);
    if (domainFromHash) domain = domainFromHash[1];

    // User node with has_spn
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

    // Credential node for the TGS hash
    if (hash) {
      const resolvedCredId = credentialId('kerberos_tgs', hash, username, domain);
      if (!seenNodes.has(resolvedCredId)) {
        nodes.push({
          id: resolvedCredId,
          type: 'credential',
          label: `TGS:${username}`,
          cred_type: 'kerberos_tgs',
          cred_material_kind: 'kerberos_tgs',
          cred_usable_for_auth: false,
          cred_evidence_kind: 'dump',
          cred_value: hash,
          cred_user: username,
          cred_domain: domain,
        });
        seenNodes.add(resolvedCredId);
      }
      edges.push({
        source: resolvedUserId,
        target: resolvedCredId,
        properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
    }
  }
}

function parseRubeusAsreproast(
  output: string, nodes: Finding['nodes'], edges: Finding['edges'],
  seenNodes: Set<string>, now: string, agentId: string,
): void {
  const blocks = output.split(/(?=\[\*\]\s*User\s*:)/i);

  for (const block of blocks) {
    const userMatch = block.match(/User\s*:\s*(\S+)/i);
    const hashMatch = block.match(/Hash\s*:\s*(\$krb5asrep\$[^\s]+)/i);
    const multiLineHash = block.match(/Hash\s*:\s*([\s\S]*?)(?=\n\s*\n|\[\*\]|$)/i);

    if (!userMatch) continue;
    const username = userMatch[1];
    let hash = hashMatch ? hashMatch[1] : undefined;

    if (!hash && multiLineHash) {
      hash = multiLineHash[1].replace(/\s+/g, '').trim();
      if (!hash.startsWith('$krb5asrep$')) hash = undefined;
    }

    // Extract domain from hash: $krb5asrep$user@DOMAIN:...
    let domain: string | undefined;
    const domainFromHash = hash?.match(/\$krb5asrep\$[^@]*@([^:]+)/);
    if (domainFromHash) domain = domainFromHash[1];

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

    if (hash) {
      const resolvedCredId = credentialId('kerberos_tgs', hash, username, domain);
      if (!seenNodes.has(resolvedCredId)) {
        nodes.push({
          id: resolvedCredId,
          type: 'credential',
          label: `ASREP:${username}`,
          cred_type: 'kerberos_tgs',
          cred_material_kind: 'kerberos_tgs',
          cred_usable_for_auth: false,
          cred_evidence_kind: 'dump',
          cred_value: hash,
          cred_user: username,
          cred_domain: domain,
        });
        seenNodes.add(resolvedCredId);
      }
      edges.push({
        source: resolvedUserId,
        target: resolvedCredId,
        properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
    }
  }
}

function parseRubeusMonitor(
  output: string, nodes: Finding['nodes'], edges: Finding['edges'],
  seenNodes: Set<string>, now: string, agentId: string,
): void {
  // Split on User lines in monitor/triage output
  const blocks = output.split(/(?=\[\*\]\s*User\s*:)/i);

  for (const block of blocks) {
    const userMatch = block.match(/User\s*:\s*(\S+)/i);
    const ticketMatch = block.match(/Base64EncodedTicket\s*:\s*(\S+)/i);
    const serviceMatch = block.match(/Service\s*:\s*(\S+)/i);

    if (!userMatch || !ticketMatch) continue;
    const rawUser = userMatch[1];
    const ticket = ticketMatch[1];
    const service = serviceMatch ? serviceMatch[1] : undefined;

    // Parse DOMAIN\user or user
    const { domain, username } = splitQualifiedAccount(rawUser);

    // Skip machine accounts
    if (username.endsWith('$')) continue;

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

    // Determine if TGT or TGS based on service field
    const isTgt = !service || service.toLowerCase().startsWith('krbtgt/');
    const credType = isTgt ? 'kerberos_tgt' : 'kerberos_tgs';
    const materialKind = isTgt ? 'kerberos_tgt' : 'kerberos_tgs';

    const resolvedCredId = credentialId(materialKind, ticket.slice(0, 40), username, domain);
    if (!seenNodes.has(resolvedCredId)) {
      nodes.push({
        id: resolvedCredId,
        type: 'credential',
        label: `${isTgt ? 'TGT' : 'TGS'}:${username}`,
        cred_type: credType,
        cred_material_kind: materialKind,
        cred_usable_for_auth: true,
        cred_evidence_kind: 'capture',
        cred_value: ticket,
        cred_user: username,
        cred_domain: domain,
      });
      seenNodes.add(resolvedCredId);
    }

    edges.push({
      source: resolvedUserId,
      target: resolvedCredId,
      properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: now, discovered_by: agentId },
    });
  }
}

// --- gobuster / feroxbuster / ffuf Parser ---

const LOGIN_PATH_PATTERNS = /\/(login|signin|auth|wp-login|admin|weblogin|sso|cas|saml|oauth)/i;

export function parseWebDirEnum(output: string, agentId: string = 'webdirenum-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();

  const discoveredPaths: Array<{ path: string; status: number; size?: number }> = [];
  let targetUrl: string | undefined;
  let hasLoginForm = false;

  if (!output.trim()) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  // Try ffuf JSON first
  try {
    const data = JSON.parse(output);
    if (data.results && Array.isArray(data.results)) {
      targetUrl = data.commandline?.match(/(?:-u\s+)(\S+)/)?.[1] || data.config?.url;
      // Normalize target URL from ffuf config
      if (!targetUrl && data.results.length > 0) {
        const firstUrl = data.results[0].url || '';
        const parsed = firstUrl.match(/^(https?:\/\/[^/]+)/i);
        if (parsed) targetUrl = parsed[1];
      }

      for (const r of data.results) {
        const url = r.url || '';
        const status = r.status || 0;
        const size = r.length || r.content_length || r.words || undefined;
        const path = url.replace(/^https?:\/\/[^/]+/i, '') || '/';
        discoveredPaths.push({ path, status, size });
        if (LOGIN_PATH_PATTERNS.test(path)) hasLoginForm = true;
      }
      return buildWebDirEnumFinding(targetUrl, discoveredPaths, hasLoginForm, agentId, now);
    }
  } catch {
    // Not JSON — try line-based
  }

  for (const rawLine of output.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;

    // Gobuster: /path (Status: 200) [Size: 1234]
    const gobusterMatch = line.match(/^(\/\S*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?/);
    if (gobusterMatch) {
      const [, path, status, size] = gobusterMatch;
      discoveredPaths.push({ path, status: parseInt(status), size: size ? parseInt(size) : undefined });
      if (LOGIN_PATH_PATTERNS.test(path)) hasLoginForm = true;
      continue;
    }

    // Feroxbuster: 200 GET 1234l 5678w 91011c http://target/path
    const feroxMatch = line.match(/^(\d{3})\s+\w+\s+\d+l?\s+\d+w?\s+(\d+)c?\s+(https?:\/\/\S+)/);
    if (feroxMatch) {
      const [, status, size, url] = feroxMatch;
      const path = url.replace(/^https?:\/\/[^/]+/i, '') || '/';
      if (!targetUrl) {
        const baseMatch = url.match(/^(https?:\/\/[^/]+)/i);
        if (baseMatch) targetUrl = baseMatch[1];
      }
      discoveredPaths.push({ path, status: parseInt(status), size: parseInt(size) });
      if (LOGIN_PATH_PATTERNS.test(path)) hasLoginForm = true;
      continue;
    }

    // Gobuster URL in output header: Url: http://target
    const urlMatch = line.match(/^(?:Target|Url):\s*(https?:\/\/\S+)/i);
    if (urlMatch && !targetUrl) {
      targetUrl = urlMatch[1].replace(/\/+$/, '');
    }
  }

  return buildWebDirEnumFinding(targetUrl, discoveredPaths, hasLoginForm, agentId, now);
}

function buildWebDirEnumFinding(
  targetUrl: string | undefined,
  discoveredPaths: Array<{ path: string; status: number; size?: number }>,
  hasLoginForm: boolean,
  agentId: string,
  now: string,
): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];

  if (discoveredPaths.length === 0) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  // Build a synthetic service node for enrichment
  // Extract host:port from URL to create a stable service node ID
  let serviceId = 'svc-unknown-http';
  let hostNodeId: string | undefined;

  if (targetUrl) {
    const urlParts = targetUrl.match(/^(https?):\/\/([^:/]+)(?::(\d+))?/i);
    if (urlParts) {
      const [, scheme, host, portStr] = urlParts;
      const port = portStr ? parseInt(portStr) : (scheme === 'https' ? 443 : 80);
      const hostKey = host.replace(/[.\s]/g, '-');
      serviceId = `svc-${hostKey}-${port}`;
      hostNodeId = `host-${hostKey}`;

      // Create host node
      const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(host);
      nodes.push({
        id: hostNodeId,
        type: 'host',
        label: host,
        ip: isIp ? host : undefined,
        hostname: isIp ? undefined : host,
        alive: true,
      });

      // Create service node
      nodes.push({
        id: serviceId,
        type: 'service',
        label: `${scheme}/${port}`,
        port,
        protocol: 'tcp',
        service_name: scheme,
        discovered_paths: discoveredPaths,
        has_login_form: hasLoginForm || undefined,
      });

      edges.push({
        source: hostNodeId,
        target: serviceId,
        properties: { type: 'RUNS', confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
    }
  }

  // If we couldn't parse a URL, still emit a service-like node
  if (nodes.length === 0) {
    nodes.push({
      id: serviceId,
      type: 'service',
      label: 'http (unknown target)',
      service_name: 'http',
      discovered_paths: discoveredPaths,
      has_login_form: hasLoginForm || undefined,
    });
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- Registry ---

const PARSERS: Record<string, (output: string, agentId?: string, context?: ParseContext) => Finding> = {
  'nmap': parseNmapXml,
  'nmap-xml': parseNmapXml,
  'netexec': parseNxc,
  'nxc': parseNxc,
  'certipy': parseCertipy,
  'secretsdump': parseSecretsdump,
  'impacket-secretsdump': parseSecretsdump,
  'kerbrute': parseKerbrute,
  'hashcat': parseHashcat,
  'responder': parseResponder,
  'ldapsearch': parseLdapsearch,
  'ldapdomaindump': parseLdapsearch,
  'ldap': parseLdapsearch,
  'enum4linux': parseEnum4linux,
  'enum4linux-ng': parseEnum4linux,
  'rubeus': parseRubeus,
  'gobuster': parseWebDirEnum,
  'feroxbuster': parseWebDirEnum,
  'ffuf': parseWebDirEnum,
  'dirbuster': parseWebDirEnum,
};

export function getSupportedParsers(): string[] {
  return Object.keys(PARSERS);
}

export function parseOutput(toolName: string, output: string, agentId?: string, context?: ParseContext): Finding | null {
  const parser = PARSERS[toolName.toLowerCase()];
  if (!parser) return null;
  return parser(output, agentId, context);
}

function parseUpn(value: string): { username: string; domain: string } | null {
  const atIndex = value.indexOf('@');
  if (atIndex <= 0 || atIndex === value.length - 1) return null;
  return {
    username: value.slice(0, atIndex),
    domain: value.slice(atIndex + 1),
  };
}

function parseKerbruteLogin(value: string): { username: string; domain: string; password: string } | null {
  const atIndex = value.indexOf('@');
  if (atIndex <= 0 || atIndex === value.length - 1) return null;

  const username = value.slice(0, atIndex);
  const remainder = value.slice(atIndex + 1);
  const colonIndex = remainder.indexOf(':');
  // colonIndex <= 0: no domain; === length-1: empty password (intentional — Kerbrute won't report empty-password success)
  if (colonIndex <= 0 || colonIndex === remainder.length - 1) return null;

  return {
    username,
    domain: remainder.slice(0, colonIndex),
    password: remainder.slice(colonIndex + 1),
  };
}
