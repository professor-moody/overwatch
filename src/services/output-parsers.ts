// ============================================================
// Output Parsers
// Parse common offensive tool outputs into structured Findings
// ============================================================

import type { Finding, NodeType, EdgeType } from '../types.js';
import { v4 as uuidv4 } from 'uuid';
import { XMLParser } from 'fast-xml-parser';
import { credentialId, domainId, hostId, splitQualifiedAccount, userId } from './parser-utils.js';

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

export function parseNmapXml(xml: string, agentId: string = 'nmap-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const hosts = extractNmapHosts(xml);

  for (const host of hosts) {
    const resolvedHostId = hostId(host.ip);

    nodes.push({
      id: resolvedHostId,
      type: 'host',
      label: host.hostname || host.ip,
      ip: host.ip,
      hostname: host.hostname,
      os: host.os,
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

export function parseNxc(output: string, agentId: string = 'nxc-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const lines = output.split('\n');
  const seenNodes = new Set<string>();

  for (const line of lines) {
    // Match NXC output: PROTOCOL  target:port  domain\user  [+/-] message
    // Example: SMB  10.10.10.5  445  ACME\jdoe  [+]  (Pwn3d!)
    const smbMatch = line.match(/SMB\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(.*?)(?:\s+\[([+-])\])\s*(.*)/i);
    if (smbMatch) {
      const [, ip, port, rest, status, message] = smbMatch;
      const resolvedHostId = hostId(ip);

      if (!seenNodes.has(resolvedHostId)) {
        nodes.push({ id: resolvedHostId, type: 'host', label: ip, ip, alive: true });
        seenNodes.add(resolvedHostId);
      }

      // Check for Pwn3d! (admin access)
      if (message.includes('Pwn3d!')) {
        const credMatch = rest.match(/([^\\]+)\\([^\s]+)/);
        if (credMatch) {
          const [, domain, username] = credMatch;
          const resolvedUserId = userId(username, domain);
          if (!seenNodes.has(resolvedUserId)) {
            nodes.push({ id: resolvedUserId, type: 'user', label: `${domain}\\${username}`, username, domain_name: domain, privileged: true });
            seenNodes.add(resolvedUserId);
          }
          edges.push({
            source: resolvedUserId,
            target: resolvedHostId,
            properties: { type: 'ADMIN_TO', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: agentId },
          });
        }
      }

      // Check for valid auth (+ status)
      if (status === '+') {
        const credMatch = rest.match(/([^\\]+)\\([^\s]+)/);
        if (credMatch) {
          const [, domain, username] = credMatch;
          const resolvedUserId = userId(username, domain);
          if (!seenNodes.has(resolvedUserId)) {
            nodes.push({ id: resolvedUserId, type: 'user', label: `${domain}\\${username}`, username, domain_name: domain });
            seenNodes.add(resolvedUserId);
          }
          edges.push({
            source: resolvedUserId,
            target: resolvedHostId,
            properties: { type: 'VALID_ON', confidence: 0.9, discovered_at: new Date().toISOString(), discovered_by: agentId },
          });
        }
      }

      continue;
    }

    // Share enumeration: SMB 10.10.10.5 445 SHARE sharename READ/WRITE
    const shareMatch = line.match(/SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)\s+(READ|WRITE|READ,\s*WRITE)/i);
    if (shareMatch) {
      const [, ip, shareName, perms] = shareMatch;
      const resolvedHostId = hostId(ip);
      const shareId = `share-${ip.replace(/\./g, '-')}-${shareName.toLowerCase()}`;

      if (!seenNodes.has(resolvedHostId)) {
        nodes.push({ id: resolvedHostId, type: 'host', label: ip, ip, alive: true });
        seenNodes.add(resolvedHostId);
      }
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
        const caId = `ca-${caName.replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase()}`;
        if (!seenNodes.has(caId)) {
          nodes.push({
            id: caId,
            type: 'certificate',
            label: caName,
            ca_name: caName,
          });
          seenNodes.add(caId);
        }
      }
    }

    // Certificate Templates
    if (data['Certificate Templates']) {
      for (const [templateName, templateData] of Object.entries(data['Certificate Templates'] as Record<string, any>)) {
        const tmplId = `cert-${templateName.replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase()}`;
        const tmpl = templateData as Record<string, any>;

        const enrolleeSuppliesSubject = tmpl['Enrollee Supplies Subject'] === true ||
          tmpl['Client Authentication'] === true;

        if (!seenNodes.has(tmplId)) {
          nodes.push({
            id: tmplId,
            type: 'certificate',
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
                  const principalId = `user-${principal.replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase()}`;
                  if (!seenNodes.has(principalId)) {
                    nodes.push({ id: principalId, type: 'user', label: principal });
                    seenNodes.add(principalId);
                  }
                  edges.push({
                    source: principalId,
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
        const tmplId = `cert-${templateMatch[1].trim().replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase()}`;
        if (!seenNodes.has(tmplId)) {
          nodes.push({
            id: tmplId,
            type: 'certificate',
            label: templateMatch[1].trim(),
            template_name: templateMatch[1].trim(),
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

export function parseSecretsdump(output: string, agentId: string = 'secretsdump-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  for (const line of output.split('\n')) {
    const m = line.trim().match(SECRETSDUMP_LINE);
    if (!m) continue;

    const [, rawUser, , , nthash] = m;

    // Parse DOMAIN\user or plain user
    const { domain, username } = splitQualifiedAccount(rawUser);

    // Skip machine accounts
    if (username.endsWith('$')) continue;

    const userLower = username.toLowerCase();
    const resolvedCredId = credentialId('ntlm_hash', nthash, username, domain);
    const resolvedUserId = userId(username, domain);
    const isPrivileged = PRIVILEGED_ACCOUNTS.has(userLower);

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
        cred_domain: domain,
        privileged: isPrivileged || undefined,
      });
      seenNodes.add(resolvedCredId);
    }

    if (!seenNodes.has(resolvedUserId)) {
      nodes.push({
        id: resolvedUserId,
        type: 'user',
        label: domain ? `${domain}\\${username}` : username,
        username,
        domain_name: domain,
        privileged: isPrivileged || undefined,
      });
      seenNodes.add(resolvedUserId);
    }

    edges.push({
      source: resolvedUserId,
      target: resolvedCredId,
      properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: now, discovered_by: agentId },
    });
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

export function parseHashcat(output: string, agentId: string = 'hashcat-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

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
      label: username ? `${username}:***` : `cracked:${hashType}`,
      cred_type: 'plaintext',
      cred_material_kind: 'plaintext_password',
      cred_usable_for_auth: true,
      cred_evidence_kind: 'crack',
      cred_value: plaintext,
      cred_user: username,
      cred_domain: domain,
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

// --- Registry ---

const PARSERS: Record<string, (output: string, agentId?: string) => Finding> = {
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
};

export function getSupportedParsers(): string[] {
  return Object.keys(PARSERS);
}

export function parseOutput(toolName: string, output: string, agentId?: string): Finding | null {
  const parser = PARSERS[toolName.toLowerCase()];
  if (!parser) return null;
  return parser(output, agentId);
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
