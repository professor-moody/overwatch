// ============================================================
// Output Parsers
// Parse common offensive tool outputs into structured Findings
// ============================================================

import type { Finding, NodeType, EdgeType } from '../types.js';
import { v4 as uuidv4 } from 'uuid';

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
    const hostId = `host-${host.ip.replace(/\./g, '-')}`;

    nodes.push({
      id: hostId,
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
        source: hostId,
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

function extractNmapHosts(xml: string): NmapHost[] {
  const hosts: NmapHost[] = [];

  // Extract each <host>...</host> block
  const hostBlocks = xml.match(/<host[^>]*>[\s\S]*?<\/host>/gi) || [];

  for (const block of hostBlocks) {
    // IP address
    const addrMatch = block.match(/<address\s+addr="([^"]+)"\s+addrtype="ipv4"/i);
    if (!addrMatch) continue;
    const ip = addrMatch[1];

    // Status
    const statusMatch = block.match(/<status\s+state="([^"]+)"/i);
    const alive = statusMatch ? statusMatch[1] === 'up' : true;

    // Hostname
    const hostnameMatch = block.match(/<hostname\s+name="([^"]+)"/i);
    const hostname = hostnameMatch ? hostnameMatch[1] : undefined;

    // OS
    const osMatch = block.match(/<osmatch\s+name="([^"]+)"/i);
    const os = osMatch ? osMatch[1] : undefined;

    // Ports
    const ports: NmapHost['ports'] = [];
    const portBlocks = block.match(/<port[^>]*>[\s\S]*?<\/port>/gi) || [];
    for (const portBlock of portBlocks) {
      const portMatch = portBlock.match(/<port\s+protocol="([^"]+)"\s+portid="(\d+)"/i);
      if (!portMatch) continue;

      const stateMatch = portBlock.match(/<state\s+state="([^"]+)"/i);
      const serviceMatch = portBlock.match(/<service\s+([^>]+)/i);

      let service: string | undefined;
      let version: string | undefined;
      let banner: string | undefined;

      if (serviceMatch) {
        const svcAttrs = serviceMatch[1];
        const nameMatch = svcAttrs.match(/name="([^"]+)"/);
        const productMatch = svcAttrs.match(/product="([^"]+)"/);
        const versionMatch = svcAttrs.match(/version="([^"]+)"/);
        const extrainfoMatch = svcAttrs.match(/extrainfo="([^"]+)"/);

        service = nameMatch ? nameMatch[1] : undefined;
        version = [productMatch?.[1], versionMatch?.[1]].filter(Boolean).join(' ') || undefined;
        banner = extrainfoMatch ? extrainfoMatch[1] : undefined;
      }

      ports.push({
        port: parseInt(portMatch[2]),
        protocol: portMatch[1],
        state: stateMatch ? stateMatch[1] : 'unknown',
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
      const hostId = `host-${ip.replace(/\./g, '-')}`;

      if (!seenNodes.has(hostId)) {
        nodes.push({ id: hostId, type: 'host', label: ip, ip, alive: true });
        seenNodes.add(hostId);
      }

      // Check for Pwn3d! (admin access)
      if (message.includes('Pwn3d!')) {
        const credMatch = rest.match(/([^\\]+)\\([^\s]+)/);
        if (credMatch) {
          const [, domain, username] = credMatch;
          const userId = `user-${domain.toLowerCase()}-${username.toLowerCase()}`;
          if (!seenNodes.has(userId)) {
            nodes.push({ id: userId, type: 'user', label: `${domain}\\${username}`, username, domain_name: domain, privileged: true });
            seenNodes.add(userId);
          }
          edges.push({
            source: userId,
            target: hostId,
            properties: { type: 'ADMIN_TO', confidence: 1.0, discovered_at: new Date().toISOString(), discovered_by: agentId },
          });
        }
      }

      // Check for valid auth (+ status)
      if (status === '+') {
        const credMatch = rest.match(/([^\\]+)\\([^\s]+)/);
        if (credMatch) {
          const [, domain, username] = credMatch;
          const userId = `user-${domain.toLowerCase()}-${username.toLowerCase()}`;
          if (!seenNodes.has(userId)) {
            nodes.push({ id: userId, type: 'user', label: `${domain}\\${username}`, username, domain_name: domain });
            seenNodes.add(userId);
          }
          edges.push({
            source: userId,
            target: hostId,
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
      const hostId = `host-${ip.replace(/\./g, '-')}`;
      const shareId = `share-${ip.replace(/\./g, '-')}-${shareName.toLowerCase()}`;

      if (!seenNodes.has(hostId)) {
        nodes.push({ id: hostId, type: 'host', label: ip, ip, alive: true });
        seenNodes.add(hostId);
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
    let domain: string | undefined;
    let username: string;
    if (rawUser.includes('\\')) {
      const parts = rawUser.split('\\');
      domain = parts[0];
      username = parts[1];
    } else {
      username = rawUser;
    }

    // Skip machine accounts
    if (username.endsWith('$')) continue;

    const userLower = username.toLowerCase();
    const credId = `cred-ntlm-${userLower}-${nthash.substring(0, 8)}`;
    const userId = domain
      ? `user-${domain.toLowerCase()}-${userLower}`
      : `user-${userLower}`;
    const isPrivileged = PRIVILEGED_ACCOUNTS.has(userLower);

    if (!seenNodes.has(credId)) {
      nodes.push({
        id: credId,
        type: 'credential',
        label: `NTLM:${username}`,
        cred_type: 'ntlm',
        cred_value: nthash,
        cred_user: username,
        cred_domain: domain,
        privileged: isPrivileged || undefined,
      });
      seenNodes.add(credId);
    }

    if (!seenNodes.has(userId)) {
      nodes.push({
        id: userId,
        type: 'user',
        label: domain ? `${domain}\\${username}` : username,
        username,
        domain_name: domain,
        privileged: isPrivileged || undefined,
      });
      seenNodes.add(userId);
    }

    edges.push({
      source: userId,
      target: credId,
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
    const enumMatch = line.match(/\[\+\]\s*VALID USERNAME:\s*(\S+)@(\S+)/i);
    if (enumMatch) {
      const [, username, domain] = enumMatch;
      const userLower = username.toLowerCase();
      const domainLower = domain.toLowerCase();
      const userId = `user-${domainLower.replace(/\./g, '-')}-${userLower}`;
      const domainId = `domain-${domainLower.replace(/\./g, '-')}`;

      if (!seenNodes.has(userId)) {
        nodes.push({ id: userId, type: 'user', label: `${username}@${domain}`, username, domain_name: domain });
        seenNodes.add(userId);
      }
      if (!seenNodes.has(domainId)) {
        nodes.push({ id: domainId, type: 'domain', label: domain, domain_name: domain });
        seenNodes.add(domainId);
      }
      edges.push({
        source: userId,
        target: domainId,
        properties: { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
      continue;
    }

    // Password spray: [+] VALID LOGIN:\tuser@domain:password
    const sprayMatch = line.match(/\[\+\]\s*VALID LOGIN:\s*(\S+)@(\S+):(.+)/i);
    if (sprayMatch) {
      const [, username, domain, password] = sprayMatch;
      const userLower = username.toLowerCase();
      const domainLower = domain.toLowerCase();
      const userId = `user-${domainLower.replace(/\./g, '-')}-${userLower}`;
      const domainId = `domain-${domainLower.replace(/\./g, '-')}`;
      const credId = `cred-plaintext-${userLower}-${domainLower.replace(/\./g, '-')}`;

      if (!seenNodes.has(userId)) {
        nodes.push({ id: userId, type: 'user', label: `${username}@${domain}`, username, domain_name: domain });
        seenNodes.add(userId);
      }
      if (!seenNodes.has(domainId)) {
        nodes.push({ id: domainId, type: 'domain', label: domain, domain_name: domain });
        seenNodes.add(domainId);
      }
      if (!seenNodes.has(credId)) {
        nodes.push({
          id: credId,
          type: 'credential',
          label: `${username}:***`,
          cred_type: 'plaintext',
          cred_value: password,
          cred_user: username,
          cred_domain: domain,
        });
        seenNodes.add(credId);
      }

      edges.push({
        source: userId,
        target: domainId,
        properties: { type: 'MEMBER_OF_DOMAIN', confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
      edges.push({
        source: userId,
        target: credId,
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

    const credId = `cred-cracked-${hashType}-${(username || hashValue || '').substring(0, 16).toLowerCase().replace(/[^a-z0-9]/g, '-')}`;
    if (seenNodes.has(credId)) continue;

    nodes.push({
      id: credId,
      type: 'credential',
      label: username ? `${username}:***` : `cracked:${hashType}`,
      cred_type: 'plaintext',
      cred_value: plaintext,
      cred_user: username,
      cred_domain: domain,
      cred_hash: hashValue,
    });
    seenNodes.add(credId);

    if (username) {
      const userLower = username.toLowerCase();
      const userId = domain
        ? `user-${domain.toLowerCase().replace(/\./g, '-')}-${userLower}`
        : `user-${userLower}`;

      if (!seenNodes.has(userId)) {
        nodes.push({
          id: userId,
          type: 'user',
          label: domain ? `${domain}\\${username}` : username,
          username,
          domain_name: domain,
        });
        seenNodes.add(userId);
      }

      edges.push({
        source: userId,
        target: credId,
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

    const userLower = username.toLowerCase();
    const domainLower = domain.toLowerCase();
    const hostId = `host-${clientIp.replace(/\./g, '-')}`;
    const userId = `user-${domainLower}-${userLower}`;
    const credId = `cred-ntlmv2-${userLower}-${clientIp.replace(/\./g, '-')}`;

    if (!seenNodes.has(hostId)) {
      nodes.push({ id: hostId, type: 'host', label: clientIp, ip: clientIp, alive: true });
      seenNodes.add(hostId);
    }
    if (!seenNodes.has(userId)) {
      nodes.push({ id: userId, type: 'user', label: `${domain}\\${username}`, username, domain_name: domain });
      seenNodes.add(userId);
    }
    if (!seenNodes.has(credId)) {
      nodes.push({
        id: credId,
        type: 'credential',
        label: `NTLMv2:${username}`,
        cred_type: 'ntlm',
        cred_value: hash,
        cred_user: username,
        cred_domain: domain,
      });
      seenNodes.add(credId);
    }

    edges.push({
      source: userId,
      target: credId,
      properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: now, discovered_by: agentId },
    });
    edges.push({
      source: userId,
      target: hostId,
      properties: { type: 'HAS_SESSION', confidence: 0.9, discovered_at: now, discovered_by: agentId },
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
