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

// --- Registry ---

const PARSERS: Record<string, (output: string, agentId?: string) => Finding> = {
  'nmap': parseNmapXml,
  'nmap-xml': parseNmapXml,
  'netexec': parseNxc,
  'nxc': parseNxc,
  'certipy': parseCertipy,
};

export function getSupportedParsers(): string[] {
  return Object.keys(PARSERS);
}

export function parseOutput(toolName: string, output: string, agentId?: string): Finding | null {
  const parser = PARSERS[toolName.toLowerCase()];
  if (!parser) return null;
  return parser(output, agentId);
}
