import type { Finding } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { XMLParser } from 'fast-xml-parser';
import { hostId } from '../parser-utils.js';

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

export function normalizeServiceName(raw?: string): string | undefined {
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
