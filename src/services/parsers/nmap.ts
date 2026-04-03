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

      const svcId = `svc-${host.ip.replace(/[.:]/g, '-')}-${port.port}`;
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
  let parsed: Record<string, unknown>;
  try {
    parsed = nmapXmlParser.parse(xml) as Record<string, unknown>;
  } catch {
    return hosts;
  }

  const nmaprun = (parsed.nmaprun ?? parsed) as Record<string, unknown>;
  const rawHostEntries = nmaprun.host;
  const hostEntries = Array.isArray(rawHostEntries) ? rawHostEntries as Record<string, unknown>[] : [];

  for (const h of hostEntries) {
    // IP address — prefer ipv4, fall back to ipv6
    const addresses: Record<string, unknown>[] = Array.isArray(h.address)
      ? h.address as Record<string, unknown>[]
      : h.address ? [h.address as Record<string, unknown>] : [];
    const ipv4 = addresses.find((a) => a['@_addrtype'] === 'ipv4');
    const ipv6 = addresses.find((a) => a['@_addrtype'] === 'ipv6');
    const addrEntry = ipv4 || ipv6;
    if (!addrEntry) continue;
    const ip = addrEntry['@_addr'] as string;

    // Status
    const statusObj = h.status as Record<string, unknown> | undefined;
    const alive = statusObj ? statusObj['@_state'] === 'up' : true;

    // Hostname
    const hostnamesObj = h.hostnames as Record<string, unknown> | undefined;
    const hostnames = hostnamesObj?.hostname;
    const hostnameEntry = (Array.isArray(hostnames) ? hostnames[0] : hostnames) as Record<string, unknown> | undefined;
    const hostname = (hostnameEntry?.['@_name'] as string) || undefined;

    // OS
    const osObj = h.os as Record<string, unknown> | undefined;
    const osmatches = osObj?.osmatch;
    const osEntry = (Array.isArray(osmatches) ? osmatches[0] : osmatches) as Record<string, unknown> | undefined;
    const os = (osEntry?.['@_name'] as string) || undefined;

    // Ports
    const ports: NmapHost['ports'] = [];
    const portsObj = h.ports as Record<string, unknown> | undefined;
    const rawPortEntries = portsObj?.port;
    const portList: Record<string, unknown>[] = Array.isArray(rawPortEntries)
      ? rawPortEntries as Record<string, unknown>[]
      : rawPortEntries ? [rawPortEntries as Record<string, unknown>] : [];

    for (const p of portList) {
      if (!p['@_protocol'] || !p['@_portid']) continue;

      const svc = p.service as Record<string, unknown> | undefined;
      let service: string | undefined;
      let version: string | undefined;
      let banner: string | undefined;

      if (svc) {
        service = (svc['@_name'] as string) || undefined;
        version = [svc['@_product'], svc['@_version']].filter(Boolean).join(' ') || undefined;
        banner = (svc['@_extrainfo'] as string) || undefined;
      }

      ports.push({
        port: parseInt(p['@_portid'] as string),
        protocol: p['@_protocol'] as string,
        state: (p.state as Record<string, unknown>)?.['@_state'] as string || 'unknown',
        service,
        version,
        banner,
      });
    }

    hosts.push({ ip, hostname, os, alive, ports });
  }

  return hosts;
}
