import type { Finding } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { XMLParser } from 'fast-xml-parser';
import { hostId, vulnerabilityId } from '../parser-utils.js';

const SEVERITY_MAP: Record<string, string> = {
  '0': 'info',
  '1': 'low',
  '2': 'medium',
  '3': 'high',
  '4': 'critical',
  'None': 'info',
  'Low': 'low',
  'Medium': 'medium',
  'High': 'high',
  'Critical': 'critical',
};

const nessusXmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  allowBooleanAttributes: true,
  isArray: (name) => ['ReportHost', 'ReportItem', 'tag'].includes(name),
  textNodeName: '#text',
});

export function parseNessus(text: string, agentId: string = 'nessus-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const seenNodes = new Set<string>();

  function addNode(node: Finding['nodes'][0]): void {
    if (!seenNodes.has(node.id)) {
      seenNodes.add(node.id);
      nodes.push(node);
    }
  }

  let parsed: Record<string, unknown>;
  try {
    parsed = nessusXmlParser.parse(text) as Record<string, unknown>;
  } catch {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes: [], edges: [] };
  }

  const nessusData = parsed.NessusClientData_v2 as Record<string, unknown> | undefined;
  if (!nessusData) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes: [], edges: [] };
  }

  const report = nessusData.Report as Record<string, unknown> | undefined;
  if (!report) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes: [], edges: [] };
  }

  const rawHosts = report.ReportHost;
  const reportHosts: Record<string, unknown>[] = Array.isArray(rawHosts)
    ? rawHosts as Record<string, unknown>[]
    : rawHosts ? [rawHosts as Record<string, unknown>] : [];

  for (const rh of reportHosts) {
    const hostName = String(rh['@_name'] || '');
    if (!hostName) continue;

    // Parse HostProperties tags
    const hostPropsObj = rh.HostProperties as Record<string, unknown> | undefined;
    const rawTags = hostPropsObj?.tag;
    const tags: Record<string, unknown>[] = Array.isArray(rawTags)
      ? rawTags as Record<string, unknown>[]
      : rawTags ? [rawTags as Record<string, unknown>] : [];

    const tagMap = new Map<string, string>();
    for (const tag of tags) {
      const name = String(tag['@_name'] || '');
      const val = String(tag['#text'] || tag as unknown as string || '');
      if (name) tagMap.set(name, val);
    }

    const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
    const ip = tagMap.get('host-ip') || (IPV4_RE.test(hostName) ? hostName : '');
    const fqdn = tagMap.get('host-fqdn') || tagMap.get('netbios-name') || (!ip ? hostName : undefined);
    const os = tagMap.get('operating-system') || tagMap.get('os') || undefined;

    // Use IP for node ID when available; fall back to hostname (FQDN) for ID only
    const resolvedIp = ip || hostName;
    const hid = hostId(resolvedIp);
    addNode({
      id: hid,
      type: 'host',
      label: fqdn || ip || hostName,
      ip: ip || undefined,
      hostname: fqdn,
      os,
      discovered_at: now,
      discovered_by: agentId,
      confidence: 1.0,
    });

    // Track services we've already created to avoid duplicate svc nodes
    const seenSvcs = new Set<string>();

    const rawItems = rh.ReportItem;
    const reportItems: Record<string, unknown>[] = Array.isArray(rawItems)
      ? rawItems as Record<string, unknown>[]
      : rawItems ? [rawItems as Record<string, unknown>] : [];

    for (const ri of reportItems) {
      const port = parseInt(String(ri['@_port'] || '0'));
      const proto = String(ri['@_protocol'] || 'tcp');
      const svcName = String(ri['@_svc_name'] || '');
      const severity = parseInt(String(ri['@_severity'] || '0'));
      const pluginId = String(ri['@_pluginID'] || '');
      const pluginName = String(ri['@_pluginName'] || '');
      const description = String(ri.description || '').trim();
      const solution = String(ri.solution || '').trim();
      const cveRaw = ri.cve;
      const cve = typeof cveRaw === 'string' ? cveRaw : Array.isArray(cveRaw) ? (cveRaw as string[])[0] : undefined;
      const cvssStr = String(ri.cvss3_base_score || ri.cvss_base_score || '');
      const cvss = cvssStr ? parseFloat(cvssStr) : undefined;
      const riskFactor = String(ri.risk_factor || '');

      // Create service node for any item with a real port
      let targetNodeId = hid;
      if (port > 0) {
        const protoPrefix = proto !== 'tcp' ? `${proto}-` : '';
        const svcId = `svc-${resolvedIp.replace(/[.:]/g, '-')}-${protoPrefix}${port}`;
        targetNodeId = svcId;
        if (!seenSvcs.has(svcId)) {
          seenSvcs.add(svcId);
          addNode({
            id: svcId,
            type: 'service',
            label: `${svcName || 'unknown'}/${port}`,
            port,
            protocol: proto,
            service_name: svcName || undefined,
            discovered_at: now,
            discovered_by: agentId,
            confidence: 1.0,
          });
          edges.push({
            source: hid,
            target: svcId,
            properties: {
              type: 'RUNS',
              confidence: 1.0,
              discovered_at: now,
              discovered_by: agentId,
            },
          });
        }
      }

      // Create vulnerability node for severity >= 1 (port=0 → anchored to host)
      if (severity >= 1) {
        const techId = cve || `plugin-${pluginId}`;
        const vuln_id = vulnerabilityId(techId, targetNodeId);
        const sevLabel = SEVERITY_MAP[String(severity)] || riskFactor.toLowerCase() || 'medium';
        const shortDesc = description.slice(0, 300);
        const vuln_notes = [
          pluginName ? `${pluginName}: ${shortDesc}` : shortDesc,
          solution ? `Remediation: ${solution.slice(0, 200)}` : '',
          sevLabel ? `Severity: ${sevLabel}` : '',
        ].filter(Boolean).join(' | ');

        addNode({
          id: vuln_id,
          type: 'vulnerability',
          label: pluginName || techId,
          cve: cve || undefined,
          cvss: Number.isFinite(cvss) ? cvss : undefined,
          vuln_type: cve ? 'cve' : 'plugin',
          notes: vuln_notes || undefined,
          discovered_at: now,
          discovered_by: agentId,
          confidence: 1.0,
        });
        edges.push({
          source: targetNodeId,
          target: vuln_id,
          properties: {
            type: 'VULNERABLE_TO',
            confidence: 1.0,
            discovered_at: now,
            discovered_by: agentId,
          },
        });
      }
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
