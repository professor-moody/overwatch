import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { hostId, vulnerabilityId, webappId } from '../parser-utils.js';

export function parseNikto(output: string, agentId: string = 'nikto-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const seenNodes = new Set<string>();
  const seenEdges = new Set<string>();

  if (!output.trim()) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  // Try JSON format first
  try {
    const data = JSON.parse(output);
    // Nikto JSON can be an object with host info or array
    const hosts = Array.isArray(data) ? data : [data];

    for (const hostData of hosts) {
      const ip = hostData.ip || hostData.host || '';
      const port = hostData.port || 80;
      const proto = port === 443 || hostData.ssl ? 'https' : 'http';
      const targetUrl = `${proto}://${ip}:${port}`;

      processNiktoTarget(ip, port, proto, targetUrl, hostData.vulnerabilities || [], nodes, edges, seenNodes, seenEdges, now, hostData.banner);
    }

    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  } catch {
    // Not JSON — parse text mode
  }

  // Text mode parsing
  let targetIp = '';
  let targetPort = 80;
  let targetProto = 'http';
  let serverBanner = '';
  const vulns: Array<{ id: string; osvdb: string; msg: string; path: string }> = [];

  for (const rawLine of output.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    // Target IP/port extraction
    const targetMatch = line.match(/^\+\s*Target IP:\s*(\S+)/i);
    if (targetMatch) { targetIp = targetMatch[1]; continue; }

    const portMatch = line.match(/^\+\s*Target Port:\s*(\d+)/i);
    if (portMatch) { targetPort = parseInt(portMatch[1]); continue; }

    // SSL detection
    if (/SSL Info:/i.test(line) || /^\+\s*Target.*https/i.test(line)) {
      targetProto = 'https';
    }

    // Server banner
    const serverMatch = line.match(/^\+\s*Server:\s*(.+)/i);
    if (serverMatch) { serverBanner = serverMatch[1].trim(); continue; }

    // Vulnerability lines: + /path: Description (OSVDB-XXXX) or + OSVDB-XXXX: /path: Description
    const vulnMatch1 = line.match(/^\+\s*(OSVDB-(\d+)):\s*(\/\S*)\s*:\s*(.+)/);
    if (vulnMatch1) {
      vulns.push({ id: vulnMatch1[1], osvdb: vulnMatch1[2], path: vulnMatch1[3], msg: vulnMatch1[4] });
      continue;
    }

    const vulnMatch2 = line.match(/^\+\s*(\/\S+)\s*:\s*(.+?)(?:\s*\((OSVDB-(\d+))\))?\.?\s*$/);
    if (vulnMatch2) {
      vulns.push({
        id: vulnMatch2[3] || `nikto-${vulns.length}`,
        osvdb: vulnMatch2[4] || '',
        path: vulnMatch2[1],
        msg: vulnMatch2[2],
      });
      continue;
    }
  }

  if (targetIp) {
    const targetUrl = `${targetProto}://${targetIp}:${targetPort}`;
    processNiktoTarget(targetIp, targetPort, targetProto, targetUrl, vulns, nodes, edges, seenNodes, seenEdges, now, serverBanner);
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

function processNiktoTarget(
  ip: string,
  port: number,
  proto: string,
  targetUrl: string,
  vulns: Array<{ id?: string; osvdb?: string; OSVDB?: string; msg?: string; message?: string; url?: string; path?: string; method?: string }>,
  nodes: Finding['nodes'],
  edges: Finding['edges'],
  seenNodes: Set<string>,
  seenEdges: Set<string>,
  now: string,
  serverBanner?: string,
): void {
  // Host node
  const hId = hostId(ip);
  if (!seenNodes.has(hId)) {
    seenNodes.add(hId);
    const isIpAddr = /^\d+\.\d+\.\d+\.\d+$/.test(ip);
    nodes.push({
      id: hId,
      type: 'host',
      label: ip,
      discovered_at: now,
      confidence: 1.0,
      ...(isIpAddr ? { ip } : { hostname: ip }),
    } as Finding['nodes'][0]);
  }

  // Service node — canonical format: svc-{ip-dashed}-{port} (no proto suffix)
  const svcId = `svc-${ip.replace(/\./g, '-')}-${port}`;
  if (!seenNodes.has(svcId)) {
    seenNodes.add(svcId);
    const svcProps: Record<string, unknown> = {
      id: svcId,
      type: 'service',
      label: `${proto}/${port}`,
      discovered_at: now,
      confidence: 1.0,
      port,
      protocol: 'tcp',
      service_name: proto,
    };
    if (serverBanner) {
      svcProps.version = serverBanner;
      svcProps.banner = serverBanner;
    }
    nodes.push(svcProps as Finding['nodes'][0]);
    edges.push({
      source: hId,
      target: svcId,
      properties: { type: 'RUNS', confidence: 1.0, discovered_at: now },
    });
  }

  // Webapp node
  const waId = webappId(targetUrl);
  if (!seenNodes.has(waId)) {
    seenNodes.add(waId);
    nodes.push({
      id: waId,
      type: 'webapp',
      label: targetUrl,
      discovered_at: now,
      confidence: 1.0,
      url: targetUrl,
    } as Finding['nodes'][0]);
    edges.push({
      source: svcId,
      target: waId,
      properties: { type: 'HOSTS', confidence: 1.0, discovered_at: now },
    });
  }

  // Vulnerability nodes
  for (const v of vulns) {
    const osvdb = v.osvdb || v.OSVDB || '';
    const vId = v.id || (osvdb ? `OSVDB-${osvdb}` : `nikto-finding`);
    const msg = v.msg || v.message || vId;
    const vulnId = vulnerabilityId(vId, waId);

    if (!seenNodes.has(vulnId)) {
      seenNodes.add(vulnId);
      nodes.push({
        id: vulnId,
        type: 'vulnerability',
        label: msg,
        discovered_at: now,
        confidence: 1.0,
        vuln_type: 'misc',
        affected_component: msg,
      } as Finding['nodes'][0]);
    }

    const edgeKey = `${waId}->${vulnId}`;
    if (!seenEdges.has(edgeKey)) {
      seenEdges.add(edgeKey);
      edges.push({
        source: waId,
        target: vulnId,
        properties: { type: 'VULNERABLE_TO', confidence: 0.7, discovered_at: now },
      });
    }
  }
}
