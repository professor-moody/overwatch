import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { XMLParser } from 'fast-xml-parser';
import { hostId, vulnerabilityId } from '../parser-utils.js';

const TLS_KNOWN_VULNS: Record<string, { cve?: string; severity: string }> = {
  'heartbleed': { cve: 'CVE-2014-0160', severity: 'critical' },
  'ccs': { cve: 'CVE-2014-0224', severity: 'high' },
  'ticketbleed': { cve: 'CVE-2016-9244', severity: 'high' },
  'ROBOT': { cve: 'CVE-2017-13099', severity: 'high' },
  'secure_renego': { severity: 'medium' },
  'secure_client_renego': { severity: 'medium' },
  'BEAST': { cve: 'CVE-2011-3389', severity: 'medium' },
  'POODLE_SSL': { cve: 'CVE-2014-3566', severity: 'high' },
  'sweet32': { cve: 'CVE-2016-2183', severity: 'medium' },
  'FREAK': { cve: 'CVE-2015-0204', severity: 'high' },
  'DROWN': { cve: 'CVE-2016-0800', severity: 'high' },
  'LOGJAM': { cve: 'CVE-2015-4000', severity: 'medium' },
  'LUCKY13': { cve: 'CVE-2013-0169', severity: 'medium' },
  'winshock': { cve: 'CVE-2014-6321', severity: 'critical' },
  'RC4': { severity: 'medium' },
};

const TESTSSL_SEVERITY_CVSS: Record<string, number> = {
  critical: 9.5,
  high: 7.5,
  medium: 5.0,
  low: 2.5,
  info: 0,
  ok: 0,
  warn: 5.0,
};

export function parseTestssl(output: string, agentId: string = 'testssl-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const seenNodes = new Set<string>();
  const seenEdges = new Set<string>();

  if (!output.trim()) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  // Try testssl JSON first
  try {
    const data = JSON.parse(output);
    const entries = Array.isArray(data) ? data : (data.scanResult || data.findings || [data]);

    // Group entries by ip:port
    const byTarget = new Map<string, Array<Record<string, unknown>>>();
    for (const entry of entries) {
      if (!entry || typeof entry !== 'object') continue;
      const ip = (entry.ip || entry.IP || '') as string;
      const port = (entry.port || '') as string;
      if (!ip && !port) {
        // Flat array of findings — all for same target
        const key = 'default';
        if (!byTarget.has(key)) byTarget.set(key, []);
        byTarget.get(key)!.push(entry);
        continue;
      }
      const key = `${ip}:${port}`;
      if (!byTarget.has(key)) byTarget.set(key, []);
      byTarget.get(key)!.push(entry);
    }

    for (const [_target, findings] of byTarget) {
      const firstWithIp = findings.find(f => f.ip || f.IP);
      const ip = (firstWithIp?.ip || firstWithIp?.IP || context?.source_host || 'unknown') as string;
      const port = parseInt((firstWithIp?.port || '443') as string) || 443;
      processTestsslFindings(ip, port, findings, nodes, edges, seenNodes, seenEdges, now);
    }

    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  } catch {
    // Not JSON — try sslscan XML
  }

  // sslscan XML parsing
  try {
    const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_' });
    const xml = parser.parse(output);
    const ssltest = xml?.document?.ssltest || xml?.ssltest;
    if (ssltest) {
      const ip = ssltest['@_host'] || context?.source_host || 'unknown';
      const port = parseInt(ssltest['@_port'] || '443') || 443;

      const hId = hostId(ip);
      if (!seenNodes.has(hId)) {
        seenNodes.add(hId);
        nodes.push({
          id: hId,
          type: 'host',
          label: ip,
          discovered_at: now,
          confidence: 1.0,
          ip: /^\d+\.\d+\.\d+\.\d+$/.test(ip) ? ip : undefined,
          hostname: /^\d+\.\d+\.\d+\.\d+$/.test(ip) ? undefined : ip,
        } as Finding['nodes'][0]);
      }

      const proto = 'https';
      const svcId = `svc-${ip.replace(/\./g, '-')}-${port}`;
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

      // Extract cipher suites
      const ciphers = ssltest.cipher;
      if (ciphers) {
        const cipherList = Array.isArray(ciphers) ? ciphers : [ciphers];
        svcProps.cipher_suites = cipherList.map((c: Record<string, string>) => c['@_cipher'] || c.cipher || String(c)).filter(Boolean);
      }

      // Extract certificate info
      const cert = ssltest.certificate;
      if (cert) {
        if (cert.subject) svcProps.cert_subject = cert.subject;
        if (cert.issuer) svcProps.cert_issuer = cert.issuer;
        if (cert['not-valid-after'] || cert.expired) {
          svcProps.cert_expiry = cert['not-valid-after'];
        }
      }

      // Extract TLS version from protocols
      const protocols = ssltest.protocol;
      if (protocols) {
        const protoList = Array.isArray(protocols) ? protocols : [protocols];
        const enabled = protoList
          .filter((p: Record<string, string>) => p['@_enabled'] === '1')
          .map((p: Record<string, string>) => `${p['@_type'] || 'TLS'}${p['@_version'] || ''}`);
        if (enabled.length > 0) svcProps.tls_version = enabled[enabled.length - 1];
      }

      if (!seenNodes.has(svcId)) {
        seenNodes.add(svcId);
        nodes.push(svcProps as Finding['nodes'][0]);
        edges.push({
          source: hId,
          target: svcId,
          properties: { type: 'RUNS', confidence: 1.0, discovered_at: now },
        });
      }

      // Check for weak ciphers / SSLv2 / SSLv3 as vulnerabilities
      if (protocols) {
        const protoList = Array.isArray(protocols) ? protocols : [protocols];
        for (const p of protoList) {
          const ver = `${p['@_type'] || ''}${p['@_version'] || ''}`;
          if (p['@_enabled'] === '1' && (ver.includes('SSLv2') || ver.includes('SSLv3'))) {
            const vulnIdentifier = ver.includes('SSLv3') ? 'POODLE_SSL' : 'SSLv2';
            const known = TLS_KNOWN_VULNS[vulnIdentifier] || TLS_KNOWN_VULNS['POODLE_SSL'];
            const vId = vulnerabilityId(known?.cve || vulnIdentifier, svcId);
            if (!seenNodes.has(vId)) {
              seenNodes.add(vId);
              nodes.push({
                id: vId,
                type: 'vulnerability',
                label: known?.cve || `Weak protocol: ${ver}`,
                discovered_at: now,
                confidence: 1.0,
                cve: known?.cve,
                cvss: TESTSSL_SEVERITY_CVSS[known?.severity || 'medium'] || 5.0,
                vuln_type: 'weak-crypto',
                affected_component: `Protocol ${ver}`,
              } as Finding['nodes'][0]);
            }
            const edgeKey = `${svcId}->${vId}`;
            if (!seenEdges.has(edgeKey)) {
              seenEdges.add(edgeKey);
              edges.push({
                source: svcId,
                target: vId,
                properties: { type: 'VULNERABLE_TO', confidence: 0.9, discovered_at: now },
              });
            }
          }
        }
      }

      return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
    }
  } catch {
    // Not valid sslscan XML either
  }

  // Text-mode fallback for human-readable testssl.sh output
  return parseTestsslText(output, agentId, context);
}

function parseTestsslText(output: string, agentId: string, context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const seenNodes = new Set<string>();
  const seenEdges = new Set<string>();

  // Extract target from testssl header: "Testing ... on <host>:<port>"
  const targetMatch = output.match(/Testing\s+\S+\s+on\s+(\S+):(\d+)/);
  const ip = targetMatch?.[1] || context?.source_host || 'unknown';
  const port = parseInt(targetMatch?.[2] || '443') || 443;

  // Only proceed if we found recognizable testssl output
  if (!targetMatch && !output.includes('Testing protocols') && !output.includes('Testing vulnerabilities')) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges,
      raw_output: 'testssl text format detected but no structured data could be extracted' };
  }

  const hId = hostId(ip);
  if (!seenNodes.has(hId)) {
    seenNodes.add(hId);
    const isIpAddr = /^\d+\.\d+\.\d+\.\d+$/.test(ip);
    nodes.push({
      id: hId, type: 'host', label: ip, discovered_at: now, confidence: 1.0,
      ...(isIpAddr ? { ip } : { hostname: ip }),
    } as Finding['nodes'][0]);
  }

  const svcId = `svc-${ip.replace(/[.:]/g, '-')}-${port}`;
  if (!seenNodes.has(svcId)) {
    seenNodes.add(svcId);
    nodes.push({
      id: svcId, type: 'service', label: `https/${port}`, discovered_at: now,
      confidence: 1.0, port, protocol: 'tcp', service_name: 'https',
    } as Finding['nodes'][0]);
    edges.push({
      source: hId, target: svcId,
      properties: { type: 'RUNS', confidence: 1.0, discovered_at: now },
    });
  }

  // Scan for known vulnerability markers in text output
  for (const [vulnKey, known] of Object.entries(TLS_KNOWN_VULNS)) {
    const vulnPattern = new RegExp(`${vulnKey}[^\\n]*(?:VULNERABLE|NOT ok)`, 'i');
    if (vulnPattern.test(output)) {
      const vId = vulnerabilityId(known.cve || vulnKey, svcId);
      if (!seenNodes.has(vId)) {
        seenNodes.add(vId);
        nodes.push({
          id: vId, type: 'vulnerability', label: known.cve || vulnKey,
          discovered_at: now, confidence: 0.9,
          cve: known.cve, cvss: TESTSSL_SEVERITY_CVSS[known.severity] || 5.0,
          vuln_type: 'weak-crypto', affected_component: vulnKey,
        } as Finding['nodes'][0]);
      }
      const edgeKey = `${svcId}->${vId}`;
      if (!seenEdges.has(edgeKey)) {
        seenEdges.add(edgeKey);
        edges.push({
          source: svcId, target: vId,
          properties: { type: 'VULNERABLE_TO', confidence: 0.8, discovered_at: now },
        });
      }
    }
  }

  // Check for weak protocols (SSLv2/SSLv3 offered)
  const weakProtoPattern = /SSL[v ]?[23]\s+.*(?:offered|yes)/gi;
  let weakMatch: RegExpExecArray | null;
  while ((weakMatch = weakProtoPattern.exec(output)) !== null) {
    const ver = weakMatch[0].includes('2') ? 'SSLv2' : 'SSLv3';
    const known = TLS_KNOWN_VULNS[ver === 'SSLv3' ? 'POODLE_SSL' : 'POODLE_SSL'];
    const vId = vulnerabilityId(known?.cve || ver, svcId);
    if (!seenNodes.has(vId)) {
      seenNodes.add(vId);
      nodes.push({
        id: vId, type: 'vulnerability', label: `Weak protocol: ${ver}`,
        discovered_at: now, confidence: 0.9,
        cve: known?.cve, cvss: TESTSSL_SEVERITY_CVSS[known?.severity || 'high'] || 7.5,
        vuln_type: 'weak-crypto', affected_component: `Protocol ${ver}`,
      } as Finding['nodes'][0]);
    }
    const edgeKey = `${svcId}->${vId}`;
    if (!seenEdges.has(edgeKey)) {
      seenEdges.add(edgeKey);
      edges.push({
        source: svcId, target: vId,
        properties: { type: 'VULNERABLE_TO', confidence: 0.8, discovered_at: now },
      });
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

function processTestsslFindings(
  ip: string,
  port: number,
  findings: Array<Record<string, unknown>>,
  nodes: Finding['nodes'],
  edges: Finding['edges'],
  seenNodes: Set<string>,
  seenEdges: Set<string>,
  now: string,
): void {
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

  const proto = 'https';
  const svcId = `svc-${ip.replace(/\./g, '-')}-${port}`;
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

  // Extract TLS properties from testssl findings
  const cipherSuites: string[] = [];
  for (const f of findings) {
    const id = ((f.id || '') as string).toLowerCase();
    const finding = (f.finding || '') as string;
    const severity = ((f.severity || 'INFO') as string).toLowerCase();

    // TLS version
    if (id.startsWith('protocol_') || id.startsWith('sslv') || id.startsWith('tls')) {
      if (finding.toLowerCase().includes('offered') || finding.toLowerCase().includes('not vulnerable')) {
        // Extract highest TLS version
        const verMatch = id.match(/(tls1_3|tls1_2|tls1_1|tls1|sslv3|sslv2)/);
        if (verMatch) {
          const verMap: Record<string, string> = {
            'tls1_3': 'TLSv1.3', 'tls1_2': 'TLSv1.2', 'tls1_1': 'TLSv1.1',
            'tls1': 'TLSv1.0', 'sslv3': 'SSLv3', 'sslv2': 'SSLv2',
          };
          svcProps.tls_version = verMap[verMatch[1]] || verMatch[1];
        }
      }
    }

    // Cipher suites
    if (id.startsWith('cipher_') || id.startsWith('cipherlist_')) {
      if (finding && !finding.includes('not offered')) {
        cipherSuites.push(finding.split(/\s+/)[0]);
      }
    }

    // Certificate info
    if (id === 'cert_commonname' || id === 'cert_cn') svcProps.cert_subject = finding;
    if (id === 'cert_notafter') svcProps.cert_expiry = finding;
    if (id === 'cert_caissuer' || id === 'cert_issuer') svcProps.cert_issuer = finding;

    // Known vulnerabilities
    const vulnKey = Object.keys(TLS_KNOWN_VULNS).find(k => id.toLowerCase().includes(k.toLowerCase()));
    if (vulnKey && severity !== 'ok' && severity !== 'info' && !finding.toLowerCase().includes('not vulnerable')) {
      const known = TLS_KNOWN_VULNS[vulnKey];
      const cve = (f.cve as string) || known.cve;
      const vId = vulnerabilityId(cve || vulnKey, svcId);

      if (!seenNodes.has(vId)) {
        seenNodes.add(vId);
        nodes.push({
          id: vId,
          type: 'vulnerability',
          label: cve || vulnKey,
          discovered_at: now,
          confidence: 1.0,
          cve,
          cvss: TESTSSL_SEVERITY_CVSS[known.severity] || 5.0,
          vuln_type: 'weak-crypto',
          affected_component: finding || vulnKey,
        } as Finding['nodes'][0]);
      }

      const edgeKey = `${svcId}->${vId}`;
      if (!seenEdges.has(edgeKey)) {
        seenEdges.add(edgeKey);
        edges.push({
          source: svcId,
          target: vId,
          properties: { type: 'VULNERABLE_TO', confidence: 0.9, discovered_at: now },
        });
      }
    }
  }

  if (cipherSuites.length > 0) svcProps.cipher_suites = cipherSuites;

  if (!seenNodes.has(svcId)) {
    seenNodes.add(svcId);
    nodes.push(svcProps as Finding['nodes'][0]);
    edges.push({
      source: hId,
      target: svcId,
      properties: { type: 'RUNS', confidence: 1.0, discovered_at: now },
    });
  }
}
