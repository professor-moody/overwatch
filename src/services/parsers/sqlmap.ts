// ============================================================
// SQLMap Output Parser
// Parses sqlmap text log output (primary) and JSON (secondary)
// into graph findings with SQLi vulnerabilities, credentials,
// and database user nodes.
// ============================================================

import type { Finding, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { hostId, vulnerabilityId, webappOriginId, userId, credentialId } from '../parser-utils.js';

// --- Main parser ---

export function parseSqlmap(output: string, agentId: string = 'sqlmap-parser', _context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const seenNodes = new Set<string>();
  const seenEdges = new Set<string>();

  if (!output.trim()) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  // Try JSON format first (sqlmap API or --output-dir JSON)
  try {
    const data = JSON.parse(output);
    if (data && typeof data === 'object') {
      return parseSqlmapJson(data, nodes, edges, seenNodes, seenEdges, now, agentId);
    }
  } catch {
    // Not JSON — parse text log
  }

  return parseSqlmapText(output, nodes, edges, seenNodes, seenEdges, now, agentId);
}

// --- Text log parser ---

function parseSqlmapText(
  output: string,
  nodes: Finding['nodes'],
  edges: Finding['edges'],
  seenNodes: Set<string>,
  seenEdges: Set<string>,
  now: string,
  agentId: string,
): Finding {
  let targetUrl = '';
  let dbms = '';
  const injections: Array<{ parameter: string; type: string; technique: string }> = [];
  const dbUsers: string[] = [];
  const crackedCreds: Array<{ username: string; password: string }> = [];

  for (const rawLine of output.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;

    // Target URL: [INFO] testing URL 'http://...' or from --url
    const urlMatch = line.match(/testing URL ['"]([^'"]+)['"]/i)
      || line.match(/starting @ URL:\s*['"]?([^\s'"]+)/i)
      || line.match(/URL:\s*['"]?([^\s'"]+)/i);
    if (urlMatch && !targetUrl) {
      targetUrl = urlMatch[1];
    }

    // Resuming from log: [INFO] resuming ... 'http://...'
    const resumeMatch = line.match(/resuming.*?['"]?(https?:\/\/[^\s'"]+)/i);
    if (resumeMatch && !targetUrl) {
      targetUrl = resumeMatch[1];
    }

    // DBMS detection
    const dbmsMatch = line.match(/back-end DBMS:\s*(.+)/i)
      || line.match(/the back-end DBMS is\s+(.+)/i);
    if (dbmsMatch) {
      dbms = dbmsMatch[1].trim();
    }

    // Injection detection
    // [INFO] Parameter: id (GET) ... is vulnerable
    const paramMatch = line.match(/Parameter:\s*(\S+)\s*\(([^)]+)\)/i);
    if (paramMatch && /vulnerable|injectable/i.test(line)) {
      injections.push({
        parameter: paramMatch[1],
        type: paramMatch[2],
        technique: '',
      });
    }

    // [INFO] (technique)...(Type: ...) -> 'X injection'
    const techniqueMatch = line.match(/Type:\s*(.+?)(?:\s*Title:|\s*Payload:|\s*$)/i);
    if (techniqueMatch && injections.length > 0) {
      const last = injections[injections.length - 1];
      if (!last.technique) {
        last.technique = techniqueMatch[1].trim();
      }
    }

    // sqlmap identified N injection point(s) — summary confirmation
    const summaryMatch = line.match(/sqlmap identified.*?(\d+).*injection point/i);
    if (summaryMatch && injections.length === 0) {
      injections.push({ parameter: 'unknown', type: 'unknown', technique: 'unknown' });
    }

    // DB users: [INFO] fetching database users / retrieved: 'root@localhost'
    const userMatch = line.match(/database management system users.*?:\s*\[.*?'([^']+)'/i)
      || line.match(/retrieved:\s*'([^']+@[^']+)'/i);
    if (userMatch) {
      const u = userMatch[1].split('@')[0];
      if (u && !dbUsers.includes(u)) dbUsers.push(u);
    }

    // Individual user lines from --users output
    const userLineMatch = line.match(/^\[\*\]\s+'?([^'@\s]+)/);
    if (userLineMatch && /fetching database users/i.test(output.slice(0, output.indexOf(line)))) {
      const u = userLineMatch[1];
      if (u && !dbUsers.includes(u)) dbUsers.push(u);
    }

    // Cracked credentials: [INFO] cracked password 'xxx' for user 'yyy'
    const crackedMatch = line.match(/cracked password\s+'([^']+)'\s+for\s+(?:user\s+)?'([^']+)'/i);
    if (crackedMatch) {
      crackedCreds.push({ username: crackedMatch[2], password: crackedMatch[1] });
    }

    // Dump table credentials: username/password patterns
    // Table: users  ... | admin | $2y$10$... |
    const tableRowMatch = line.match(/^\|\s+(\S+)\s+\|\s+(\S+)\s+\|/);
    if (tableRowMatch) {
      const [, col1, col2] = tableRowMatch;
      // Heuristic: if col2 looks like a hash or password
      if (col2 && /^\$\d|^[a-f0-9]{32,}$/i.test(col2) && col1 !== 'username' && col1 !== 'id') {
        if (!crackedCreds.some(c => c.username === col1)) {
          crackedCreds.push({ username: col1, password: col2 });
        }
      }
    }
  }

  // If no target URL found, try to extract from any URL in the output
  if (!targetUrl) {
    const anyUrl = output.match(/https?:\/\/[^\s'"<>]+/);
    if (anyUrl) targetUrl = anyUrl[0];
  }

  if (!targetUrl && injections.length === 0) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  // Build graph nodes from extracted data
  buildSqlmapNodes(targetUrl, dbms, injections, dbUsers, crackedCreds, nodes, edges, seenNodes, seenEdges, now);

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- JSON parser ---

function parseSqlmapJson(
  data: Record<string, unknown>,
  nodes: Finding['nodes'],
  edges: Finding['edges'],
  seenNodes: Set<string>,
  seenEdges: Set<string>,
  now: string,
  agentId: string,
): Finding {
  const targetUrl = (data.url || data.target_url || '') as string;
  const dbms = (data.dbms || data.back_end_dbms || '') as string;

  const injections: Array<{ parameter: string; type: string; technique: string }> = [];
  const rawVulns = (data.vulnerabilities || data.data || []) as Array<Record<string, unknown>>;
  for (const v of rawVulns) {
    injections.push({
      parameter: String(v.parameter || v.place || 'unknown'),
      type: String(v.type || v.ptype || 'unknown'),
      technique: String(v.title || v.technique || ''),
    });
  }

  const dbUsers: string[] = [];
  const rawUsers = (data.users || []) as string[];
  for (const u of rawUsers) {
    const name = u.split('@')[0];
    if (name && !dbUsers.includes(name)) dbUsers.push(name);
  }

  const crackedCreds: Array<{ username: string; password: string }> = [];
  const rawPasswords = (data.passwords || {}) as Record<string, Array<Record<string, string>>>;
  for (const [user, hashes] of Object.entries(rawPasswords)) {
    for (const h of hashes) {
      if (h.clear) {
        crackedCreds.push({ username: user, password: h.clear });
      }
    }
  }

  if (targetUrl || injections.length > 0) {
    buildSqlmapNodes(targetUrl, dbms, injections, dbUsers, crackedCreds, nodes, edges, seenNodes, seenEdges, now);
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

// --- Shared node builder ---

function buildSqlmapNodes(
  targetUrl: string,
  dbms: string,
  injections: Array<{ parameter: string; type: string; technique: string }>,
  dbUsers: string[],
  crackedCreds: Array<{ username: string; password: string }>,
  nodes: Finding['nodes'],
  edges: Finding['edges'],
  seenNodes: Set<string>,
  seenEdges: Set<string>,
  now: string,
): void {
  let ip = '';
  let port = 80;
  let proto = 'http';

  if (targetUrl) {
    try {
      const parsed = new URL(targetUrl);
      ip = parsed.hostname;
      proto = parsed.protocol.replace(':', '');
      port = parsed.port ? parseInt(parsed.port) : (proto === 'https' ? 443 : 80);
    } catch { /* skip */ }
  }
  if (!ip) return;

  const targetOrigin = `${proto}://${ip}:${port}`;

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

  // Service node
  const svcId = `svc-${ip.replace(/\./g, '-')}-${port}`;
  if (!seenNodes.has(svcId)) {
    seenNodes.add(svcId);
    nodes.push({
      id: svcId,
      type: 'service',
      label: `${proto}/${port}`,
      discovered_at: now,
      confidence: 1.0,
      port,
      protocol: 'tcp',
      service_name: proto,
    } as Finding['nodes'][0]);
    edges.push({
      source: hId,
      target: svcId,
      properties: { type: 'RUNS', confidence: 1.0, discovered_at: now },
    });
  }

  // Webapp node
  const waId = webappOriginId(targetOrigin);
  if (!seenNodes.has(waId)) {
    seenNodes.add(waId);
    nodes.push({
      id: waId,
      type: 'webapp',
      label: targetOrigin,
      discovered_at: now,
      confidence: 1.0,
      url: targetOrigin,
    } as Finding['nodes'][0]);
    addEdge(svcId, waId, 'HOSTS', 1.0, now, edges, seenEdges);
  }

  // Vulnerability nodes — one per injection point
  for (const inj of injections) {
    const paramKey = `${inj.parameter}-${inj.type}`;
    const vulnId = vulnerabilityId(`sqli-${paramKey}`, waId);

    if (!seenNodes.has(vulnId)) {
      seenNodes.add(vulnId);
      nodes.push({
        id: vulnId,
        type: 'vulnerability',
        label: `SQL Injection: ${inj.parameter} (${inj.type})`,
        discovered_at: now,
        confidence: 0.95,
        vuln_type: 'sqli',
        cvss: 8.5,
        exploitable: true,
        ...(dbms ? { dbms } : {}),
        injection_type: inj.type,
        parameter: inj.parameter,
        ...(inj.technique ? { technique: inj.technique } : {}),
      } as Finding['nodes'][0]);
    }

    addEdge(waId, vulnId, 'VULNERABLE_TO', 0.95, now, edges, seenEdges);
  }

  // DB user nodes
  for (const username of dbUsers) {
    const uId = userId(username);
    if (!seenNodes.has(uId)) {
      seenNodes.add(uId);
      nodes.push({
        id: uId,
        type: 'user',
        label: username,
        discovered_at: now,
        confidence: 0.85,
        db_user: true,
      } as Finding['nodes'][0]);
    }
  }

  // Cracked credential nodes
  for (const cred of crackedCreds) {
    const isHash = /^\$\d|^[a-f0-9]{32,}$/i.test(cred.password);
    const materialKind: string = isHash ? 'ntlm_hash' : 'plaintext_password';
    const credType: string = isHash ? 'ntlm' : 'plaintext';
    const cId = credentialId(isHash ? 'hash' : 'password', cred.password, cred.username);

    if (!seenNodes.has(cId)) {
      seenNodes.add(cId);
      nodes.push({
        id: cId,
        type: 'credential',
        label: `${cred.username}:${isHash ? 'hash' : 'password'}`,
        discovered_at: now,
        confidence: 0.9,
        cred_material_kind: materialKind,
        cred_type: credType,
        cred_user: cred.username,
        cred_usable_for_auth: true,
        ...(isHash ? { cred_hash: cred.password } : { cred_value: cred.password }),
      } as Finding['nodes'][0]);
    }

    // EXPLOITS: each vulnerability node → credential (SQLi yielded these creds)
    for (const inj of injections) {
      const paramKey = `${inj.parameter}-${inj.type}`;
      const vulnId = vulnerabilityId(`sqli-${paramKey}`, waId);
      addEdge(vulnId, cId, 'EXPLOITS', 0.85, now, edges, seenEdges);
    }
  }
}

// --- Helpers ---

function addEdge(
  source: string,
  target: string,
  type: string,
  confidence: number,
  now: string,
  edges: Finding['edges'],
  seenEdges: Set<string>,
): void {
  const key = `${source}->${target}:${type}`;
  if (!seenEdges.has(key)) {
    seenEdges.add(key);
    edges.push({
      source,
      target,
      properties: { type: type as Finding['edges'][0]['properties']['type'], confidence, discovered_at: now },
    });
  }
}
