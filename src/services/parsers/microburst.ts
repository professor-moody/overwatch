// ============================================================
// MicroBurst — Azure recon (Get-AzPasswords, Invoke-EnumerateAzureSubDomains, etc.)
//
// Operationally the most valuable MicroBurst output is Get-AzPasswords:
// dumps of storage account keys, key vault secrets, automation account
// credentials, and app service connection strings. Each of those is a
// usable credential that should land on the graph as a `credential`
// node with the right material kind.
//
// Output format is PowerShell tabular text. We accept either:
//   1. The default Format-Table output ("Type   Name   Value   Source")
//   2. CSV output (`Get-AzPasswords | Export-Csv`)
//   3. JSON output (`Get-AzPasswords | ConvertTo-Json`)
//
// The parser stays focused — full coverage of every MicroBurst module is
// out of scope; we want the credentials it surfaces, mapped to the
// existing credential model (with Phase 1 token-shaped extensions).
// ============================================================

import type { Finding, NodeProperties, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { credentialId } from '../parser-utils.js';

interface SecretRow {
  type: string;
  name: string;
  value: string;
  source?: string;
  notes?: string;
}

function classifyMaterialKind(typeRaw: string): NodeProperties['cred_material_kind'] {
  const t = typeRaw.toLowerCase();
  if (t.includes('storage')) return 'app_password';
  if (t.includes('keyvault') || t.includes('key vault')) return 'plaintext_password';
  if (t.includes('automation')) return 'plaintext_password';
  if (t.includes('app service') || t.includes('appservice') || t.includes('connection')) return 'app_password';
  if (t.includes('runbook')) return 'plaintext_password';
  if (t.includes('service principal') || t.includes('sp ')) return 'oauth_client_secret';
  if (t.includes('token')) return 'oidc_access_token';
  return 'plaintext_password';
}

function tryJson(output: string): SecretRow[] | null {
  try {
    const obj = JSON.parse(output);
    const arr = Array.isArray(obj) ? obj : [obj];
    return arr
      .filter((r): r is Record<string, unknown> => !!r && typeof r === 'object')
      .map(r => ({
        type: String(r.Type ?? r.type ?? ''),
        name: String(r.Name ?? r.name ?? ''),
        value: String(r.Value ?? r.value ?? ''),
        source: r.Source ? String(r.Source) : undefined,
      }));
  } catch {
    return null;
  }
}

function tryCsv(output: string): SecretRow[] | null {
  const lines = output.split('\n').map(l => l.trim()).filter(Boolean);
  if (lines.length < 2) return null;
  const header = lines[0].toLowerCase();
  if (!header.includes('"type"') && !header.includes('type,')) return null;
  const rows: SecretRow[] = [];
  for (let i = 1; i < lines.length; i++) {
    const parts = lines[i].split(',').map(p => p.replace(/^"|"$/g, ''));
    if (parts.length < 3) continue;
    rows.push({ type: parts[0], name: parts[1], value: parts[2], source: parts[3] });
  }
  return rows.length > 0 ? rows : null;
}

function tryTable(output: string): SecretRow[] | null {
  // Format-Table output: header line followed by hyphen separator.
  const lines = output.split('\n');
  const headerIdx = lines.findIndex(l => /\bType\b/i.test(l) && /\bName\b/i.test(l) && /\bValue\b/i.test(l));
  if (headerIdx < 0 || headerIdx + 1 >= lines.length) return null;
  // Compute column boundaries from the header line (Format-Table uses
  // whitespace-aligned columns).
  const header = lines[headerIdx];
  const cols = ['Type', 'Name', 'Value', 'Source'];
  const positions = cols.map(c => {
    const idx = header.indexOf(c);
    return idx >= 0 ? idx : -1;
  });
  if (positions[0] < 0 || positions[1] < 0 || positions[2] < 0) return null;
  const rows: SecretRow[] = [];
  for (let i = headerIdx + 2; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) break;
    const slice = (start: number, end: number) => line.slice(start, end >= 0 ? end : undefined).trim();
    const type = slice(positions[0], positions[1]);
    const name = slice(positions[1], positions[2]);
    const value = slice(positions[2], positions[3]);
    const source = positions[3] >= 0 ? slice(positions[3], -1) : undefined;
    if (!type || !value) continue;
    rows.push({ type, name, value, source });
  }
  return rows.length > 0 ? rows : null;
}

export function parseMicroBurst(output: string, agentId: string = 'microburst-parser', _context?: ParseContext): Finding {
  const nodes: NodeProperties[] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  const rows = tryJson(output) ?? tryCsv(output) ?? tryTable(output);
  if (!rows) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  for (const row of rows) {
    const kind = classifyMaterialKind(row.type);
    const fingerprint = `${row.source ?? ''}|${row.name}|${row.value}`;
    const credId = credentialId(kind ?? 'plaintext_password', fingerprint, row.name, undefined);
    if (seenNodes.has(credId)) continue;
    nodes.push({
      id: credId,
      type: 'credential',
      label: `azure-secret:${row.type}:${row.name}`,
      cred_type: kind === 'oauth_client_secret' ? 'oauth_secret' : kind === 'oidc_access_token' ? 'oidc_token' : kind === 'app_password' ? 'app_password' : 'plaintext',
      cred_material_kind: kind,
      cred_value: row.value,
      cred_user: row.name,
      cred_evidence_kind: 'dump',
      cred_usable_for_auth: true,
      cred_domain_source: 'parser_context',
      discovered_at: now,
      confidence: 1.0,
      ...(row.source ? { dump_source_host: row.source } : {}),
    });
    seenNodes.add(credId);
  }
  void edges; // No relations emitted in this pass; secrets stand alone.
  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
