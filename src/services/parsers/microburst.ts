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
  /** F5: set when the row was extracted via the column-truncation path
   *  (Format-Table) or any other lossy parse — operators should treat
   *  the credential as suspect rather than directly usable. */
  partial?: boolean;
}

/**
 * F5: minimal but correct CSV row parser. Handles quoted values that
 * contain commas (very common for connection strings) and the
 * `""`-as-escaped-quote convention. Returns null when the line is
 * structurally invalid.
 */
function parseCsvRow(line: string): string[] | null {
  const out: string[] = [];
  let i = 0;
  const n = line.length;
  while (i < n) {
    let cell = '';
    if (line[i] === '"') {
      i++;
      while (i < n) {
        if (line[i] === '"') {
          if (i + 1 < n && line[i + 1] === '"') {
            cell += '"';
            i += 2;
            continue;
          }
          i++;
          break;
        }
        cell += line[i];
        i++;
      }
      // Skip comma after closing quote.
      if (i < n && line[i] === ',') i++;
      else if (i < n) return null; // malformed (quoted field not followed by , or EOL)
    } else {
      while (i < n && line[i] !== ',') {
        cell += line[i];
        i++;
      }
      if (i < n && line[i] === ',') i++;
    }
    out.push(cell);
  }
  return out;
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
  // F5: use a real CSV row parser instead of split(','). Splitting on
  // commas corrupts connection strings, JWTs, and any other value that
  // legitimately contains commas — and the result was being marked as
  // a usable credential, so operators tried dead secrets.
  const lines = output.split('\n').map(l => l.trim()).filter(Boolean);
  if (lines.length < 2) return null;
  const headerLower = lines[0].toLowerCase();
  if (!headerLower.includes('"type"') && !headerLower.includes('type,')) return null;
  const headerCells = parseCsvRow(lines[0]);
  if (!headerCells) return null;
  const idx = (name: string) => headerCells.findIndex(h => h.toLowerCase().trim() === name);
  const typeIdx = idx('type');
  const nameIdx = idx('name');
  const valueIdx = idx('value');
  const sourceIdx = idx('source');
  if (typeIdx < 0 || nameIdx < 0 || valueIdx < 0) return null;

  const rows: SecretRow[] = [];
  for (let i = 1; i < lines.length; i++) {
    const cells = parseCsvRow(lines[i]);
    if (!cells) continue;
    if (cells.length <= Math.max(typeIdx, nameIdx, valueIdx)) continue;
    rows.push({
      type: cells[typeIdx] ?? '',
      name: cells[nameIdx] ?? '',
      value: cells[valueIdx] ?? '',
      source: sourceIdx >= 0 ? cells[sourceIdx] : undefined,
    });
  }
  return rows.length > 0 ? rows : null;
}

function tryTable(output: string): SecretRow[] | null {
  // Format-Table output: header line followed by hyphen separator.
  // F5: column boundaries truncate any value longer than the rendered
  // column width — that's a property of PowerShell formatting, not
  // something we can recover. We DO continue to parse table output
  // (it's a common operator paste), but we mark every row partial so
  // downstream consumers know not to treat the value as authoritative.
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
  const valueColumnWidth = positions[3] >= 0 ? positions[3] - positions[2] : Infinity;
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
    // Heuristic: if the value field uses every available column byte and
    // ends at or after the next column boundary, PowerShell almost
    // certainly truncated it.
    const truncated = value.length >= valueColumnWidth - 1;
    rows.push({ type, name, value, source, partial: true, notes: truncated ? 'value may be truncated by Format-Table column width' : 'parsed from Format-Table; structured CSV/JSON preferred' });
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
      // F5: row.partial is true for any value that came through the
      // Format-Table parser (PowerShell column boundaries can silently
      // truncate). Propagate that to the credential node and mark it
      // not-directly-usable so coverage / spray tools don't try a dead
      // secret. Operators should re-export to JSON/CSV for full fidelity.
      cred_usable_for_auth: row.partial ? false : true,
      partial: row.partial || undefined,
      notes: row.notes,
      cred_domain_source: 'parser_context',
      discovered_at: now,
      confidence: row.partial ? 0.5 : 1.0,
      ...(row.source ? { dump_source_host: row.source } : {}),
    });
    seenNodes.add(credId);
  }
  void edges; // No relations emitted in this pass; secrets stand alone.
  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
