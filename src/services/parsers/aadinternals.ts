// ============================================================
// AADInternals parser — Entra advanced enumeration.
//
// Most operationally relevant cmdlets:
//   - Get-AADIntTenantInfo  → tenant id, domains, federation/PHS/PTA mode
//   - Get-AADIntLoginInformation → cloud_only / federated / managed
//   - Get-AADIntUsers → tenant users (sometimes via *-MS-Graph paths)
//
// Output is PowerShell custom-object text. We accept JSON (preferred,
// `| ConvertTo-Json`) and a best-effort key:value text-shape parser
// for the default Format-List output.
//
// Emits an `idp` node (Entra) with federation_mode and tenant_id. When
// users are present, also emits idp_principal nodes.
// ============================================================

import type { Finding, NodeProperties, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { idpId, idpPrincipalId } from '../parser-utils.js';

interface TenantInfo {
  tenantId?: string;
  tenantName?: string;
  authenticationMode?: string; // Cloud, Federated, Managed
  passwordHashSync?: boolean;
  passThroughAuth?: boolean;
  domains?: string[];
}

interface AADBundle {
  tenant?: TenantInfo;
  users?: Array<Record<string, unknown>>;
}

function tryJson(output: string): AADBundle | null {
  try {
    const obj = JSON.parse(output);
    if (Array.isArray(obj)) {
      // Could be just users or just tenant — heuristic
      const first = obj[0];
      if (first && typeof first === 'object' && (first as Record<string, unknown>).TenantId) {
        const t = first as Record<string, unknown>;
        return {
          tenant: {
            tenantId: String(t.TenantId ?? ''),
            tenantName: String(t.TenantName ?? t.DisplayName ?? ''),
            authenticationMode: String(t.AuthenticationMode ?? ''),
            domains: Array.isArray(t.Domains) ? (t.Domains as unknown[]).map(String) : [],
          },
        };
      }
      return { users: obj as Array<Record<string, unknown>> };
    }
    if (obj && typeof obj === 'object') {
      const t = obj as Record<string, unknown>;
      if (t.TenantId || t.tenantId) {
        return {
          tenant: {
            tenantId: String(t.TenantId ?? t.tenantId),
            tenantName: String(t.TenantName ?? t.tenantName ?? ''),
            authenticationMode: String(t.AuthenticationMode ?? t.authenticationMode ?? ''),
            passwordHashSync: t.PasswordHashSync === true,
            passThroughAuth: t.PassThroughAuth === true,
            domains: Array.isArray(t.Domains) ? (t.Domains as unknown[]).map(String) : [],
          },
        };
      }
    }
    return null;
  } catch {
    return null;
  }
}

function tryFormatList(output: string): AADBundle | null {
  // PowerShell Format-List output shape:
  //   PropertyName : Value
  // We pull out a few well-known names.
  if (!/TenantId\s*:/.test(output)) return null;
  const grab = (name: string) => {
    const m = output.match(new RegExp(`^${name}\\s*:\\s*(.+)$`, 'mi'));
    return m ? m[1].trim() : undefined;
  };
  const tenantId = grab('TenantId');
  if (!tenantId) return null;
  return {
    tenant: {
      tenantId,
      tenantName: grab('TenantName') ?? grab('DisplayName'),
      authenticationMode: grab('AuthenticationMode'),
    },
  };
}

function deriveFederationMode(t: TenantInfo): NodeProperties['federation_mode'] | undefined {
  const mode = (t.authenticationMode ?? '').toLowerCase();
  if (t.passThroughAuth) return 'pass_through_auth';
  if (t.passwordHashSync) return 'password_hash_sync';
  if (mode.includes('federated')) return 'federated';
  if (mode.includes('managed') || mode.includes('cloud')) return 'cloud_only';
  return undefined;
}

export function parseAadInternals(output: string, agentId: string = 'aadinternals-parser', _context?: ParseContext): Finding {
  const nodes: NodeProperties[] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  const bundle = tryJson(output) ?? tryFormatList(output);
  if (!bundle) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  if (bundle.tenant) {
    const t = bundle.tenant;
    const tenantKey = t.tenantId ?? t.tenantName ?? 'unknown';
    const idpNodeId = idpId('entra', tenantKey);
    if (!seenNodes.has(idpNodeId)) {
      nodes.push({
        id: idpNodeId,
        type: 'idp',
        label: `entra:${t.tenantName ?? t.tenantId ?? 'tenant'}`,
        idp_kind: 'entra',
        tenant_id: t.tenantId,
        issuer_url: t.tenantId ? `https://login.microsoftonline.com/${t.tenantId}/v2.0` : undefined,
        federation_mode: deriveFederationMode(t),
        discovered_via: agentId,
        discovered_at: now,
        confidence: 1.0,
        ...(t.domains && t.domains.length > 0 ? { domain_name: t.domains[0] } : {}),
      });
      seenNodes.add(idpNodeId);
    }
  }

  for (const user of bundle.users ?? []) {
    const upn = String(user.UserPrincipalName ?? user.upn ?? user.email ?? '');
    const oid = String(user.ObjectId ?? user.objectId ?? user.id ?? upn);
    if (!upn && !oid) continue;
    const tenantKey = bundle.tenant?.tenantId ?? bundle.tenant?.tenantName ?? 'unknown';
    const nodeId = idpPrincipalId('entra', tenantKey, oid || upn);
    if (seenNodes.has(nodeId)) continue;
    nodes.push({
      id: nodeId,
      type: 'idp_principal',
      label: upn || oid,
      idp_user_id: oid,
      idp_principal_kind: 'user',
      upn,
      discovered_at: now,
      confidence: 1.0,
    });
    seenNodes.add(nodeId);
  }

  void edges;
  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
