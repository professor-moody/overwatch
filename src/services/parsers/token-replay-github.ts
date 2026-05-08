// ============================================================
// GitHub API token-replay response parser.
//
// Probes `/user` (or other authenticated endpoint) using a captured
// PAT, GitHub App installation token, or OAuth user token. Successful
// 200 returns a JSON user object; 401 marks the credential expired.
//
// Where possible we capture the token's observed scopes from the
// `X-OAuth-Scopes` response header (operator must include
// `--include`/`-i` when invoking curl so headers land in stdout).
// ============================================================

import type { EdgeType, Finding, NodeProperties, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';

interface ReplayContext extends ParseContext {
  source_credential_id?: string;
  source_idp_application_id?: string;
  status_code?: number;
}

function extractStatusAndBody(output: string): { status: number; body: string; headers: string } {
  const m = output.match(/^\[STATUS:(\d{3})\]\s*\n?([\s\S]*)$/);
  if (m) return { status: parseInt(m[1]), body: m[2], headers: '' };
  // When operator passes `curl -i`, headers come first followed by a blank line then body.
  const headerEnd = output.indexOf('\n\n');
  if (headerEnd > 0 && /^HTTP\//i.test(output.slice(0, headerEnd))) {
    const headers = output.slice(0, headerEnd);
    const body = output.slice(headerEnd + 2);
    const statusM = headers.match(/^HTTP\/[\d.]+\s+(\d{3})/);
    return { status: statusM ? parseInt(statusM[1]) : 0, body, headers };
  }
  return { status: 0, body: output, headers: '' };
}

function extractScopes(headers: string): string[] | undefined {
  const m = headers.match(/^X-OAuth-Scopes:\s*(.+)$/im);
  if (!m) return undefined;
  return m[1].split(',').map(s => s.trim()).filter(Boolean);
}

interface GitHubUser { login?: string; id?: number; email?: string; name?: string }

function parseGitHubResponse(body: string): GitHubUser | null {
  try {
    const obj = JSON.parse(body) as Record<string, unknown>;
    if (typeof obj.login === 'string' || typeof obj.id === 'number') return obj as GitHubUser;
    return null;
  } catch {
    return null;
  }
}

export function parseTokenReplayGitHub(output: string, agentId: string = 'token-replay-github', context?: ParseContext): Finding {
  const nodes: NodeProperties[] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const ctx = (context ?? {}) as ReplayContext;
  const credId = ctx.source_credential_id;
  const appId = ctx.source_idp_application_id;

  const { status, body, headers } = extractStatusAndBody(output);

  if (status === 401 || status === 403) {
    if (credId) {
      nodes.push({
        id: credId,
        type: 'credential',
        label: 'replay-result',
        discovered_at: now,
        confidence: 1.0,
        credential_status: status === 401 ? 'expired' : 'active',
        notes: `github /user returned ${status}`,
        partial: true,
      });
    }
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  if (status !== 200 && status !== 0) {
    if (credId) {
      nodes.push({
        id: credId,
        type: 'credential',
        label: 'replay-result',
        discovered_at: now,
        confidence: 0.5,
        partial: true,
        notes: `github /user returned ${status} — inconclusive`,
      });
    }
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  const user = parseGitHubResponse(body);
  if (!user) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  const scopes = extractScopes(headers);
  if (credId) {
    nodes.push({
      id: credId,
      type: 'credential',
      label: 'replay-result',
      discovered_at: now,
      confidence: 1.0,
      cred_usable_for_auth: true,
      cred_mfa_satisfied: true,
      credential_status: 'active',
      cred_user: user.login,
      cred_scopes: scopes,
      notes: `github /user replay succeeded for ${user.login ?? user.id ?? 'user'}${scopes ? ` (scopes: ${scopes.join(' ')})` : ''}`,
    });
  }

  if (credId && appId) {
    edges.push({
      source: credId,
      target: appId,
      properties: {
        type: 'VALID_FOR_APP' as EdgeType,
        confidence: 1.0,
        discovered_at: now,
        discovered_by: agentId,
        notes: 'github /user replay confirmed token works',
      },
    });
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
