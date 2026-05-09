// ============================================================
// Overwatch — Entra/Azure playbook (A.4)
//
// Two MCP tools:
//
//   - exchange_refresh_token: instrumented curl to Microsoft's
//     /oauth2/v2.0/token endpoint. Mints a fresh access token from a
//     captured refresh token. Approval-gated by default (materially
//     escalates access).
//
//   - expand_entra_credential: returns a tenant-dump recon plan for a
//     captured Entra access token. Walks /me, /users, /applications,
//     /servicePrincipals, /groups via existing token-replay-msgraph
//     and the new msgraph-* parsers.
//
// Refresh token values are NEVER written to the activity log description
// — the body is constructed at execution time from the credential node's
// cred_value. The runner's existing redaction handles `Authorization` /
// bearer arguments; for POST bodies we additionally instruct the
// operator to use `--data-urlencode` flags (kept off the command_repr
// where possible).
// ============================================================

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';
import { isCredentialUsableForAuth, isTokenCredential } from '../services/credential-utils.js';

interface PlaybookStep {
  step: number;
  description: string;
  command: string;
  parse_with?: string;
  parser_context?: Record<string, unknown>;
  technique: string;
  est_noise: number;
  expected: string;
  blocking?: boolean;
}

const ENTRA_TOKEN_KINDS = new Set(['oidc_access_token', 'oidc_refresh_token', 'token']);

export function registerEntraPlaybookTools(server: McpServer, engine: GraphEngine): void {
  // =========================================================
  // exchange_refresh_token — mint a fresh access token
  // =========================================================
  server.registerTool(
    'exchange_refresh_token',
    {
      title: 'Exchange Entra Refresh Token',
      description: `Generate a step to exchange a captured Entra refresh token for a
fresh access token via Microsoft\'s /oauth2/v2.0/token endpoint.

Returns a single step (a curl POST). The operator runs it through
\`run_bash\` — the approval queue gates the call (refresh-token
exchange materially escalates access). On success, a new
oidc_access_token credential lands in the graph; on invalid_grant the
source credential is marked credential_status: 'expired'.`,
      inputSchema: {
        credential_id: z.string().min(1).describe('Refresh token credential id (cred_material_kind: oidc_refresh_token).'),
        client_id: z.string().describe('OAuth client id the refresh token was issued for.'),
        scope: z.string().default('https://graph.microsoft.com/.default offline_access').describe('Requested OAuth scope. Defaults to MS Graph default + offline_access for refresh continuity.'),
        tenant_id: z.string().optional().describe('Tenant id or "common" / "organizations". Defaults to the credential\'s cred_issuer if available, else "common".'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('exchange_refresh_token', async (params) => {
      const { credential_id, client_id, scope, tenant_id } = params as {
        credential_id: string;
        client_id: string;
        scope: string;
        tenant_id?: string;
      };
      const cred = engine.getNode(credential_id);
      if (!cred) return errorResponse(`Credential ${credential_id} not found`);
      if (cred.type !== 'credential') return errorResponse(`Node ${credential_id} is type=${cred.type}`);
      if (cred.cred_material_kind !== 'oidc_refresh_token') {
        return errorResponse(`Credential ${credential_id} has cred_material_kind=${cred.cred_material_kind}, expected oidc_refresh_token`);
      }
      // NOTE: refresh tokens explicitly return false from
      // isCredentialUsableForAuth (they're not directly authenticable —
      // exchange_refresh_token's whole purpose is to make them so). We
      // gate on lifecycle status / expiry instead.
      const status = cred.credential_status as string | undefined;
      if (status === 'expired' || status === 'rotated' || status === 'revoked') {
        return errorResponse(`Credential ${credential_id} is ${status}; cannot exchange`);
      }

      const tenant = tenant_id ?? (cred.cred_issuer as string | undefined)?.match(/login\.microsoftonline\.com\/([^/]+)/)?.[1] ?? 'common';
      const tokenUrl = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;

      // The refresh_token value lives in the credential node; the
      // operator passes it explicitly. We do NOT inline it here so the
      // recon plan stays safe to log/audit/share.
      const command = [
        `curl -sS -X POST ${tokenUrl}`,
        `-H 'Content-Type: application/x-www-form-urlencoded'`,
        `--data-urlencode 'grant_type=refresh_token'`,
        `--data-urlencode "client_id=${client_id}"`,
        `--data-urlencode "scope=${scope}"`,
        `--data-urlencode "refresh_token=$REFRESH_TOKEN"`,
      ].join(' \\\n  ');

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            credential_id,
            tenant: tenant,
            command,
            execution_hint: 'Set REFRESH_TOKEN=<refresh-token-value> in the shell environment before running. Pipe stdout to `parse_with: token_replay_msgraph` to ingest the new access token. Approval-gated by default; the engagement OPSEC blacklist can be set to require explicit approval.',
            on_success: 'New oidc_access_token credential node lands in graph with cred_token_expires_at set from response.expires_in.',
            on_failure: 'invalid_grant marks the source credential credential_status: expired. invalid_scope / invalid_client surface as errors without status flip.',
          }, null, 2),
        }],
      };
    }),
  );

  // =========================================================
  // expand_entra_credential — tenant-dump recon plan
  // =========================================================
  server.registerTool(
    'expand_entra_credential',
    {
      title: 'Expand Entra Credential',
      description: `Generate a tenant-dump recon plan for a captured Entra access token.

Plan walks:
  1. \`curl ... /v1.0/me\`               → token_replay_msgraph (validate + UPN)
  2. \`curl ... /v1.0/users?$top=999\`   → msgraph-users (idp_principal per user)
  3. \`curl ... /v1.0/applications\`     → msgraph-applications
  4. \`curl ... /v1.0/servicePrincipals\` → msgraph-serviceprincipals
  5. \`curl ... /v1.0/groups\`           → msgraph-groups

Each step is a quiet read against MS Graph; reads auto-approve under
the noise budget. Pagination follow-ups (@odata.nextLink) are the
operator\'s responsibility — the plan emits a single page per resource.`,
      inputSchema: {
        credential_id: z.string().min(1).describe('Entra access token credential id.'),
        tenant_id: z.string().optional().describe('Tenant id or domain (overrides credential\'s cred_issuer).'),
        include_groups: z.boolean().default(true).describe('Include /groups enumeration step.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('expand_entra_credential', async (params) => {
      const { credential_id, tenant_id, include_groups } = params as {
        credential_id: string;
        tenant_id?: string;
        include_groups: boolean;
      };
      const cred = engine.getNode(credential_id);
      if (!cred) return errorResponse(`Credential ${credential_id} not found`);
      if (cred.type !== 'credential') return errorResponse(`Node ${credential_id} is type=${cred.type}`);
      if (!isTokenCredential(cred)) return errorResponse(`Credential ${credential_id} is not a token`);
      const kind = cred.cred_material_kind as string | undefined;
      if (!kind || !ENTRA_TOKEN_KINDS.has(kind)) {
        return errorResponse(`Credential ${credential_id} has cred_material_kind=${kind}, expected one of: ${[...ENTRA_TOKEN_KINDS].join(', ')}`);
      }
      if (!isCredentialUsableForAuth(cred)) {
        return errorResponse(`Credential ${credential_id} is not usable for auth`);
      }

      const tenant = tenant_id
        ?? (cred.cred_issuer as string | undefined)?.match(/login\.microsoftonline\.com\/([^/]+)/)?.[1]
        ?? (cred.tenant_id as string | undefined)
        ?? 'common';

      const steps: PlaybookStep[] = [];
      let n = 0;

      const authHeader = `-H 'Authorization: Bearer $ENTRA_TOKEN'`;

      steps.push({
        step: ++n,
        description: 'Validate the token and capture UPN/oid via /v1.0/me. Sets cred_mfa_satisfied: true on the source credential when the response is 200.',
        command: `curl -sS -i ${authHeader} https://graph.microsoft.com/v1.0/me`,
        parse_with: 'token_replay_msgraph',
        parser_context: { source_credential_id: credential_id },
        technique: 'recon_idp_principal',
        est_noise: 0.05,
        expected: 'idp_principal node updated with object_id + UPN; VALID_FOR_APP edge.',
        blocking: true,
      });

      steps.push({
        step: ++n,
        description: 'List all directory users (page 1, $top=999). Walk @odata.nextLink for full coverage.',
        command: `curl -sS ${authHeader} 'https://graph.microsoft.com/v1.0/users?$top=999'`,
        parse_with: 'msgraph-users',
        parser_context: { tenant_id: tenant, source_credential_id: credential_id },
        technique: 'recon_idp_principal',
        est_noise: 0.15,
        expected: 'idp_principal nodes per user.',
      });

      steps.push({
        step: ++n,
        description: 'List app registrations.',
        command: `curl -sS ${authHeader} 'https://graph.microsoft.com/v1.0/applications?$top=999'`,
        parse_with: 'msgraph-applications',
        parser_context: { tenant_id: tenant },
        technique: 'recon_idp_application',
        est_noise: 0.15,
        expected: 'idp_application nodes (entra_application).',
      });

      steps.push({
        step: ++n,
        description: 'List service principals (app instances within the tenant). Their oauth2PermissionScopes carry the human-readable scope names CONSENT_ABUSE pattern-matches against.',
        command: `curl -sS ${authHeader} 'https://graph.microsoft.com/v1.0/servicePrincipals?$top=999'`,
        parse_with: 'msgraph-serviceprincipals',
        parser_context: { tenant_id: tenant },
        technique: 'recon_idp_application',
        est_noise: 0.15,
        expected: 'idp_application nodes (entra_service_principal).',
      });

      if (include_groups) {
        steps.push({
          step: ++n,
          description: 'List directory groups.',
          command: `curl -sS ${authHeader} 'https://graph.microsoft.com/v1.0/groups?$top=999'`,
          parse_with: 'msgraph-groups',
          parser_context: { tenant_id: tenant },
          technique: 'recon_group',
          est_noise: 0.1,
          expected: 'group nodes for security/unified groups.',
        });
      }

      engine.addNode({
        id: credential_id,
        type: 'credential',
        label: cred.label as string,
        discovered_at: cred.discovered_at as string,
        confidence: cred.confidence as number,
        recon_playbook_invoked_at: new Date().toISOString(),
        recon_playbook_step_count: steps.length,
      });

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            credential_id,
            tenant,
            step_count: steps.length,
            steps,
            execution_hint: 'Set ENTRA_TOKEN=<access-token-value> in the shell. Each curl uses -sS so progress meter is suppressed but errors propagate. CONSENT_ABUSE inference fires after step 4 lands; review the dashboard FindingsPanel for flagged apps.',
          }, null, 2),
        }],
      };
    }),
  );
}

function errorResponse(message: string) {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify({ error: message }, null, 2) }],
    isError: true,
  };
}
