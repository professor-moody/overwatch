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
import { safePlaybookArg } from './_playbook-utils.js';
import { PlaybookCommandService } from '../services/playbook-command-service.js';

interface PlaybookStep {
  step: number;
  step_id?: string;
  description: string;
  command: string | null;
  parse_with?: string;
  parser_context?: Record<string, unknown>;
  technique: string;
  est_noise: number;
  expected: string;
  blocking?: boolean;
  runner?: 'run_bash';
  /** Adapter hint: bind env var(s) from credential ids in run_bash.env. */
  env_from_credential?: Record<string, string>;
  ready?: boolean;
  status?: 'ready' | 'blocked';
  depends_on?: string[];
  required_bindings?: string[];
  produces_bindings?: string[];
  blocked_reason?: string;
}

const ENTRA_TOKEN_KINDS = new Set(['oidc_access_token', 'token']);

function concreteTenant(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length === 0) return undefined;
  return /^(common|organizations|consumers|unknown)$/i.test(value) ? undefined : value;
}

function jwtTenant(token: unknown): string | undefined {
  if (typeof token !== 'string') return undefined;
  try {
    const segment = token.split('.')[1];
    if (!segment) return undefined;
    const claims = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as { tid?: unknown };
    return concreteTenant(claims.tid);
  } catch {
    return undefined;
  }
}

function isEntraMarkedCredential(cred: Record<string, unknown>, explicitTenant?: string): boolean {
  if (concreteTenant(explicitTenant)) return true;
  if (concreteTenant(cred.tenant_id)) return true;
  return [cred.provider, cred.cred_provider, cred.cred_audience, cred.cred_issuer, cred.idp_kind]
    .some(value => typeof value === 'string'
      && /(microsoftonline\.com|graph\.microsoft\.com|(^|[/:._-])(entra|azure)([/:._-]|$))/i.test(value));
}

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
        refresh_token_env_var: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/).default('OVERWATCH_ENTRA_REFRESH_TOKEN').describe('run_bash.env variable that will be populated from the selected refresh credential.'),
        new_run: z.boolean().default(false).describe('Start another run instead of resuming the matching logical run.'),
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
        refresh_token_env_var?: string;
        new_run?: boolean;
      };
      const refreshTokenEnvVar = (params as { refresh_token_env_var?: string }).refresh_token_env_var ?? 'OVERWATCH_ENTRA_REFRESH_TOKEN';
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

      // Fence every value interpolated into the emitted curl command: tenant is
      // derived from a parsed credential issuer, and client_id/scope are
      // operator-supplied — none may inject shell into a suggested run_bash step.
      const tenant = safePlaybookArg(tenant_id ?? (cred.cred_issuer as string | undefined)?.match(/login\.microsoftonline\.com\/([^/]+)/)?.[1] ?? 'common');
      const tokenUrl = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;

      // The refresh_token value lives in the credential node; the
      // operator passes it explicitly. We do NOT inline it here so the
      // recon plan stays safe to log/audit/share.
      const tokenGuard = `: "\${${refreshTokenEnvVar}:?Pass ${refreshTokenEnvVar} in run_bash.env from selected credential ${credential_id}}"`;
      const curlCommand = [
        `curl -sS --fail-with-body -X POST '${tokenUrl}'`,
        `-H 'Content-Type: application/x-www-form-urlencoded'`,
        `--data-urlencode 'grant_type=refresh_token'`,
        `--data-urlencode "client_id=${safePlaybookArg(client_id)}"`,
        `--data-urlencode "scope=${safePlaybookArg(scope)}"`,
        `--data-urlencode "refresh_token=$${refreshTokenEnvVar}"`,
      ].join(' \\\n  ');
      const command = `${tokenGuard}; ${curlCommand}`;
      const parserContext = {
        source_credential_id: credential_id,
        tenant_id: tenant,
        client_id: safePlaybookArg(client_id),
        requested_scope: safePlaybookArg(scope),
        credential_execution_binding: `env:${refreshTokenEnvVar}`,
      };
      const step: PlaybookStep = {
        step: 1,
        step_id: 'exchange-refresh-token',
        description: 'Exchange the selected Entra refresh token for a new access token.',
        command,
        parse_with: 'entra-token-exchange',
        parser_context: parserContext,
        runner: 'run_bash',
        env_from_credential: { [refreshTokenEnvVar]: credential_id },
        technique: 'token_replay',
        est_noise: 0.15,
        expected: 'A derived oidc_access_token credential, or a precise source-credential exchange failure update.',
        blocking: true,
      };
      const durable = new PlaybookCommandService(engine).open({
        definition: {
          definition_id: 'entra-refresh-exchange',
          definition_version: 1,
          provider: 'entra',
          title: 'Entra refresh-token exchange',
        },
        credential_id,
        normalized_inputs: {
          client_id,
          scope,
          tenant_id: tenant,
          refresh_token_env_var: refreshTokenEnvVar,
        },
        bindings: {
          tenant_id: tenant,
          client_id,
          credential_execution_binding: `env:${refreshTokenEnvVar}`,
        },
        steps: [{ ...step }],
        new_run: (params as { new_run?: boolean }).new_run === true,
      });

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            credential_id,
            run_id: durable.run.run_id,
            playbook_run_status: durable.run.status,
            playbook_report_status: durable.run.report_status,
            playbook_created: durable.created,
            playbook_steps: durable.run.steps,
            tenant: tenant,
            command,
            parse_with: 'entra-token-exchange',
            parser_context: parserContext,
            credential_binding: `env:${refreshTokenEnvVar}`,
            env_from_credential: { [refreshTokenEnvVar]: credential_id },
            step,
            steps: [step],
            execution_hint: `Run this step with run_bash.env.${refreshTokenEnvVar} populated from credential ${credential_id}; keep parse_with and parser_context unchanged. The command fails before network access when the binding is absent.`,
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
        token_env_var: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/).default('OVERWATCH_ENTRA_TOKEN').describe('run_bash.env variable that will be populated from the selected access credential.'),
        confirm_provider: z.boolean().default(false).describe('Explicitly confirm an otherwise-unmarked access token is an Entra credential.'),
        new_run: z.boolean().default(false).describe('Start another run instead of resuming the matching logical run.'),
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
        token_env_var?: string;
        confirm_provider?: boolean;
        new_run?: boolean;
      };
      const tokenEnvVar = (params as { token_env_var?: string }).token_env_var ?? 'OVERWATCH_ENTRA_TOKEN';
      const cred = engine.getNode(credential_id);
      if (!cred) return errorResponse(`Credential ${credential_id} not found`);
      if (cred.type !== 'credential') return errorResponse(`Node ${credential_id} is type=${cred.type}`);
      if (!isTokenCredential(cred)) return errorResponse(`Credential ${credential_id} is not a token`);
      const kind = cred.cred_material_kind as string | undefined;
      if (!kind || !ENTRA_TOKEN_KINDS.has(kind)) {
        return errorResponse(`Credential ${credential_id} has cred_material_kind=${kind}, expected one of: ${[...ENTRA_TOKEN_KINDS].join(', ')}`);
      }
      if (!isEntraMarkedCredential(cred, tenant_id) && (params as { confirm_provider?: boolean }).confirm_provider !== true) {
        return errorResponse(`Credential ${credential_id} has no Entra/Microsoft Graph provider marker. Correct its metadata or set confirm_provider=true explicitly.`);
      }
      if (!isCredentialUsableForAuth(cred)) {
        return errorResponse(`Credential ${credential_id} is not usable for auth`);
      }

      const issuerTenant = (cred.cred_issuer as string | undefined)?.match(/login\.microsoftonline\.com\/([^/]+)/)?.[1];
      const tenant = concreteTenant(tenant_id)
        ?? concreteTenant(cred.tenant_id)
        ?? concreteTenant(issuerTenant)
        ?? jwtTenant(cred.cred_value);
      const tenantResolved = !!tenant;
      const tenantBlockedReason = 'A concrete Entra tenant is not bound. Run and ingest /me, then re-expand the credential.';

      const steps: PlaybookStep[] = [];
      let n = 0;

      const credentialBinding = `env:${tokenEnvVar}`;
      const envFromCredential = { [tokenEnvVar]: credential_id };
      const tokenGuard = `: "\${${tokenEnvVar}:?Pass ${tokenEnvVar} in run_bash.env from selected credential ${credential_id}}"`;
      const authHeader = `-H "Authorization: Bearer $${tokenEnvVar}"`;
      const graphCommand = (args: string): string => `${tokenGuard}; curl -sS ${args}`;

      steps.push({
        step: ++n,
        step_id: 'me',
        description: 'Validate the token and capture UPN/oid via /v1.0/me. Sets cred_mfa_satisfied: true on the source credential when the response is 200.',
        command: graphCommand(`-i ${authHeader} https://graph.microsoft.com/v1.0/me`),
        parse_with: 'token_replay_msgraph',
        parser_context: { source_credential_id: credential_id, ...(tenant ? { tenant_id: tenant } : {}), credential_execution_binding: credentialBinding },
        runner: 'run_bash',
        env_from_credential: envFromCredential,
        technique: 'recon_idp_principal',
        est_noise: 0.05,
        expected: 'idp_principal node updated with object_id + UPN; VALID_FOR_APP edge.',
        blocking: true,
        ready: true,
        status: 'ready',
        depends_on: [],
        produces_bindings: ['tenant_id'],
      });

      steps.push({
        step: ++n,
        step_id: 'users',
        description: 'List all directory users (page 1, $top=999). Walk @odata.nextLink for full coverage.',
        command: tenantResolved ? graphCommand(`${authHeader} 'https://graph.microsoft.com/v1.0/users?$top=999'`) : null,
        parse_with: 'msgraph-users',
        parser_context: { tenant_id: tenant, source_credential_id: credential_id, credential_execution_binding: credentialBinding },
        runner: 'run_bash',
        env_from_credential: envFromCredential,
        technique: 'recon_idp_principal',
        est_noise: 0.15,
        expected: 'idp_principal nodes per user.',
        ready: tenantResolved,
        status: tenantResolved ? 'ready' : 'blocked',
        depends_on: ['me'],
        required_bindings: ['tenant_id'],
        blocked_reason: tenantResolved ? undefined : tenantBlockedReason,
      });

      steps.push({
        step: ++n,
        step_id: 'applications',
        description: 'List app registrations.',
        command: tenantResolved ? graphCommand(`${authHeader} 'https://graph.microsoft.com/v1.0/applications?$top=999'`) : null,
        parse_with: 'msgraph-applications',
        parser_context: { tenant_id: tenant, source_credential_id: credential_id, credential_execution_binding: credentialBinding },
        runner: 'run_bash',
        env_from_credential: envFromCredential,
        technique: 'recon_idp_application',
        est_noise: 0.15,
        expected: 'idp_application nodes (entra_application).',
        ready: tenantResolved,
        status: tenantResolved ? 'ready' : 'blocked',
        depends_on: ['me'],
        required_bindings: ['tenant_id'],
        blocked_reason: tenantResolved ? undefined : tenantBlockedReason,
      });

      steps.push({
        step: ++n,
        step_id: 'service-principals',
        description: 'List service principals (app instances within the tenant) and retain the scopes and app roles they expose.',
        command: tenantResolved ? graphCommand(`${authHeader} 'https://graph.microsoft.com/v1.0/servicePrincipals?$top=999'`) : null,
        parse_with: 'msgraph-serviceprincipals',
        parser_context: { tenant_id: tenant, source_credential_id: credential_id, credential_execution_binding: credentialBinding },
        runner: 'run_bash',
        env_from_credential: envFromCredential,
        technique: 'recon_idp_application',
        est_noise: 0.15,
        expected: 'idp_application nodes (entra_service_principal).',
        ready: tenantResolved,
        status: tenantResolved ? 'ready' : 'blocked',
        depends_on: ['me'],
        required_bindings: ['tenant_id'],
        blocked_reason: tenantResolved ? undefined : tenantBlockedReason,
      });

      if (include_groups) {
        steps.push({
          step: ++n,
          step_id: 'groups',
          description: 'List directory groups.',
          command: tenantResolved ? graphCommand(`${authHeader} 'https://graph.microsoft.com/v1.0/groups?$top=999'`) : null,
          parse_with: 'msgraph-groups',
          parser_context: { tenant_id: tenant, source_credential_id: credential_id, credential_execution_binding: credentialBinding },
          runner: 'run_bash',
          env_from_credential: envFromCredential,
          technique: 'recon_group',
          est_noise: 0.1,
          expected: 'group nodes for security/unified groups.',
          ready: tenantResolved,
          status: tenantResolved ? 'ready' : 'blocked',
          depends_on: ['me'],
          required_bindings: ['tenant_id'],
          blocked_reason: tenantResolved ? undefined : tenantBlockedReason,
        });
      }

      const durable = new PlaybookCommandService(engine).open({
        definition: {
          definition_id: 'entra-credential',
          definition_version: 2,
          provider: 'entra',
          title: 'Entra credential expansion',
        },
        credential_id,
        normalized_inputs: {
          requested_tenant_id: concreteTenant(tenant_id) ?? null,
          include_groups,
          token_env_var: tokenEnvVar,
          confirm_provider: (params as { confirm_provider?: boolean }).confirm_provider === true,
        },
        bindings: {
          ...(tenant ? { tenant_id: tenant } : {}),
          credential_execution_binding: credentialBinding,
        },
        steps: steps.map(step => ({ ...step })),
        new_run: (params as { new_run?: boolean }).new_run === true,
      });

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            credential_id,
            run_id: durable.run.run_id,
            playbook_run_status: durable.run.status,
            playbook_report_status: durable.run.report_status,
            playbook_created: durable.created,
            playbook_steps: durable.run.steps,
            plan_version: 2,
            tenant: tenant ?? null,
            tenant_status: tenantResolved ? 'resolved' : 'unresolved',
            credential_binding: credentialBinding,
            env_from_credential: envFromCredential,
            step_count: steps.length,
            steps,
            execution_hint: !tenantResolved
              ? `Populate run_bash.env.${tokenEnvVar} from credential ${credential_id}, run and ingest the ready /me step, then re-expand to bind a concrete tenant.`
              : `Populate run_bash.env.${tokenEnvVar} from credential ${credential_id}. Every command fails before network access when the binding is absent.`,
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
