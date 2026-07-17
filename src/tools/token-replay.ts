// ============================================================
// Overwatch — validate_token_credential tool (Track D / Phase 6).
//
// Live token replay: take a captured OIDC/SAML/cookie credential
// already in the graph, probe the matching IdP/cloud API to confirm
// the token actually works, and update the credential's status +
// emit a VALID_FOR_APP / ASSUMES_ROLE edge based on the response.
//
// Architecture: subprocess via curl/awscli. The engine stays fully
// offline; outbound HTTPS goes through the existing process boundary
// the same way nmap / nxc / sqlmap do. Reuses runInstrumentedProcess
// (validate → approval → action_started → spawn → evidence →
// action_completed → optional parse_with ingest), so:
//   - Scope is enforced by the runner's existing target_url validation.
//   - OPSEC noise is recorded the same way as run_bash.
//   - Evidence (response body, status code) is captured.
//   - Approval gates apply per the engagement OPSEC config.
//
// The bearer / cookie value is NEVER written to the activity log
// description or details — only the credential's sha256 fingerprint.
// The full token lives only in the curl `-H` argument and the
// evidence blob, both of which go through the standard Phase 1
// client_safe redaction in reports.
// ============================================================

import { z } from 'zod';
import { createHash } from 'crypto';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';
import { isCredentialMfaBlocked, isCredentialUsableForAuth, isTokenCredential } from '../services/credential-utils.js';
import { runInstrumentedProcess, MAX_TIMEOUT_MS } from './_process-runner.js';
import { cloudIdentityId } from '../services/parser-utils.js';
import {
  playbookProcessLifecycle,
  withPlaybookAttemptCompletion,
} from '../services/playbook-run-service.js';

const PROVIDERS = ['microsoft_graph', 'aws_sts', 'okta', 'github'] as const;
type Provider = typeof PROVIDERS[number];

interface ProviderConfig {
  defaultEndpoint: string;
  parser: string;
  /** Audience-shape sanity check; the operator can bypass with allow_audience_mismatch=true. */
  audienceMatches: (credAud: string | undefined, endpoint: string) => boolean;
  /** Build curl args for this provider given the credential and endpoint. */
  buildCurl: (credValue: string, endpoint: string, extraArgs?: string[], credNode?: Record<string, unknown>) => string[];
}

const PROVIDER_CONFIG: Record<Provider, ProviderConfig> = {
  microsoft_graph: {
    defaultEndpoint: 'https://graph.microsoft.com/v1.0/me',
    parser: 'token_replay_msgraph',
    audienceMatches: (a, ep) => !a || a.includes('graph.microsoft.com') || ep.startsWith('https://graph.microsoft.com'),
    buildCurl: (token, endpoint, extra) => [
      '-sS', '--max-time', '15',
      '-w', '\n[STATUS:%{http_code}]',
      '-H', `Authorization: Bearer ${token}`,
      '-H', 'Accept: application/json',
      ...(extra ?? []),
      endpoint,
    ],
  },
  aws_sts: {
    defaultEndpoint: 'https://sts.amazonaws.com',
    parser: 'token_replay_awssts',
    // STS is invoked via `aws sts assume-role-with-web-identity`, not curl.
    // For the audience match, the token's `aud` is typically `sts.amazonaws.com`.
    audienceMatches: (a) => !a || a.includes('sts.amazonaws.com') || a.includes('aws.amazon.com'),
    // We don't actually use buildCurl for STS — see runStsCli below.
    buildCurl: () => [],
  },
  okta: {
    defaultEndpoint: 'https://example.okta.com/api/v1/users/me',
    parser: 'token_replay_okta',
    audienceMatches: (_a, ep) => /\.okta\.com\b/i.test(ep) || /\.oktapreview\.com\b/i.test(ep),
    buildCurl: (token, endpoint, extra, credNode) => {
      const kind = typeof credNode?.cred_material_kind === 'string' ? credNode.cred_material_kind : undefined;
      const scheme = isJwt(token) || kind === 'oidc_access_token' || kind === 'oidc_id_token'
        ? 'Bearer'
        : 'SSWS';
      return [
        '-sS', '--max-time', '15',
        '-w', '\n[STATUS:%{http_code}]',
        '-H', `Authorization: ${scheme} ${token}`,
        '-H', 'Accept: application/json',
        ...(extra ?? []),
        endpoint,
      ];
    },
  },
  github: {
    defaultEndpoint: 'https://api.github.com/user',
    parser: 'token_replay_github',
    audienceMatches: (_a, ep) => ep.startsWith('https://api.github.com'),
    buildCurl: (token, endpoint, extra) => [
      '-sSi', '--max-time', '15',
      '-w', '\n[STATUS:%{http_code}]',
      '-H', `Authorization: Bearer ${token}`,
      '-H', 'Accept: application/vnd.github+json',
      ...(extra ?? []),
      endpoint,
    ],
  },
};

interface TokenReplayParams {
  credential_id: string;
  provider: Provider;
  endpoint?: string;
  extra_args?: string[];
  allow_audience_mismatch?: boolean;
  // Provider-specific extras (forwarded to the parser via parser_context).
  target_idp_application_id?: string;
  target_role_arn?: string;
  target_cloud_identity_id?: string;
  // Lifecycle threading.
  action_id?: string;
  frontier_item_id?: string;
  agent_id?: string;
  noise_estimate?: number;
  timeout_ms?: number;
  command_id?: string;
  idempotency_key?: string;
  playbook_run_id?: string;
  playbook_step_id?: string;
  playbook_attempt_id?: string;
}

function fingerprint(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 16);
}

function isJwt(value: string): boolean {
  const token = value.replace(/^Bearer\s+/i, '').trim();
  const parts = token.split('.');
  return parts.length === 3 && parts.every(part => part.length > 0);
}

export function registerTokenReplayTool(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'validate_token_credential',
    {
      title: 'Validate Token Credential (live replay)',
      description: `Probe an IdP / cloud API with a captured token credential to confirm it actually authenticates, then update the credential's status + emit a VALID_FOR_APP edge based on the response. Closes the loop on jwt-tool / evilginx / aadinternals captures so OIDC_FEDERATION_PIVOT inference can fire on confirmed-usable tokens.

Architecture: subprocess via curl (or awscli for STS). Goes through the standard action lifecycle (validate → approval → action_started → spawn → evidence → action_completed). The engine itself never makes outbound network calls — every replay is auditable as a normal curl invocation.

Provider coverage:
- microsoft_graph: GET /v1.0/me with Bearer token. Parser: token_replay_msgraph.
- aws_sts: AssumeRoleWithWebIdentity for OIDC federation tokens. Parser: token_replay_awssts.
- okta: GET /api/v1/users/me or /api/v1/sessions/me with SSWS token / cookie. Parser: token_replay_okta.
- github: GET /user with Bearer token (PAT or App installation). Parser: token_replay_github.

Sensitive token values are NEVER logged in plain text — the action description and details carry only a sha256 fingerprint. The full token is in the curl -H argument (visible only in the captured evidence blob, which is client_safe-redacted in reports).`,
      inputSchema: {
        credential_id: z.string().describe('Credential node id to replay. Must be a token credential (jwt-tool, evilginx, aadinternals, MicroBurst, etc.).'),
        provider: z.enum(PROVIDERS).describe('Which provider API to probe.'),
        endpoint: z.string().optional().describe("Override the default endpoint (e.g. 'https://graph.microsoft.com/v1.0/users' for tenant-wide reads)."),
        extra_args: z.array(z.string()).optional().describe('Additional curl args (e.g. ["-X","POST","-d",...]).'),
        allow_audience_mismatch: z.boolean().optional().describe('Allow the replay even when the token audience does not match the endpoint (for exploratory probes).'),
        target_idp_application_id: z.string().optional().describe('idp_application node id; emitted as the target of the VALID_FOR_APP edge on success.'),
        target_role_arn: z.string().optional().describe('AWS STS only: ARN of the role to assume.'),
        target_cloud_identity_id: z.string().optional().describe('AWS STS only: cloud_identity node id for the target role; used as the target of the ASSUMES_ROLE edge.'),
        action_id: z.string().optional().describe('Stable action ID. Auto-generated if omitted.'),
        frontier_item_id: z.string().optional().describe('Frontier item this action came from'),
        agent_id: z.string().optional().describe('Agent or session responsible for the action'),
        noise_estimate: z.number().min(0).max(1).optional().describe('Override the technique default (0.05 for token_replay).'),
        timeout_ms: z.number().int().min(1000).max(MAX_TIMEOUT_MS).optional(),
        command_id: z.string().min(1).optional().describe('Stable application-command ID for status correlation and safe retries.'),
        idempotency_key: z.string().min(1).optional().describe('Stable retry key. Reusing it with identical input returns the original result without executing again.'),
        playbook_run_id: z.string().min(1).optional().describe('Durable playbook run linkage returned by start_playbook_step.'),
        playbook_step_id: z.string().min(1).optional().describe('Durable playbook step linkage returned by start_playbook_step.'),
        playbook_attempt_id: z.string().min(1).optional().describe('Durable playbook attempt linkage returned by start_playbook_step.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorBoundary('validate_token_credential', async (params: TokenReplayParams) => {
      const onExecutionState = playbookProcessLifecycle(engine, params);
      return withPlaybookAttemptCompletion(engine, params, async () => {
      const credNode = engine.getNode(params.credential_id);
      if (!credNode || credNode.type !== 'credential') {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: `Credential not found: ${params.credential_id}` }, null, 2) }],
          isError: true,
        };
      }
      if (!isTokenCredential(credNode)) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: `Credential ${params.credential_id} is not a token credential (cred_material_kind: ${credNode.cred_material_kind}). Token replay requires oidc_*, saml, oauth_secret, pat, app_password, or session_cookie material.` }, null, 2) }],
          isError: true,
        };
      }
      if (!isCredentialUsableForAuth(credNode)) {
        const reason = isCredentialMfaBlocked(credNode)
          ? 'mfa_blocked'
          : credNode.credential_status === 'expired'
            ? 'expired'
            : 'not_usable';
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: `Credential ${params.credential_id} is not usable for auth (${reason}). Refusing to replay.` }, null, 2) }],
          isError: true,
        };
      }

      const tokenValue = credNode.cred_value as string | undefined;
      if (!tokenValue) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: `Credential ${params.credential_id} has no cred_value to replay (likely a redacted-only stub).` }, null, 2) }],
          isError: true,
        };
      }

      const cfg = PROVIDER_CONFIG[params.provider];
      const endpoint = params.endpoint ?? cfg.defaultEndpoint;
      if (!params.allow_audience_mismatch && !cfg.audienceMatches(credNode.cred_audience as string | undefined, endpoint)) {
        return {
          content: [{ type: 'text', text: JSON.stringify({
            error: `Audience mismatch: credential audience ${credNode.cred_audience ?? '(unset)'} does not match endpoint ${endpoint} for provider ${params.provider}. Set allow_audience_mismatch=true to override.`,
          }, null, 2) }],
          isError: true,
        };
      }

      const fp = fingerprint(tokenValue);
      const tokenLabel = `<redacted token sha256:${fp}…>`;

      // For STS, dispatch a different binary + argv shape.
      if (params.provider === 'aws_sts') {
        if (!params.target_role_arn) {
          return {
            content: [{ type: 'text', text: JSON.stringify({ error: 'aws_sts replay requires target_role_arn' }, null, 2) }],
            isError: true,
          };
        }
        let targetCloudIdentityId = params.target_cloud_identity_id;
        if (targetCloudIdentityId) {
          const expectedId = cloudIdentityId(params.target_role_arn);
          const target = engine.getNode(targetCloudIdentityId);
          const targetProvider = target?.provider ?? target?.cloud_provider;
          if (!target || target.type !== 'cloud_identity' || targetCloudIdentityId !== expectedId
              || target.arn !== params.target_role_arn || targetProvider !== 'aws'
              || !params.target_role_arn.includes(':role/')) {
            return {
              content: [{ type: 'text', text: JSON.stringify({
                error: 'target_cloud_identity_id must name the canonical existing AWS role for target_role_arn',
              }, null, 2) }],
              isError: true,
            };
          }
        } else {
          const expectedId = cloudIdentityId(params.target_role_arn);
          const candidate = engine.getNode(expectedId);
          if (candidate?.type === 'cloud_identity' && candidate.arn === params.target_role_arn
              && (candidate.provider === 'aws' || candidate.cloud_provider === 'aws')) {
            targetCloudIdentityId = expectedId;
          }
        }
        const sessionName = `overwatch-replay-${fp}`;
        const stsArgs = [
          'sts', 'assume-role-with-web-identity',
          '--role-arn', params.target_role_arn,
          '--role-session-name', sessionName,
          '--web-identity-token', tokenValue,
          '--output', 'json',
        ];
        const commandRepr = `aws sts assume-role-with-web-identity --role-arn ${params.target_role_arn} --role-session-name ${sessionName} --web-identity-token ${tokenLabel}`;
        const result = await runInstrumentedProcess(engine, {
          binary: 'aws',
          args: stsArgs,
          command_repr: commandRepr,
          action_id: params.action_id,
          frontier_item_id: params.frontier_item_id,
          agent_id: params.agent_id,
          description: `Token replay: ${params.provider} → AssumeRoleWithWebIdentity ${params.target_role_arn}`,
          tool_name: 'validate_token_credential',
          technique: 'token_replay',
          target_url: endpoint,
          target_node: targetCloudIdentityId,
          validate: true,
          parse_with: cfg.parser,
          parser_context: {
            source_credential_id: params.credential_id,
            target_role_arn: params.target_role_arn,
            target_cloud_identity_id: targetCloudIdentityId,
          } as Record<string, unknown>,
          noise_estimate: params.noise_estimate,
          timeout_ms: params.timeout_ms,
          command_id: params.command_id,
          idempotency_key: params.idempotency_key,
          onExecutionState,
          invoking_tool: 'run_tool',
        });
        return result;
      }

      const curlArgs = cfg.buildCurl(tokenValue, endpoint, params.extra_args, credNode as Record<string, unknown>);
      // command_repr replaces the bearer with the redacted label so the
      // activity log description doesn't carry the raw token.
      const commandRepr = `curl ${curlArgs.map(a => a === tokenValue ? tokenLabel : a.includes(`Bearer ${tokenValue}`) ? a.replace(tokenValue, tokenLabel) : a.includes(`SSWS ${tokenValue}`) ? a.replace(tokenValue, tokenLabel) : /[\s'"]/.test(a) ? `'${a.replace(/'/g, "'\\''").replace(tokenValue, tokenLabel)}'` : a).join(' ')}`;

      const result = await runInstrumentedProcess(engine, {
        binary: 'curl',
        args: curlArgs,
        command_repr: commandRepr,
        action_id: params.action_id,
        frontier_item_id: params.frontier_item_id,
        agent_id: params.agent_id,
        description: `Token replay: ${params.provider} → ${endpoint}`,
        tool_name: 'validate_token_credential',
        technique: 'token_replay',
        target_url: endpoint,
        target_node: params.target_idp_application_id,
        validate: true,
        parse_with: cfg.parser,
        parser_context: {
          source_credential_id: params.credential_id,
          source_idp_application_id: params.target_idp_application_id,
        } as Record<string, unknown>,
        noise_estimate: params.noise_estimate,
        timeout_ms: params.timeout_ms,
        command_id: params.command_id,
        idempotency_key: params.idempotency_key,
        onExecutionState,
        invoking_tool: 'run_tool',
      });
      return result;
      }, { begin_execution: false });
    }),
  );
}
