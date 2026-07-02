// ============================================================
// Overwatch — test_webapp_credential tool (Web / External track).
//
// Test an operator-provided or discovered credential against a web
// application in a single call, then record the result so credential
// coverage retires and the authenticated-rescan rule fires.
//
// This closes the web-auth loop that `validate_token_credential` only
// covers for IdP / cloud SSO providers (Entra, Okta, AWS STS, GitHub):
//   - form  → POST username/password to a login endpoint
//   - basic → HTTP Basic (`-u user:pass`)
//   - bearer→ `Authorization: Bearer <token>` (or a custom header)
//   - cookie→ `Cookie: <name>=<value>` (session replay)
//
// Architecture: subprocess via curl through runInstrumentedProcess, the
// same lifecycle nmap / nxc / validate_token_credential use
// (validate → approval → action_started → spawn → evidence →
// action_completed → parse_with ingest). The engine stays fully offline;
// scope is enforced by the runner's target_url validation before spawn.
//
// The secret (password / token / cookie value) is NEVER written to the
// activity log: command_repr carries only a sha256 fingerprint, and the
// raw argv is withheld from the persisted events + tool response via
// runInstrumentedProcess's `redact_args_in_log`. The raw secret is used
// only to spawn curl. If a target reflects it in its response, the runner
// scrubs it from the captured stdout/stderr (via `redact_secrets`) in the
// tool response and the live dashboard tee; the parser never emits it into
// the finding, and the stored evidence blob is client_safe-redacted in reports.
//
// Status trust: curl's -w marker carries a per-call random nonce
// (`[OWSTATUS:<code>:<nonce>]`) that the target can't predict, so the
// parser can't be tricked into a success verdict by an echoed fake marker,
// and headers/body are parsed by curl's block structure so an injected
// `HTTP/…` block in the target-controlled body can't forge a match.
// ============================================================

import { z } from 'zod';
import { createHash, randomBytes } from 'crypto';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';
import { isCredentialMfaBlocked, isCredentialUsableForAuth } from '../services/credential-utils.js';
import { runInstrumentedProcess, MAX_TIMEOUT_MS } from './_process-runner.js';

const METHODS = ['form', 'basic', 'bearer', 'cookie'] as const;
type Method = typeof METHODS[number];

interface WebCredParams {
  credential_id: string;
  target_url: string;
  method: Method;
  login_path?: string;
  username_field?: string;
  password_field?: string;
  header_name?: string;
  success?: {
    status?: number | number[];
    body_contains?: string;
    body_excludes?: string;
    redirect_contains?: string;
  };
  // Lifecycle threading.
  action_id?: string;
  frontier_item_id?: string;
  agent_id?: string;
  noise_estimate?: number;
  timeout_ms?: number;
}

function fingerprint(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 16);
}

/** Resolve login_path against the target origin; absolute URLs pass through. */
function resolveLoginUrl(targetUrl: string, loginPath?: string): string {
  if (!loginPath) return targetUrl;
  try {
    return new URL(loginPath, targetUrl).toString();
  } catch {
    return targetUrl;
  }
}

/** Shell-quote a single arg (after redaction) for the human-readable command_repr. */
function quoteArg(arg: string): string {
  if (arg === '') return "''";
  if (/^[A-Za-z0-9_./:@%-]+$/.test(arg)) return arg;
  return `'${arg.replace(/'/g, "'\\''")}'`;
}

export function registerTestWebappCredentialTool(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'test_webapp_credential',
    {
      title: 'Test Webapp Credential (live auth attempt)',
      description: `Test a credential already in the graph against a web application in one call, then record the result so credential coverage retires and authenticated re-scan fires. Complements validate_token_credential (which only handles IdP / cloud SSO providers) by covering ordinary web auth: form logins, HTTP Basic, generic bearer / API-key headers, and session-cookie replay.

Methods:
- form:   POST username/password to a login endpoint (login_path). Fields default to username/password; override with username_field / password_field.
- basic:  HTTP Basic auth (-u cred_user:secret) against target_url.
- bearer: Authorization: Bearer <token>. Set header_name to send a custom header (e.g. X-API-Key) with the raw value instead.
- cookie: Cookie: <name>=<value> replay. header_name is the cookie name (default 'session').

Success detection: you MUST pass a 'success' criterion (status code(s), body_contains, body_excludes, redirect_contains) to confirm — there is no status-only default, because every status-only heuristic (a form 302, an API 200, even a Basic 2xx on a path that ignores the header) is target-controlled and can't distinguish real access from a benign or crafted response. Pick a positive signal the authenticated response has and an unauthenticated one doesn't: success.redirect_contains for a form login (the post-login landing path, e.g. '/dashboard' — not '/'), success.body_contains for an API (a field only an authed response returns), success.status for a strictly protected endpoint. Criteria are ANDed. When success.status is omitted, redirect_contains implies a 3xx and body_contains implies a <400 status; so don't combine a redirect landing (3xx) with body_contains, or supply success.status to override the built-in gates. body_excludes marks failure even if the status matched, so keep it a specific phrase ('Invalid password', not 'error').

Outcomes: confirmed success → AUTHENTICATED_AS (credential → webapp) + VALID_ON (credential → service): retires the credential_test frontier item and triggers rule-authenticated-rescan. Confirmed failure (401/403, or an explicit criterion that wasn't met / a body_excludes hit) → TESTED_CRED (credential → service): retires the pair without claiming access. Inconclusive (unreachable, curl killed, or no criterion supplied) → nothing stamped. Password reuse falls out for free — the same plaintext credential is also surfaced against any in-scope non-web services it pairs with.

Architecture: subprocess via curl. Goes through the standard action lifecycle (validate → approval → action_started → spawn → evidence → action_completed). Scope is enforced on the request URL before spawn. The secret is NEVER written to the activity log — command_repr and the persisted event details carry only a sha256 fingerprint (the raw argv is withheld from the log/response); the raw secret is used solely to spawn curl and appears only in the captured evidence blob, which is client_safe-redacted in reports.`,
      inputSchema: {
        credential_id: z.string().describe('Credential node id to test. Must be usable for auth (not expired / rotated / MFA-blocked).'),
        target_url: z.string().describe('The web app / API base URL to authenticate against (scope-checked before spawn). For form auth this is the origin; set login_path for the login endpoint.'),
        method: z.enum(METHODS).describe('Auth method: form | basic | bearer | cookie.'),
        login_path: z.string().optional().describe("form only: login endpoint, absolute or relative to target_url (e.g. '/login'). Defaults to target_url."),
        username_field: z.string().optional().describe("form only: username form field name (default 'username')."),
        password_field: z.string().optional().describe("form only: password form field name (default 'password')."),
        header_name: z.string().optional().describe("bearer: custom header to carry the raw token (e.g. 'X-API-Key'); default 'Authorization: Bearer <token>'. cookie: the cookie name (default 'session')."),
        success: z.object({
          status: z.union([z.number().int(), z.array(z.number().int())]).optional().describe('HTTP status(es) that mean success.'),
          body_contains: z.string().optional().describe('Substring that must appear in the response body.'),
          body_excludes: z.string().optional().describe('Substring whose presence means FAILURE even if the status matched (e.g. "Invalid password").'),
          redirect_contains: z.string().optional().describe('Substring the Location header must contain (post-login redirect target).'),
        }).optional().describe('Success criteria — REQUIRED to confirm a success (no status-only default). Without it the result is inconclusive and nothing is stamped.'),
        action_id: z.string().optional().describe('Stable action ID. Auto-generated if omitted.'),
        frontier_item_id: z.string().optional().describe('Frontier item this action came from (the credential_test it retires).'),
        agent_id: z.string().optional().describe('Agent or session responsible for the action.'),
        noise_estimate: z.number().min(0).max(1).optional().describe('Override the technique default (0.15 for web_credential_test).'),
        timeout_ms: z.number().int().min(1000).max(MAX_TIMEOUT_MS).optional(),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorBoundary('test_webapp_credential', async (params: WebCredParams) => {
      const credNode = engine.getNode(params.credential_id);
      if (!credNode || credNode.type !== 'credential') {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: `Credential not found: ${params.credential_id}` }, null, 2) }],
          isError: true,
        };
      }
      if (!isCredentialUsableForAuth(credNode)) {
        const reason = isCredentialMfaBlocked(credNode)
          ? 'mfa_blocked'
          : credNode.credential_status === 'expired'
            ? 'expired'
            : credNode.credential_status === 'rotated'
              ? 'rotated'
              : 'not_usable';
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: `Credential ${params.credential_id} is not usable for auth (${reason}). Refusing to test.` }, null, 2) }],
          isError: true,
        };
      }

      const secret = typeof credNode.cred_value === 'string' ? credNode.cred_value : undefined;
      if (!secret) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: `Credential ${params.credential_id} has no cred_value to test (likely a redacted-only stub).` }, null, 2) }],
          isError: true,
        };
      }
      const credUser = typeof credNode.cred_user === 'string' ? credNode.cred_user : undefined;
      if ((params.method === 'form' || params.method === 'basic') && !credUser) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: `Credential ${params.credential_id} has no cred_user; ${params.method} auth needs a username.` }, null, 2) }],
          isError: true,
        };
      }

      // Unforgeable status marker: curl appends `\n[OWSTATUS:<code>:<nonce>]`
      // via -w AFTER the (target-controlled) body. The target can't predict
      // the per-call nonce, so it can't spoof a success status by embedding a
      // fake marker in its response body. The parser trusts ONLY a marker
      // carrying this nonce; if it's absent (e.g. curl killed on timeout) the
      // verdict is inconclusive rather than target-driven.
      const nonce = randomBytes(8).toString('hex');
      // curl's own per-request budget tracks the caller's timeout_ms (default
      // 20s) so a small timeout_ms doesn't get the process killed mid-request
      // before curl can finish. The runner's hard kill gets +5s of headroom
      // (below) so curl times out cleanly first (emitting a 000 marker).
      const reqSeconds = params.timeout_ms ? Math.max(1, Math.ceil(params.timeout_ms / 1000)) : 20;
      const base = ['-sS', '-i', '--max-time', String(reqSeconds), '-w', `\n[OWSTATUS:%{http_code}:${nonce}]`];

      // Build the real argv AND its redacted mirror in lockstep, so the
      // secret is redacted precisely where it sits (never a blind global
      // substring replace that could corrupt unrelated tokens). Only the
      // repr feeds command_repr; the real args are used to spawn.
      const fp = fingerprint(secret);
      const label = `<redacted secret sha256:${fp}…>`;
      let args: string[];
      let reprArgs: string[];
      let requestUrl = params.target_url;
      switch (params.method) {
        case 'form': {
          requestUrl = resolveLoginUrl(params.target_url, params.login_path);
          const uf = params.username_field || 'username';
          const pf = params.password_field || 'password';
          const prefix = `${encodeURIComponent(uf)}=${encodeURIComponent(credUser as string)}&${encodeURIComponent(pf)}=`;
          args = [...base, '-X', 'POST', '-d', `${prefix}${encodeURIComponent(secret)}`, requestUrl];
          reprArgs = [...base, '-X', 'POST', '-d', `${prefix}${label}`, requestUrl];
          break;
        }
        case 'basic':
          args = [...base, '-u', `${credUser}:${secret}`, requestUrl];
          reprArgs = [...base, '-u', `${credUser}:${label}`, requestUrl];
          break;
        case 'bearer': {
          const build = (v: string) => (params.header_name ? `${params.header_name}: ${v}` : `Authorization: Bearer ${v}`);
          args = [...base, '-H', build(secret), requestUrl];
          reprArgs = [...base, '-H', build(label), requestUrl];
          break;
        }
        case 'cookie': {
          const cookieName = params.header_name || 'session';
          args = [...base, '-b', `${cookieName}=${secret}`, requestUrl];
          reprArgs = [...base, '-b', `${cookieName}=${label}`, requestUrl];
          break;
        }
      }
      const commandRepr = `curl ${reprArgs.map(quoteArg).join(' ')}`;

      // Normalize success criteria for the parser context.
      const successStatus = params.success?.status !== undefined
        ? (Array.isArray(params.success.status) ? params.success.status : [params.success.status])
        : undefined;

      return runInstrumentedProcess(engine, {
        binary: 'curl',
        args,
        command_repr: commandRepr,
        redact_args_in_log: true,
        // The runner scrubs these from the captured stdout/stderr in the tool
        // response + live tee, in case the target reflects the submitted secret
        // (raw, or the url-encoded form used in a form body).
        redact_secrets: [...new Set([secret, encodeURIComponent(secret)])],
        action_id: params.action_id,
        frontier_item_id: params.frontier_item_id,
        agent_id: params.agent_id,
        description: `Web credential test: ${params.method} ${credUser ? `${credUser} → ` : ''}${requestUrl}`,
        tool_name: 'test_webapp_credential',
        technique: 'web_credential_test',
        target_url: requestUrl,
        validate: true,
        parse_with: 'test_webapp_credential',
        parser_context: {
          source_credential_id: params.credential_id,
          // The parser attributes VALID_ON / AUTHENTICATED_AS to the origin we
          // actually authenticated against (request_url), which equals
          // target_url for every method except a cross-origin form login_path.
          request_url: requestUrl,
          target_url: params.target_url,
          method: params.method,
          cred_user: credUser,
          status_nonce: nonce,
          success_status: successStatus,
          success_body_contains: params.success?.body_contains,
          success_body_excludes: params.success?.body_excludes,
          success_redirect_contains: params.success?.redirect_contains,
        } as Record<string, unknown>,
        noise_estimate: params.noise_estimate,
        // +5s so the runner's hard kill fires after curl's own --max-time,
        // letting curl exit cleanly (and still emit its status marker); clamped
        // so it never exceeds the runner's ceiling.
        timeout_ms: params.timeout_ms ? Math.min(MAX_TIMEOUT_MS, params.timeout_ms + 5000) : undefined,
        invoking_tool: 'run_tool',
      });
    }),
  );
}
