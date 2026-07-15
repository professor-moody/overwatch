// ============================================================
// Overwatch — expand_github_credential tool (A.2)
//
// Returns a structured recon plan for a captured GitHub PAT (or App
// token / OAuth token). The plan walks /user → /user/orgs → /user/repos
// → per-repo secrets / branch protection / deploy keys / Actions OIDC
// trust. Each step names a `parse_with` parser to ingest the JSON
// response back into the graph.
//
// All steps are read-only via `gh api`; under the default approve-
// critical mode they auto-approve under the noise budget. The
// per-repo expansion is capped by `max_repos` (default 200) to keep
// the plan tractable for large orgs.
// ============================================================

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';
import { safePlaybookArg } from './_playbook-utils.js';
import { isCredentialUsableForAuth } from '../services/credential-utils.js';

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
  env_from_credential?: Record<string, string>;
  ready?: boolean;
  status?: 'ready' | 'blocked';
  depends_on?: string[];
  blocked_reason?: string;
}

const GH_CRED_KINDS = new Set(['pat', 'oidc_access_token', 'token']);

function isGithubMarkedCredential(cred: Record<string, unknown>): boolean {
  return [cred.provider, cred.cred_provider, cred.cred_audience, cred.cred_issuer, cred.idp_kind]
    .some(value => typeof value === 'string' && /(^|[/:._-])github([/:._-]|$)|api\.github\.com/i.test(value));
}

export function registerGithubPlaybookTool(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'expand_github_credential',
    {
      title: 'Expand GitHub Credential',
      description: `Generate a structured recon plan for a captured GitHub credential
(PAT / OAuth token / fine-grained PAT / GitHub App installation token).

Plan walks:
  1. \`gh api /user\`                         → token-replay-github (validate + scopes)
  2. \`gh api /user/orgs\`                    → gh-api-orgs (org idp nodes)
  3. \`gh api /user/repos --paginate\`        → gh-api-repos (idp_application per repo)
  4. Per repo (capped by max_repos):
     - /repos/{o}/{r}/actions/secrets        → gh-api-secrets
     - /repos/{o}/{r}/branches/<default>/protection → gh-api-branch-protection
     - /repos/{o}/{r}/keys                   → gh-api-deploy-keys
     - /repos/{o}/{r}/actions/oidc-customization/sub → github-actions-oidc

Returns the plan; does not execute. Run each step via \`run_bash\`
with the named \`parse_with\` value. The plan caps repo
expansion at \`max_repos\` to stay tractable on large orgs.`,
      inputSchema: {
        credential_id: z.string().min(1).describe('Credential node id. Must be a token-shaped GitHub credential.'),
        max_repos: z.number().int().min(1).max(2000).default(200).describe('Cap on per-repo expansion. Steps 4a–4d are emitted for the first N repos returned by /user/repos.'),
        include_orgs: z.boolean().default(true).describe('Include /user/orgs enumeration step.'),
        candidate_repos: z.array(z.union([
          z.string().regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/),
          z.object({
            repo_full_name: z.string().regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/),
            default_branch: z.string().min(1).max(255),
          }),
        ])).optional().describe('Optional `owner/repo` strings or `{repo_full_name, default_branch}` records. A string remains compatible; branch protection is blocked until its default branch is known.'),
        token_env_var: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/).default('OVERWATCH_GITHUB_TOKEN').describe('Environment variable containing this selected credential at execution time. Commands fail closed when it is unset.'),
        confirm_provider: z.boolean().default(false).describe('Explicitly confirm an otherwise-unmarked token is a GitHub credential.'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('expand_github_credential', async (params) => {
      const { credential_id, max_repos, include_orgs, candidate_repos } = params as {
        credential_id: string;
        max_repos: number;
        include_orgs: boolean;
        candidate_repos?: Array<string | { repo_full_name: string; default_branch: string }>;
        token_env_var?: string;
        confirm_provider?: boolean;
      };
      const tokenEnvVar = (params as { token_env_var?: string }).token_env_var ?? 'OVERWATCH_GITHUB_TOKEN';

      const cred = engine.getNode(credential_id);
      if (!cred) return errorResponse(`Credential ${credential_id} not found`);
      if (cred.type !== 'credential') return errorResponse(`Node ${credential_id} is type=${cred.type}`);
      const kind = cred.cred_material_kind as string | undefined;
      if (!kind || !GH_CRED_KINDS.has(kind)) {
        return errorResponse(`Credential ${credential_id} has cred_material_kind=${kind}, not a GitHub-shaped token. Expected one of: ${[...GH_CRED_KINDS].join(', ')}`);
      }
      // PAT was the original public input shape and is unambiguously GitHub in
      // Overwatch. Generic token kinds still require an explicit provider gate.
      if (kind !== 'pat' && !isGithubMarkedCredential(cred) && (params as { confirm_provider?: boolean }).confirm_provider !== true) {
        return errorResponse(`Credential ${credential_id} has no GitHub provider/audience marker. Correct its metadata or set confirm_provider=true explicitly.`);
      }
      if (!isCredentialUsableForAuth(cred)) {
        return errorResponse(`Credential ${credential_id} is not usable for auth`);
      }

      const steps: PlaybookStep[] = [];
      let n = 0;
      const credentialBinding = `env:${tokenEnvVar}`;
      const envFromCredential = { [tokenEnvVar]: credential_id };
      const gh = (args: string): string =>
        `: "\${${tokenEnvVar}:?Populate run_bash.env.${tokenEnvVar} from credential ${credential_id}}"; GH_TOKEN="$${tokenEnvVar}" gh api ${args}`;

      // Step 1: validate + capture scopes.
      steps.push({
        step: ++n,
        description: 'Validate the token and capture OAuth scopes from response headers. Use `-i` so the scopes header is parsed.',
        command: gh('-i /user'),
        parse_with: 'token_replay_github',
        parser_context: { source_credential_id: credential_id, credential_execution_binding: credentialBinding },
        runner: 'run_bash',
        env_from_credential: envFromCredential,
        technique: 'recon_idp_principal',
        est_noise: 0.05,
        expected: 'Updates credential with cred_user, cred_scopes; emits VALID_FOR_APP edge.',
        blocking: true,
      });

      if (include_orgs) {
        steps.push({
          step: ++n,
          description: 'Enumerate organizations the token has membership in.',
          command: gh('/user/orgs --paginate --slurp'),
          parse_with: 'gh-api-orgs',
          parser_context: { source_credential_id: credential_id, credential_execution_binding: credentialBinding },
          runner: 'run_bash',
          env_from_credential: envFromCredential,
          technique: 'recon_idp_principal',
          est_noise: 0.1,
          expected: 'idp nodes (idp_kind: github_org) per org; cred_orgs stamped on the credential.',
        });
      }

      let repoList: Array<{ repo_full_name: string; default_branch?: string }> | undefined;
      if (candidate_repos && candidate_repos.length > 0) {
        repoList = candidate_repos.slice(0, max_repos).map(candidate => typeof candidate === 'string'
          ? { repo_full_name: candidate }
          : candidate);
      } else {
        steps.push({
          step: ++n,
          description: 'List all repositories visible to the token. Use --paginate to walk the full list.',
          command: gh('/user/repos --paginate --slurp'),
          parse_with: 'gh-api-repos',
          parser_context: { source_credential_id: credential_id, credential_execution_binding: credentialBinding },
          runner: 'run_bash',
          env_from_credential: envFromCredential,
          technique: 'recon_idp_application',
          est_noise: 0.15,
          expected: 'idp_application per repo (idp_kind: github_org, app_kind: github_repo).',
          blocking: true,
        });
      }

      // Per-repo expansion when an explicit list is provided.
      if (repoList) {
        for (const candidate of repoList) {
          // Fence the operator-supplied repo before it lands in `gh api /repos/'${repo}'/…`.
          const repo = safePlaybookArg(candidate.repo_full_name);
          const owner = repo.split('/')[0];
          const existingRepo = engine.getNodesByType('idp_application')
            .find(node => node.repo_full_name === candidate.repo_full_name);
          const defaultBranch = safePlaybookArg(candidate.default_branch ?? existingRepo?.default_branch ?? '') || undefined;
          steps.push({
            step: ++n,
            description: `List Actions secrets for ${repo}.`,
            command: gh(`/repos/'${repo}'/actions/secrets --paginate --slurp`),
            parse_with: 'gh-api-secrets',
            parser_context: { repo_full_name: repo, source_credential_id: credential_id, credential_execution_binding: credentialBinding },
            runner: 'run_bash',
            env_from_credential: envFromCredential,
            technique: 'recon_credential',
            est_noise: 0.1,
            expected: 'credential nodes for each Actions secret (cred_value is fingerprint-only — values are not exposed by the API).',
          });
          if (!defaultBranch) {
            steps.push({
              step: ++n,
              step_id: `repo-details-${repo.replace('/', '-')}`,
              description: `Resolve ${repo}'s default branch before branch-protection inspection.`,
              command: gh(`/repos/'${repo}'`),
              parse_with: 'gh-api-repos',
              parser_context: { repo_full_name: repo, source_credential_id: credential_id, credential_execution_binding: credentialBinding },
              runner: 'run_bash',
              env_from_credential: envFromCredential,
              technique: 'recon_idp_application',
              est_noise: 0.05,
              expected: 'Repo application metadata including the canonical default_branch binding.',
              ready: true,
              status: 'ready',
            });
          }
          steps.push({
            step: ++n,
            step_id: `branch-protection-${repo.replace('/', '-')}`,
            description: `Pull branch protection for ${repo}'s resolved default branch.`,
            command: defaultBranch ? gh(`/repos/'${repo}'/branches/'${defaultBranch}'/protection`) : null,
            parse_with: 'gh-api-branch-protection',
            parser_context: { repo_full_name: repo, ...(defaultBranch ? { branch_name: defaultBranch } : {}), source_credential_id: credential_id, credential_execution_binding: credentialBinding },
            runner: 'run_bash',
            env_from_credential: envFromCredential,
            technique: 'recon_idp_application',
            est_noise: 0.05,
            expected: 'Stamps branch_protection_gaps + finding_severity on the repo idp_application.',
            ready: !!defaultBranch,
            status: defaultBranch ? 'ready' : 'blocked',
            depends_on: defaultBranch ? [] : [`repo-details-${repo.replace('/', '-')}`],
            blocked_reason: defaultBranch ? undefined : 'Default branch is unknown. Run and ingest repo-details, then re-expand.',
          });
          steps.push({
            step: ++n,
            description: `List deploy keys for ${repo}. Read-write keys with private-half capture become lateral-move candidates.`,
            command: gh(`/repos/'${repo}'/keys --paginate --slurp`),
            parse_with: 'gh-api-deploy-keys',
            parser_context: { repo_full_name: repo, source_credential_id: credential_id, credential_execution_binding: credentialBinding },
            runner: 'run_bash',
            env_from_credential: envFromCredential,
            technique: 'recon_credential',
            est_noise: 0.05,
            expected: 'Public deploy-key credential records with write capability metadata; reusable auth remains false until private material is captured.',
          });
          steps.push({
            step: ++n,
            description: `Capture Actions OIDC subject-claim customization for ${repo}. Misconfigured patterns are flagged by the CI_TRUST_WILDCARD inference rule once ingested.`,
            command: gh(`/repos/'${repo}'/actions/oidc-customization/sub`),
            parse_with: 'github-actions-oidc',
            parser_context: { repo_full_name: repo, owner, source_credential_id: credential_id, credential_execution_binding: credentialBinding },
            runner: 'run_bash',
            env_from_credential: envFromCredential,
            technique: 'recon_idp_application',
            est_noise: 0.05,
            expected: 'ci_github_actions idp_application carrying the repository OIDC customization metadata.',
          });
        }
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            credential_id,
            step_count: steps.length,
            max_repos,
            credential_binding: credentialBinding,
            env_from_credential: envFromCredential,
            steps,
            execution_hint: candidate_repos
              ? `Populate run_bash.env.${tokenEnvVar} from credential ${credential_id}; run only ready per-repo steps and re-expand after any repo-details binding lands.`
              : `Populate run_bash.env.${tokenEnvVar} from credential ${credential_id}. Run /user/repos first; once parsed, a follow-up call with candidate_repos drives per-repo expansion.`,
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
