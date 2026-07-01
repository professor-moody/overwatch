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
  description: string;
  command: string;
  parse_with?: string;
  parser_context?: Record<string, unknown>;
  technique: string;
  est_noise: number;
  expected: string;
  blocking?: boolean;
}

const GH_CRED_KINDS = new Set(['pat', 'oidc_access_token', 'oauth_client_secret', 'token']);

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

Returns the plan; does not execute. Run each step via \`run_bash\` (or
\`run_tool\`) with the named \`parse_with\` value. The plan caps repo
expansion at \`max_repos\` to stay tractable on large orgs.`,
      inputSchema: {
        credential_id: z.string().min(1).describe('Credential node id. Must be a token-shaped GitHub credential.'),
        max_repos: z.number().int().min(1).max(2000).default(200).describe('Cap on per-repo expansion. Steps 4a–4d are emitted for the first N repos returned by /user/repos.'),
        include_orgs: z.boolean().default(true).describe('Include /user/orgs enumeration step.'),
        candidate_repos: z.array(z.string()).optional().describe('Optional explicit list of `owner/repo` strings to expand. When provided, the plan skips the /user/repos pagination step and uses this list verbatim (still subject to max_repos).'),
      },
      annotations: {
        readOnlyHint: false,
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
        candidate_repos?: string[];
      };

      const cred = engine.getNode(credential_id);
      if (!cred) return errorResponse(`Credential ${credential_id} not found`);
      if (cred.type !== 'credential') return errorResponse(`Node ${credential_id} is type=${cred.type}`);
      const kind = cred.cred_material_kind as string | undefined;
      if (!kind || !GH_CRED_KINDS.has(kind)) {
        return errorResponse(`Credential ${credential_id} has cred_material_kind=${kind}, not a GitHub-shaped token. Expected one of: ${[...GH_CRED_KINDS].join(', ')}`);
      }
      if (!isCredentialUsableForAuth(cred)) {
        return errorResponse(`Credential ${credential_id} is not usable for auth`);
      }

      const steps: PlaybookStep[] = [];
      let n = 0;

      // Step 1: validate + capture scopes.
      steps.push({
        step: ++n,
        description: 'Validate the token and capture OAuth scopes from response headers. Use `-i` so the scopes header is parsed.',
        command: `gh api -i /user`,
        parse_with: 'token_replay_github',
        parser_context: { source_credential_id: credential_id },
        technique: 'recon_idp_principal',
        est_noise: 0.05,
        expected: 'Updates credential with cred_user, cred_scopes; emits VALID_FOR_APP edge.',
        blocking: true,
      });

      if (include_orgs) {
        steps.push({
          step: ++n,
          description: 'Enumerate organizations the token has membership in.',
          command: `gh api /user/orgs --paginate`,
          parse_with: 'gh-api-orgs',
          parser_context: { source_credential_id: credential_id },
          technique: 'recon_idp_principal',
          est_noise: 0.1,
          expected: 'idp nodes (idp_kind: github_org) per org; cred_orgs stamped on the credential.',
        });
      }

      let repoList: string[] | undefined;
      if (candidate_repos && candidate_repos.length > 0) {
        repoList = candidate_repos.slice(0, max_repos);
      } else {
        steps.push({
          step: ++n,
          description: 'List all repositories visible to the token. Use --paginate to walk the full list.',
          command: `gh api /user/repos --paginate`,
          parse_with: 'gh-api-repos',
          parser_context: { source_credential_id: credential_id },
          technique: 'recon_idp_application',
          est_noise: 0.15,
          expected: 'idp_application per repo (idp_kind: github_org, app_kind: github_repo).',
          blocking: true,
        });
      }

      // Per-repo expansion when an explicit list is provided.
      if (repoList) {
        for (const rawRepo of repoList) {
          // Fence the operator-supplied repo before it lands in `gh api /repos/'${repo}'/…`.
          const repo = safePlaybookArg(rawRepo);
          const owner = repo.split('/')[0];
          steps.push({
            step: ++n,
            description: `List Actions secrets for ${repo}.`,
            command: `gh api /repos/'${repo}'/actions/secrets`,
            parse_with: 'gh-api-secrets',
            parser_context: { repo_full_name: repo, source_credential_id: credential_id },
            technique: 'recon_credential',
            est_noise: 0.1,
            expected: 'credential nodes for each Actions secret (cred_value is fingerprint-only — values are not exposed by the API).',
          });
          steps.push({
            step: ++n,
            description: `Pull branch protection for ${repo}'s default branch (main/master).`,
            command: `gh api /repos/'${repo}'/branches/main/protection`,
            parse_with: 'gh-api-branch-protection',
            parser_context: { repo_full_name: repo, branch_name: 'main' },
            technique: 'recon_idp_application',
            est_noise: 0.05,
            expected: 'Stamps branch_protection_gaps + finding_severity on the repo idp_application.',
          });
          steps.push({
            step: ++n,
            description: `List deploy keys for ${repo}. Read-write keys with private-half capture become lateral-move candidates.`,
            command: `gh api /repos/'${repo}'/keys`,
            parse_with: 'gh-api-deploy-keys',
            parser_context: { repo_full_name: repo },
            technique: 'recon_credential',
            est_noise: 0.05,
            expected: 'credential nodes (cred_material_kind: ssh_key) per deploy key.',
          });
          steps.push({
            step: ++n,
            description: `Capture Actions OIDC subject-claim customization for ${repo}. Misconfigured patterns are flagged by the CI_TRUST_WILDCARD inference rule once ingested.`,
            command: `gh api /repos/'${repo}'/actions/oidc-customization/sub`,
            parse_with: 'github-actions-oidc',
            parser_context: { repo_full_name: repo, owner },
            technique: 'recon_idp_application',
            est_noise: 0.05,
            expected: 'sub_claim_pattern stamped on the github_org / repo idp_application.',
          });
        }
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
            step_count: steps.length,
            max_repos,
            steps,
            execution_hint: candidate_repos
              ? 'Per-repo steps are pre-expanded for the supplied candidate_repos list.'
              : 'Run /user/repos first; once parsed, the operator (or a follow-up call to expand_github_credential with candidate_repos populated) drives per-repo expansion.',
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
