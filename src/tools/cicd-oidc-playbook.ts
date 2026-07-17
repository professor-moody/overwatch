// ============================================================
// Overwatch — expand_oidc_capture tool (A.3)
//
// Given a captured CI/CD OIDC token (GitHub Actions / GitLab CI /
// CircleCI), enumerate the cloud_identity targets it can assume and
// emit one frontier-step per role to confirm via STS replay. Reuses
// the existing validate_token_credential tool + token-replay-awssts
// parser; no new parsers needed.
//
// The OIDC_FEDERATION_PIVOT inference rule already infers ASSUMES_ROLE
// edges from the audience match. This playbook turns those *inferred*
// edges into actionable confirm-steps so the operator can prove which
// pivots actually work.
// ============================================================

import { z } from 'zod';
import { createHash } from 'node:crypto';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';
import { isCredentialUsableForAuth, isTokenCredential } from '../services/credential-utils.js';
import { cloudIdentityId } from '../services/parser-utils.js';
import { PlaybookCommandService } from '../services/playbook-command-service.js';

interface ReplayStep {
  step: number;
  step_id: string;
  description: string;
  tool: 'validate_token_credential';
  args: Record<string, unknown>;
  expected: string;
  inferred_edge_id?: string;
  est_noise: number;
}

export function registerCicdOidcPlaybookTool(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'expand_oidc_capture',
    {
      title: 'Expand CI/CD OIDC Capture',
      description: `For a captured OIDC token (GitHub Actions / GitLab CI / CircleCI),
walk the inferred ASSUMES_ROLE edges (from OIDC_FEDERATION_PIVOT) and
emit one validate_token_credential step per candidate cloud role.
Each replay confirms whether the OIDC token actually assumes the
inferred role, mints temp credentials, and lets the AWS playbook
(\`expand_aws_credential\`) chain into the resulting session.

Creates or resumes a matching durable run; it does not itself execute a target
step. Each claimed step is a tool invocation (not a shell command) — call
validate_token_credential with the provided args and retained linkage.`,
      inputSchema: {
        credential_id: z.string().min(1).describe('Credential node id of the captured OIDC token.'),
        max_targets: z.number().int().min(1).max(20).default(10).describe('Cap on candidate roles. Highest-confidence ISSUES_TOKENS_FOR matches first.'),
        new_run: z.boolean().default(false).describe('Start another run instead of resuming the matching open run.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('expand_oidc_capture', async (params) => {
      const { credential_id, max_targets } = params as {
        credential_id: string;
        max_targets: number;
        new_run?: boolean;
      };

      const cred = engine.getNode(credential_id);
      if (!cred) return errorResponse(`Credential ${credential_id} not found`);
      if (cred.type !== 'credential') return errorResponse(`Node ${credential_id} is type=${cred.type}`);
      if (!isTokenCredential(cred)) return errorResponse(`Credential ${credential_id} is not a token; expand_oidc_capture only works on token-shaped credentials`);
      if (!isCredentialUsableForAuth(cred)) return errorResponse(`Credential ${credential_id} is not usable for auth (expired / MFA-blocked)`);

      const audience = cred.cred_audience as string | undefined;
      if (!audience) return errorResponse('Credential has no cred_audience; OIDC pivot requires an audience claim');

      // Walk the graph for idp_application nodes whose audience matches,
      // then collect their ISSUES_TOKENS_FOR → cloud_identity targets.
      const candidates: Array<{ cloudId: string; roleArn: string; appLabel?: string; confidence: number }> = [];
      const blockedCandidates: Array<{ cloud_identity_id: string; role_arn?: string; reason: string }> = [];
      const seen = new Set<string>();

      const apps = engine.getNodesByType('idp_application');
      const graph = engine.exportGraph();
      for (const app of apps) {
        const appAud = app.audience as string | undefined;
        const appCid = app.client_id as string | undefined;
        if (audience !== appAud && audience !== appCid) continue;

        const out = graph.edges.filter(e => e.source === app.id && e.properties.type === 'ISSUES_TOKENS_FOR');
        for (const e of out) {
          if (seen.has(e.target)) continue;
          seen.add(e.target);
          const tgt = engine.getNode(e.target);
          if (!tgt || tgt.type !== 'cloud_identity') continue;
          const roleArn = typeof tgt.arn === 'string' ? tgt.arn : undefined;
          const provider = tgt.provider ?? tgt.cloud_provider;
          if (!roleArn || !/^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role\/.+/.test(roleArn)
              || provider !== 'aws' || cloudIdentityId(roleArn) !== e.target) {
            blockedCandidates.push({
              cloud_identity_id: e.target,
              role_arn: roleArn,
              reason: 'Target must be the canonical cloud_identity for a valid AWS IAM role ARN.',
            });
            continue;
          }
          candidates.push({
            cloudId: e.target,
            roleArn,
            appLabel: app.label as string | undefined,
            confidence: (e.properties.confidence as number | undefined) ?? 0.7,
          });
        }
      }

      candidates.sort((a, b) => b.confidence - a.confidence);
      const top = candidates.slice(0, max_targets);

      const steps: ReplayStep[] = top.map((c, i) => ({
        step: i + 1,
        step_id: `replay-${createHash('sha256').update(c.cloudId).digest('hex').slice(0, 16)}`,
        description: `Replay token against ${c.roleArn ?? c.cloudId} (via ${c.appLabel ?? 'inferred federation app'}). Confirms the inferred ASSUMES_ROLE edge.`,
        tool: 'validate_token_credential',
        args: {
          credential_id,
          provider: 'aws_sts',
          target_role_arn: c.roleArn,
          target_cloud_identity_id: c.cloudId,
        },
        expected: 'On success: new aws_session_credentials credential (short-lived) + ASSUMES_ROLE edge confirmed (confidence 1.0). Chain into expand_aws_credential for the temp creds to enumerate the role\'s reachable resources.',
        est_noise: 0.15,
      }));

      const durable = new PlaybookCommandService(engine).open({
        definition: {
          definition_id: 'oidc-capture',
          definition_version: 1,
          provider: 'oidc',
          title: 'CI/CD OIDC federation replay',
        },
        credential_id,
        normalized_inputs: { max_targets },
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
            audience,
            candidates_considered: candidates.length + blockedCandidates.length,
            eligible_candidates: candidates.length,
            blocked_candidates: blockedCandidates,
            step_count: steps.length,
            steps,
            execution_hint: 'Each step calls validate_token_credential. Successful replays mint temp AWS creds — chain into expand_aws_credential for follow-on enumeration.',
            no_targets: candidates.length === 0
              ? blockedCandidates.length > 0
                ? 'Matching federation targets exist, but none has a canonical valid AWS IAM role identity. Repair or re-ingest those targets before replay.'
                : 'No idp_application nodes match this credential\'s audience. Run github-actions-oidc / gitlab-ci-oidc / circleci-oidc parsers first to ingest the federation graph.'
              : undefined,
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
