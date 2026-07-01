// ============================================================
// Overwatch — expand_aws_credential tool (A.1)
//
// Given a captured AWS credential (an access key, an STS session, an
// OIDC-federated assumed role, etc.), emit a structured recon plan
// the operator (or a subagent) can execute step-by-step. Each step
// names a CLI invocation, a parser to ingest the output, the technique
// tag for OPSEC bookkeeping, and what shape of nodes/edges to expect.
//
// **Why a plan and not a driver:** the engine deliberately keeps the
// operator-in-the-loop posture. Each step in the plan goes through
// run_bash / run_tool, hits the existing approval gate (low-noise
// reads auto-approve under approve-critical), and the parser ingests
// the result back into the graph. Inference fires after each step,
// growing the graph and (potentially) producing follow-up frontier
// items.
//
// The credential node also gets stamped with `recon_playbook_*` fields
// so the dashboard can surface "playbook invoked at T, N/M steps run"
// without keeping a separate state machine.
// ============================================================

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';
import { isCredentialUsableForAuth } from '../services/credential-utils.js';
import { safePlaybookArg } from './_playbook-utils.js';

// Credential material kinds we'll accept as "AWS-shaped". The Token-D
// AWS STS replay parser mints assumed-role temp creds as
// `oidc_access_token` (the cred_material_kind union doesn't carry an
// AWS-specific variant); long-lived access keys typically arrive as
// generic `token` or `pat`. The operator is the one invoking the
// playbook — when in doubt we accept usable token-shaped creds.
const AWS_CRED_KINDS = new Set(['oidc_access_token', 'token', 'pat', 'oauth_client_secret']);

interface PlaybookStep {
  step: number;
  description: string;
  command: string;
  parse_with?: string;
  technique: string;
  est_noise: number;
  expected: string;
  /** Whether the next step depends on this one ingesting first (operator should wait for parse_with to complete). */
  blocking?: boolean;
  /** When true the step is a write/mutation — kept off the default plan; surfaced only with explicit opt-in. */
  destructive?: boolean;
}

export function registerAwsPlaybookTool(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'expand_aws_credential',
    {
      title: 'Expand AWS Credential',
      description: `Generate a structured recon plan for a captured AWS credential.

Returns a numbered list of CLI commands to run end-to-end:
  1. \`aws sts get-caller-identity\` — confirm who the credential is for
  2. \`aws iam get-account-summary\` — quick "what is this account" snapshot
  3. \`aws iam list-attached-user-policies\` / \`list-attached-role-policies\`
  4. (optional) \`cloudfox aws inventory\` — full bulk inventory
  5. After ingest: \`aws s3api list-objects-v2\` per accessible bucket,
     \`aws lambda list-functions\` per region/account.

Each step names the parser to use (\`parse_with\`), the OPSEC technique
tag, an estimated noise score, and what nodes/edges should land.

The credential node is stamped with \`recon_playbook_invoked_at\` and
\`recon_playbook_step_count\` so dashboards / reports can surface that
the playbook has been run.

This tool returns the plan; it does not execute it. Run each step via
\`run_bash\` or \`run_tool\` with the indicated \`parse_with\` value.`,
      inputSchema: {
        credential_id: z.string().min(1).describe('The credential node id to expand. Must be an AWS-flavored credential (aws_session_credentials, aws_access_key, or an oidc_access_token whose audience targets STS).'),
        regions: z.array(z.string()).optional().describe('AWS regions to enumerate. Defaults to engagement scope or [us-east-1].'),
        skip_inventory: z.boolean().default(false).describe('Skip the optional cloudfox/scoutsuite bulk inventory step.'),
        include_destructive: z.boolean().default(false).describe('Include destructive/write probe steps (e.g. dry-run create-access-key) in the plan. Off by default — keeps the plan strictly read-only.'),
      },
      annotations: {
        readOnlyHint: false, // mutates credential node attrs
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('expand_aws_credential', async (params) => {
      const { credential_id, regions, skip_inventory, include_destructive } = params as {
        credential_id: string;
        regions?: string[];
        skip_inventory: boolean;
        include_destructive: boolean;
      };

      const cred = engine.getNode(credential_id);
      if (!cred) {
        return errorResponse(`Credential ${credential_id} not found in graph`);
      }
      if (cred.type !== 'credential') {
        return errorResponse(`Node ${credential_id} is type=${cred.type}, expected credential`);
      }
      const kind = cred.cred_material_kind as string | undefined;
      if (!kind || !AWS_CRED_KINDS.has(kind)) {
        return errorResponse(`Credential ${credential_id} has cred_material_kind=${kind}, not an AWS credential. Expected one of: ${[...AWS_CRED_KINDS].join(', ')}`);
      }
      if (!isCredentialUsableForAuth(cred)) {
        return errorResponse(`Credential ${credential_id} is not usable for auth (status=${cred.credential_status}, mfa_required=${cred.cred_mfa_required}, mfa_satisfied=${cred.cred_mfa_satisfied})`);
      }

      // The engagement scope schema doesn't currently carry an
      // aws_regions field; when omitted we default to us-east-1 (most
      // common). Operators can override via the `regions` arg.
      // Sanitize every value interpolated into an emitted command string: the
      // region/profile are operator-supplied and the principal is derived from a
      // PARSED credential (attacker-influenced), so fence them against shell
      // injection into a suggested run_bash step. Placeholders keep their angle
      // brackets because the fallback is applied AFTER sanitizing the real value.
      const effectiveRegions = (regions && regions.length > 0 ? regions : ['us-east-1']).map(safePlaybookArg);

      // Build the plan. AWS CLI invocations expect AWS_PROFILE to be set
      // by the operator; we describe the command rather than hard-code
      // credential injection (the credential value lives in the graph
      // node, not in the recon plan).
      const profile = safePlaybookArg((cred.aws_profile as string | undefined) ?? '') || '<your-profile>';
      const principal = safePlaybookArg((cred.cred_user as string | undefined) ?? credential_id ?? '') || '<principal>';

      const steps: PlaybookStep[] = [];
      let n = 0;

      steps.push({
        step: ++n,
        description: 'Confirm the credential\'s caller identity (account, ARN, principal type).',
        command: `aws --profile '${profile}' sts get-caller-identity --output json`,
        parse_with: 'aws-sts-identity',
        technique: 'recon_cloud_identity',
        est_noise: 0.05,
        expected: 'cloud_identity node + OWNS_CRED edge from principal → credential.',
        blocking: true,
      });

      steps.push({
        step: ++n,
        description: 'Pull a fast account-level summary (user/group/role counts, MFA posture, password policy summary).',
        command: `aws --profile '${profile}' iam get-account-summary --output json`,
        parse_with: 'aws-iam-summary',
        technique: 'recon_cloud_identity',
        est_noise: 0.05,
        expected: 'account_summary stamp on the cloud_identity / linked account node.',
      });

      steps.push({
        step: ++n,
        description: 'List attached managed policies for the caller principal. Substitute --user-name or --role-name based on the caller-identity result from step 1.',
        command: `aws --profile '${profile}' iam list-attached-user-policies --user-name '${principal}' --output json`,
        parse_with: 'cloudfox',
        technique: 'recon_cloud_identity',
        est_noise: 0.1,
        expected: 'cloud_policy nodes + ATTACHED_TO edges to the cloud_identity.',
      });

      if (!skip_inventory) {
        steps.push({
          step: ++n,
          description: 'Run a CloudFox inventory pass — quickly catalogues EC2/Lambda/RDS/S3/IAM across regions.',
          command: `cloudfox aws --profile '${profile}' all-checks ${effectiveRegions.map(r => `--regions '${r}'`).join(' ')}`,
          parse_with: 'cloudfox',
          technique: 'recon_cloud_resources',
          est_noise: 0.4,
          expected: 'cloud_resource nodes per service + BACKED_BY / ALLOWS edges.',
        });
      }

      steps.push({
        step: ++n,
        description: 'List S3 buckets visible to the credential. After this lands, follow up per-bucket with list-objects-v2 for the buckets the operator wants to investigate.',
        command: `aws --profile '${profile}' s3api list-buckets --output json`,
        parse_with: 'cloudfox',
        technique: 'recon_cloud_resources',
        est_noise: 0.1,
        expected: 'cloud_resource (S3) nodes.',
      });

      for (const region of effectiveRegions) {
        steps.push({
          step: ++n,
          description: `List Lambda functions in ${region}. Look for environment variables that contain secrets or cross-account assume-role references.`,
          command: `aws --profile '${profile}' --region '${region}' lambda list-functions --output json`,
          parse_with: 'cloudfox',
          technique: 'recon_cloud_resources',
          est_noise: 0.1,
          expected: 'cloud_resource (Lambda) nodes.',
        });
      }

      if (include_destructive) {
        // Reserved hooks for write probes the operator may opt into. We
        // don't ship anything destructive on by default. The engagement
        // OPSEC blacklist still gates these via the approval queue.
        steps.push({
          step: ++n,
          description: 'OPTIONAL: dry-run create-access-key against the caller user (AWS rejects --dry-run for IAM mutations, so this remains an explicit-opt-in audit hint, not a real probe). Use only with operator approval.',
          command: `# write probe — requires explicit approval; commented out by default\n# aws --profile '${profile}' iam create-access-key --user-name '${principal}'`,
          technique: 'cred_create',
          est_noise: 0.7,
          expected: 'NEW credential node on success; AccessDenied or LimitExceeded otherwise.',
          destructive: true,
        });
      }

      // Stamp the credential so the dashboard / reports can surface
      // playbook invocation. We don't track per-step completion here —
      // each parser ingest mutates the graph independently. addNode is
      // a merge for existing nodes; the credential id stays stable.
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
            principal,
            regions: effectiveRegions,
            step_count: steps.length,
            steps,
            execution_hint: 'Run each step via `run_bash` (or `run_tool` for parser-aware invocations). Pass `parse_with` from the step. The approval queue auto-approves low-noise reads under the configured budget; cloudfox bulk inventory may gate depending on engagement OPSEC.',
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
