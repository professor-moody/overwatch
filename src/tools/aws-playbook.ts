// ============================================================
// Overwatch — expand_aws_credential
//
// Durable AWS reconnaissance planning. STS attribution remains the binding
// boundary: callers run the ready identity step, ingest it, then re-expand the
// same run so dependent execution descriptors can be resolved.
// ============================================================

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import type { NodeProperties, ParseContext } from '../types.js';
import { withErrorBoundary } from './error-boundary.js';
import { isCredentialUsableForAuth } from '../services/credential-utils.js';
import { safePlaybookArg } from './_playbook-utils.js';
import { PlaybookCommandService } from '../services/playbook-command-service.js';

const AWS_CRED_KINDS = new Set(['aws_session_credentials', 'oidc_access_token', 'token']);

type BindingStatus = 'unresolved' | 'resolved' | 'ambiguous' | 'incomplete';
type AwsPrincipalKind = 'user' | 'role' | 'root' | 'federated' | 'unknown';

interface AwsBindings {
  account_id: string;
  caller_arn: string;
  principal_kind: AwsPrincipalKind;
  principal_name?: string;
  target_cloud_identity_id: string;
}

interface BindingResolution {
  status: BindingStatus;
  bindings?: AwsBindings;
  source_identity_id?: string;
  reason?: string;
  confirmed_execution_binding?: string;
}

interface PlaybookStep {
  step: number;
  step_id: string;
  description: string;
  /** Null marks a dependency-blocked descriptor; adapters must not execute it. */
  command: string | null;
  parse_with?: string;
  parser_context?: ParseContext;
  parse_stream?: 'stdout' | 'stderr' | 'combined' | 'auto';
  runner?: 'run_tool' | 'run_bash';
  env_from_credential?: Record<string, string>;
  technique: string;
  est_noise: number;
  expected: string;
  blocking?: boolean;
  destructive?: boolean;
  depends_on: string[];
  required_bindings: string[];
  produces_bindings?: string[];
  ready: boolean;
  status: 'ready' | 'blocked';
  blocked_reason?: string;
}

function principalName(arn: string, kind: AwsPrincipalKind): string | undefined {
  if (kind === 'user') return arn.match(/:user\/(.+)$/)?.[1]?.split('/').pop();
  if (kind === 'role') {
    return arn.match(/:assumed-role\/([^/]+)\//)?.[1]
      ?? arn.match(/:role\/(.+)$/)?.[1]?.split('/').pop();
  }
  return undefined;
}

function normalizedPrincipalKind(node: NodeProperties): AwsPrincipalKind {
  const callerKind = String(node.caller_kind ?? '').toLowerCase();
  if (callerKind === 'user') return 'user';
  if (callerKind === 'role' || callerKind === 'role_session') return 'role';
  if (callerKind === 'root') return 'root';
  if (callerKind === 'federated') return 'federated';
  const arn = String(node.arn ?? '');
  if (/:user\//.test(arn)) return 'user';
  if (/:role\//.test(arn) || /:assumed-role\//.test(arn)) return 'role';
  if (/:root$/.test(arn)) return 'root';
  if (/:federated-user\//.test(arn)) return 'federated';
  return 'unknown';
}

function resolveBindings(
  engine: GraphEngine,
  credentialId: string,
  expectedExecutionBinding?: string,
): BindingResolution {
  const graph = engine.exportGraph();
  const nodeById = new Map(graph.nodes.map(node => [node.id, node.properties]));
  const confirmedEdges = graph.edges
    .filter(edge => edge.target === credentialId
      && edge.properties.type === 'OWNS_CRED'
      && edge.properties.confidence >= 0.99
      && edge.properties.binding_source === 'aws_sts_get_caller_identity');
  const bindingMatchedEdges = expectedExecutionBinding
    ? confirmedEdges.filter(edge => edge.properties.credential_execution_binding === expectedExecutionBinding)
    : confirmedEdges;
  if (confirmedEdges.length > 0 && expectedExecutionBinding && bindingMatchedEdges.length === 0) {
    const observed = [...new Set(confirmedEdges.map(edge => String(
      edge.properties.credential_execution_binding ?? 'unspecified',
    )))];
    return {
      status: 'incomplete',
      reason: `Caller identity was confirmed under ${observed.join(', ')}, not the current ${expectedExecutionBinding} execution binding. Re-run caller-identity.`,
    };
  }
  const ownerIds = [...new Set(bindingMatchedEdges.map(edge => edge.source))];
  const candidates = ownerIds
    .map(id => ({ id, node: nodeById.get(id) }))
    .filter((entry): entry is { id: string; node: NodeProperties } => {
      if (!entry.node || entry.node.type !== 'cloud_identity') return false;
      const provider = entry.node.provider ?? entry.node.cloud_provider;
      return provider === 'aws' || String(entry.node.arn ?? '').startsWith('arn:aws:');
    });

  if (candidates.length === 0) {
    return { status: 'unresolved', reason: 'Run and ingest caller-identity, then re-expand this credential.' };
  }
  if (candidates.length > 1) {
    return {
      status: 'ambiguous',
      reason: `Credential has ${candidates.length} confirmed AWS caller identities; refusing to guess.`,
    };
  }

  const { id, node } = candidates[0];
  const confirmedExecutionBinding = bindingMatchedEdges.find(edge => edge.source === id)
    ?.properties.credential_execution_binding as string | undefined;
  const callerArn = typeof node.arn === 'string' ? node.arn : '';
  const accountId = callerArn.match(/^arn:aws[a-zA-Z-]*:(?:iam|sts)::(\d{12}):/)?.[1] ?? '';
  const stampedAccount = typeof node.cloud_account === 'string' ? node.cloud_account : undefined;
  const principalKind = normalizedPrincipalKind(node);
  if (!callerArn || !accountId || (stampedAccount !== undefined && stampedAccount !== accountId)) {
    return {
      status: 'incomplete', source_identity_id: id,
      reason: 'The confirmed caller identity is missing or conflicts with its STS ARN/account binding.',
    };
  }
  return {
    status: 'resolved',
    source_identity_id: id,
    confirmed_execution_binding: confirmedExecutionBinding,
    bindings: {
      account_id: accountId,
      caller_arn: callerArn,
      principal_kind: principalKind,
      principal_name: typeof node.principal_name === 'string'
        ? node.principal_name
        : principalName(callerArn, principalKind),
      target_cloud_identity_id: id,
    },
  };
}

function awsPrefix(profile: string | undefined): string {
  return profile ? `aws --profile '${profile}'` : 'aws';
}

function cloudFoxCommand(profile: string | undefined, credentialPrelude?: string): string {
  const profileArg = profile ? ` --profile '${profile}'` : '';
  return [
    'set -euo pipefail',
    ...(credentialPrelude ? [credentialPrelude] : []),
    'tmp="$(mktemp -d "${TMPDIR:-/tmp}/overwatch-cloudfox-XXXXXX")"',
    'trap \'rm -rf "$tmp"\' EXIT',
    `cloudfox aws${profileArg} --outdir "$tmp" all-checks 1>&2`,
    'find "$tmp/cloudfox-output/aws" -type f \\',
    "  \\( -name 'principals*.json' -o -name 'permissions*.json' -o -name 'lambda*.json' -o -name 'buckets*.json' -o -name 'instances*.json' -o -name 'role-trusts*.json' \\) -print0 |",
    "while IFS= read -r -d '' file; do",
    '  module="$(basename "$file" .json)"',
    "  jq -c --arg module \"$module\" '.[] | {module:$module,record:.}' \"$file\"",
    'done | jq -s \'{format:"cloudfox-json-files-v1",records:.}\'',
  ].join('\n');
}

function awsMarkerValue(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(awsMarkerValue);
  if (typeof value !== 'string') return false;
  return /(^|[/:._-])aws([/:._-]|$)|amazonaws\.com|sts\.amazonaws\.com|^arn:aws:/i.test(value);
}

function isAwsMarkedCredential(cred: NodeProperties): boolean {
  if (cred.cred_material_kind === 'aws_session_credentials') return true;
  return [
    cred.provider,
    cred.cloud_provider,
    cred.credential_provider,
    cred.cred_provider,
    cred.cred_audience,
    cred.cred_issuer,
    cred.target_role_arn,
  ].some(awsMarkerValue);
}

export function registerAwsPlaybookTool(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'expand_aws_credential',
    {
      title: 'Expand AWS Credential',
      description: `Generate a dependency-aware AWS reconnaissance plan for a captured credential.

Run the ready STS step first and ingest it. Re-run this tool after the caller
identity lands; account, policy, S3, Lambda, and CloudFox steps then receive
server-resolved account/caller/principal bindings. Blocked steps carry a null
command rather than guessing attribution. The logical plan and every attempt
are durable; repeated calls resume the matching open run by default.`,
      inputSchema: {
        credential_id: z.string().min(1).describe('AWS-shaped credential node id.'),
        regions: z.array(z.string().regex(/^[a-z]{2}(?:-[a-z0-9]+)+-\d+$/)).optional().describe('AWS regions to enumerate. Defaults to us-east-1; duplicates are removed.'),
        aws_profile: z.string().regex(/^[A-Za-z0-9_+=,.@-]{1,128}$/).optional().describe('Explicit AWS CLI profile bound to this selected credential. Overrides credential metadata.'),
        session_credentials_env_var: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/).default('OVERWATCH_AWS_SESSION_CREDENTIALS').describe('run_bash.env variable populated from a selected aws_session_credentials JSON credential.'),
        use_ambient_credentials: z.boolean().default(false).describe('Explicitly acknowledge that the current AWS environment/default chain contains this selected AWS-marked credential.'),
        skip_inventory: z.boolean().default(false).describe('Skip the optional CloudFox inventory step.'),
        include_destructive: z.boolean().default(false).describe('Include an explicit-opt-in IAM write-probe hint.'),
        new_run: z.boolean().default(false).describe('Start another run instead of resuming the matching open run.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('expand_aws_credential', async (params) => {
      const { credential_id, regions, skip_inventory, include_destructive } = params as {
        credential_id: string;
        regions?: string[];
        aws_profile?: string;
        session_credentials_env_var?: string;
        use_ambient_credentials?: boolean;
        skip_inventory: boolean;
        include_destructive: boolean;
        new_run?: boolean;
      };

      const cred = engine.getNode(credential_id);
      if (!cred) return errorResponse(`Credential ${credential_id} not found in graph`);
      if (cred.type !== 'credential') return errorResponse(`Node ${credential_id} is type=${cred.type}, expected credential`);
      const kind = cred.cred_material_kind as string | undefined;
      if (!kind || !AWS_CRED_KINDS.has(kind)) {
        return errorResponse(`Credential ${credential_id} has cred_material_kind=${kind}, not an AWS credential. Expected one of: ${[...AWS_CRED_KINDS].join(', ')}`);
      }
      if (!isCredentialUsableForAuth(cred)) {
        return errorResponse(`Credential ${credential_id} is not usable for auth (status=${cred.credential_status}, mfa_required=${cred.cred_mfa_required}, mfa_satisfied=${cred.cred_mfa_satisfied})`);
      }

      const requestedProfile = (params as { aws_profile?: string }).aws_profile;
      const sessionCredentialsEnvVar = (params as { session_credentials_env_var?: string }).session_credentials_env_var ?? 'OVERWATCH_AWS_SESSION_CREDENTIALS';
      const useAmbientCredentials = (params as { use_ambient_credentials?: boolean }).use_ambient_credentials === true;
      const effectiveRegions = [...new Set((regions?.length ? regions : ['us-east-1']).map(safePlaybookArg))];
      const profile = safePlaybookArg(requestedProfile ?? (cred.aws_profile as string | undefined) ?? '') || undefined;
      const awsMarked = isAwsMarkedCredential(cred) || !!profile;
      if (!awsMarked) {
        return errorResponse(`Credential ${credential_id} has no AWS provider/audience marker. Supply an explicit aws_profile bound to it or correct the credential metadata.`);
      }
      const sessionCredential = kind === 'aws_session_credentials' && !profile;
      const sessionCredentialPrelude = sessionCredential ? [
        `: "\${${sessionCredentialsEnvVar}:?Pass ${sessionCredentialsEnvVar} in run_bash.env from selected credential ${credential_id}}"`,
        `ow_aws_access_key_id="$(jq -er '.AccessKeyId' <<<"$${sessionCredentialsEnvVar}")"`,
        `ow_aws_secret_access_key="$(jq -er '.SecretAccessKey' <<<"$${sessionCredentialsEnvVar}")"`,
        `ow_aws_session_token="$(jq -er '.SessionToken' <<<"$${sessionCredentialsEnvVar}")"`,
        'test -n "$ow_aws_access_key_id" -a -n "$ow_aws_secret_access_key" -a -n "$ow_aws_session_token"',
        'export AWS_ACCESS_KEY_ID="$ow_aws_access_key_id" AWS_SECRET_ACCESS_KEY="$ow_aws_secret_access_key" AWS_SESSION_TOKEN="$ow_aws_session_token"',
      ].join(' && ') : undefined;
      const envFromCredential = sessionCredential ? { [sessionCredentialsEnvVar]: credential_id } : undefined;
      const executionBound = !!profile || sessionCredential || useAmbientCredentials;
      const executionBinding = profile ? `profile:${profile}`
        : sessionCredential ? `env:${sessionCredentialsEnvVar}`
          : useAmbientCredentials ? 'ambient:explicit' : null;
      const executionBindingIdentity = profile ? `profile:${profile}`
        : sessionCredential ? `session_credential:${credential_id}`
          : useAmbientCredentials ? 'ambient:explicit' : undefined;
      const prefix = sessionCredentialPrelude ? `${sessionCredentialPrelude} && aws` : awsPrefix(profile);
      const resolution = resolveBindings(engine, credential_id, executionBindingIdentity);
      const bindings = resolution.bindings;
      const executionReason = 'No execution credential is bound. Supply aws_profile or explicitly set use_ambient_credentials=true for an AWS-marked credential.';
      const dependencyReason = !executionBound ? executionReason : resolution.reason ?? 'Caller identity bindings are unavailable.';
      const identityReady = executionBound && resolution.status === 'resolved' && !!bindings;
      const policyReady = identityReady
        && (bindings.principal_kind === 'user' || bindings.principal_kind === 'role')
        && !!bindings.principal_name;
      const context: ParseContext | undefined = bindings ? {
        source_credential_id: credential_id,
        cloud_provider: 'aws',
        cloud_account: bindings.account_id,
        aws_account: bindings.account_id,
        account_id: bindings.account_id,
        caller_arn: bindings.caller_arn,
        principal_kind: bindings.principal_kind,
        target_cloud_identity_id: bindings.target_cloud_identity_id,
        credential_execution_binding: executionBinding ?? undefined,
        credential_execution_binding_identity: executionBindingIdentity,
      } : undefined;

      const steps: PlaybookStep[] = [];
      const add = (step: Omit<PlaybookStep, 'step' | 'status'>) => steps.push({
        step: steps.length + 1,
        status: step.ready ? 'ready' : 'blocked',
        ...step,
      });
      add({
        step_id: 'caller-identity',
        description: 'Confirm the credential caller and bind its account, ARN, and principal kind.',
        command: executionBound ? `${prefix} sts get-caller-identity --output json` : null,
        parse_with: 'aws-sts-identity',
        parser_context: {
          source_credential_id: credential_id,
          cloud_provider: 'aws',
          credential_execution_binding: executionBinding ?? undefined,
          credential_execution_binding_identity: executionBindingIdentity,
        },
        env_from_credential: envFromCredential,
        runner: 'run_bash', technique: 'recon_cloud_identity', est_noise: 0.05,
        expected: 'AWS cloud_identity + confirmed OWNS_CRED edge to the source credential.',
        blocking: true, depends_on: [], required_bindings: [],
        produces_bindings: ['account_id', 'caller_arn', 'principal_kind', 'principal_name', 'target_cloud_identity_id'],
        ready: executionBound,
        blocked_reason: executionBound ? undefined : executionReason,
      });

      add({
        step_id: 'account-summary',
        description: 'Pull an account-level IAM summary and attach it to the confirmed caller.',
        command: identityReady ? `${prefix} iam get-account-summary --output json` : null,
        parse_with: 'aws-iam-summary', parser_context: identityReady ? context : undefined,
        env_from_credential: envFromCredential,
        runner: 'run_bash', technique: 'recon_cloud_identity', est_noise: 0.05,
        expected: 'account_summary metadata on the confirmed AWS cloud_identity.',
        depends_on: ['caller-identity'], required_bindings: ['account_id', 'caller_arn', 'target_cloud_identity_id'],
        ready: identityReady, blocked_reason: identityReady ? undefined : dependencyReason,
      });

      const policyKind = bindings?.principal_kind;
      const policyName = bindings?.principal_name ? safePlaybookArg(bindings.principal_name) : undefined;
      const policyCommand = policyReady
        ? policyKind === 'user'
          ? `${prefix} iam list-attached-user-policies --user-name '${policyName}' --output json`
          : `${prefix} iam list-attached-role-policies --role-name '${policyName}' --output json`
        : null;
      const policyBlockedReason = identityReady && !policyReady
        ? `Caller kind '${bindings?.principal_kind ?? 'unknown'}' cannot select user-versus-role policy enumeration.`
        : dependencyReason;
      add({
        step_id: 'attached-policies',
        description: 'List managed policies attached to the confirmed IAM user or role.',
        command: policyCommand, parse_with: 'aws-iam-attached-policies',
        parser_context: policyReady ? context : undefined,
        env_from_credential: envFromCredential,
        runner: 'run_bash', technique: 'recon_cloud_identity', est_noise: 0.1,
        expected: 'cloud_policy nodes linked from the caller with HAS_POLICY edges.',
        depends_on: ['caller-identity'],
        required_bindings: ['account_id', 'caller_arn', 'principal_kind', 'principal_name', 'target_cloud_identity_id'],
        ready: policyReady, blocked_reason: policyReady ? undefined : policyBlockedReason,
      });

      if (!skip_inventory) {
        add({
          step_id: 'cloudfox-inventory',
          description: 'Run CloudFox and emit a normalized envelope from its generated JSON files.',
          command: identityReady ? cloudFoxCommand(profile, sessionCredentialPrelude) : null,
          parse_with: 'cloudfox', parser_context: identityReady ? context : undefined,
          env_from_credential: envFromCredential,
          parse_stream: 'stdout', runner: 'run_bash', technique: 'recon_cloud_resources', est_noise: 0.4,
          expected: 'AWS identities, policies, trust edges, and resources from actual CloudFox JSON records.',
          depends_on: ['caller-identity'], required_bindings: ['account_id', 'target_cloud_identity_id'],
          ready: identityReady, blocked_reason: identityReady ? undefined : dependencyReason,
        });
      }

      add({
        step_id: 's3-buckets',
        description: 'List S3 buckets visible to the credential.',
        command: identityReady ? `${prefix} s3api list-buckets --output json` : null,
        parse_with: 'aws-s3-list-buckets', parser_context: identityReady ? context : undefined,
        env_from_credential: envFromCredential,
        runner: 'run_bash', technique: 'recon_cloud_resources', est_noise: 0.1,
        expected: 'cloud_resource nodes with resource_type=s3_bucket.',
        depends_on: ['caller-identity'], required_bindings: ['account_id', 'target_cloud_identity_id'],
        ready: identityReady, blocked_reason: identityReady ? undefined : dependencyReason,
      });

      for (const region of effectiveRegions) {
        add({
          step_id: `lambda-functions-${region}`,
          description: `List Lambda functions in ${region} and retain their execution-role bindings.`,
          command: identityReady ? `${prefix} --region '${region}' lambda list-functions --output json` : null,
          parse_with: 'aws-lambda-list-functions',
          parser_context: identityReady ? { ...context, cloud_region: region } : undefined,
          env_from_credential: envFromCredential,
          runner: 'run_bash', technique: 'recon_cloud_resources', est_noise: 0.1,
          expected: 'Lambda cloud_resource nodes linked to execution-role cloud_identity nodes with MANAGED_BY.',
          depends_on: ['caller-identity'], required_bindings: ['account_id', 'target_cloud_identity_id'],
          ready: identityReady, blocked_reason: identityReady ? undefined : dependencyReason,
        });
      }

      if (include_destructive) {
        const destructiveReady = policyReady && bindings?.principal_kind === 'user';
        add({
          step_id: 'create-access-key-probe',
          description: 'OPTIONAL write probe: create an access key for the confirmed IAM user.',
          command: destructiveReady
            ? `# requires explicit operator approval\n# ${prefix} iam create-access-key --user-name '${safePlaybookArg(bindings!.principal_name!)}'`
            : null,
          technique: 'cred_create', est_noise: 0.7,
          expected: 'A new credential on success; AccessDenied or LimitExceeded otherwise.',
          destructive: true, depends_on: ['caller-identity'],
          required_bindings: ['principal_kind=user', 'principal_name'],
          ready: destructiveReady,
          blocked_reason: destructiveReady ? undefined : 'Write probe is only defined for a uniquely bound IAM user.',
        });
      }

      const durable = new PlaybookCommandService(engine).open({
        definition: {
          definition_id: 'aws-credential',
          definition_version: 2,
          provider: 'aws',
          title: 'AWS credential expansion',
        },
        credential_id,
        normalized_inputs: {
          regions: effectiveRegions,
          aws_profile: requestedProfile ?? null,
          session_credentials_env_var: sessionCredentialsEnvVar,
          use_ambient_credentials: useAmbientCredentials,
          skip_inventory,
          include_destructive,
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
            regions: effectiveRegions,
            profile: profile ?? null,
            /** Deprecated compatibility alias; prefer bindings.principal_name. */
            principal: bindings?.principal_name
              ?? safePlaybookArg((cred.cred_user as string | undefined) ?? credential_id),
            credential_binding: executionBinding,
            credential_binding_identity: executionBindingIdentity ?? null,
            env_from_credential: envFromCredential,
            credential_source: profile ? `AWS profile ${profile}`
              : sessionCredential ? `AWS session JSON from run_bash.env.${sessionCredentialsEnvVar}`
              : useAmbientCredentials ? 'Explicitly acknowledged AWS environment/default credential chain'
                : 'Unbound',
            binding_status: resolution.status,
            bindings: bindings ?? null,
            binding_source_identity_id: resolution.source_identity_id,
            confirmed_credential_binding: resolution.confirmed_execution_binding,
            binding_warning: resolution.reason,
            step_count: steps.length,
            ready_step_count: steps.filter(step => step.ready).length,
            steps,
            execution_hint: !executionBound
              ? 'Bind the selected credential with aws_profile, or explicitly acknowledge a matching AWS environment/default chain with use_ambient_credentials=true.'
              : sessionCredential
              ? `Populate run_bash.env.${sessionCredentialsEnvVar} with the selected credential's JSON material (not its node id), then run one ready step at a time with the returned parser metadata.`
              : identityReady
              ? 'Run one ready step at a time through run_tool/run_bash, passing parser_context, parse_with, and parse_stream exactly as returned.'
              : 'Run caller-identity first with its parser context, ingest the result, then call expand_aws_credential again to resolve dependent commands.',
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
