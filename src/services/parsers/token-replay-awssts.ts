// ============================================================
// AWS STS token-replay response parser.
//
// Consumes the captured stdout from an AWS STS AssumeRoleWithWebIdentity
// call (`aws sts assume-role-with-web-identity --role-arn <arn>
// --role-session-name <name> --web-identity-token <token>`) using a
// captured OIDC federation token (typically from GitHub Actions OIDC,
// GitLab CI OIDC, or Entra workload identity federation).
//
// On success, STS returns a `Credentials` block containing temporary
// AWS access keys + a session token. We:
//   - Emit a NEW credential node for the assumed-role temp creds
//     (cred_material_kind: 'aws_session_credentials'). Note: this is a
//     short-lived credential — cred_token_expires_at comes straight
//     from the STS Expiration field.
//   - Emit an ASSUMES_ROLE edge from the original credential to the
//     cloud_identity for the role (with confidence 1.0 — replay
//     confirmed, not inferred).
//   - Mark the original federation token as cred_mfa_satisfied: true
//     (federation tokens that successfully assume a role have already
//     traversed any MFA gates the IdP requires).
// ============================================================

import type { EdgeType, Finding, NodeProperties, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { credentialId } from '../parser-utils.js';

interface ReplayContext extends ParseContext {
  source_credential_id?: string;
  /** ARN of the role that was assumed (target cloud_identity node). */
  target_role_arn?: string;
  /** Pre-resolved cloud_identity node id for the target role. */
  target_cloud_identity_id?: string;
  status_code?: number;
}

function extractStatusAndBody(output: string): { status: number; body: string } {
  // STS via awscli has no HTTP status — the `_process-runner` prefixes
  // a `[STATUS:<exit_code>]` marker. Accept any digit count (HTTP 401
  // alongside awscli exit 0/1/255).
  const m = output.match(/^\[STATUS:(\d+)\]\s*\n?([\s\S]*)$/);
  if (m) return { status: parseInt(m[1]), body: m[2] };
  return { status: 0, body: output };
}

interface StsCredentials {
  AccessKeyId?: string;
  SecretAccessKey?: string;
  SessionToken?: string;
  Expiration?: string;
}
interface StsResponse {
  Credentials?: StsCredentials;
  AssumedRoleUser?: { Arn?: string; AssumedRoleId?: string };
}

function parseStsResponse(body: string): StsResponse | null {
  // STS response is JSON when the CLI is invoked with `--output json`,
  // otherwise XML. Operators driving the replay should request JSON.
  try {
    const obj = JSON.parse(body);
    if (obj?.Credentials?.AccessKeyId) return obj as StsResponse;
    return null;
  } catch {
    return null;
  }
}

export function parseTokenReplayAwsSts(output: string, agentId: string = 'token-replay-awssts', context?: ParseContext): Finding {
  const nodes: NodeProperties[] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const ctx = (context ?? {}) as ReplayContext;
  const sourceCredId = ctx.source_credential_id;
  const targetRoleArn = ctx.target_role_arn;
  const targetCloudId = ctx.target_cloud_identity_id;

  const { status, body } = extractStatusAndBody(output);

  // STS calls aren't pure HTTP — `aws sts` exits 0 on success and non-zero
  // with a textual error on failure. Treat status 0 as "exit code 0" and
  // try to parse JSON; status non-200 from a curl-style invocation as
  // failure.
  if (status === 401 || status === 403) {
    if (sourceCredId) {
      nodes.push({
        id: sourceCredId,
        type: 'credential',
        label: 'replay-result',
        discovered_at: now,
        confidence: 1.0,
        credential_status: 'expired',
        notes: `aws sts replay returned ${status} — federation token rejected`,
        partial: true,
      });
    }
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  const sts = parseStsResponse(body);
  if (!sts || !sts.Credentials) {
    if (sourceCredId) {
      nodes.push({
        id: sourceCredId,
        type: 'credential',
        label: 'replay-result',
        discovered_at: now,
        confidence: 0.5,
        partial: true,
        notes: 'aws sts replay produced no Credentials block (inconclusive)',
      });
    }
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  // Mint the assumed-role short-lived credential as a new node.
  const accessKey = sts.Credentials.AccessKeyId ?? '';
  const sessionToken = sts.Credentials.SessionToken ?? '';
  const fingerprint = `${accessKey}|${sessionToken.slice(0, 16)}`;
  const tempCredId = credentialId('aws_session_credentials', fingerprint, accessKey, undefined);
  nodes.push({
    id: tempCredId,
    type: 'credential',
    label: `aws-session:${sts.AssumedRoleUser?.AssumedRoleId ?? accessKey}`,
    cred_type: 'token',
    cred_material_kind: 'oidc_access_token',
    cred_value: JSON.stringify({
      AccessKeyId: accessKey,
      // SecretAccessKey + SessionToken intentionally redacted from the
      // label/value summary; full values stay only in evidence storage.
    }),
    cred_user: sts.AssumedRoleUser?.AssumedRoleId,
    cred_audience: targetRoleArn,
    cred_token_expires_at: sts.Credentials.Expiration,
    cred_evidence_kind: 'capture',
    cred_usable_for_auth: true,
    cred_mfa_required: false,
    cred_mfa_satisfied: true,
    discovered_at: now,
    confidence: 1.0,
  });

  // ASSUMES_ROLE edge from the original federation token → cloud_identity.
  if (sourceCredId && targetCloudId) {
    edges.push({
      source: sourceCredId,
      target: targetCloudId,
      properties: {
        type: 'ASSUMES_ROLE' as EdgeType,
        confidence: 1.0, // replay confirmed
        discovered_at: now,
        discovered_by: agentId,
        notes: 'AssumeRoleWithWebIdentity succeeded (live replay)',
      },
    });
  }

  // Refresh the source credential's MFA-satisfied flag (the OIDC
  // federation flow traversed any MFA gates the IdP enforced).
  if (sourceCredId) {
    nodes.push({
      id: sourceCredId,
      type: 'credential',
      label: 'replay-result',
      discovered_at: now,
      confidence: 1.0,
      cred_mfa_satisfied: true,
      credential_status: 'active',
      notes: 'aws sts replay confirmed federation works',
    });
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
