#!/usr/bin/env npx tsx
// ============================================================
// Smoke-test engagement seed for the credential playbook + reporting
// flow shipped in plan A.1–A.4 / B.1–B.4.
//
// Spins up an engagement at ./smoke-engagement/ with:
//   - 1 AWS access-key-shaped credential
//   - 1 GitHub PAT
//   - 1 captured CI/CD OIDC token + matching idp_application + cloud_identity
//   - 1 Entra refresh token + 1 Entra access token + tenant idp
//   - An objective targeting the OIDC-federated cloud_identity so
//     attack-paths render with at least one chain.
//
// Run:
//   npx tsx scripts/smoke-engagement.ts
//
// Then point the MCP server at the seeded engagement (see
// docs/smoke-test.md for full instructions).
// ============================================================

import { GraphEngine } from '../src/services/graph-engine.js';
import type { EngagementConfig } from '../src/types.js';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';

const ENG_DIR = './smoke-engagement';
const CONFIG_FILE = join(ENG_DIR, 'config.json');
const STATE_FILE = join(ENG_DIR, 'state.json');

if (existsSync(ENG_DIR)) {
  console.log(`Removing existing ${ENG_DIR}/ for clean smoke run`);
  rmSync(ENG_DIR, { recursive: true, force: true });
}
mkdirSync(ENG_DIR, { recursive: true });

const now = new Date().toISOString();

const config: EngagementConfig = {
  id: 'smoke-credential-playbooks',
  name: 'Smoke: Credential Playbooks + Reporting',
  created_at: now,
  profile: 'cloud',
  scope: {
    cidrs: [],
    domains: ['acme.local', 'acme-corp.com'],
    exclusions: [],
    aws_accounts: ['111122223333'],
    azure_subscriptions: ['acme-prod'],
  },
  opsec: {
    name: 'pentest',
    enabled: true,
    max_noise: 0.7,
    approval_mode: 'approve-critical',
  },
  objectives: [
    {
      id: 'obj-aws-admin',
      description: 'Reach AWS PowerUser role via OIDC federation pivot',
      target_node_type: 'cloud_identity',
      target_criteria: { arn: 'arn:aws:iam::111122223333:role/PowerUser' },
      achieved: false,
    },
  ],
};

// Write the config to its own file so the MCP server's loadConfig
// (which reads OVERWATCH_CONFIG and parses it as engagementConfigSchema)
// finds a clean config — the state file shape is different.
writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), 'utf8');

const engine = new GraphEngine(config, STATE_FILE);

// =============================================
// 1. AWS — captured access key (assume-role-style temp creds)
// =============================================
engine.addNode({
  id: 'cred-aws-power',
  type: 'credential',
  label: 'aws-prod-poweruser-temp',
  cred_type: 'token',
  cred_material_kind: 'oidc_access_token',
  cred_user: 'svc-deploy',
  cred_audience: 'sts.amazonaws.com',
  cred_evidence_kind: 'capture',
  credential_status: 'active',
  cred_token_expires_at: new Date(Date.now() + 3_600_000).toISOString(),
  cred_value: '<seeded for smoke; never exfiltrated>',
  discovered_at: now,
  confidence: 1.0,
} as never);

// =============================================
// 2. GitHub PAT
// =============================================
engine.addNode({
  id: 'cred-gh-pat',
  type: 'credential',
  label: 'gh-pat-svc-deploy',
  cred_type: 'token',
  cred_material_kind: 'pat',
  cred_user: 'svc-deploy',
  cred_audience: 'api.github.com',
  cred_evidence_kind: 'capture',
  credential_status: 'active',
  cred_value: '<seeded for smoke; never exfiltrated>',
  discovered_at: now,
  confidence: 1.0,
} as never);

// =============================================
// 3. CI/CD OIDC token + matching federation graph
// =============================================
const githubOidcIdp = {
  id: 'idp-gha-acme',
  type: 'idp',
  label: 'github-actions:acme',
  idp_kind: 'ci_github_actions',
  tenant_id: 'acme-corp',
  discovered_at: now,
  confidence: 1.0,
} as const;

const ghaApp = {
  id: 'idp-app-acme-deploy',
  type: 'idp_application',
  label: 'acme-corp/webapp:gha-prod-deploy',
  idp_id: 'idp-gha-acme',
  idp_kind: 'ci_github_actions',
  tenant_id: 'acme-corp',
  app_kind: 'github_actions_workflow',
  client_id: 'gha-prod-deploy',
  audience: 'sts.amazonaws.com',
  sub_claim_pattern: 'repo:acme-corp/webapp:ref:refs/heads/main',
  discovered_at: now,
  confidence: 1.0,
} as const;

const cloudIdPower = {
  id: 'cloud-id-poweruser',
  type: 'cloud_identity',
  label: 'arn:aws:iam::111122223333:role/PowerUser',
  cloud_provider: 'aws',
  cloud_account: '111122223333',
  arn: 'arn:aws:iam::111122223333:role/PowerUser',
  principal_type: 'role',
  discovered_at: now,
  confidence: 1.0,
} as const;

engine.addNode(githubOidcIdp as never);
engine.addNode(ghaApp as never);
engine.addNode(cloudIdPower as never);

engine.addEdge('idp-app-acme-deploy', 'cloud-id-poweruser', {
  type: 'ISSUES_TOKENS_FOR',
  confidence: 0.95,
  discovered_at: now,
} as never);

engine.addNode({
  id: 'cred-oidc-gha',
  type: 'credential',
  label: 'gha-oidc-token-prod-deploy',
  cred_type: 'token',
  cred_material_kind: 'oidc_access_token',
  cred_audience: 'sts.amazonaws.com',
  // Must match the idp_application's sub_claim_pattern below, or the S4-A2
  // subject-claim validation in OIDC_FEDERATION_PIVOT skips this token and the
  // seeded attack path (host-jumpbox → cred-oidc-gha → cloud-id-poweruser)
  // never renders. (Seed drifted after S4-A2 added subject validation.)
  cred_subject: 'repo:acme-corp/webapp:ref:refs/heads/main',
  cred_issuer: 'https://token.actions.githubusercontent.com',
  cred_evidence_kind: 'capture',
  credential_status: 'active',
  cred_token_expires_at: new Date(Date.now() + 600_000).toISOString(),
  cred_value: '<seeded for smoke; never exfiltrated>',
  discovered_at: now,
  confidence: 1.0,
} as never);

// =============================================
// 4. Entra (Azure) — refresh token + access token
// =============================================
const entraIdp = {
  id: 'idp-entra-acme',
  type: 'idp',
  label: 'entra:acme.onmicrosoft.com',
  idp_kind: 'entra',
  tenant_id: 'acme.onmicrosoft.com',
  issuer_url: 'https://login.microsoftonline.com/acme.onmicrosoft.com/v2.0',
  discovered_at: now,
  confidence: 1.0,
} as const;
engine.addNode(entraIdp as never);

engine.addNode({
  id: 'cred-entra-rt',
  type: 'credential',
  label: 'entra-refresh-token-alice',
  cred_type: 'token',
  cred_material_kind: 'oidc_refresh_token',
  cred_user: 'alice@acme.local',
  cred_audience: 'https://graph.microsoft.com',
  cred_issuer: 'https://login.microsoftonline.com/acme.onmicrosoft.com/v2.0',
  cred_evidence_kind: 'capture',
  credential_status: 'active',
  discovered_at: now,
  confidence: 1.0,
  cred_value: '<seeded for smoke; never exfiltrated>',
} as never);

engine.addNode({
  id: 'cred-entra-at',
  type: 'credential',
  label: 'entra-access-token-alice',
  cred_type: 'token',
  cred_material_kind: 'oidc_access_token',
  cred_user: 'alice@acme.local',
  cred_audience: 'https://graph.microsoft.com',
  cred_issuer: 'https://login.microsoftonline.com/acme.onmicrosoft.com/v2.0',
  tenant_id: 'acme.onmicrosoft.com',
  cred_mfa_required: true,
  cred_mfa_satisfied: true,
  cred_evidence_kind: 'capture',
  credential_status: 'active',
  cred_token_expires_at: new Date(Date.now() + 3_600_000).toISOString(),
  discovered_at: now,
  confidence: 1.0,
  cred_value: '<seeded for smoke; never exfiltrated>',
} as never);

// =============================================
// 5. A live host with a session, so attack paths have a starting point
//    that can reach the cloud_identity objective via cred-oidc-gha.
// =============================================
engine.addNode({
  id: 'host-jumpbox',
  type: 'host',
  label: 'jumpbox.acme.local',
  ip: '10.10.10.11',
  os: 'Ubuntu 22.04',
  discovered_at: now,
  confidence: 1.0,
} as never);

engine.addEdge('host-jumpbox', 'cred-oidc-gha', {
  type: 'OWNS_CRED',
  confidence: 1.0,
  discovered_at: now,
} as never);

// Path-analyzer needs a host with either a live HAS_SESSION or an
// ADMIN_TO edge at confidence ≥ 0.9 to qualify it as a starting point.
// HAS_SESSION edges synthesized in seed scripts get reaped by the
// session-tracker on engine restart (no tracked process behind them),
// so we use ADMIN_TO instead — which is exactly the right model for
// "the operator already has admin on the jumpbox."
engine.addNode({
  id: 'user-operator',
  type: 'user',
  label: 'operator',
  username: 'operator',
  domain: 'acme.local',
  discovered_at: now,
  confidence: 1.0,
} as never);

engine.addEdge('user-operator', 'host-jumpbox', {
  type: 'ADMIN_TO',
  confidence: 1.0,
  discovered_at: now,
} as never);

// Cross-tier inference fires automatically on ingestFinding(); the
// addNode/addEdge calls above are direct mutations that bypass it. We
// need the OIDC_FEDERATION_PIVOT rule to fire so the attack-path
// renderer has an inferred ASSUMES_ROLE edge to chase. Run a tiny
// no-op finding through the ingest path to trigger inference once.
engine.ingestFinding({
  id: 'smoke-trigger-inference',
  agent_id: 'smoke-seed',
  timestamp: now,
  nodes: [],
  edges: [],
});

console.log('');
console.log('Smoke engagement seeded:');
console.log(`  Engagement dir: ${ENG_DIR}/`);
console.log(`  Config file:    ${CONFIG_FILE}`);
console.log(`  State file:     ${STATE_FILE}`);
console.log(`  Engagement id:  ${config.id}`);
console.log('');
console.log('Seeded credentials:');
console.log('  cred-aws-power    AWS poweruser temp creds (oidc_access_token shape)');
console.log('  cred-gh-pat       GitHub PAT for svc-deploy');
console.log('  cred-oidc-gha    Captured GHA OIDC token (audience: sts.amazonaws.com)');
console.log('  cred-entra-rt     Entra refresh token for alice@acme.local');
console.log('  cred-entra-at     Entra access token for alice@acme.local (post-MFA)');
console.log('');
console.log('Next steps:');
console.log(`  1. Start MCP server pointing at the smoke engagement:`);
console.log(`     OVERWATCH_CONFIG=${CONFIG_FILE} OVERWATCH_STATE_FILE=${STATE_FILE} node dist/index.js`);
console.log(`  2. Open the dashboard at http://localhost:8384`);
console.log(`  3. Follow docs/smoke-test.md`);
