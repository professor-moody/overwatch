// ============================================================
// Report QA fixture.
//
// Deterministic, local-only engagement used by report artifact QA. It
// exercises the report assembler without starting the dashboard server.
// ============================================================

import { mkdtempSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { GraphEngine } from './graph-engine.js';
import { SkillIndex } from './skill-index.js';
import { engagementConfigSchema, type EdgeProperties, type EngagementConfig, type NodeProperties } from '../types.js';

const NOW = new Date('2026-05-15T18:23:34.963Z');
const iso = (minutesAgo = 0) => new Date(NOW.getTime() - minutesAgo * 60_000).toISOString();

export const REPORT_QA_SECRET_MARKERS = [
  'Backup2024!',
  'demo-gha-oidc-jwt-redacted',
  'demo-okta-session-cookie-redacted',
  '/Users/operator/projects/overwatch',
] as const;

export interface ReportQaFixture {
  engine: GraphEngine;
  skills: SkillIndex;
  rootDir: string;
  stateFilePath: string;
  evidenceIds: {
    rdp: string;
    shared: string;
    oidc: string;
  };
  cleanup: () => void;
}

export interface ReportQaFixtureOptions {
  rootDir?: string;
  stateFilePath?: string;
}

type NodeInput = Omit<Partial<NodeProperties>, 'id' | 'type' | 'label'> & Pick<NodeProperties, 'id' | 'type' | 'label'> & Record<string, unknown>;

function node(props: NodeInput): NodeProperties {
  return {
    discovered_at: iso(120),
    confidence: 1,
    ...props,
  } as NodeProperties;
}

function edge(type: EdgeProperties['type'], extra: Partial<EdgeProperties> = {}): EdgeProperties {
  return {
    type,
    discovered_at: iso(60),
    confidence: 1,
    ...extra,
  } as EdgeProperties;
}

export function createReportQaFixture(options: ReportQaFixtureOptions = {}): ReportQaFixture {
  const config: EngagementConfig = {
    id: 'report-qa-demo',
    name: 'Report QA Demo',
    created_at: iso(240),
    profile: 'hybrid',
    scope: {
      cidrs: ['10.10.10.0/24'],
      domains: ['corp.local'],
      exclusions: [],
      url_patterns: ['*.corp.local'],
    },
    opsec: {
      name: 'pentest',
      enabled: true,
      max_noise: 1,
      approval_mode: 'approve-all',
      blacklisted_techniques: ['credential_dump'],
    },
    objectives: [
      {
        id: 'obj-domain',
        description: 'Compromise domain controller',
        target_node_type: 'host',
        target_criteria: { hostname: 'DC01' },
        achievement_edge_types: ['ADMIN_TO', 'HAS_SESSION'],
        achieved: false,
      },
      {
        id: 'obj-cloud',
        description: 'Reach payroll backup archive',
        target_node_type: 'cloud_resource',
        target_criteria: { provider_resource_id: 'corp-payroll-archive' },
        achievement_edge_types: ['POLICY_ALLOWS', 'CAN_REACH'],
        achieved: false,
      },
    ],
    phases: [
      {
        id: 'recon',
        name: 'Reconnaissance',
        order: 0,
        strategies: ['enumeration'],
        entry_criteria: [{ type: 'always' }],
        exit_criteria: [{ type: 'node_count', node_type: 'host', min: 2 }],
      },
      {
        id: 'exploit',
        name: 'Exploitation',
        order: 1,
        strategies: ['credential_spray', 'post_exploitation'],
        entry_criteria: [{ type: 'phase_completed', phase_id: 'recon' }],
        exit_criteria: [{ type: 'objective_achieved', objective_id: 'obj-domain' }],
      },
    ],
  };
  const validatedConfig = engagementConfigSchema.parse(config);

  // Allocate fixture-owned storage only after the static config is complete so
  // config/schema failures cannot strand temporary evidence and state trees.
  const rootDir = options.rootDir ?? mkdtempSync(join(tmpdir(), 'overwatch-report-qa-fixture-'));
  mkdirSync(rootDir, { recursive: true });
  const stateFilePath = options.stateFilePath ?? join(rootDir, 'state-report-qa.json');
  const skillsDir = join(rootDir, 'skills');
  mkdirSync(skillsDir, { recursive: true });

  const engine = new GraphEngine(validatedConfig, stateFilePath);
  const skills = new SkillIndex(skillsDir);

  const nodes = [
    node({ id: 'user-jdoe', type: 'user', label: 'jdoe', username: 'jdoe', domain: 'corp.local' }),
    node({ id: 'host-ws01', type: 'host', label: 'WS01.corp.local', hostname: 'WS01', ip: '10.10.10.50', os: 'Windows 11', alive: true, domain_joined: true }),
    node({ id: 'host-dc01', type: 'host', label: 'DC01.corp.local', hostname: 'DC01', ip: '10.10.10.10', os: 'Windows Server 2019', alive: true, domain_joined: true }),
    node({ id: 'svc-rdp-ws01', type: 'service', label: 'RDP (3389)', service_name: 'rdp', protocol: 'tcp', port: 3389 }),
    node({ id: 'cred-jdoe-ntlm', type: 'credential', label: 'jdoe:NTLM', cred_type: 'ntlm', cred_material_kind: 'ntlm_hash', cred_user: 'jdoe', cred_domain: 'corp.local', credential_status: 'active', cred_usable_for_auth: true, cred_value: 'aad3b435b51404ee:5d41402abc4b2a76' }),
    node({ id: 'cred-gha-oidc', type: 'credential', label: 'GitHub Actions OIDC token', cred_type: 'oidc_token', cred_material_kind: 'oidc_access_token', cred_user: 'repo:corp/benefits-portal:ref:refs/heads/main', cred_audience: 'sts.amazonaws.com', credential_status: 'active', cred_usable_for_auth: true, cred_value: 'demo-gha-oidc-jwt-redacted' }),
    node({ id: 'webapp-benefits', type: 'webapp', label: 'Benefits Portal', url: 'https://benefits.corp.local', technology: 'Express', has_login_form: true }),
    node({ id: 'vuln-benefits-idor', type: 'vulnerability', label: 'Benefits export IDOR', vuln_type: 'idor', cwe: 'CWE-639', cvss: 8.1, exploitable: true, exploit_available: true }),
    node({ id: 'idp-app-gha', type: 'idp_application', label: 'benefits-portal deploy', app_name: 'benefits-portal deploy', idp_kind: 'ci_github_actions', audience: 'sts.amazonaws.com' }),
    node({ id: 'cloud-role-deploy', type: 'cloud_identity', label: 'AWS DeployRole', provider: 'aws', principal_type: 'role', arn: 'arn:aws:iam::111122223333:role/DeployRole' }),
    node({ id: 'cloud-role-admin', type: 'cloud_identity', label: 'AWS AdminRole', provider: 'aws', principal_type: 'role', arn: 'arn:aws:iam::111122223333:role/AdminRole' }),
    node({ id: 'cloud-policy-admin', type: 'cloud_policy', label: 'AdministratorAccess', provider: 'aws', policy_name: 'AdministratorAccess', effect: 'allow', actions: ['*'], resources: ['*'] }),
    node({ id: 's3-payroll', type: 'cloud_resource', label: 's3://corp-payroll-archive', provider: 'aws', resource_type: 's3_bucket', provider_resource_id: 'corp-payroll-archive', region: 'us-east-1', public: true }),
  ];
  for (const item of nodes) engine.addNode(item);

  engine.addEdge('user-jdoe', 'host-ws01', edge('HAS_SESSION', { session_live: true, session_id: 'report-qa-ws01', confidence: 1 }));
  engine.addEdge('host-ws01', 'svc-rdp-ws01', edge('RUNS'));
  engine.addEdge('user-jdoe', 'cred-jdoe-ntlm', edge('OWNS_CRED'));
  engine.addEdge('cred-jdoe-ntlm', 'svc-rdp-ws01', edge('VALID_ON', { confirmed: true, confidence: 0.96 }));
  engine.addEdge('user-jdoe', 'cred-gha-oidc', edge('OWNS_CRED', { confidence: 0.95 }));
  engine.addEdge('cred-gha-oidc', 'idp-app-gha', edge('VALID_FOR_APP', { confirmed: true, confidence: 0.95 }));
  engine.addEdge('host-ws01', 'webapp-benefits', edge('CAN_REACH', { confidence: 0.85, inferred: true }));
  engine.addEdge('webapp-benefits', 'vuln-benefits-idor', edge('VULNERABLE_TO', { confidence: 0.95, severity: 'high', technique_id: 'T1190' }));
  engine.addEdge('vuln-benefits-idor', 'webapp-benefits', edge('EXPLOITS', { confidence: 0.95, tested: true, severity: 'high', technique_id: 'T1190' }));
  engine.addEdge('idp-app-gha', 'cloud-role-deploy', edge('ISSUES_TOKENS_FOR', { confirmed: true, confidence: 0.95 }));
  engine.addEdge('cloud-role-deploy', 'cloud-role-admin', edge('ASSUMES_ROLE', { confidence: 0.92, inferred: true }));
  engine.addEdge('cloud-role-admin', 'cloud-policy-admin', edge('HAS_POLICY', { confidence: 0.95 }));
  engine.addEdge('cloud-policy-admin', 's3-payroll', edge('POLICY_ALLOWS', { confidence: 0.9, inferred: true }));
  engine.addEdge('host-dc01', 's3-payroll', edge('RELATED', { confidence: 0.4, inferred: true }));

  const rdpEvidence = engine.getEvidenceStore().store({
    action_id: 'act-report-qa-rdp',
    evidence_type: 'command_output',
    filename: 'rdp-validation.txt',
    raw_output: [
      'xfreerdp /v:10.10.10.50 /u:jdoe /pth:<redacted>',
      'corp\\jdoe',
      'hostname: WS01',
      'operator workspace: /Users/operator/projects/overwatch',
      'credential note: Backup2024!',
    ].join('\n'),
  });
  const sharedEvidence = engine.getEvidenceStore().store({
    action_id: 'act-report-qa-web',
    evidence_type: 'command_output',
    filename: 'benefits-idor.txt',
    raw_output: [
      'GET /api/export?employee_id=1044 -> 200',
      'GET /api/export?employee_id=1045 -> 200',
      'Different employee record returned from the same authenticated context.',
    ].join('\n'),
  });
  const oidcEvidence = engine.getEvidenceStore().store({
    action_id: 'act-report-qa-oidc',
    evidence_type: 'command_output',
    filename: 'oidc-replay.txt',
    raw_output: [
      'aws sts assume-role-with-web-identity --role-arn arn:aws:iam::111122223333:role/DeployRole',
      'token=demo-gha-oidc-jwt-redacted',
      'AssumeRoleWithWebIdentity succeeded; CloudTrail event recorded.',
    ].join('\n'),
  });

  engine.logActionEvent({
    description: 'Engagement initialized from report QA fixture.',
    event_type: 'system',
    category: 'system',
    agent_id: 'fixture',
  });
  engine.logActionEvent({
    description: 'Nmap discovery identified WS01 and DC01 with RDP and domain services.',
    event_type: 'finding_ingested',
    category: 'finding',
    agent_id: 'nmap-agent',
    action_id: 'act-report-qa-recon',
    target_node_ids: ['host-ws01', 'host-dc01', 'svc-rdp-ws01'],
    tool_name: 'nmap',
    result_classification: 'success',
  });
  engine.logActionEvent({
    description: 'RDP validation confirmed an active jdoe session on WS01.',
    event_type: 'action_completed',
    category: 'finding',
    agent_id: 'operator',
    action_id: 'act-report-qa-rdp',
    target_node_ids: ['host-ws01', 'cred-jdoe-ntlm'],
    command_repr: 'xfreerdp /v:10.10.10.50 /u:jdoe /pth:<redacted>',
    tool_name: 'xfreerdp',
    result_classification: 'success',
    outcome: 'success',
    details: { stdout_evidence_id: rdpEvidence },
  });
  engine.logActionEvent({
    description: 'Benefits Portal IDOR returned another employee export record.',
    event_type: 'action_completed',
    category: 'finding',
    agent_id: 'web-agent',
    action_id: 'act-report-qa-web',
    target_node_ids: ['webapp-benefits', 'vuln-benefits-idor'],
    command_repr: 'curl https://benefits.corp.local/api/export?employee_id=1045',
    tool_name: 'curl',
    result_classification: 'success',
    outcome: 'success',
    details: { stdout_evidence_id: sharedEvidence },
  });
  engine.logActionEvent({
    description: 'OIDC replay used the GitHub Actions token to assume AWS DeployRole.',
    event_type: 'action_completed',
    category: 'frontier',
    agent_id: 'cloud-agent',
    action_id: 'act-report-qa-oidc',
    target_node_ids: ['cred-gha-oidc', 'cloud-role-deploy', 'cloud-role-admin'],
    command_repr: 'aws sts assume-role-with-web-identity --role-arn arn:aws:iam::111122223333:role/DeployRole --web-identity-token <redacted>',
    tool_name: 'aws',
    result_classification: 'success',
    outcome: 'success',
    details: { stdout_evidence_id: oidcEvidence },
  });
  engine.logActionEvent({
    description: 'Parser caveat: one cloud inventory record was missing an object ID and was skipped.',
    event_type: 'parse_output',
    category: 'finding',
    agent_id: 'cloud-agent',
    action_id: 'act-report-qa-parser',
    result_classification: 'partial',
    target_node_ids: ['cloud-role-admin'],
    details: { ingest_summary: [{ processed_records: 3, dropped_records: 1, dropped_by_reason: { missing_object_id: 1 } }] },
  });

  return {
    engine,
    skills,
    rootDir,
    stateFilePath,
    evidenceIds: {
      rdp: rdpEvidence,
      shared: sharedEvidence,
      oidc: oidcEvidence,
    },
    cleanup: () => rmSync(rootDir, { recursive: true, force: true }),
  };
}
