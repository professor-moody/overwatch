#!/usr/bin/env npx tsx
// Recordable demo cockpit: starts GraphEngine + DashboardServer with a
// deterministic, local-only engagement that exercises the operator dashboard.

import { unlinkSync, existsSync, readFileSync } from 'fs';
import type { AdapterHandle, EdgeProperties, EngagementConfig, NodeProperties, SessionCapabilities } from '../src/types.js';
import { GraphEngine } from '../src/services/graph-engine.js';
import { DashboardServer } from '../src/services/dashboard-server.js';
import { InProcessTapeController } from '../src/services/in-process-tape.js';
import { SessionManager, type SessionAdapterFactory } from '../src/services/session-manager.js';
import type { OpsecContext } from '../src/services/opsec-tracker.js';
import { setTelemetry } from '../src/tools/error-boundary.js';
import { ToolTelemetry } from '../src/services/tool-telemetry.js';
import type { ToolDescriptor } from '../src/services/tool-descriptor-registry.js';

const STATE_FILE = './state-demo-dashboard.json';
const requestedDashboardPort = Number.parseInt(process.env.OVERWATCH_DEMO_DASHBOARD_PORT || process.env.OVERWATCH_DASHBOARD_PORT || '8384', 10);
const DASHBOARD_PORT = Number.isFinite(requestedDashboardPort) ? requestedDashboardPort : 8384;
const NOW = new Date('2026-05-15T18:23:34.963Z');
const iso = (minutesAgo = 0) => new Date(NOW.getTime() - minutesAgo * 60_000).toISOString();

const ACTION_RDP = 'a11ca7e0001';
const ACTION_SMB = 'a11ca7e0002';
const ACTION_CRED = 'a11ca7e0003';
const ACTION_CI = 'a11ca7e0004';

if (existsSync(STATE_FILE)) unlinkSync(STATE_FILE);

class DemoPtyHandle implements AdapterHandle {
  pid = 4242;
  capabilities: SessionCapabilities = {
    has_stdin: true,
    has_stdout: true,
    supports_resize: true,
    supports_signals: true,
    tty_quality: 'full',
  };

  private dataCallbacks: Array<(chunk: string) => void> = [];
  private exitCallbacks: Array<(info: { exitCode?: number; signal?: number }) => void> = [];
  private commandBuffer = '';
  private closed = false;

  constructor(private prompt: string, private profile: 'windows' | 'linux') {
    setTimeout(() => {
      this.emit(this.profile === 'windows'
        ? `Microsoft Windows [Version 10.0.22631.3593]\r\n${this.prompt}`
        : `Last login: Fri May 15 13:20:03 2026 from 10.10.10.5\r\n${this.prompt}`);
    }, 25);
  }

  write(data: string): void {
    if (this.closed) return;
    for (const char of data) {
      if (char === '\r' || char === '\n') {
        const command = this.commandBuffer.trim();
        this.commandBuffer = '';
        if (command) this.emit(`\r\n${this.responseFor(command)}\r\n${this.prompt}`);
        else this.emit(`\r\n${this.prompt}`);
      } else if (char === '\u007f') {
        this.commandBuffer = this.commandBuffer.slice(0, -1);
      } else {
        this.commandBuffer += char;
        this.emit(char);
      }
    }
  }

  resize(): void {
    this.emit('\r\n[demo terminal resized]\r\n' + this.prompt);
  }

  kill(): void {
    this.closed = true;
    for (const cb of this.exitCallbacks) cb({ signal: 15 });
  }

  close(): void {
    this.closed = true;
  }

  onData(cb: (chunk: string) => void): void {
    this.dataCallbacks.push(cb);
  }

  onExit(cb: (info: { exitCode?: number; signal?: number }) => void): void {
    this.exitCallbacks.push(cb);
  }

  private emit(chunk: string): void {
    for (const cb of this.dataCallbacks) cb(chunk);
  }

  private responseFor(command: string): string {
    const cmd = command.toLowerCase();
    if (cmd === 'whoami') return this.profile === 'windows' ? 'corp\\jdoe' : 'svc_backup';
    if (cmd === 'hostname') return this.profile === 'windows' ? 'WS01' : 'db01';
    if (cmd === 'ipconfig' || cmd === 'ifconfig') {
      return this.profile === 'windows'
        ? 'Ethernet adapter Ethernet0:\r\n   IPv4 Address. . . . . . . . . . . : 10.10.10.50'
        : 'eth0: inet 10.10.10.30 netmask 255.255.255.0';
    }
    if (cmd === 'dir' || cmd === 'ls') {
      return this.profile === 'windows'
        ? '05/15/2026  01:19 PM    <DIR>          Desktop\r\n05/15/2026  01:19 PM             2,048 runbook.txt'
        : 'backup.sql  cron.d  service-account-notes.txt';
    }
    if (cmd === 'net user') return 'Administrator  jdoe  svc_backup  krbtgt';
    if (cmd === 'help') return 'Demo commands: whoami, hostname, ipconfig, dir, net user, help';
    return `demo-shell: "${command}" is a safe no-op in this recording fixture. Try help.`;
  }
}

class DemoPtyAdapter implements SessionAdapterFactory {
  kind = 'local_pty' as const;

  async spawn(options: Record<string, unknown>): Promise<AdapterHandle> {
    const host = typeof options.host === 'string' ? options.host.toLowerCase() : '';
    const profile = host.includes('db01') ? 'linux' : 'windows';
    const prompt = profile === 'windows' ? 'corp\\jdoe@WS01 C:\\Users\\jdoe> ' : 'svc_backup@db01:~$ ';
    return new DemoPtyHandle(prompt, profile);
  }
}

const config: EngagementConfig = {
  id: 'demo-engagement',
  name: 'Demo Engagement',
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
    max_noise: 1.2,
    approval_mode: 'approve-all',
    approval_timeout_ms: 3_600_000,
    blacklisted_techniques: ['credential_dump'],
  },
  objectives: [
    {
      id: 'obj-1',
      description: 'Compromise domain controller',
      target_node_type: 'host',
      target_criteria: { hostname: 'DC01' },
      achievement_edge_types: ['ADMIN_TO', 'HAS_SESSION'],
      achieved: false,
    },
    {
      id: 'obj-2',
      description: 'Exfiltrate sensitive data',
      target_node_type: 'cloud_resource',
      target_criteria: { resource_type: 's3_bucket', provider_resource_id: 'corp-payroll-archive' },
      achievement_edge_types: ['POLICY_ALLOWS', 'CAN_REACH'],
      achieved: false,
    },
    {
      id: 'obj-3',
      description: 'Reach production cloud admin role',
      target_node_type: 'cloud_identity',
      target_criteria: { arn: 'arn:aws:iam::111122223333:role/AdminRole' },
      achievement_edge_types: ['ASSUMES_ROLE'],
      achieved: false,
    },
  ],
  phases: [
    {
      id: 'recon',
      name: 'Reconnaissance',
      order: 0,
      strategies: ['enumeration', 'network_discovery'],
      entry_criteria: [{ type: 'always' }],
      exit_criteria: [{ type: 'node_count', node_type: 'host', min: 5 }],
    },
    {
      id: 'exploit',
      name: 'Exploitation',
      order: 1,
      strategies: ['credential_spray', 'post_exploitation'],
      entry_criteria: [{ type: 'phase_completed', phase_id: 'recon' }],
      exit_criteria: [{ type: 'objective_achieved', objective_id: 'obj-1' }],
      approval_overrides: { mode: 'approve-all' },
    },
  ],
};

const engine = new GraphEngine(config, STATE_FILE);
const sessionManager = new SessionManager(engine, 0);
sessionManager.registerAdapter(new DemoPtyAdapter());

const hosts = [
  { id: 'dc01', type: 'host' as const, label: 'DC01.corp.local', ip: '10.10.10.10', os: 'Windows Server 2019', hostname: 'DC01', alive: true, domain_joined: true, edr: 'Defender for Endpoint' },
  { id: 'web01', type: 'host' as const, label: 'WEB01.corp.local', ip: '10.10.10.20', os: 'Ubuntu 22.04', hostname: 'WEB01', alive: true },
  { id: 'db01', type: 'host' as const, label: 'DB01.corp.local', ip: '10.10.10.30', os: 'Windows Server 2022', hostname: 'DB01', alive: true, domain_joined: true },
  { id: 'fs01', type: 'host' as const, label: 'FS01.corp.local', ip: '10.10.10.40', os: 'Windows Server 2019', hostname: 'FS01', alive: true, domain_joined: true },
  { id: 'ws01', type: 'host' as const, label: 'WS01.corp.local', ip: '10.10.10.50', os: 'Windows 11', hostname: 'WS01', alive: true, domain_joined: true },
  { id: 'ws02', type: 'host' as const, label: 'WS02.corp.local', ip: '10.10.10.51', os: 'Windows 11', hostname: 'WS02', alive: true, domain_joined: true },
];

const users = [
  { id: 'user-admin', type: 'user' as const, label: 'Administrator', username: 'Administrator', domain: 'corp.local' },
  { id: 'user-jdoe', type: 'user' as const, label: 'jdoe', username: 'jdoe', domain: 'corp.local' },
  { id: 'user-svc', type: 'user' as const, label: 'svc_backup', username: 'svc_backup', domain: 'corp.local' },
  { id: 'group-domain-admins', type: 'group' as const, label: 'Domain Admins', name: 'Domain Admins', domain: 'corp.local' },
];

const creds = [
  { id: 'cred-jdoe-ntlm', type: 'credential' as const, label: 'jdoe:NTLM', cred_type: 'ntlm' as const, cred_material_kind: 'ntlm_hash', hash: 'aad3b435b51404ee:5d41402abc4b2a76', credential_status: 'active', reachable: true, cred_user: 'jdoe', cred_domain: 'corp.local' },
  { id: 'cred-svc-pass', type: 'credential' as const, label: 'svc_backup:password', cred_type: 'plaintext' as const, cred_material_kind: 'plaintext_password', plaintext: 'Backup2024!', credential_status: 'active', reachable: true, cred_user: 'svc_backup', cred_domain: 'corp.local' },
  {
    id: 'cred-okta-cookie',
    type: 'credential' as const,
    label: 'jdoe:Okta session',
    cred_type: 'session_cookie' as const,
    cred_material_kind: 'session_cookie',
    credential_status: 'active',
    cred_user: 'jdoe@corp.local',
    cred_audience: 'https://benefits.corp.local',
    cred_scopes: ['openid', 'profile', 'email', 'groups'],
    cred_issuer: 'https://corp.okta.example',
    cred_token_expires_at: iso(-105),
    cred_mfa_required: true,
    cred_mfa_satisfied: true,
    cred_value: 'demo-okta-session-cookie-redacted',
    reachable: true,
  },
  {
    id: 'cred-gha-oidc',
    type: 'credential' as const,
    label: 'GitHub Actions OIDC token',
    cred_type: 'oidc_token' as const,
    cred_material_kind: 'oidc_access_token',
    credential_status: 'active',
    cred_user: 'repo:corp/benefits-portal:ref:refs/heads/main',
    cred_audience: 'sts.amazonaws.com',
    cred_scopes: ['sts:AssumeRoleWithWebIdentity'],
    cred_issuer: 'https://token.actions.githubusercontent.com',
    cred_token_expires_at: iso(-55),
    cred_mfa_required: false,
    cred_mfa_satisfied: true,
    cred_value: 'demo-gha-oidc-jwt-redacted',
    reachable: true,
  },
  {
    // Already lapsed → exercises the "Expired tokens" chip/banner + the red
    // "expired Nm ago" TTL label. (cred-gha-oidc above, expiring in ~55m, is the
    // "Expiring soon" case; cred-okta-cookie ~105m out is the "ok" case.)
    id: 'cred-legacy-pat',
    type: 'credential' as const,
    label: 'ci-bot:GitHub PAT (legacy)',
    cred_type: 'token' as const,
    cred_material_kind: 'pat',
    credential_status: 'active',
    cred_user: 'ci-bot',
    cred_audience: 'github.com',
    cred_scopes: ['repo', 'read:org'],
    cred_issuer: 'https://github.com',
    cred_token_expires_at: iso(90),
    cred_value: 'demo-legacy-pat-redacted',
    reachable: false,
  },
];

const services = [
  { id: 'svc-smb-dc01', type: 'service' as const, label: 'SMB (445)', port: 445, protocol: 'tcp', service_name: 'smb', banner: 'Windows Server SMB' },
  { id: 'svc-ldap-dc01', type: 'service' as const, label: 'LDAP (389)', port: 389, protocol: 'tcp', service_name: 'ldap' },
  { id: 'svc-http-web01', type: 'service' as const, label: 'HTTP (80)', port: 80, protocol: 'tcp', service_name: 'http' },
  { id: 'svc-https-web01', type: 'service' as const, label: 'HTTPS (443)', port: 443, protocol: 'tcp', service_name: 'https' },
  { id: 'svc-mssql-db01', type: 'service' as const, label: 'MSSQL (1433)', port: 1433, protocol: 'tcp', service_name: 'mssql', linked_servers: ['FS01'] },
  { id: 'svc-rdp-ws01', type: 'service' as const, label: 'RDP (3389)', port: 3389, protocol: 'tcp', service_name: 'rdp' },
];

const apps = [
  { id: 'webapp-portal', type: 'webapp' as const, label: 'Benefits Portal', url: 'https://benefits.corp.local', framework: 'Express', auth_type: 'oidc', hvt: true, hvt_reason: 'SSO bridge to cloud backup role' },
  { id: 'vuln-idor-benefits', type: 'vulnerability' as const, label: 'IDOR in benefits export', vuln_type: 'idor', severity: 'high', cwe: 'CWE-639' },
  { id: 'idp-okta', type: 'idp' as const, label: 'Okta Corp', idp_kind: 'okta', tenant_id: 'corp-okta', issuer_url: 'https://corp.okta.example', federation_mode: 'saml+oidc' },
  { id: 'idp-app-benefits', type: 'idp_application' as const, label: 'Benefits Portal SSO', app_name: 'Benefits Portal', idp_id: 'idp-okta', idp_kind: 'okta', tenant_id: 'corp-okta', audience: 'https://benefits.corp.local', app_mfa_required: true },
  { id: 'idp-principal-jdoe', type: 'idp_principal' as const, label: 'jdoe@corp.local', username: 'jdoe@corp.local', idp_id: 'idp-okta', idp_kind: 'okta', tenant_id: 'corp-okta', mfa_factors: ['webauthn', 'push'], groups: ['Domain Users', 'Benefits Exporters'] },
  { id: 'idp-gha', type: 'idp' as const, label: 'GitHub Actions OIDC', idp_kind: 'ci_github_actions', tenant_id: 'corp', issuer_url: 'https://token.actions.githubusercontent.com', federation_mode: 'oidc' },
  { id: 'idp-app-gha-deploy', type: 'idp_application' as const, label: 'benefits-portal deploy', app_name: 'benefits-portal deploy', idp_id: 'idp-gha', idp_kind: 'ci_github_actions', tenant_id: 'corp', audience: 'sts.amazonaws.com', app_mfa_required: false },
  { id: 'idp-principal-ci-release', type: 'idp_principal' as const, label: 'repo:corp/benefits-portal:main', username: 'repo:corp/benefits-portal:ref:refs/heads/main', idp_id: 'idp-gha', idp_kind: 'ci_github_actions', tenant_id: 'corp' },
  { id: 'cloud-role-backup', type: 'cloud_identity' as const, label: 'AWS BackupRole', provider: 'aws', cloud_provider: 'aws', cloud_account: '111122223333', account_id: '111122223333', arn: 'arn:aws:iam::111122223333:role/BackupRole', principal_type: 'role', hvt: true, hvt_reason: 'Can read payroll backup archive' },
  { id: 'cloud-role-deploy', type: 'cloud_identity' as const, label: 'AWS DeployRole', provider: 'aws', cloud_provider: 'aws', cloud_account: '111122223333', account_id: '111122223333', arn: 'arn:aws:iam::111122223333:role/DeployRole', principal_type: 'role', hvt: true, hvt_reason: 'CI role can assume production admin' },
  { id: 'cloud-role-admin', type: 'cloud_identity' as const, label: 'AWS AdminRole', provider: 'aws', cloud_provider: 'aws', cloud_account: '111122223333', account_id: '111122223333', arn: 'arn:aws:iam::111122223333:role/AdminRole', principal_type: 'role', hvt: true, hvt_reason: 'Production cloud administration objective' },
  { id: 'cloud-policy-backup-read', type: 'cloud_policy' as const, label: 'BackupReadPolicy', provider: 'aws', cloud_account: '111122223333', policy_name: 'BackupReadPolicy', effect: 'allow', actions: ['s3:GetObject', 's3:ListBucket'], resources: ['arn:aws:s3:::corp-payroll-archive/*'] },
  { id: 'cloud-policy-admin-access', type: 'cloud_policy' as const, label: 'AdministratorAccess', provider: 'aws', cloud_account: '111122223333', policy_name: 'AdministratorAccess', effect: 'allow', actions: ['*'], resources: ['*'] },
  { id: 's3-payroll-archive', type: 'cloud_resource' as const, label: 's3://corp-payroll-archive', provider: 'aws', cloud_provider: 'aws', resource_type: 's3_bucket', resource_kind: 's3_bucket', provider_resource_id: 'corp-payroll-archive', region: 'us-east-1', hvt: true, hvt_reason: 'Sensitive payroll export archive' },
  { id: 'lambda-benefits-export', type: 'cloud_resource' as const, label: 'lambda:benefits-export', provider: 'aws', cloud_provider: 'aws', resource_type: 'lambda', provider_resource_id: 'benefits-export', region: 'us-east-1' },
];

engine.ingestFinding({
  id: 'f-hosts',
  agent_id: 'nmap-agent',
  action_id: 'a11ca7e1000',
  frontier_item_id: 'frontier-discovery-corp',
  tool_name: 'nmap',
  timestamp: iso(90),
  target_node_ids: ['dc01', 'web01', 'db01', 'fs01', 'ws01', 'ws02'],
  nodes: [...hosts, ...services],
  edges: [
    { source: 'dc01', target: 'svc-smb-dc01', properties: { type: 'RUNS', confidence: 1.0, discovered_at: iso(90) } },
    { source: 'dc01', target: 'svc-ldap-dc01', properties: { type: 'RUNS', confidence: 1.0, discovered_at: iso(90) } },
    { source: 'web01', target: 'svc-http-web01', properties: { type: 'RUNS', confidence: 1.0, discovered_at: iso(88) } },
    { source: 'web01', target: 'svc-https-web01', properties: { type: 'RUNS', confidence: 1.0, discovered_at: iso(88) } },
    { source: 'db01', target: 'svc-mssql-db01', properties: { type: 'RUNS', confidence: 1.0, discovered_at: iso(86) } },
    { source: 'ws01', target: 'svc-rdp-ws01', properties: { type: 'RUNS', confidence: 1.0, discovered_at: iso(86) } },
  ],
  evidence: { type: 'command_output', filename: 'nmap-demo.txt', content: 'Host discovery found DC01, WEB01, DB01, FS01, WS01, WS02 with SMB/RDP/MSSQL/HTTP services.' },
  raw_output: 'Nmap scan report for 10.10.10.10\n445/tcp open microsoft-ds\n389/tcp open ldap\nNmap scan report for 10.10.10.50\n3389/tcp open ms-wbt-server',
});

engine.ingestFinding({
  id: 'f-users-creds',
  agent_id: 'enum-agent',
  action_id: 'a11ca7e1001',
  frontier_item_id: 'frontier-node-dc01',
  tool_name: 'enum4linux',
  timestamp: iso(70),
  target_node_ids: ['dc01', 'user-jdoe', 'cred-jdoe-ntlm', 'cred-svc-pass'],
  nodes: [...users, ...creds],
  edges: [
    { source: 'user-admin', target: 'group-domain-admins', properties: { type: 'MEMBER_OF', confidence: 1.0, discovered_at: iso(70), confirmed: true } },
    { source: 'user-jdoe', target: 'cred-jdoe-ntlm', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: iso(70), confirmed: true } },
    { source: 'user-svc', target: 'cred-svc-pass', properties: { type: 'OWNS_CRED', confidence: 1.0, discovered_at: iso(70), confirmed: true } },
    { source: 'user-jdoe', target: 'ws01', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: iso(22), session_live: true, session_id: 'demo-live-ws01' } },
    { source: 'user-svc', target: 'db01', properties: { type: 'HAS_SESSION', confidence: 0.9, discovered_at: iso(45), session_live: false, session_id: 'demo-closed-db01', session_closed_at: iso(12) } },
    { source: 'cred-jdoe-ntlm', target: 'svc-rdp-ws01', properties: { type: 'TESTED_CRED', confidence: 0.95, discovered_at: iso(28), confirmed: true } },
    { source: 'cred-svc-pass', target: 'svc-mssql-db01', properties: { type: 'VALID_ON', confidence: 0.95, discovered_at: iso(33), confirmed: true } },
  ],
  evidence: { type: 'command_output', filename: 'enum4linux-demo.txt', content: 'Domain users and two reusable credentials were extracted from SMB enumeration.' },
  raw_output: '[+] Enumerating users using SID S-1-5-21-demo\njdoe\nsvc_backup\n[+] Credential material recovered from demo parser',
});

engine.ingestFinding({
  id: 'f-app-cloud',
  agent_id: 'web-agent',
  action_id: 'a11ca7e1002',
  frontier_item_id: 'frontier-webapp-benefits',
  tool_name: 'httpx',
  timestamp: iso(42),
  target_node_ids: ['webapp-portal', 'vuln-idor-benefits', 'idp-app-benefits', 's3-payroll-archive'],
  nodes: apps,
  edges: [
    { source: 'web01', target: 'webapp-portal', properties: { type: 'HOSTS', confidence: 1.0, discovered_at: iso(42), confirmed: true } },
    { source: 'webapp-portal', target: 'vuln-idor-benefits', properties: { type: 'VULNERABLE_TO', confidence: 0.9, discovered_at: iso(42), finding_type: 'IDOR', severity: 'high', technique_id: 'T1190' } },
    { source: 'vuln-idor-benefits', target: 'webapp-portal', properties: { type: 'EXPLOITS', confidence: 0.92, discovered_at: iso(39), tested: true, finding_type: 'IDOR', severity: 'high', technique_id: 'T1190' } },
    { source: 'webapp-portal', target: 'idp-app-benefits', properties: { type: 'AUTHENTICATES_VIA', confidence: 1.0, discovered_at: iso(42), confirmed: true } },
    { source: 'idp-okta', target: 'domain-corp-local', properties: { type: 'FEDERATES_WITH', confidence: 0.95, discovered_at: iso(42), confirmed: true } },
    { source: 'idp-principal-jdoe', target: 'idp-app-benefits', properties: { type: 'ASSIGNED_TO_APP', confidence: 1.0, discovered_at: iso(42), confirmed: true } },
    { source: 'idp-principal-jdoe', target: 'idp-app-benefits', properties: { type: 'MFA_REQUIRED_FOR', confidence: 1.0, discovered_at: iso(42), confirmed: true } },
    { source: 'cred-okta-cookie', target: 'idp-app-benefits', properties: { type: 'VALID_FOR_APP', confidence: 0.75, discovered_at: iso(38), confirmed: false } },
    { source: 'cred-okta-cookie', target: 'idp-principal-jdoe', properties: { type: 'VALID_FOR_IDP_PRINCIPAL', confidence: 0.8, discovered_at: iso(38), confirmed: true } },
    { source: 'idp-app-benefits', target: 'cloud-role-backup', properties: { type: 'ISSUES_TOKENS_FOR', confidence: 0.9, discovered_at: iso(38), inferred: true } },
    { source: 'cloud-role-backup', target: 'cloud-policy-backup-read', properties: { type: 'HAS_POLICY', confidence: 0.95, discovered_at: iso(36), inferred: true } },
    { source: 'cloud-policy-backup-read', target: 's3-payroll-archive', properties: { type: 'POLICY_ALLOWS', confidence: 0.95, discovered_at: iso(36), inferred: true } },
    { source: 'webapp-portal', target: 'lambda-benefits-export', properties: { type: 'BACKED_BY', confidence: 0.85, discovered_at: iso(39), inferred: true } },
    { source: 'webapp-portal', target: 's3-payroll-archive', properties: { type: 'CAN_REACH', confidence: 0.7, discovered_at: iso(39), inferred: true, via: 'benefits export IDOR' } },
    { source: 'idp-gha', target: 'domain-corp-local', properties: { type: 'FEDERATES_WITH', confidence: 0.75, discovered_at: iso(41), inferred: true } },
    { source: 'idp-principal-ci-release', target: 'idp-app-gha-deploy', properties: { type: 'ASSIGNED_TO_APP', confidence: 1.0, discovered_at: iso(41), confirmed: true } },
    { source: 'cred-gha-oidc', target: 'idp-app-gha-deploy', properties: { type: 'VALID_FOR_APP', confidence: 0.9, discovered_at: iso(38), confirmed: true } },
    { source: 'cred-gha-oidc', target: 'idp-principal-ci-release', properties: { type: 'VALID_FOR_IDP_PRINCIPAL', confidence: 0.9, discovered_at: iso(38), confirmed: true } },
    { source: 'idp-app-gha-deploy', target: 'cloud-role-deploy', properties: { type: 'ISSUES_TOKENS_FOR', confidence: 0.95, discovered_at: iso(38), confirmed: true } },
    { source: 'cloud-role-deploy', target: 'cloud-role-admin', properties: { type: 'ASSUMES_ROLE', confidence: 0.92, discovered_at: iso(35), inferred: true } },
    { source: 'cloud-role-admin', target: 'cloud-policy-admin-access', properties: { type: 'HAS_POLICY', confidence: 0.95, discovered_at: iso(35), inferred: true } },
    { source: 'cloud-policy-admin-access', target: 's3-payroll-archive', properties: { type: 'POLICY_ALLOWS', confidence: 0.9, discovered_at: iso(35), inferred: true } },
  ],
  evidence: { type: 'command_output', filename: 'benefits-idor-demo.txt', content: 'Changing employee_id in the export request returned another user record in the demo fixture.' },
  raw_output: 'GET /api/export?employee_id=1044 -> 200\nGET /api/export?employee_id=1045 -> 200 (different employee record)',
});

function graphNodes(): NodeProperties[] {
  return engine.exportGraph().nodes.map((node: any) => ({ id: node.id, ...(node.properties || {}) }) as NodeProperties);
}

function canonicalNodeId(label: string, predicate: (node: NodeProperties) => boolean): string {
  const node = graphNodes().find(predicate);
  if (!node) throw new Error(`Demo fixture could not resolve canonical node: ${label}`);
  return node.id;
}

function addEdge(source: string, target: string, props: Partial<EdgeProperties> & Pick<EdgeProperties, 'type'>): void {
  engine.addEdge(source, target, {
    confidence: 1.0,
    discovered_at: iso(30),
    ...props,
  } as EdgeProperties);
}

const ids = {
  domain: canonicalNodeId('corp.local domain', n => n.type === 'domain' && n.domain_name === 'corp.local'),
  dc01: canonicalNodeId('DC01', n => n.type === 'host' && n.hostname === 'DC01'),
  web01: canonicalNodeId('WEB01', n => n.type === 'host' && n.hostname === 'WEB01'),
  db01: canonicalNodeId('DB01', n => n.type === 'host' && n.hostname === 'DB01'),
  fs01: canonicalNodeId('FS01', n => n.type === 'host' && n.hostname === 'FS01'),
  ws01: canonicalNodeId('WS01', n => n.type === 'host' && n.hostname === 'WS01'),
  jdoe: canonicalNodeId('jdoe', n => n.type === 'user' && n.username === 'jdoe'),
  admin: canonicalNodeId('Administrator', n => n.type === 'user' && n.username === 'Administrator'),
  svc: canonicalNodeId('svc_backup', n => n.type === 'user' && n.username === 'svc_backup'),
  domainAdmins: canonicalNodeId('Domain Admins', n => n.type === 'group' && n.label === 'Domain Admins'),
  credJdoe: canonicalNodeId('jdoe NTLM credential', n => n.type === 'credential' && n.label === 'jdoe:NTLM'),
  credSvc: canonicalNodeId('svc_backup credential', n => n.type === 'credential' && n.label === 'svc_backup:password'),
  credOkta: canonicalNodeId('jdoe Okta session', n => n.type === 'credential' && n.label === 'jdoe:Okta session'),
  credGha: canonicalNodeId('GitHub Actions OIDC token', n => n.type === 'credential' && n.label === 'GitHub Actions OIDC token'),
  rdpWs01: canonicalNodeId('WS01 RDP service', n => n.type === 'service' && n.service_name === 'rdp' && n.label === 'RDP (3389)'),
  smbDc01: canonicalNodeId('DC01 SMB service', n => n.type === 'service' && n.service_name === 'smb' && n.label === 'SMB (445)'),
  mssqlDb01: canonicalNodeId('DB01 MSSQL service', n => n.type === 'service' && n.service_name === 'mssql'),
  webapp: canonicalNodeId('Benefits Portal', n => n.type === 'webapp' && n.url === 'https://benefits.corp.local'),
  vulnIdor: canonicalNodeId('Benefits IDOR', n => n.type === 'vulnerability' && n.vuln_type === 'idor'),
  okta: canonicalNodeId('Okta IdP', n => n.type === 'idp' && n.idp_kind === 'okta'),
  benefitsApp: canonicalNodeId('Benefits Portal SSO app', n => n.type === 'idp_application' && n.app_name === 'Benefits Portal'),
  oktaPrincipal: canonicalNodeId('jdoe Okta principal', n => n.type === 'idp_principal' && n.username === 'jdoe@corp.local'),
  gha: canonicalNodeId('GitHub Actions IdP', n => n.type === 'idp' && n.idp_kind === 'ci_github_actions'),
  ghaApp: canonicalNodeId('GitHub Actions deploy app', n => n.type === 'idp_application' && n.app_name === 'benefits-portal deploy'),
  ghaPrincipal: canonicalNodeId('CI release principal', n => n.type === 'idp_principal' && n.label === 'repo:corp/benefits-portal:main'),
  backupRole: canonicalNodeId('AWS BackupRole', n => n.type === 'cloud_identity' && n.arn === 'arn:aws:iam::111122223333:role/BackupRole'),
  deployRole: canonicalNodeId('AWS DeployRole', n => n.type === 'cloud_identity' && n.arn === 'arn:aws:iam::111122223333:role/DeployRole'),
  adminRole: canonicalNodeId('AWS AdminRole', n => n.type === 'cloud_identity' && n.arn === 'arn:aws:iam::111122223333:role/AdminRole'),
  backupPolicy: canonicalNodeId('BackupReadPolicy', n => n.type === 'cloud_policy' && n.policy_name === 'BackupReadPolicy'),
  adminPolicy: canonicalNodeId('AdministratorAccess', n => n.type === 'cloud_policy' && n.policy_name === 'AdministratorAccess'),
  payrollBucket: canonicalNodeId('payroll archive bucket', n => n.type === 'cloud_resource' && n.provider_resource_id === 'corp-payroll-archive'),
  benefitsLambda: canonicalNodeId('benefits export lambda', n => n.type === 'cloud_resource' && n.provider_resource_id === 'benefits-export'),
};

// Canonical cross-finding relationships. Ingest normalizes host/user ids, so
// anything linking separate findings must use the resolved graph ids.
addEdge(ids.jdoe, ids.ws01, { type: 'HAS_SESSION', confidence: 1.0, discovered_at: iso(22), session_live: true, session_id: 'demo-live-ws01' });
addEdge(ids.svc, ids.db01, { type: 'HAS_SESSION', confidence: 0.9, discovered_at: iso(45), session_live: false, session_id: 'demo-closed-db01', session_closed_at: iso(12) });
addEdge(ids.credJdoe, ids.rdpWs01, { type: 'TESTED_CRED', confidence: 0.95, discovered_at: iso(28), confirmed: true });
addEdge(ids.credSvc, ids.mssqlDb01, { type: 'VALID_ON', confidence: 0.95, discovered_at: iso(33), confirmed: true });
addEdge(ids.jdoe, ids.credOkta, { type: 'OWNS_CRED', confidence: 1.0, discovered_at: iso(38), confirmed: true });
addEdge(ids.jdoe, ids.credGha, { type: 'OWNS_CRED', confidence: 0.85, discovered_at: iso(34), inferred: true, notes: 'Demo fixture: CI token recovered from jdoe developer workspace evidence.' });
addEdge(ids.jdoe, ids.domainAdmins, { type: 'MEMBER_OF', confidence: 0.92, discovered_at: iso(31), inferred: true });
addEdge(ids.domainAdmins, ids.dc01, { type: 'ADMIN_TO', confidence: 0.93, discovered_at: iso(31), inferred: true, opsec_noise: 0.45 });
addEdge(ids.web01, ids.webapp, { type: 'HOSTS', confidence: 1.0, discovered_at: iso(42), confirmed: true });
addEdge(ids.ws01, ids.webapp, { type: 'CAN_REACH', confidence: 0.8, discovered_at: iso(32), inferred: true, via_pivot: ids.jdoe });
addEdge(ids.webapp, ids.benefitsLambda, { type: 'BACKED_BY', confidence: 0.86, discovered_at: iso(32), inferred: true });
addEdge(ids.benefitsLambda, ids.backupRole, { type: 'MANAGED_BY', confidence: 0.82, discovered_at: iso(32), inferred: true });
addEdge(ids.okta, ids.domain, { type: 'FEDERATES_WITH', confidence: 0.95, discovered_at: iso(42), confirmed: true });
addEdge(ids.gha, ids.domain, { type: 'FEDERATES_WITH', confidence: 0.75, discovered_at: iso(41), inferred: true });

const state = engine.getState();
const frontierByNode = new Map<string, string>();
for (const item of state.frontier) {
  const node = item.node_id || item.target_node || item.edge_target || item.edge_source;
  if (node && !frontierByNode.has(node)) frontierByNode.set(node, item.id);
}
const fiWs01 = frontierByNode.get(ids.ws01) || state.frontier[0]?.id || 'frontier-demo-ws01';
const fiDb01 = frontierByNode.get(ids.db01) || state.frontier[1]?.id || fiWs01;
const fiCred = frontierByNode.get(ids.credOkta) || frontierByNode.get(ids.benefitsApp) || state.frontier[2]?.id || fiWs01;
const fiCi = frontierByNode.get(ids.credGha) || frontierByNode.get(ids.ghaApp) || state.frontier[3]?.id || fiCred;
const fiWeb = frontierByNode.get(ids.webapp) || state.frontier[4]?.id || fiDb01;
const fiDc = frontierByNode.get(ids.dc01) || state.frontier[5]?.id || fiDb01;

const queue = engine.getPendingActionQueue();
const opsec = (noise: number, signals: string[] = []): OpsecContext => ({
  global_noise_spent: 0.32,
  noise_budget_remaining: Math.max(0, config.opsec.max_noise - noise),
  recommended_approach: noise >= 0.75 ? 'loud' : noise >= 0.35 ? 'normal' : 'quiet',
  defensive_signals: signals,
  warning: signals.length ? 'Defensive signals observed in the last phase.' : undefined,
});

void queue.submit({
  action_id: ACTION_RDP,
  technique: 'rdp_lateral_movement',
  target_node: ids.ws01,
  target_ip: '10.10.10.50',
  description: 'Attach to WS01 with jdoe NTLM and confirm interactive desktop access.',
  opsec_context: opsec(0.82, ['RDP logon event 4624', 'EDR interactive login watchlist']),
  validation_result: 'warning_only',
  frontier_item_id: fiWs01,
  agent_id: 'agent-spray-1',
});
void queue.submit({
  action_id: ACTION_SMB,
  technique: 'smb_share_enumeration',
  target_node: ids.dc01,
  target_ip: '10.10.10.10',
  description: 'Enumerate DC01 administrative shares using svc_backup and collect access evidence.',
  opsec_context: opsec(0.42),
  validation_result: 'valid',
  frontier_item_id: fiDc,
  agent_id: 'agent-smb-1',
});
void queue.submit({
  action_id: ACTION_CRED,
  technique: 'validate_token_credential',
  target_node: ids.benefitsApp,
  description: 'Replay captured Okta session cookie against the Benefits Portal app endpoint.',
  opsec_context: opsec(0.18),
  validation_result: 'valid',
  frontier_item_id: fiCred,
  agent_id: 'agent-token-1',
});
void queue.submit({
  action_id: ACTION_CI,
  technique: 'assume_oidc_role',
  target_node: ids.deployRole,
  description: 'Replay the captured GitHub Actions OIDC token to assume AWS DeployRole, then inspect the AdminRole trust edge.',
  opsec_context: opsec(0.22, ['CloudTrail AssumeRoleWithWebIdentity event']),
  validation_result: 'warning_only',
  frontier_item_id: fiCi,
  agent_id: 'agent-ci-1',
});

// --- campaigns first, so each agent can carry its campaign_id: the campaign
//     BOARD view groups agents into per-campaign swimlanes × status lanes, and
//     the per-campaign OPSEC gauge reads each campaign's own noise. ---
const draftCampaign = engine.createCampaign({
  name: 'Credential validation wave',
  strategy: 'credential_spray',
  item_ids: [fiWs01, fiCred].filter(Boolean),
});
const activeCampaign = engine.createCampaign({
  name: 'Domain control evidence sweep',
  strategy: 'enumeration',
  item_ids: [fiDc, fiDb01].filter(Boolean),
});
engine.activateCampaign(activeCampaign.id);
engine.updateCampaignProgress(activeCampaign.id, activeCampaign.items[0], 'success', 'finding-host-dc01');
const parentCampaign = engine.createCampaign({
  name: 'Post-exploitation cleanup map',
  strategy: 'post_exploitation',
  item_ids: [fiWeb, fiCred].filter(Boolean),
});
const childCampaign = engine.splitCampaign(parentCampaign.id, 1)?.[0];
if (childCampaign) {
  engine.activateCampaign(childCampaign.id);
  for (const item of childCampaign.items) engine.updateCampaignProgress(childCampaign.id, item, 'success', 'finding-host-ws01');
}
const postExCampaignId = childCampaign?.id ?? parentCampaign.id;

// --- agents, each tagged with its campaign so the board groups them into
//     swimlanes. The four below carry distinct frontier_item_ids (one lease
//     each); they land in: Needs-You (pending approval), Completed, and the
//     Ungrouped swimlane (task-ci-1 has no campaign). ---
engine.registerAgent({
  id: 'task-smb-1',
  agent_id: 'agent-smb-1',
  assigned_at: iso(25),
  status: 'running',
  subgraph_node_ids: [ids.dc01, ids.smbDc01, ids.credSvc],
  skill: 'smb_enumeration',
  frontier_item_id: fiDc,
  campaign_id: activeCampaign.id,
});
engine.registerAgent({
  id: 'task-spray-1',
  agent_id: 'agent-spray-1',
  assigned_at: iso(22),
  status: 'running',
  subgraph_node_ids: [ids.ws01, ids.rdpWs01, ids.credJdoe],
  skill: 'credential_spray',
  frontier_item_id: fiWs01,
  campaign_id: draftCampaign.id,
});
engine.registerAgent({
  id: 'task-web-1',
  agent_id: 'web-agent',
  assigned_at: iso(42),
  completed_at: iso(36),
  status: 'completed',
  subgraph_node_ids: [ids.webapp, ids.benefitsApp, ids.backupRole, ids.payrollBucket],
  skill: 'webapp_testing',
  frontier_item_id: fiWeb,
  campaign_id: postExCampaignId,
  result_summary: 'Confirmed IDOR and SSO trust path to cloud backup role.',
});
engine.registerAgent({
  id: 'task-ci-1',
  agent_id: 'agent-ci-1',
  assigned_at: iso(18),
  status: 'running',
  subgraph_node_ids: [ids.credGha, ids.ghaApp, ids.deployRole, ids.adminRole],
  skill: 'cloud_identity',
  frontier_item_id: fiCi,
});

// Extra agents to populate the remaining board lanes. They omit frontier_item_id
// (no lease) so several can share a campaign without lease conflicts — the board
// groups by campaign_id, not frontier item.
engine.registerAgent({
  id: 'task-enum-2', agent_id: 'agent-enum-2', assigned_at: iso(11), status: 'running',
  subgraph_node_ids: [ids.dc01, ids.smbDc01], skill: 'network_enumeration', campaign_id: activeCampaign.id,
}); // → Running lane (no approval, no question)
engine.registerAgent({
  id: 'task-plan-1', agent_id: 'agent-plan-1', assigned_at: iso(3), status: 'pending',
  subgraph_node_ids: [ids.ws01], skill: 'credential_spray', campaign_id: draftCampaign.id,
}); // → Planned lane (not yet started)
engine.registerAgent({
  id: 'task-fail-1', agent_id: 'agent-fail-1', assigned_at: iso(30), completed_at: iso(20), status: 'failed',
  subgraph_node_ids: [ids.credOkta, ids.benefitsApp], skill: 'token_validation', campaign_id: draftCampaign.id,
  result_summary: 'Token replay failed: Okta cookie expired (401).',
}); // → Failed lane

// Three agents that hit the SAME decision point → they cluster into ONE
// "answer once → fan out" card in the Needs-You queue, and sit in the active
// campaign's Blocked lane on the board.
const CLUSTER_Q = 'Noise budget is tight on this segment — spray a small credential list, or stay quiet and pivot?';
const CLUSTER_OPTS = ['spray (noisy)', 'stay quiet'];
['agent-recon-a', 'agent-recon-b', 'agent-recon-c'].forEach((label, i) => {
  const taskId = `task-recon-${i}`;
  engine.registerAgent({
    id: taskId, agent_id: label, assigned_at: iso(9 - i), status: 'running',
    subgraph_node_ids: [ids.dc01], skill: 'network_enumeration', campaign_id: activeCampaign.id,
  });
  engine.getAgentQueryStore().add({ task_id: taskId, agent_id: label, question: CLUSTER_Q, options: CLUSTER_OPTS });
});

// A heartbeating-but-idle agent → "stuck" (distinct from blocked): running, not
// waiting on the operator, but its last attributed action is ~14m old (>
// STUCK_IDLE_MS 8m). current_action_at is derived from the latest non-bookkeeping
// event, so seed one old finding and nothing newer for this agent.
engine.registerAgent({
  id: 'task-stuck-1', agent_id: 'agent-stuck-1', assigned_at: iso(20), status: 'running',
  subgraph_node_ids: [ids.fs01], skill: 'network_enumeration', campaign_id: activeCampaign.id,
});
engine.ingestFinding({
  id: 'f-stuck-1', agent_id: 'agent-stuck-1', timestamp: iso(14),
  target_node_ids: [ids.fs01], nodes: [], edges: [],
  evidence: { type: 'command_output', filename: 'stuck-demo.txt', content: 'enumeration stalled; no new results.' },
});

// --- per-campaign OPSEC noise so each campaign's gauge differs (this campaign's
//     noise contribution vs. the global budget). ---
engine.recordOpsecNoise({ campaign_id: activeCampaign.id, noise_estimate: 0.45 });
engine.recordOpsecNoise({ campaign_id: draftCampaign.id, noise_estimate: 0.12 });
engine.recordOpsecNoise({ campaign_id: postExCampaignId, noise_estimate: 0.28 });

engine.logActionEvent({
  description: 'Selected RDP validation because jdoe has confirmed credential material and WS01 is one hop from domain services.',
  event_type: 'thought',
  category: 'reasoning',
  agent_id: 'agent-spray-1',
  action_id: ACTION_RDP,
  frontier_item_id: fiWs01,
  target_node_ids: [ids.ws01, ids.credJdoe],
  details: {
    kind: 'selection',
    confidence: 0.78,
    considered_alternatives: ['SMB admin share enumeration', 'Password spray against WEB01'],
    related_action_ids: [ACTION_SMB],
    tags: ['demo', 'recording'],
  },
});
engine.logActionEvent({
  description: 'RDP action validated with OPSEC warnings; queued for terminal approval.',
  event_type: 'action_validated',
  category: 'approval',
  agent_id: 'agent-spray-1',
  action_id: ACTION_RDP,
  frontier_item_id: fiWs01,
  target_node_ids: [ids.ws01],
  technique: 'rdp_lateral_movement',
  validation_result: 'warning_only',
  details: {
    approval_status: 'pending',
    warnings: ['Interactive logon is noisy', 'EDR watches new RDP sessions'],
    command: 'overwatch approve a11ca7e0001',
  },
});
engine.logActionEvent({
  description: 'Credential spray: testing jdoe against RDP',
  event_type: 'action_started',
  agent_id: 'agent-spray-1',
  action_id: ACTION_RDP,
  frontier_item_id: fiWs01,
  category: 'frontier',
  target_node_ids: [ids.ws01, ids.rdpWs01, ids.credJdoe],
  command_repr: 'xfreerdp /v:10.10.10.50 /u:jdoe /pth:<redacted>',
  tool_name: 'xfreerdp',
});
engine.logActionEvent({
  description: 'SMB share enumeration started on DC01',
  event_type: 'action_started',
  agent_id: 'agent-smb-1',
  action_id: ACTION_SMB,
  frontier_item_id: fiDc,
  category: 'frontier',
  target_node_ids: [ids.dc01, ids.smbDc01],
  command_repr: 'nxc smb 10.10.10.10 -u svc_backup -p <redacted> --shares',
  tool_name: 'netexec',
});
engine.logActionEvent({
  description: 'SMB share enumeration found SYSVOL and Backup share; backup share requires review before collection.',
  event_type: 'action_completed',
  agent_id: 'agent-smb-1',
  action_id: ACTION_SMB,
  frontier_item_id: fiDc,
  category: 'finding',
  outcome: 'success',
  result_classification: 'success',
  target_node_ids: [ids.dc01, ids.fs01],
  command_repr: 'nxc smb 10.10.10.10 --shares',
  tool_name: 'netexec',
});
engine.logActionEvent({
  description: 'Token replay against Benefits Portal returned 401; cookie likely expired or scoped to browser binding.',
  event_type: 'action_failed',
  agent_id: 'agent-token-1',
  action_id: ACTION_CRED,
  frontier_item_id: fiCred,
  category: 'frontier',
  outcome: 'failure',
  result_classification: 'failure',
  target_node_ids: [ids.credOkta, ids.benefitsApp],
  command_repr: 'curl -H "Cookie: sid=<redacted>" https://benefits.corp.local/api/me',
  tool_name: 'curl',
});
engine.logActionEvent({
  description: 'OIDC replay path selected because GitHub Actions token can mint AWS DeployRole credentials and reach AdminRole.',
  event_type: 'thought',
  category: 'reasoning',
  agent_id: 'agent-ci-1',
  action_id: ACTION_CI,
  frontier_item_id: fiCi,
  target_node_ids: [ids.credGha, ids.deployRole, ids.adminRole],
  details: {
    kind: 'selection',
    confidence: 0.84,
    related_action_ids: [ACTION_CRED],
    tags: ['demo', 'identity', 'cloud'],
  },
});
engine.logActionEvent({
  description: 'OIDC cloud role replay validated with CloudTrail visibility warning; queued for terminal approval.',
  event_type: 'action_validated',
  category: 'approval',
  agent_id: 'agent-ci-1',
  action_id: ACTION_CI,
  frontier_item_id: fiCi,
  target_node_ids: [ids.credGha, ids.deployRole],
  technique: 'assume_oidc_role',
  validation_result: 'warning_only',
  details: {
    approval_status: 'pending',
    warnings: ['AssumeRoleWithWebIdentity creates CloudTrail evidence'],
    command: `overwatch approve ${ACTION_CI}`,
  },
});
engine.logActionEvent({
  description: 'Operator opened mock terminal for WS01; terminal is local-only demo PTY.',
  event_type: 'session_opened',
  category: 'system',
  agent_id: 'operator',
  action_id: ACTION_RDP,
  frontier_item_id: fiWs01,
  target_node_ids: [ids.ws01],
  details: { session_id: 'demo-live-ws01' },
});
engine.logActionEvent({
  description: 'Demo parser caveat: malformed Nmap sample produced no graph data.',
  event_type: 'parse_output',
  category: 'finding',
  agent_id: 'demo-trust',
  action_id: 'trust-demo-parse-empty',
  result_classification: 'failure',
  target_node_ids: [ids.web01],
  details: { parse_status: 'no_data', parsed_nodes: 0, parsed_edges: 0, ingested: false },
});
engine.logActionEvent({
  description: 'Demo ingest caveat: AzureHound skipped records missing object IDs.',
  event_type: 'parse_output',
  category: 'finding',
  agent_id: 'demo-trust',
  action_id: 'trust-demo-dropped-records',
  result_classification: 'partial',
  target_node_ids: [ids.credGha, ids.deployRole],
  details: {
    ingest_summary: [{
      processed_records: 4,
      dropped_records: 2,
      dropped_by_reason: { 'azroleassignments.missing_principal_id': 2 },
    }],
  },
});
engine.logActionEvent({
  description: 'Demo path caveat: path projection failed while fitting a malformed edge.',
  event_type: 'system',
  category: 'system',
  agent_id: 'demo-trust',
  target_node_ids: [ids.credJdoe, ids.dc01],
  details: { analysis_status: 'analysis_failed', from_node: ids.credJdoe, to_node: ids.dc01 },
});
engine.logActionEvent({
  description: 'Demo path caveat: requested endpoint missing from graph.',
  event_type: 'system',
  category: 'system',
  agent_id: 'demo-trust',
  target_node_ids: [ids.adminRole],
  details: { analysis_status: 'missing_endpoint', from_node: ids.deployRole, to_node: 'cloud-identity-missing' },
});
engine.logActionEvent({
  description: 'Demo IAM caveat: role simulation indeterminate after depth cap.',
  event_type: 'action_completed',
  category: 'frontier',
  agent_id: 'demo-trust',
  action_id: 'trust-demo-iam',
  result_classification: 'partial',
  target_node_ids: [ids.deployRole, ids.adminRole],
  details: { decision: 'indeterminate', depth_capped: true },
});
engine.logActionEvent({
  description: 'Demo evidence caveat: command output exceeded inline buffer.',
  event_type: 'action_completed',
  category: 'frontier',
  agent_id: 'demo-trust',
  action_id: 'trust-demo-truncated',
  result_classification: 'partial',
  target_node_ids: [ids.db01],
  details: { stdout_truncated: true, stdout_dropped_bytes: 16384, stdout_total_bytes: 32768 },
});

await sessionManager.create({
  kind: 'local_pty',
  title: 'WS01 jdoe shell',
  host: 'WS01.corp.local',
  user: 'corp\\jdoe',
  agent_id: 'agent-spray-1',
  target_node: ids.ws01,
  principal_node: ids.jdoe,
  credential_node: ids.credJdoe,
  action_id: ACTION_RDP,
  frontier_item_id: fiWs01,
  initial_wait_ms: 100,
  default_validation: {
    technique: 'demo_terminal_command',
    target_node: ids.ws01,
    target_ip: '10.10.10.50',
    allow_unverified_scope: false,
    agent_id: 'operator',
  },
});
const historical = await sessionManager.create({
  kind: 'local_pty',
  title: 'DB01 svc_backup shell',
  host: 'DB01.corp.local',
  user: 'corp\\svc_backup',
  agent_id: 'agent-db-1',
  target_node: ids.db01,
  principal_node: ids.svc,
  credential_node: ids.credSvc,
  action_id: 'a11ca7e0005',
  frontier_item_id: fiDb01,
  initial_wait_ms: 100,
});
sessionManager.close(historical.metadata.id, 'dashboard', true);
sessionManager.update(historical.metadata.id, {
  notes: 'Historical demo session closed after collecting service inventory.',
}, 'dashboard', true);

const telemetry = new ToolTelemetry();
setTelemetry(telemetry);
const tools = ['get_state', 'next_task', 'validate_action', 'report_finding', 'parse_output', 'query_graph', 'log_action_event', 'register_agent', 'send_to_session'];
for (let i = 0; i < 80; i++) {
  const tool = tools[i % tools.length];
  telemetry.record(tool, 20 + (i % 17) * 9, i % 23 === 0);
}
for (let i = 0; i < 20; i++) {
  telemetry.record('get_state', 50, false);
  telemetry.record('next_task', 30, false);
  telemetry.record('validate_action', 20, false);
}

const dashboard = new DashboardServer(engine, DASHBOARD_PORT, undefined, sessionManager);
dashboard.attachTape(new InProcessTapeController(engine));
const toolManifest = JSON.parse(readFileSync(
  new URL('../docs/reference/tool-schema-manifest.json', import.meta.url),
  'utf8',
)) as { tools: ToolDescriptor[] };
dashboard.attachMcpTools(toolManifest.tools);

const result = await dashboard.start();
if (result.started) {
  console.log(`\nDemo dashboard running at http://localhost:${DASHBOARD_PORT}`);
  console.log('   Vite dev server (with HMR) at http://localhost:5173');
  console.log(`   Graph: ${hosts.length} hosts, ${users.length} users, ${creds.length} creds, ${services.length} services`);
  console.log(`   Pending actions: ${queue.getPendingCount()}, sessions: ${sessionManager.list().length}, campaigns: ${engine.listCampaigns().length}, agents: ${engine.getAllAgents().length}`);
  console.log('   Attach to "WS01 jdoe shell" and try: whoami, hostname, ipconfig, dir, net user');
  console.log('\n   New cockpit features to look at:');
  console.log('     • Campaigns → "Board" toggle: agents grouped into per-campaign swimlanes × status lanes');
  console.log('     • Campaigns → pick a campaign: the "Campaign Noise" gauge (per-campaign OPSEC contribution)');
  console.log('     • Agents → "Needs you" queue: 3 recon agents asking the same question cluster into one answer-once card\n');
} else {
  console.error('Failed to start dashboard:', result.error);
  process.exit(1);
}

process.on('SIGINT', async () => {
  console.log('\nShutting down...');
  await dashboard.stop();
  if (existsSync(STATE_FILE)) unlinkSync(STATE_FILE);
  process.exit(0);
});
