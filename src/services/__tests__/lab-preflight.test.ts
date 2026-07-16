import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { GraphEngine } from '../graph-engine.js';
import { runLabPreflight, summarizeInlineLabReadiness } from '../lab-preflight.js';
import { parseBloodHoundFile } from '../bloodhound-ingest.js';
import { parseNmapXml, parseNxc, parseSecretsdump } from '../parsers/index.js';
import type { EngagementConfig } from '../../types.js';
import type { ToolStatus } from '../tool-check.js';

const testEngines: GraphEngine[] = [];
const testDirs: string[] = [];

function cleanup() {
  for (const engine of testEngines.splice(0)) {
    try { engine.dispose(); } catch {}
  }
  for (const dir of testDirs.splice(0)) {
    try { rmSync(dir, { recursive: true, force: true }); } catch {}
  }
}

function makeConfig(overrides: Partial<EngagementConfig> = {}): EngagementConfig {
  return {
    id: 'test-preflight',
    name: 'Lab Preflight Test',
    created_at: '2026-03-21T00:00:00Z',
    scope: {
      cidrs: ['10.10.10.0/28'],
      domains: ['acme.local'],
      exclusions: [],
    },
    objectives: [],
    opsec: {
      name: 'pentest',
      max_noise: 0.7,
    },
    ...overrides,
  };
}

function createTestEngine(config: EngagementConfig): GraphEngine {
  const dir = mkdtempSync(join(tmpdir(), 'overwatch-preflight-'));
  testDirs.push(dir);
  const engine = new GraphEngine(config, join(dir, 'state.json'));
  testEngines.push(engine);
  return engine;
}

function installedTools(names: string[]): ToolStatus[] {
  const installed = new Set(names);
  const known = [
    'nmap',
    'netexec',
    'bloodhound-python',
    'impacket-secretsdump',
    'hashcat',
    'john',
  ];

  return known.map(name => ({
    name,
    installed: installed.has(name),
    path: installed.has(name) ? `/usr/bin/${name}` : undefined,
    version: installed.has(name) ? 'test-version' : undefined,
  }));
}

describe('lab preflight', () => {
  afterEach(cleanup);

  it('returns blocked for GOAD profile when required tools are missing', () => {
    const engine = createTestEngine(makeConfig());

    const report = runLabPreflight(engine, {
      profile: 'goad_ad',
      toolStatuses: installedTools(['nmap']),
      dashboard: { enabled: true, running: true, address: 'http://localhost:8384' },
    });

    expect(report.status).toBe('blocked');
    expect(report.missing_required_tools).toEqual(expect.arrayContaining(['netexec_or_nxc', 'bloodhound-python']));
  });

  it('returns ready for a healthy GOAD mixed-source scenario when required tools exist', () => {
    const engine = createTestEngine(makeConfig());

    const bhResult = parseBloodHoundFile(JSON.stringify({
      data: [{
        ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1001',
        Properties: {
          name: 'DC01.ACME.LOCAL',
          ip: '10.10.10.5',
          operatingsystem: 'Windows Server 2022',
          domain: 'acme.local',
        },
        Status: { Connectable: true },
        Aces: [],
        LocalAdmins: [],
        RemoteDesktopUsers: [],
        PSRemoteUsers: [],
        DcomUsers: [],
        AllowedToDelegate: [],
        AllowedToAct: [],
      }],
      meta: { type: 'computers', count: 1, version: 5 },
    }), 'computers.json');

    const nmapFinding = parseNmapXml(`<?xml version="1.0"?>
      <nmaprun>
        <host>
          <status state="up"/>
          <address addr="10.10.10.5" addrtype="ipv4"/>
          <hostnames><hostname name="DC01.ACME.LOCAL"/></hostnames>
          <ports>
            <port protocol="tcp" portid="445">
              <state state="open"/>
              <service name="microsoft-ds"/>
            </port>
          </ports>
        </host>
      </nmaprun>`);

    const nxcFinding = parseNxc('SMB  10.10.10.5  445  ACME\\scanner  [+]  Windows Server 2022');
    const secretsdumpFinding = parseSecretsdump('ACME.LOCAL\\svc_backup:500:aad3b435b51404eeaad3b435b51404ee:11223344556677889900AABBCCDDEEFF:::');

    engine.ingestFinding(bhResult.finding!);
    engine.ingestFinding(nmapFinding);
    engine.ingestFinding(nxcFinding);
    engine.ingestFinding(secretsdumpFinding);

    const report = runLabPreflight(engine, {
      profile: 'goad_ad',
      toolStatuses: installedTools(['nmap', 'netexec', 'bloodhound-python', 'impacket-secretsdump']),
      dashboard: { enabled: true, running: true, address: 'http://localhost:8384' },
    });

    expect(report.status).toBe('ready');
    expect(report.graph_stage).toBe('mid_run');
    expect(report.checks.find(check => check.name === 'graph_health')?.status).toBe('pass');
  });

  it('auto-resolves GOAD-style BH+nmap split hosts via FQDN short-name matching', () => {
    const engine = createTestEngine(makeConfig());

    const bhResult = parseBloodHoundFile(JSON.stringify({
      data: [{
        ObjectIdentifier: 'S-1-5-21-1234-5678-9012-1001',
        Properties: {
          name: 'DC01.ACME.LOCAL',
          operatingsystem: 'Windows Server 2022',
          domain: 'acme.local',
        },
        Status: { Connectable: true },
        Aces: [],
        LocalAdmins: [],
        RemoteDesktopUsers: [],
        PSRemoteUsers: [],
        DcomUsers: [],
        AllowedToDelegate: [],
        AllowedToAct: [],
      }],
      meta: { type: 'computers', count: 1, version: 5 },
    }), 'computers.json');

    const nmapFinding = parseNmapXml(`<?xml version="1.0"?>
      <nmaprun>
        <host>
          <status state="up"/>
          <address addr="10.10.10.5" addrtype="ipv4"/>
          <hostnames><hostname name="DC01.ACME.LOCAL"/></hostnames>
          <ports>
            <port protocol="tcp" portid="445">
              <state state="open"/>
              <service name="microsoft-ds"/>
            </port>
          </ports>
        </host>
      </nmaprun>`);

    engine.ingestFinding(bhResult.finding!);
    engine.ingestFinding(nmapFinding);

    // BH hostname-only host should be auto-merged into the nmap IP-based host
    const graph = engine.exportGraph();
    const hosts = graph.nodes.filter(n => n.properties.type === 'host' && n.properties.hostname);
    const dc01Nodes = hosts.filter(n =>
      typeof n.properties.hostname === 'string' && n.properties.hostname.toLowerCase().includes('dc01'));
    expect(dc01Nodes.length).toBe(1);
    expect(dc01Nodes[0].properties.ip).toBe('10.10.10.5');

    const report = runLabPreflight(engine, {
      profile: 'goad_ad',
      toolStatuses: installedTools(['nmap', 'netexec', 'bloodhound-python']),
      dashboard: { enabled: true, running: true, address: 'http://localhost:8384' },
    });

    // No critical split identity issues — status should not be blocked
    expect(report.status).not.toBe('blocked');
    expect(report.checks.find(check => check.name === 'graph_health')?.status).not.toBe('fail');
  });

  it('network profile passes with CIDR scope and nmap only', () => {
    const config = makeConfig({
      profile: 'network' as const,
      scope: { cidrs: ['10.10.110.0/24'], domains: [], exclusions: ['10.10.110.2'] },
    });
    const engine = createTestEngine(config);

    const nmapFinding = parseNmapXml(`<?xml version="1.0"?>
      <nmaprun>
        <host>
          <status state="up"/>
          <address addr="10.10.110.5" addrtype="ipv4"/>
          <ports>
            <port protocol="tcp" portid="445">
              <state state="open"/>
              <service name="microsoft-ds"/>
            </port>
          </ports>
        </host>
      </nmaprun>`);
    engine.ingestFinding(nmapFinding);

    const report = runLabPreflight(engine, {
      profile: 'network',
      toolStatuses: installedTools(['nmap']),
      dashboard: { enabled: false, running: false },
    });

    expect(report.status).toBe('warning'); // warning from dashboard/cred tools, not blocked
    expect(report.profile).toBe('network');
    expect(report.missing_required_tools).toEqual([]);
    expect(report.graph_stage).toBe('mid_run');
    expect(report.checks.find(c => c.name === 'scope_shape')?.status).toBe('pass');
  });

  it('infers single_host profile when no profile set and no domains', () => {
    const config = makeConfig({
      scope: { cidrs: ['10.10.110.0/24'], domains: [], exclusions: [] },
    });
    const engine = createTestEngine(config);

    const report = runLabPreflight(engine, {
      toolStatuses: installedTools(['nmap']),
      dashboard: { enabled: false, running: false },
    });

    expect(report.profile).toBe('single_host');
  });

  it('uses explicit network profile when set in config', () => {
    const config = makeConfig({
      profile: 'network' as const,
      scope: { cidrs: ['10.10.110.0/24'], domains: [], exclusions: [] },
    });
    const engine = createTestEngine(config);

    const report = runLabPreflight(engine, {
      toolStatuses: installedTools(['nmap']),
      dashboard: { enabled: false, running: false },
    });

    expect(report.profile).toBe('network');
  });

  it('network profile recommends Nmap sweep for empty graph', () => {
    const config = makeConfig({
      profile: 'network' as const,
      scope: { cidrs: ['10.10.110.0/24'], domains: [], exclusions: [] },
    });
    const engine = createTestEngine(config);

    const report = runLabPreflight(engine, {
      profile: 'network',
      toolStatuses: installedTools(['nmap']),
      dashboard: { enabled: false, running: false },
    });

    expect(report.recommended_next_steps.some(s => s.includes('Nmap sweep'))).toBe(true);
  });

  it('allows single-host profile without BloodHound tooling', () => {
    const config = makeConfig({
      scope: {
        cidrs: ['10.10.10.0/30'],
        domains: [],
        exclusions: [],
      },
    });
    const engine = createTestEngine(config);

    const nmapFinding = parseNmapXml(`<?xml version="1.0"?>
      <nmaprun>
        <host>
          <status state="up"/>
          <address addr="10.10.10.2" addrtype="ipv4"/>
          <ports>
            <port protocol="tcp" portid="80">
              <state state="open"/>
              <service name="http"/>
            </port>
          </ports>
        </host>
      </nmaprun>`);

    engine.ingestFinding(nmapFinding);

    const report = runLabPreflight(engine, {
      profile: 'single_host',
      toolStatuses: installedTools(['nmap']),
      dashboard: { enabled: false, running: false },
    });

    expect(report.status).toBe('warning');
    expect(report.missing_required_tools).toEqual([]);
    expect(report.graph_stage).toBe('mid_run');
  });

  it('summarizes inline readiness for get_state', () => {
    const engine = createTestEngine(makeConfig({
      scope: { cidrs: [], domains: [], exclusions: [] },
    }));

    const summary = summarizeInlineLabReadiness(engine);

    expect(summary.status).toBe('warning');
    expect(summary.top_issues.some(issue => issue.includes('Graph is empty'))).toBe(true);
  });

  it('inline readiness warns about missing domains only for goad_ad profile', () => {
    const engine = createTestEngine(makeConfig({
      profile: 'goad_ad' as const,
      scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    }));

    const summary = summarizeInlineLabReadiness(engine);

    expect(summary.status).toBe('warning');
    expect(summary.top_issues.some(issue => issue.includes('No scoped domains'))).toBe(true);
  });

  it('inline readiness does not warn about missing domains for network profile', () => {
    const engine = createTestEngine(makeConfig({
      profile: 'network' as const,
      scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    }));

    const summary = summarizeInlineLabReadiness(engine);

    expect(summary.top_issues.some(issue => issue.includes('No scoped domains'))).toBe(false);
  });

  it('includes incomplete recovery details in the existing persistence check', () => {
    const engine = createTestEngine(makeConfig({
      profile: 'single_host' as const,
    }));
    const incompleteRecovery = {
        outcome: 'incomplete',
        source: 'state',
        complete: false,
        writable: false,
        reason: 'sequence gap',
        base_checkpoint: 2,
        highest_allocated_seq: 6,
        highest_allocated_logical_seq: 6,
        highest_allocated_frame_seq: 18,
        highest_on_disk_seq: 6,
        highest_physical_frame_seq: 18,
        highest_contiguous_applied_seq: 4,
        highest_contiguous_applied_logical_seq: 4,
        consecutive_persistence_failures: 0,
        journal: {
          enabled: true,
          read: 4,
          attempted: 2,
          applied: 2,
          skipped: 0,
          failed: 0,
          malformed: false,
          preserved: true,
        },
      } as const;
    Object.assign(engine, {
      getPersistenceRecoveryStatus: vi.fn(() => incompleteRecovery),
      getStatePersistenceRecoveryStatus: vi.fn(() => incompleteRecovery),
    });

    const report = runLabPreflight(engine, {
      profile: 'single_host',
      toolStatuses: installedTools(['nmap']),
      dashboard: { enabled: false, running: false },
    });
    const inline = summarizeInlineLabReadiness(engine);
    const persistence = report.checks.find(check => check.name === 'persistence');

    expect(persistence?.status).toBe('fail');
    expect(persistence?.message).toContain('sequence gap');
    expect(persistence?.details?.recovery).toMatchObject({
      outcome: 'incomplete',
      writable: false,
      highest_contiguous_applied_seq: 4,
      highest_contiguous_applied_logical_seq: 4,
      highest_on_disk_seq: 6,
      highest_physical_frame_seq: 18,
    });
    expect(inline.status).toBe('blocked');
    expect(inline.top_issues[0]).toContain('sequence gap');
  });

  it('reports configuration consistency as a distinct readiness check', () => {
    const engine = createTestEngine(makeConfig({ profile: 'single_host' as const }));

    const report = runLabPreflight(engine, {
      profile: 'single_host',
      toolStatuses: installedTools(['nmap']),
      dashboard: { enabled: false, running: false },
    });

    expect(report.checks.find(check => check.name === 'config_consistency')).toMatchObject({
      status: 'pass',
      message: expect.stringContaining('fileless'),
    });
  });

  it('blocks inline and full readiness when configuration reconciliation is required', () => {
    const engine = createTestEngine(makeConfig({ profile: 'single_host' as const }));
    const configRecovery = {
      status: 'diverged' as const,
      resolution_required: true,
      intent_present: false,
      file_valid: true,
      file_revision: 2,
      state_revision: 3,
      file_hash: 'a'.repeat(64),
      state_hash: 'b'.repeat(64),
      reason: 'file and state differ',
    };
    const persistence = engine.getPersistenceRecoveryStatus();
    Object.assign(engine, {
      getConfigRecoveryStatus: vi.fn(() => configRecovery),
      getPersistenceRecoveryStatus: vi.fn(() => ({
        ...persistence,
        outcome: 'incomplete' as const,
        complete: false,
        writable: false,
        reason: configRecovery.reason,
        config_recovery: configRecovery,
      })),
    });

    const report = runLabPreflight(engine, {
      profile: 'single_host',
      toolStatuses: installedTools(['nmap']),
      dashboard: { enabled: false, running: false },
    });
    const inline = summarizeInlineLabReadiness(engine);
    const check = report.checks.find(item => item.name === 'config_consistency');

    expect(check).toMatchObject({ status: 'fail' });
    expect(check?.message).toContain('file and state differ');
    expect(check?.details).not.toHaveProperty('config');
    expect(inline.status).toBe('blocked');
    expect(inline.top_issues[0]).toContain('explicit reconciliation');
  });

  it('warns when an interrupted configuration write recovered on startup', () => {
    const engine = createTestEngine(makeConfig({ profile: 'single_host' as const }));
    Object.assign(engine, {
      getConfigRecoveryStatus: vi.fn(() => ({
        status: 'recovered' as const,
        resolution_required: false,
        intent_present: false,
        file_valid: true,
        file_revision: 4,
        state_revision: 4,
        file_hash: 'c'.repeat(64),
        state_hash: 'c'.repeat(64),
      })),
    });

    const report = runLabPreflight(engine, {
      profile: 'single_host',
      toolStatuses: installedTools(['nmap']),
      dashboard: { enabled: false, running: false },
    });

    expect(report.checks.find(check => check.name === 'config_consistency')).toMatchObject({
      status: 'warning',
      message: expect.stringContaining('recovered'),
    });
  });

  it('web_app profile passes scope check with url_patterns and checks for web tools', () => {
    const config = makeConfig({
      profile: 'web_app' as const,
      scope: { cidrs: [], domains: [], exclusions: [], url_patterns: ['*.example.com', 'app.corp.io/api/*'] },
    });
    const engine = createTestEngine(config);

    const webTools: ToolStatus[] = [
      { name: 'nuclei', installed: true, version: '3.0.0', path: '/usr/bin/nuclei' },
      { name: 'nikto', installed: false },
      { name: 'gobuster', installed: true, version: '3.6.0', path: '/usr/bin/gobuster' },
      { name: 'feroxbuster', installed: false },
      { name: 'ffuf', installed: false },
      { name: 'nmap', installed: true, version: '7.94', path: '/usr/bin/nmap' },
    ];

    const report = runLabPreflight(engine, {
      profile: 'web_app',
      toolStatuses: webTools,
      dashboard: { enabled: false, running: false },
    });

    expect(report.profile).toBe('web_app');
    const scopeCheck = report.checks.find(c => c.name === 'scope_shape');
    expect(scopeCheck?.status).toBe('pass');
    expect(scopeCheck?.message).toContain('URL scope');
    const scannerCheck = report.checks.find(c => c.name === 'tool_web_scanner');
    expect(scannerCheck?.status).toBe('pass');
    const dirCheck = report.checks.find(c => c.name === 'tool_dir_enum');
    expect(dirCheck?.status).toBe('pass');
  });

  it('cloud profile passes scope check with aws_accounts and checks for cloud tools', () => {
    const config = makeConfig({
      profile: 'cloud' as const,
      scope: { cidrs: [], domains: [], exclusions: [], aws_accounts: ['123456789012'] },
    });
    const engine = createTestEngine(config);

    const cloudTools: ToolStatus[] = [
      { name: 'pacu', installed: true, version: '1.0.0', path: '/usr/bin/pacu' },
      { name: 'prowler', installed: false },
      { name: 'nmap', installed: true, version: '7.94', path: '/usr/bin/nmap' },
    ];

    const report = runLabPreflight(engine, {
      profile: 'cloud',
      toolStatuses: cloudTools,
      dashboard: { enabled: false, running: false },
    });

    expect(report.profile).toBe('cloud');
    const scopeCheck = report.checks.find(c => c.name === 'scope_shape');
    expect(scopeCheck?.status).toBe('pass');
    expect(scopeCheck?.message).toContain('Cloud account scope');
    const auditCheck = report.checks.find(c => c.name === 'tool_cloud_audit');
    expect(auditCheck?.status).toBe('pass');
  });
});
