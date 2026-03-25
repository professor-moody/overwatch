import { afterEach, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import { GraphEngine } from '../graph-engine.js';
import { runLabPreflight, summarizeInlineLabReadiness } from '../lab-preflight.js';
import { parseBloodHoundFile } from '../bloodhound-ingest.js';
import { parseNmapXml, parseNxc, parseSecretsdump } from '../output-parsers.js';
import type { EngagementConfig } from '../../types.js';
import type { ToolStatus } from '../tool-check.js';

const TEST_STATE_FILE = './state-test-preflight.json';

function cleanup() {
  try {
    if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
  } catch {}
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
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

    const report = runLabPreflight(engine, {
      profile: 'goad_ad',
      toolStatuses: installedTools(['nmap']),
      dashboard: { enabled: true, running: true, address: 'http://localhost:8384' },
    });

    expect(report.status).toBe('blocked');
    expect(report.missing_required_tools).toEqual(expect.arrayContaining(['netexec_or_nxc', 'bloodhound-python']));
  });

  it('returns ready for a healthy GOAD mixed-source scenario when required tools exist', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

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
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

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
    const engine = new GraphEngine(config, TEST_STATE_FILE);

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
    const engine = new GraphEngine(config, TEST_STATE_FILE);

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
    const engine = new GraphEngine(config, TEST_STATE_FILE);

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
    const engine = new GraphEngine(config, TEST_STATE_FILE);

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
    const engine = new GraphEngine(config, TEST_STATE_FILE);

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
    const engine = new GraphEngine(makeConfig({
      scope: { cidrs: [], domains: [], exclusions: [] },
    }), TEST_STATE_FILE);

    const summary = summarizeInlineLabReadiness(engine);

    expect(summary.status).toBe('warning');
    expect(summary.top_issues.some(issue => issue.includes('Graph is empty'))).toBe(true);
  });

  it('inline readiness warns about missing domains only for goad_ad profile', () => {
    const engine = new GraphEngine(makeConfig({
      profile: 'goad_ad' as const,
      scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    }), TEST_STATE_FILE);

    const summary = summarizeInlineLabReadiness(engine);

    expect(summary.status).toBe('warning');
    expect(summary.top_issues.some(issue => issue.includes('No scoped domains'))).toBe(true);
  });

  it('inline readiness does not warn about missing domains for network profile', () => {
    const engine = new GraphEngine(makeConfig({
      profile: 'network' as const,
      scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    }), TEST_STATE_FILE);

    const summary = summarizeInlineLabReadiness(engine);

    expect(summary.top_issues.some(issue => issue.includes('No scoped domains'))).toBe(false);
  });
});
