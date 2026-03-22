import { describe, expect, it, afterEach } from 'vitest';
import { unlinkSync, existsSync } from 'fs';
import { GraphEngine } from '../graph-engine.js';
import { parseBloodHoundFile } from '../bloodhound-ingest.js';
import { parseNmapXml, parseSecretsdump } from '../output-parsers.js';

const TEST_STATE_FILE = './state-test-health.json';

function cleanup() {
  try {
    if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
  } catch {}
}

function makeConfig() {
  return {
    id: 'test-health',
    name: 'Health Test Engagement',
    created_at: '2026-03-21T00:00:00Z',
    scope: {
      cidrs: ['10.10.10.0/28'],
      domains: ['acme.local'],
      exclusions: [],
    },
    objectives: [],
    opsec: {
      name: 'pentest' as const,
      max_noise: 0.7,
    },
  };
}

describe('graph health', () => {
  afterEach(cleanup);

  it('reports duplicate hosts by IP as critical', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding({
      id: 'dup-ip',
      agent_id: 'test-agent',
      timestamp: '2026-03-21T10:00:00Z',
      nodes: [
        { id: 'host-a', type: 'host', label: 'host-a', ip: '10.10.10.10', alive: true },
        { id: 'host-b', type: 'host', label: 'host-b', ip: '10.10.10.10', alive: true },
      ],
      edges: [],
    });

    const report = engine.getHealthReport();
    expect(report.status).toBe('critical');
    expect(report.issues.some(issue => issue.check === 'split_host_identity_ip')).toBe(true);
  });

  it('reports mixed hostname/ip split identities as critical', () => {
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

    const report = engine.getHealthReport();
    expect(report.issues.some(issue => issue.check === 'split_host_identity_hostname')).toBe(true);
  });

  it('reports type constraint violations as critical', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding({
      id: 'bad-edge',
      agent_id: 'test-agent',
      timestamp: '2026-03-21T10:00:00Z',
      nodes: [
        { id: 'svc-a', type: 'service', label: 'svc-a' },
        { id: 'host-a', type: 'host', label: 'host-a', ip: '10.10.10.9', alive: true },
      ],
      edges: [
        { source: 'svc-a', target: 'host-a', properties: { type: 'RUNS', confidence: 1.0, discovered_at: '2026-03-21T10:00:00Z' } },
      ],
    });

    const report = engine.getHealthReport();
    expect(report.issues.some(issue => issue.check === 'edge_type_constraint')).toBe(true);
  });

  it('reports stale relay target inference after SMB signing is corrected', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding({
      id: 'relay-seed',
      agent_id: 'test-agent',
      timestamp: '2026-03-21T10:00:00Z',
      nodes: [
        { id: 'user-attacker', type: 'user', label: 'attacker' },
        { id: 'svc-smb', type: 'service', label: 'SMB', port: 445, service_name: 'smb', smb_signing: false },
      ],
      edges: [
        { source: 'user-attacker', target: 'host-10-10-10-1', properties: { type: 'HAS_SESSION', confidence: 1.0, discovered_at: '2026-03-21T10:00:00Z' } },
        { source: 'host-10-10-10-2', target: 'svc-smb', properties: { type: 'RUNS', confidence: 1.0, discovered_at: '2026-03-21T10:00:00Z' } },
      ],
    });

    engine.ingestFinding({
      id: 'relay-corrected',
      agent_id: 'test-agent',
      timestamp: '2026-03-21T10:05:00Z',
      nodes: [
        { id: 'svc-smb', type: 'service', label: 'SMB', port: 445, service_name: 'smb', smb_signing: true },
      ],
      edges: [],
    });

    const report = engine.getHealthReport();
    expect(report.issues.some(issue => issue.check === 'stale_inferred_edge')).toBe(true);
  });

  it('returns healthy mixed-source fixture when canonical host identity is shared', () => {
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

    const secretsdumpFinding = parseSecretsdump('ACME.LOCAL\\svc_backup:500:aad3b435b51404eeaad3b435b51404ee:11223344556677889900AABBCCDDEEFF:::');

    engine.ingestFinding(bhResult.finding!);
    engine.ingestFinding(nmapFinding);
    engine.ingestFinding(secretsdumpFinding);

    const report = engine.getHealthReport();
    expect(report.counts_by_severity.critical).toBe(0);

    const graph = engine.exportGraph();
    const host = graph.nodes.find(node => node.id === 'host-10-10-10-5');
    expect(host?.properties.first_seen_at).toBeDefined();
    expect(host?.properties.last_seen_at).toBeDefined();
    expect(host?.properties.sources).toEqual(expect.arrayContaining(['bloodhound-ingest', 'nmap-parser']));
  });
});
