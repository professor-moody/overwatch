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
    engine.addNode({ id: 'host-a', type: 'host', label: 'host-a', ip: '10.10.10.10', alive: true, discovered_at: '2026-03-21T10:00:00Z', confidence: 1 });
    engine.addNode({ id: 'host-b', type: 'host', label: 'host-b', ip: '10.10.10.10', alive: true, discovered_at: '2026-03-21T10:00:00Z', confidence: 1 });

    const report = engine.getHealthReport();
    expect(report.status).toBe('critical');
    expect(report.issues.some(issue => issue.check === 'split_host_identity_ip')).toBe(true);
  });

  it('converges mixed hostname/ip host identities into one canonical host', () => {
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
    expect(report.issues.some(issue => issue.check === 'split_host_identity_hostname')).toBe(false);
    expect(report.issues.some(issue => issue.check === 'identity_marker_collision')).toBe(false);
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
    const issue = report.issues.find(candidate => candidate.check === 'edge_type_constraint');
    expect(issue).toBeDefined();
    expect(issue?.details?.violations).toBeDefined();
  });

  it('suggests replacing RUNS->share with RELATED in machine-readable health details', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding({
      id: 'bad-share-edge',
      agent_id: 'test-agent',
      timestamp: '2026-03-21T10:00:00Z',
      nodes: [{ id: 'share-public', type: 'share', label: 'public' }],
      edges: [
        { source: 'host-10-10-10-1', target: 'share-public', properties: { type: 'RUNS', confidence: 1.0, discovered_at: '2026-03-21T10:00:00Z' } },
      ],
    });

    const issue = engine.getHealthReport().issues.find(candidate => candidate.check === 'edge_type_constraint');
    expect(issue?.details?.suggested_fix).toEqual(expect.objectContaining({ kind: 'replace_edge_type', edge_type: 'RELATED' }));
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

  it('escalates unresolved PKI identities as identity issues', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.addNode({
      id: 'bh-ca-ca-object-1',
      type: 'ca',
      label: 'Unknown CA',
      bh_sid: 'CA-OBJECT-1',
      identity_status: 'unresolved',
      discovered_at: '2026-03-21T10:00:00Z',
      confidence: 0.5,
    });

    const issue = engine.getHealthReport().issues.find(candidate => candidate.check === 'unresolved_identity');
    expect(issue).toBeDefined();
    expect(issue?.severity).toBe('critical');
  });

  it('reports identity marker collisions across canonical nodes', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.addNode({
      id: 'user-test-local-jsmith',
      type: 'user',
      label: 'JSMITH@TEST.LOCAL',
      username: 'jsmith',
      domain_name: 'test.local',
      identity_markers: ['user:acct:test-local:jsmith'],
      identity_status: 'canonical',
      discovered_at: '2026-03-21T10:00:00Z',
      confidence: 1,
    });
    engine.addNode({
      id: 'user-alt-jsmith',
      type: 'user',
      label: 'JSMITH@TEST.LOCAL',
      username: 'jsmith',
      domain_name: 'test.local',
      identity_markers: ['user:acct:test-local:jsmith'],
      identity_status: 'canonical',
      discovered_at: '2026-03-21T10:00:00Z',
      confidence: 1,
    });

    const issue = engine.getHealthReport().issues.find(candidate => candidate.check === 'identity_marker_collision');
    expect(issue).toBeDefined();
    expect(issue?.severity).toBe('critical');
  });

  it('treats duplicate credential account identity as warning, not critical', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.addNode({
      id: 'cred-a',
      type: 'credential',
      label: 'jorah hash',
      cred_type: 'ntlm',
      cred_material_kind: 'ntlm_hash',
      cred_hash: '186f0c43150b42deadbeef0011223344',
      cred_user: 'jorah.mormont',
      cred_domain: 'essos.local',
      discovered_at: '2026-03-21T10:00:00Z',
      confidence: 1,
    });
    engine.addNode({
      id: 'cred-b',
      type: 'credential',
      label: 'jorah duplicate',
      cred_type: 'ntlm',
      cred_material_kind: 'ntlm_hash',
      cred_hash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      cred_user: 'jorah.mormont',
      cred_domain: 'essos.local',
      discovered_at: '2026-03-21T10:00:00Z',
      confidence: 1,
    });

    const issue = engine.getHealthReport().issues.find(candidate => candidate.check === 'identity_marker_collision');
    expect(issue).toBeDefined();
    expect(issue?.severity).toBe('warning');
  });

  it('warns on shared credential material across different accounts without reporting identity collision', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.addNode({
      id: 'cred-viserys',
      type: 'credential',
      label: 'viserys hash',
      cred_type: 'ntlm',
      cred_material_kind: 'ntlm_hash',
      cred_hash: '846f08aaaaaaaaaaaaaaaaaaaaaaaaaa',
      cred_user: 'viserys.targaryen',
      cred_domain: 'essos.local',
      discovered_at: '2026-03-21T10:00:00Z',
      confidence: 1,
    });
    engine.addNode({
      id: 'cred-khal',
      type: 'credential',
      label: 'khal hash',
      cred_type: 'ntlm',
      cred_material_kind: 'ntlm_hash',
      cred_hash: '846f08aaaaaaaaaaaaaaaaaaaaaaaaaa',
      cred_user: 'khal.drogo',
      cred_domain: 'essos.local',
      discovered_at: '2026-03-21T10:00:00Z',
      confidence: 1,
    });

    const report = engine.getHealthReport();
    expect(report.issues.some(issue => issue.check === 'identity_marker_collision')).toBe(false);
    const issue = report.issues.find(candidate => candidate.check === 'shared_credential_material');
    expect(issue).toBeDefined();
    expect(issue?.severity).toBe('warning');
  });

  it('warns when a credential account is missing domain qualification', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding({
      id: 'ambiguous-cred',
      agent_id: 'test-agent',
      timestamp: '2026-03-21T10:00:00Z',
      nodes: [{
        id: 'cred-admin-ambiguous',
        type: 'credential',
        label: 'administrator hash',
        cred_type: 'ntlm',
        cred_material_kind: 'ntlm_hash',
        cred_hash: '11223344556677889900aabbccddeeff',
        cred_user: 'administrator',
      }],
      edges: [],
    });

    const issue = engine.getHealthReport().issues.find(candidate => candidate.check === 'credential_identity_ambiguity');
    expect(issue).toBeDefined();
    expect(issue?.severity).toBe('warning');
  });

  it('does not report identity collisions for same-hash credentials when domain context is missing', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding({
      id: 'ambiguous-admins',
      agent_id: 'test-agent',
      timestamp: '2026-03-21T10:00:00Z',
      nodes: [
        {
          id: 'cred-admin-a',
          type: 'credential',
          label: 'administrator hash a',
          cred_type: 'ntlm',
          cred_material_kind: 'ntlm_hash',
          cred_hash: '31d6cfe0d16ae931b73c59d7e0c089c0',
          cred_user: 'administrator',
        },
        {
          id: 'cred-admin-b',
          type: 'credential',
          label: 'administrator hash b',
          cred_type: 'ntlm',
          cred_material_kind: 'ntlm_hash',
          cred_hash: '31d6cfe0d16ae931b73c59d7e0c089c0',
          cred_user: 'krbtgt',
        },
      ],
      edges: [],
    });

    const report = engine.getHealthReport();
    expect(report.issues.some(issue => issue.check === 'identity_marker_collision')).toBe(false);
    expect(report.issues.some(issue => issue.check === 'shared_credential_material')).toBe(true);
    expect(report.status).not.toBe('critical');
  });
});
