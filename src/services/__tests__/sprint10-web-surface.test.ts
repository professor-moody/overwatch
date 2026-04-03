import { describe, it, expect, afterEach } from 'vitest';
import { GraphEngine } from '../graph-engine.js';
import { parseNuclei, parseNikto, parseTestssl, parseOutput } from '../parsers/index.js';
import { webappId, vulnerabilityId } from '../parser-utils.js';
import { validateEdgeEndpoints } from '../graph-schema.js';
import type { EngagementConfig, Finding } from '../../types.js';
import { NODE_TYPES, EDGE_TYPES } from '../../types.js';
import { unlinkSync, existsSync } from 'fs';

const TEST_STATE_FILE = './state-test-sprint10.json';

function makeConfig(overrides: Partial<EngagementConfig> = {}): EngagementConfig {
  return {
    id: 'test-s10',
    name: 'Sprint 10 Test',
    created_at: '2026-03-27T00:00:00Z',
    scope: {
      cidrs: ['10.10.10.0/24'],
      domains: ['test.local'],
      exclusions: [],
    },
    objectives: [{
      id: 'obj-1',
      description: 'Get DA',
      target_node_type: 'user',
      target_criteria: { privileged: true },
      achieved: false,
    }],
    opsec: { name: 'pentest', max_noise: 0.7 },
    ...overrides,
  };
}

function cleanup() {
  if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
}

const now = new Date().toISOString();

function makeFinding(nodes: Finding['nodes'], edges: Finding['edges'] = []): Finding {
  return { id: `f-${Date.now()}`, agent_id: 'test', timestamp: now, nodes, edges };
}

// ============================================================
// 10.1: Node Types
// ============================================================
describe('10.1 — Node types: webapp and vulnerability', () => {
  it('NODE_TYPES includes webapp and vulnerability', () => {
    expect(NODE_TYPES).toContain('webapp');
    expect(NODE_TYPES).toContain('vulnerability');
  });

  afterEach(cleanup);

  it('webapp node can be ingested with all typed properties', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'webapp-test', type: 'webapp', label: 'http://10.10.10.5:8080',
      discovered_at: now, confidence: 1.0,
      url: 'http://10.10.10.5:8080',
      technology: 'Apache Tomcat',
      framework: 'Java',
      auth_type: 'form',
      has_api: true,
      cms_type: 'tomcat',
      has_login_form: true,
    }]));
    const node = engine.getNode('webapp-test');
    expect(node).toBeDefined();
    expect(node!.type).toBe('webapp');
    expect(node!.url).toBe('http://10.10.10.5:8080');
    expect(node!.technology).toBe('Apache Tomcat');
    expect(node!.cms_type).toBe('tomcat');
    expect(node!.has_login_form).toBe(true);
  });

  it('vulnerability node can be ingested with all typed properties', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'vuln-test', type: 'vulnerability', label: 'CVE-2021-44228',
      discovered_at: now, confidence: 1.0,
      cve: 'CVE-2021-44228',
      cvss: 10.0,
      vuln_type: 'rce',
      exploitable: true,
      exploit_available: true,
      affected_component: 'Log4j',
    }]));
    const node = engine.getNode('vuln-test');
    expect(node).toBeDefined();
    expect(node!.type).toBe('vulnerability');
    expect(node!.cve).toBe('CVE-2021-44228');
    expect(node!.cvss).toBe(10.0);
    expect(node!.vuln_type).toBe('rce');
    expect(node!.exploitable).toBe(true);
  });

  it('service node accepts TLS enrichment properties', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'svc-tls-test', type: 'service', label: 'https/443',
      discovered_at: now, confidence: 1.0,
      port: 443, protocol: 'tcp', service_name: 'https',
      tls_version: 'TLSv1.2',
      cipher_suites: ['TLS_AES_256_GCM_SHA384'],
      cert_subject: 'CN=example.com',
      cert_expiry: '2027-01-01',
      cert_issuer: "Let's Encrypt",
    }]));
    const node = engine.getNode('svc-tls-test');
    expect(node).toBeDefined();
    expect(node!.tls_version).toBe('TLSv1.2');
    expect(node!.cipher_suites).toEqual(['TLS_AES_256_GCM_SHA384']);
    expect(node!.cert_subject).toBe('CN=example.com');
  });
});

// ============================================================
// 10.2: Edge Types + Constraints
// ============================================================
describe('10.2 — Edge types and constraints', () => {
  it('EDGE_TYPES includes all 4 new web edge types', () => {
    expect(EDGE_TYPES).toContain('HOSTS');
    expect(EDGE_TYPES).toContain('AUTHENTICATED_AS');
    expect(EDGE_TYPES).toContain('VULNERABLE_TO');
    expect(EDGE_TYPES).toContain('EXPLOITS');
  });

  it('HOSTS: service → webapp is valid', () => {
    const result = validateEdgeEndpoints('HOSTS', 'service', 'webapp', { source_id: 's', target_id: 't' });
    expect(result.valid).toBe(true);
  });

  it('HOSTS: host → webapp is invalid', () => {
    const result = validateEdgeEndpoints('HOSTS', 'host', 'webapp', { source_id: 's', target_id: 't' });
    expect(result.valid).toBe(false);
  });

  it('AUTHENTICATED_AS: credential → webapp is valid', () => {
    const result = validateEdgeEndpoints('AUTHENTICATED_AS', 'credential', 'webapp', { source_id: 's', target_id: 't' });
    expect(result.valid).toBe(true);
  });

  it('VULNERABLE_TO: webapp → vulnerability is valid', () => {
    const result = validateEdgeEndpoints('VULNERABLE_TO', 'webapp', 'vulnerability', { source_id: 's', target_id: 't' });
    expect(result.valid).toBe(true);
  });

  it('VULNERABLE_TO: service → vulnerability is valid', () => {
    const result = validateEdgeEndpoints('VULNERABLE_TO', 'service', 'vulnerability', { source_id: 's', target_id: 't' });
    expect(result.valid).toBe(true);
  });

  it('VULNERABLE_TO: host → vulnerability is invalid', () => {
    const result = validateEdgeEndpoints('VULNERABLE_TO', 'host', 'vulnerability', { source_id: 's', target_id: 't' });
    expect(result.valid).toBe(false);
  });

  it('EXPLOITS: vulnerability → host is valid', () => {
    const result = validateEdgeEndpoints('EXPLOITS', 'vulnerability', 'host', { source_id: 's', target_id: 't' });
    expect(result.valid).toBe(true);
  });

  it('EXPLOITS: vulnerability → credential is valid', () => {
    const result = validateEdgeEndpoints('EXPLOITS', 'vulnerability', 'credential', { source_id: 's', target_id: 't' });
    expect(result.valid).toBe(true);
  });

  it('EXPLOITS: vulnerability → webapp is valid', () => {
    const result = validateEdgeEndpoints('EXPLOITS', 'vulnerability', 'webapp', { source_id: 's', target_id: 't' });
    expect(result.valid).toBe(true);
  });

  it('POTENTIAL_AUTH now accepts webapp as target', () => {
    const result = validateEdgeEndpoints('POTENTIAL_AUTH', 'credential', 'webapp', { source_id: 's', target_id: 't' });
    expect(result.valid).toBe(true);
  });
});

// ============================================================
// Deterministic ID Helpers
// ============================================================
describe('Deterministic ID helpers', () => {
  it('webappId produces stable IDs from URLs', () => {
    expect(webappId('http://10.10.10.5:8080/app')).toBe(webappId('http://10.10.10.5:8080/app'));
    expect(webappId('http://10.10.10.5:8080/app/')).toBe(webappId('http://10.10.10.5:8080/app'));
  });

  it('webappId strips default ports', () => {
    expect(webappId('http://example.com:80/app')).toBe(webappId('http://example.com/app'));
    expect(webappId('https://example.com:443/app')).toBe(webappId('https://example.com/app'));
  });

  it('webappId preserves non-default ports', () => {
    const id8080 = webappId('http://10.10.10.5:8080');
    const id80 = webappId('http://10.10.10.5');
    expect(id8080).not.toBe(id80);
  });

  it('webappId is case insensitive', () => {
    expect(webappId('HTTP://Example.Com/App')).toBe(webappId('http://example.com/App'));
  });

  it('vulnerabilityId produces stable IDs', () => {
    const id1 = vulnerabilityId('CVE-2021-44228', 'webapp-test');
    const id2 = vulnerabilityId('CVE-2021-44228', 'webapp-test');
    expect(id1).toBe(id2);
    expect(id1).toMatch(/^vuln-/);
  });

  it('vulnerabilityId differentiates by target', () => {
    const id1 = vulnerabilityId('CVE-2021-44228', 'webapp-a');
    const id2 = vulnerabilityId('CVE-2021-44228', 'webapp-b');
    expect(id1).not.toBe(id2);
  });
});

// ============================================================
// 10.3: Inference Rules
// ============================================================
describe('10.3 — Web inference rules', () => {
  afterEach(cleanup);

  it('inferDefaultCredentials fires for wordpress webapp', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const result = engine.ingestFinding(makeFinding([{
      id: 'webapp-wp', type: 'webapp', label: 'http://10.10.10.5/wordpress',
      discovered_at: now, confidence: 1.0,
      url: 'http://10.10.10.5/wordpress',
      cms_type: 'wordpress',
    }]));

    // Should create a default credential node and POTENTIAL_AUTH edge
    const credNode = engine.getNode('cred-default-wordpress');
    expect(credNode).toBeDefined();
    expect(credNode!.type).toBe('credential');
    expect(credNode!.cred_user).toBe('admin');
    expect(credNode!.cred_evidence_kind).toBe('manual');
    expect(result.inferred_edges.length).toBeGreaterThan(0);
  });

  it('inferDefaultCredentials creates credential once for multiple webapps', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'webapp-wp1', type: 'webapp', label: 'http://10.10.10.5/wp1',
      discovered_at: now, confidence: 1.0, cms_type: 'wordpress',
    }]));
    engine.ingestFinding(makeFinding([{
      id: 'webapp-wp2', type: 'webapp', label: 'http://10.10.10.6/wp2',
      discovered_at: now, confidence: 1.0, cms_type: 'wordpress',
    }]));
    // Credential should exist once
    expect(engine.getNode('cred-default-wordpress')).toBeDefined();
  });

  it('inferDefaultCredentials does not fire for unknown CMS', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const result = engine.ingestFinding(makeFinding([{
      id: 'webapp-custom', type: 'webapp', label: 'http://10.10.10.5/custom',
      discovered_at: now, confidence: 1.0, cms_type: 'custom-app',
    }]));
    expect(engine.getNode('cred-default-custom-app')).toBeNull();
    expect(result.inferred_edges.length).toBe(0);
  });

  it('rule-login-spray-candidate fires for webapp with login form', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    // Seed a credential
    engine.ingestFinding(makeFinding([{
      id: 'cred-test', type: 'credential', label: 'admin',
      discovered_at: now, confidence: 1.0,
      cred_type: 'plaintext', cred_usable_for_auth: true,
      credential_status: 'active',
    }]));
    // Ingest webapp with login form
    const result = engine.ingestFinding(makeFinding([{
      id: 'webapp-login', type: 'webapp', label: 'http://10.10.10.5/login',
      discovered_at: now, confidence: 1.0,
      has_login_form: true,
    }]));
    expect(result.inferred_edges.length).toBeGreaterThan(0);
  });

  it('rule-login-spray-candidate does not fire without login form', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'cred-test2', type: 'credential', label: 'admin2',
      discovered_at: now, confidence: 1.0,
      cred_type: 'plaintext', cred_usable_for_auth: true,
      credential_status: 'active',
    }]));
    const result = engine.ingestFinding(makeFinding([{
      id: 'webapp-nologin', type: 'webapp', label: 'http://10.10.10.5/static',
      discovered_at: now, confidence: 1.0,
    }]));
    // No login form = no spray rule
    expect(result.inferred_edges.length).toBe(0);
  });
});

// ============================================================
// 10.4: Nuclei Parser
// ============================================================
describe('10.4 — Nuclei parser', () => {
  it('returns empty finding for empty input', () => {
    const result = parseNuclei('');
    expect(result.nodes).toHaveLength(0);
    expect(result.edges).toHaveLength(0);
  });

  it('parses single JSONL finding', () => {
    const input = JSON.stringify({
      'template-id': 'cve-2021-44228',
      type: 'http',
      host: 'http://10.10.10.5:8080',
      'matched-at': 'http://10.10.10.5:8080/api/test',
      info: {
        name: 'Log4j RCE',
        severity: 'critical',
        tags: 'cve,rce,CVE-2021-44228',
      },
    });
    const result = parseNuclei(input);

    // Should have: host, service, webapp, vulnerability nodes
    const types = result.nodes.map(n => n.type);
    expect(types).toContain('webapp');
    expect(types).toContain('vulnerability');
    expect(types).toContain('service');
    expect(types).toContain('host');

    const vuln = result.nodes.find(n => n.type === 'vulnerability');
    expect(vuln!.cve).toBe('CVE-2021-44228');
    expect(vuln!.cvss).toBe(9.5);
    expect(vuln!.exploitable).toBe(true);

    // Edges: RUNS, HOSTS, VULNERABLE_TO
    const edgeTypes = result.edges.map(e => e.properties.type);
    expect(edgeTypes).toContain('HOSTS');
    expect(edgeTypes).toContain('VULNERABLE_TO');
    expect(edgeTypes).toContain('RUNS');
  });

  it('parses multiple JSONL findings and deduplicates', () => {
    const lines = [
      JSON.stringify({
        'template-id': 'xss-detection',
        type: 'http',
        host: 'http://10.10.10.5',
        'matched-at': 'http://10.10.10.5/page1',
        info: { name: 'XSS', severity: 'medium', tags: 'xss' },
      }),
      JSON.stringify({
        'template-id': 'sqli-detection',
        type: 'http',
        host: 'http://10.10.10.5',
        'matched-at': 'http://10.10.10.5/page2',
        info: { name: 'SQLi', severity: 'high', tags: 'sqli' },
      }),
    ].join('\n');
    const result = parseNuclei(lines);

    const vulns = result.nodes.filter(n => n.type === 'vulnerability');
    expect(vulns.length).toBe(2);
    expect(vulns.map(v => v.vuln_type)).toContain('xss');
    expect(vulns.map(v => v.vuln_type)).toContain('sqli');
  });

  it('maps severity to CVSS correctly', () => {
    const severities = ['critical', 'high', 'medium', 'low', 'info'];
    const expected = [9.5, 7.5, 5.0, 2.5, 0];

    for (let i = 0; i < severities.length; i++) {
      const input = JSON.stringify({
        'template-id': `test-${severities[i]}`,
        type: 'http',
        host: 'http://10.10.10.5',
        'matched-at': `http://10.10.10.5/${severities[i]}`,
        info: { name: `Test ${severities[i]}`, severity: severities[i] },
      });
      const result = parseNuclei(input);
      const vuln = result.nodes.find(n => n.type === 'vulnerability');
      expect(vuln!.cvss).toBe(expected[i]);
    }
  });

  it('extracts CVE from classification field', () => {
    const input = JSON.stringify({
      'template-id': 'test-cve',
      type: 'http',
      host: 'http://10.10.10.5',
      'matched-at': 'http://10.10.10.5/test',
      info: {
        name: 'Test',
        severity: 'high',
        classification: { 'cve-id': ['CVE-2023-12345'] },
      },
    });
    const result = parseNuclei(input);
    const vuln = result.nodes.find(n => n.type === 'vulnerability');
    expect(vuln!.cve).toBe('CVE-2023-12345');
  });

  it('produces deterministic vulnerability IDs', () => {
    const input = JSON.stringify({
      'template-id': 'stable-id-test',
      type: 'http',
      host: 'http://10.10.10.5',
      'matched-at': 'http://10.10.10.5/test',
      info: { name: 'Test', severity: 'medium' },
    });
    const r1 = parseNuclei(input);
    const r2 = parseNuclei(input);
    const v1 = r1.nodes.find(n => n.type === 'vulnerability')!;
    const v2 = r2.nodes.find(n => n.type === 'vulnerability')!;
    expect(v1.id).toBe(v2.id);
  });

  it('skips non-JSON lines gracefully', () => {
    const input = 'not json\n' + JSON.stringify({
      'template-id': 'test',
      type: 'http',
      host: 'http://10.10.10.5',
      'matched-at': 'http://10.10.10.5/test',
      info: { name: 'Test', severity: 'info' },
    });
    const result = parseNuclei(input);
    expect(result.nodes.length).toBeGreaterThan(0);
  });
});

// ============================================================
// 10.5: Nikto Parser
// ============================================================
describe('10.5 — Nikto parser', () => {
  it('returns empty finding for empty input', () => {
    const result = parseNikto('');
    expect(result.nodes).toHaveLength(0);
    expect(result.edges).toHaveLength(0);
  });

  it('parses text mode output', () => {
    const input = [
      '+ Target IP: 10.10.10.5',
      '+ Target Port: 8080',
      '+ Server: Apache/2.4.41 (Ubuntu)',
      '+ OSVDB-3268: /icons/: Directory indexing found.',
      '+ /login: Login page found (OSVDB-1234)',
    ].join('\n');
    const result = parseNikto(input);

    const types = result.nodes.map(n => n.type);
    expect(types).toContain('host');
    expect(types).toContain('service');
    expect(types).toContain('webapp');
    expect(types).toContain('vulnerability');

    const svc = result.nodes.find(n => n.type === 'service');
    expect(svc!.version).toBe('Apache/2.4.41 (Ubuntu)');

    const edgeTypes = result.edges.map(e => e.properties.type);
    expect(edgeTypes).toContain('RUNS');
    expect(edgeTypes).toContain('HOSTS');
    expect(edgeTypes).toContain('VULNERABLE_TO');
  });

  it('parses JSON mode output', () => {
    const input = JSON.stringify({
      ip: '10.10.10.5',
      port: 443,
      ssl: true,
      banner: 'nginx/1.18.0',
      vulnerabilities: [
        { id: 'OSVDB-561', OSVDB: '561', msg: 'Default page detected', url: '/index.html' },
      ],
    });
    const result = parseNikto(input);

    const types = result.nodes.map(n => n.type);
    expect(types).toContain('host');
    expect(types).toContain('service');
    expect(types).toContain('webapp');
    expect(types).toContain('vulnerability');
  });

  it('creates webapp node from target URL', () => {
    const input = JSON.stringify({
      ip: '10.10.10.5',
      port: 80,
      vulnerabilities: [],
    });
    const result = parseNikto(input);
    const wa = result.nodes.find(n => n.type === 'webapp');
    expect(wa).toBeDefined();
    expect(wa!.url).toContain('10.10.10.5');
  });
});

// ============================================================
// 10.6: testssl/sslscan Parser
// ============================================================
describe('10.6 — testssl/sslscan parser', () => {
  it('returns empty finding for empty input', () => {
    const result = parseTestssl('');
    expect(result.nodes).toHaveLength(0);
    expect(result.edges).toHaveLength(0);
  });

  it('parses testssl JSON with vulnerability detection', () => {
    const input = JSON.stringify([
      { id: 'protocol_tls1_2', ip: '10.10.10.5', port: '443', severity: 'OK', finding: 'offered' },
      { id: 'heartbleed', ip: '10.10.10.5', port: '443', severity: 'CRITICAL', finding: 'VULNERABLE', cve: 'CVE-2014-0160' },
      { id: 'cert_commonName', ip: '10.10.10.5', port: '443', severity: 'INFO', finding: 'example.com' },
    ]);
    const result = parseTestssl(input);

    const types = result.nodes.map(n => n.type);
    expect(types).toContain('host');
    expect(types).toContain('service');
    expect(types).toContain('vulnerability');

    const vuln = result.nodes.find(n => n.type === 'vulnerability');
    expect(vuln).toBeDefined();
    expect(vuln!.cve).toBe('CVE-2014-0160');
    expect(vuln!.vuln_type).toBe('weak-crypto');

    const edgeTypes = result.edges.map(e => e.properties.type);
    expect(edgeTypes).toContain('VULNERABLE_TO');
    expect(edgeTypes).toContain('RUNS');
  });

  it('enriches service with TLS properties from testssl', () => {
    const input = JSON.stringify([
      { id: 'protocol_tls1_2', ip: '10.10.10.5', port: '443', severity: 'OK', finding: 'offered' },
      { id: 'cert_commonName', ip: '10.10.10.5', port: '443', severity: 'INFO', finding: 'example.com' },
      { id: 'cert_notAfter', ip: '10.10.10.5', port: '443', severity: 'INFO', finding: '2027-01-01' },
      { id: 'cert_caIssuer', ip: '10.10.10.5', port: '443', severity: 'INFO', finding: "Let's Encrypt" },
    ]);
    const result = parseTestssl(input);
    const svc = result.nodes.find(n => n.type === 'service');
    expect(svc).toBeDefined();
    // TLS version should be set from the protocol finding
    expect(svc!.tls_version).toBeDefined();
  });

  it('parses sslscan XML output', () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<document>
  <ssltest host="10.10.10.5" port="443">
    <protocol type="SSL" version="v3" enabled="1" />
    <protocol type="TLS" version="v1.2" enabled="1" />
    <cipher status="accepted" cipher="AES256-SHA" />
    <certificate>
      <subject>CN=example.com</subject>
      <issuer>Let's Encrypt</issuer>
      <not-valid-after>2027-01-01</not-valid-after>
    </certificate>
  </ssltest>
</document>`;
    const result = parseTestssl(xml);

    const types = result.nodes.map(n => n.type);
    expect(types).toContain('host');
    expect(types).toContain('service');

    const svc = result.nodes.find(n => n.type === 'service');
    expect(svc!.cert_subject).toBe('CN=example.com');
    expect(svc!.cert_issuer).toBe("Let's Encrypt");
    expect(svc!.cipher_suites).toContain('AES256-SHA');

    // SSLv3 enabled should create a vulnerability
    const vuln = result.nodes.find(n => n.type === 'vulnerability');
    expect(vuln).toBeDefined();
    expect(vuln!.cve).toBe('CVE-2014-3566'); // POODLE
  });

  it('does not create vulnerability for non-vulnerable findings', () => {
    const input = JSON.stringify([
      { id: 'protocol_tls1_2', ip: '10.10.10.5', port: '443', severity: 'OK', finding: 'offered' },
      { id: 'heartbleed', ip: '10.10.10.5', port: '443', severity: 'OK', finding: 'not vulnerable' },
    ]);
    const result = parseTestssl(input);
    const vulns = result.nodes.filter(n => n.type === 'vulnerability');
    expect(vulns).toHaveLength(0);
  });
});

// ============================================================
// 10.7: Frontier Awareness
// ============================================================
describe('10.7 — Frontier awareness', () => {
  afterEach(cleanup);

  it('webapp missing technology/auth_type produces frontier item', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'webapp-frontier', type: 'webapp', label: 'http://10.10.10.5',
      discovered_at: now, confidence: 1.0,
    }]));
    const state = engine.getState();
    const frontierItem = state.frontier.find(f => f.node_id === 'webapp-frontier');
    expect(frontierItem).toBeDefined();
    expect(frontierItem!.missing_properties).toContain('technology');
    expect(frontierItem!.missing_properties).toContain('auth_type');
  });

  it('webapp with technology and auth_type is not in frontier', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'webapp-complete', type: 'webapp', label: 'http://10.10.10.5',
      discovered_at: now, confidence: 1.0,
      technology: 'Apache', auth_type: 'form',
    }]));
    const state = engine.getState();
    const frontierItem = state.frontier.find(f => f.node_id === 'webapp-complete' && f.type === 'incomplete_node');
    expect(frontierItem).toBeUndefined();
  });

  it('estimateFanOut returns 8 for webapp nodes', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding([{
      id: 'webapp-fanout', type: 'webapp', label: 'http://10.10.10.5/test',
      discovered_at: now, confidence: 1.0,
    }]));
    const state = engine.getState();
    const item = state.frontier.find(f => f.node_id === 'webapp-fanout');
    expect(item).toBeDefined();
    expect(item!.graph_metrics.fan_out_estimate).toBe(8);
  });
});

// ============================================================
// Regression: P1-a — Non-HTTP Nuclei targets get distinct service IDs
// ============================================================
describe('regression — Nuclei non-HTTP service ID attribution', () => {
  it('produces distinct service IDs for different host:port targets', () => {
    const output = [
      JSON.stringify({ 'template-id': 'redis-unauth', host: '10.10.10.5:6379', type: 'tcp', 'matched-at': '10.10.10.5:6379', info: { name: 'Redis Unauth', severity: 'high' } }),
      JSON.stringify({ 'template-id': 'ftp-anon', host: '10.10.10.6:21', type: 'tcp', 'matched-at': '10.10.10.6:21', info: { name: 'FTP Anon', severity: 'medium' } }),
    ].join('\n');
    const result = parseNuclei(output);
    const svcNodes = result.nodes.filter(n => n.type === 'service');
    const svcIds = svcNodes.map(n => n.id);
    expect(svcIds).toContain('svc-10-10-10-5-6379');
    expect(svcIds).toContain('svc-10-10-10-6-21');
    expect(svcIds).not.toContain('svc-unknown-http');
  });

  it('does not collapse different TCP services onto svc-unknown-http', () => {
    const output = JSON.stringify({ 'template-id': 'redis-unauth', host: '10.10.10.5:6379', type: 'tcp', 'matched-at': '10.10.10.5:6379', info: { name: 'Redis Unauth', severity: 'high' } });
    const result = parseNuclei(output);
    const svcNode = result.nodes.find(n => n.type === 'service');
    expect(svcNode).toBeDefined();
    expect(svcNode!.id).not.toBe('svc-unknown-http');
    expect(svcNode!.id).toBe('svc-10-10-10-5-6379');
  });
});

// ============================================================
// Regression: P1-b — New parsers use canonical service ID format
// ============================================================
describe('regression — canonical service ID format alignment', () => {
  it('Nuclei HTTP service ID matches web-enum format (no -proto suffix)', () => {
    const output = JSON.stringify({
      'template-id': 'tech-detect', host: 'http://10.10.10.50:8080',
      type: 'http', 'matched-at': 'http://10.10.10.50:8080/login',
      info: { name: 'Tech detect', severity: 'info' },
    });
    const result = parseNuclei(output);
    const svcNode = result.nodes.find(n => n.type === 'service');
    expect(svcNode).toBeDefined();
    // Canonical format: svc-{ip-dashed}-{port} — no protocol suffix
    expect(svcNode!.id).toBe('svc-10-10-10-50-8080');
  });

  it('Nikto service ID matches nmap format', () => {
    const output = [
      '+ Target IP:          10.10.10.50',
      '+ Target Port:        80',
      '+ Server: Apache/2.4.41',
      '+ /admin: Admin panel found',
    ].join('\n');
    const result = parseNikto(output);
    const svcNode = result.nodes.find(n => n.type === 'service');
    expect(svcNode).toBeDefined();
    expect(svcNode!.id).toBe('svc-10-10-10-50-80');
  });

  it('testssl service ID matches nmap format', () => {
    const output = JSON.stringify([
      { id: 'cert_commonname', ip: '10.10.10.50', port: '443', severity: 'INFO', finding: 'test.local' },
    ]);
    const result = parseTestssl(output);
    const svcNode = result.nodes.find(n => n.type === 'service');
    expect(svcNode).toBeDefined();
    expect(svcNode!.id).toBe('svc-10-10-10-50-443');
  });
});

// ============================================================
// Regression: P2 — Login-spray rule only fans out plaintext credentials
// ============================================================
describe('regression — login-spray credential filtering', () => {
  afterEach(cleanup);

  it('creates POTENTIAL_AUTH only from plaintext credentials, not SSH keys or tokens', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding(makeFinding(
      [
        { id: 'webapp-login', type: 'webapp' as const, label: 'Login App', discovered_at: now, confidence: 1.0, url: 'http://10.10.10.50/login', has_login_form: true },
        { id: 'cred-plaintext', type: 'credential' as const, label: 'admin:pass', discovered_at: now, confidence: 1.0, cred_type: 'plaintext', cred_material_kind: 'plaintext_password', cred_usable_for_auth: true, credential_status: 'active' },
        { id: 'cred-sshkey', type: 'credential' as const, label: 'id_rsa', discovered_at: now, confidence: 1.0, cred_type: 'ssh_key', cred_material_kind: 'ssh_key', cred_usable_for_auth: true, credential_status: 'active' },
        { id: 'cred-token', type: 'credential' as const, label: 'jwt-token', discovered_at: now, confidence: 1.0, cred_type: 'token', cred_material_kind: 'token', cred_usable_for_auth: true, credential_status: 'active' },
        { id: 'cred-ntlm', type: 'credential' as const, label: 'ntlm-hash', discovered_at: now, confidence: 1.0, cred_type: 'ntlm', cred_material_kind: 'ntlm_hash', cred_usable_for_auth: true, credential_status: 'active' },
      ],
    ));

    // Check edges targeting the webapp (inbound to webapp-login)
    const edges = engine.queryGraph({ from_node: 'webapp-login', direction: 'inbound', edge_type: 'POTENTIAL_AUTH' });
    const sources = edges.edges.map(e => e.source);
    // Only plaintext_password credential should have POTENTIAL_AUTH to webapp
    expect(sources).toContain('cred-plaintext');
    expect(sources).not.toContain('cred-sshkey');
    expect(sources).not.toContain('cred-token');
    expect(sources).not.toContain('cred-ntlm');
  });
});

// ============================================================
// Parser Registry
// ============================================================
describe('Parser registry — new aliases', () => {
  it('nuclei alias resolves', () => {
    expect(parseOutput('nuclei', '', 'test')).toBeDefined();
  });

  it('nikto alias resolves', () => {
    expect(parseOutput('nikto', '', 'test')).toBeDefined();
  });

  it('testssl alias resolves', () => {
    expect(parseOutput('testssl', '', 'test')).toBeDefined();
  });

  it('testssl.sh alias resolves', () => {
    expect(parseOutput('testssl.sh', '', 'test')).toBeDefined();
  });

  it('sslscan alias resolves', () => {
    expect(parseOutput('sslscan', '', 'test')).toBeDefined();
  });
});
