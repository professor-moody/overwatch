import { describe, it, expect, afterEach } from 'vitest';
import { GraphEngine as BaseGraphEngine } from '../graph-engine.js';
import { parseNuclei, parseNikto, parseTestssl, parseOutput } from '../parsers/index.js';
import { webappId, vulnerabilityId } from '../parser-utils.js';
import { validateEdgeEndpoints } from '../graph-schema.js';
import type { EngagementConfig, Finding } from '../../types.js';
import { NODE_TYPES, EDGE_TYPES } from '../../types.js';
import { unlinkSync, existsSync } from 'fs';
import { cleanupTestPersistence } from '../../__tests__/helpers/cleanup-test-persistence.js';

const TEST_STATE_FILE = './state-test-sprint10.json';
const engines = new Set<BaseGraphEngine>();

class GraphEngine extends BaseGraphEngine {
  constructor(config: EngagementConfig, stateFilePath?: string, configFilePath?: string) {
    super(config, stateFilePath, configFilePath);
    engines.add(this);
  }
}

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
  for (const engine of engines) engine.dispose();
  engines.clear();
  cleanupTestPersistence(TEST_STATE_FILE);
  if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
}

afterEach(cleanup);

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
    // Phase F: severity=info no longer creates a vulnerability node (it's
    // treated as service enrichment). The remaining severities still map
    // to their canonical CVSS bands.
    const severities = ['critical', 'high', 'medium', 'low'];
    const expected = [9.5, 7.5, 5.0, 2.5];

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

  it('recognizes a takeover result (tag) → subdomain_takeover vuln + VULNERABLE_TO + connected takeover_candidate subdomain', () => {
    const input = JSON.stringify({
      'template-id': 'aws-bucket-takeover',
      type: 'http',
      host: 'https://legacy.acme.com',
      'matched-at': 'https://legacy.acme.com',
      info: { name: 'AWS S3 Bucket Takeover', severity: 'high', tags: ['takeover', 'aws'] },
    });
    const result = parseNuclei(input);
    const vuln = result.nodes.find(n => n.type === 'vulnerability')!;
    expect(vuln.vuln_type).toBe('subdomain_takeover');
    expect(vuln.exploitable).toBe(true);
    const edgeTypes = result.edges.map(e => e.properties.type);
    expect(edgeTypes).toContain('VULNERABLE_TO');
    const sub = result.nodes.find(n => n.type === 'subdomain');
    expect(sub?.subdomain_name).toBe('legacy.acme.com');
    expect((sub as Record<string, unknown>).takeover_candidate).toBe(true);
    // The subdomain is connected (SUBDOMAIN_OF its domain + RESOLVES_TO the host)
    // so it sits in the same component as the vulnerability, not an island.
    expect(result.nodes.some(n => n.type === 'domain' && n.label === 'acme.com')).toBe(true);
    expect(edgeTypes).toContain('SUBDOMAIN_OF');
    const resolves = result.edges.find(e => e.properties.type === 'RESOLVES_TO' && e.source === sub!.id);
    expect(resolves).toBeDefined();
    expect(result.nodes.some(n => n.id === resolves!.target && n.type === 'host')).toBe(true);
  });

  it('connects the takeover subdomain even when the FQDN carries a trailing dot (host id drift)', () => {
    const input = JSON.stringify({
      'template-id': 'aws-bucket-takeover', type: 'http',
      host: 'https://legacy.acme.com.', 'matched-at': 'https://legacy.acme.com.',
      info: { name: 'Takeover', severity: 'high', tags: ['takeover'] },
    });
    const result = parseNuclei(input);
    const sub = result.nodes.find(n => n.type === 'subdomain')!;
    const resolves = result.edges.find(e => e.properties.type === 'RESOLVES_TO' && e.source === sub.id);
    expect(resolves).toBeDefined();
    expect(result.nodes.some(n => n.id === resolves!.target && n.type === 'host')).toBe(true);
  });

  it('empty host / non-HTTP takeover degrades gracefully: subdomain connects via SUBDOMAIN_OF, no dangling edge', () => {
    for (const input of [
      // Empty host (no HTTP host node → no RESOLVES_TO, but still connected to domain).
      JSON.stringify({ 'template-id': 'aws-bucket-takeover', type: 'http', host: '', 'matched-at': 'https://legacy.acme.com', info: { name: 'T', severity: 'high', tags: ['takeover'] } }),
      // Non-HTTP takeover (dns) — RESOLVES_TO is gated on the HTTP host node.
      JSON.stringify({ 'template-id': 'cname-fingerprint', type: 'dns', host: 'legacy.acme.com', 'matched-at': 'legacy.acme.com', info: { name: 'T', severity: 'high', tags: ['takeover'] } }),
    ]) {
      const result = parseNuclei(input);
      const sub = result.nodes.find(n => n.type === 'subdomain')!;
      expect((sub as Record<string, unknown>).takeover_candidate).toBe(true);
      expect(result.edges.some(e => e.properties.type === 'SUBDOMAIN_OF' && e.source === sub.id)).toBe(true);
      // No dangling edge: every edge endpoint is a node in the finding.
      const ids = new Set(result.nodes.map(n => n.id));
      for (const e of result.edges) {
        expect(ids.has(e.source)).toBe(true);
        expect(ids.has(e.target)).toBe(true);
      }
    }
  });

  it('a schemeless matched-at (unparseable service) emits no dangling HOSTS/RUNS edge', () => {
    const input = JSON.stringify({
      'template-id': 'aws-bucket-takeover', type: 'http', host: 'legacy.acme.com', 'matched-at': 'legacy.acme.com',
      info: { name: 'T', severity: 'high', tags: ['takeover'] },
    });
    const result = parseNuclei(input);
    const ids = new Set(result.nodes.map(n => n.id));
    for (const e of result.edges) {
      expect(ids.has(e.source)).toBe(true);
      expect(ids.has(e.target)).toBe(true);
    }
  });

  it('does NOT classify an unrelated "takeover"-named template (account-takeover) as a subdomain takeover', () => {
    const input = JSON.stringify({
      'template-id': 'account-takeover-via-oauth',
      type: 'http', host: 'https://app.acme.com', 'matched-at': 'https://app.acme.com/login',
      info: { name: 'OAuth account takeover check', severity: 'info', tags: ['oauth', 'auth'] },
    });
    const result = parseNuclei(input);
    // info severity + no `takeover` tag + no takeovers/ path → suppressed, no vuln, no subdomain.
    expect(result.nodes.some(n => n.type === 'vulnerability')).toBe(false);
    expect(result.nodes.some(n => n.type === 'subdomain')).toBe(false);
  });

  it('recognizes a takeover template even at severity=info (path-based) and still emits the vuln', () => {
    const input = JSON.stringify({
      'template-id': 'http/takeovers/github-takeover',
      type: 'http',
      host: 'https://docs.acme.com',
      'matched-at': 'https://docs.acme.com',
      info: { name: 'GitHub Pages Takeover', severity: 'info', tags: ['detect'] },
    });
    const result = parseNuclei(input);
    const vuln = result.nodes.find(n => n.type === 'vulnerability');
    expect(vuln?.vuln_type).toBe('subdomain_takeover');
  });

  it('a non-takeover result on a hostname target is unaffected (no takeover_candidate subdomain)', () => {
    // Uses a HOSTNAME target so "no subdomain node" proves the takeover path
    // didn't fire (not merely that the host was an IP).
    const input = JSON.stringify({
      'template-id': 'xss-detection',
      type: 'http', host: 'http://sub.acme.com', 'matched-at': 'http://sub.acme.com/p',
      info: { name: 'XSS', severity: 'medium', tags: 'xss' },
    });
    const result = parseNuclei(input);
    expect(result.nodes.some(n => n.type === 'subdomain')).toBe(false);
    // No takeover semantics leak onto a normal vuln: type stays xss and no
    // RESOLVES_TO edge is synthesized (that only happens on the takeover path).
    const vuln = result.nodes.find(n => n.type === 'vulnerability')!;
    expect(vuln.vuln_type).toBe('xss');
    expect(result.edges.some(e => e.properties.type === 'RESOLVES_TO')).toBe(false);
  });

  it('a non-HTTP result with an empty host is skipped (no phantom svc-unknown, no dangling VULNERABLE_TO)', () => {
    const input = JSON.stringify({
      'template-id': 'redis-unauth', type: 'tcp', host: '',
      info: { name: 'Redis Unauth', severity: 'high', tags: 'redis' },
    });
    const result = parseNuclei(input);
    // No identifiable target → nothing emitted (rather than a colliding svc-unknown).
    expect(result.nodes).toHaveLength(0);
    expect(result.edges).toHaveLength(0);
  });

  it('a non-HTTP result WITH a host:port emits a service + VULNERABLE_TO with a resolvable source', () => {
    const input = JSON.stringify({
      'template-id': 'redis-unauth', type: 'tcp', host: '10.10.10.5:6379',
      info: { name: 'Redis Unauth', severity: 'high', tags: 'redis' },
    });
    const result = parseNuclei(input);
    const vEdge = result.edges.find(e => e.properties.type === 'VULNERABLE_TO')!;
    expect(result.nodes.some(n => n.id === vEdge.source && n.type === 'service')).toBe(true);
  });

  it('does not emit a subdomain node when the takeover target is an apex domain or an IP', () => {
    const apex = parseNuclei(JSON.stringify({
      'template-id': 'takeover-x', type: 'http', host: 'https://acme.com', 'matched-at': 'https://acme.com',
      info: { name: 'Takeover', severity: 'high', tags: ['takeover'] },
    }));
    expect(apex.nodes.some(n => n.type === 'subdomain')).toBe(false);
    const ip = parseNuclei(JSON.stringify({
      'template-id': 'takeover-x', type: 'http', host: 'https://203.0.113.5', 'matched-at': 'https://203.0.113.5',
      info: { name: 'Takeover', severity: 'high', tags: ['takeover'] },
    }));
    expect(ip.nodes.some(n => n.type === 'subdomain')).toBe(false);
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

// ============================================================
// Regression: P1 — Nuclei text output parsing
// ============================================================
describe('regression — Nuclei text output parsing', () => {
  it('parses standard Nuclei text-mode output lines', () => {
    const input = [
      '[CVE-2021-41773] [http] [critical] http://10.10.10.5/cgi-bin/.%2e/%2e%2e/etc/passwd',
      '[tech-detect:nginx] [http] [info] http://10.10.10.5',
    ].join('\n');
    const result = parseNuclei(input);

    expect(result.nodes.length).toBeGreaterThan(0);
    const vulns = result.nodes.filter(n => n.type === 'vulnerability');
    // Phase F: severity=info templates without a CVE no longer create a
    // vulnerability node — they enrich the target service/webapp.
    expect(vulns.length).toBe(1);
    const cveVuln = vulns.find(v => v.cve === 'CVE-2021-41773');
    expect(cveVuln).toBeDefined();
    expect(cveVuln!.cvss).toBe(9.5);
    expect(cveVuln!.exploitable).toBe(true);

    const enriched = result.nodes.find(n =>
      Array.isArray((n as Record<string, unknown>).technologies) &&
      ((n as Record<string, unknown>).technologies as string[]).includes('nginx')
    );
    expect(enriched).toBeDefined();
  });

  it('handles mixed text lines with non-matching lines', () => {
    const input = [
      '                   __     _',
      '   ____  __  _____/ /__  (_)',
      '[CVE-2024-1234] [http] [high] http://10.10.10.5/vuln',
      'some other garbage line',
      '',
    ].join('\n');
    const result = parseNuclei(input);
    const vulns = result.nodes.filter(n => n.type === 'vulnerability');
    expect(vulns.length).toBe(1);
  });

  it('text-mode output produces host, service, webapp, and vulnerability nodes', () => {
    const input = '[sqli-detect] [http] [high] http://10.10.10.5:8080/search?q=1';
    const result = parseNuclei(input);
    const types = result.nodes.map(n => n.type);
    expect(types).toContain('host');
    expect(types).toContain('service');
    expect(types).toContain('webapp');
    expect(types).toContain('vulnerability');

    const edgeTypes = result.edges.map(e => e.properties.type);
    expect(edgeTypes).toContain('RUNS');
    expect(edgeTypes).toContain('HOSTS');
    expect(edgeTypes).toContain('VULNERABLE_TO');
  });
});

// ============================================================
// Regression: P1 — Nikto path-aware vulnerability identity
// ============================================================
describe('regression — Nikto per-path vulnerability identity', () => {
  it('produces distinct vulnerability nodes for same OSVDB on different paths', () => {
    const input = [
      '+ Target IP: 10.10.10.5',
      '+ Target Port: 80',
      '+ OSVDB-3268: /admin: Directory indexing found.',
      '+ OSVDB-3268: /backup-admin: Directory indexing found.',
    ].join('\n');
    const result = parseNikto(input);

    const vulns = result.nodes.filter(n => n.type === 'vulnerability');
    expect(vulns.length).toBe(2);
    expect(vulns[0].id).not.toBe(vulns[1].id);

    const labels = vulns.map(v => v.label);
    expect(labels.some(l => l!.includes('/admin'))).toBe(true);
    expect(labels.some(l => l!.includes('/backup-admin'))).toBe(true);

    const vulnEdges = result.edges.filter(e => e.properties.type === 'VULNERABLE_TO');
    expect(vulnEdges.length).toBe(2);
  });

  it('stores affected_path on vulnerability node', () => {
    const input = JSON.stringify({
      ip: '10.10.10.5',
      port: 80,
      vulnerabilities: [
        { id: 'OSVDB-561', OSVDB: '561', msg: 'Default page detected', path: '/index.html' },
      ],
    });
    const result = parseNikto(input);
    const vuln = result.nodes.find(n => n.type === 'vulnerability');
    expect(vuln).toBeDefined();
    expect(vuln!.affected_path).toBe('/index.html');
  });
});

// ============================================================
// Regression: P2 — Nuclei and Nikto produce same webapp ID for same origin
// ============================================================
describe('regression — cross-tool webapp identity convergence', () => {
  it('Nuclei and Nikto produce the same webapp node ID for the same origin', () => {
    const nucleiInput = JSON.stringify({
      'template-id': 'xss-test',
      type: 'http',
      host: 'http://10.10.10.5:8080',
      'matched-at': 'http://10.10.10.5:8080/login?q=1',
      info: { name: 'XSS', severity: 'medium', tags: 'xss' },
    });
    const nucleiResult = parseNuclei(nucleiInput);

    const niktoInput = [
      '+ Target IP: 10.10.10.5',
      '+ Target Port: 8080',
      '+ OSVDB-3268: /icons/: Directory indexing found.',
    ].join('\n');
    const niktoResult = parseNikto(niktoInput);

    const nucleiWebapp = nucleiResult.nodes.find(n => n.type === 'webapp');
    const niktoWebapp = niktoResult.nodes.find(n => n.type === 'webapp');
    expect(nucleiWebapp).toBeDefined();
    expect(niktoWebapp).toBeDefined();
    expect(nucleiWebapp!.id).toBe(niktoWebapp!.id);
  });
});

// =============================================
// Nuclei IPv6 regression
// =============================================
describe('regression — Nuclei IPv6 host handling', () => {
  it('correctly extracts IPv6 host from HTTP matched-at URL', () => {
    const input = JSON.stringify({
      'template-id': 'CVE-2024-9999',
      type: 'http',
      host: 'http://[2001:db8::1]:8443',
      'matched-at': 'https://[2001:db8::1]:8443/vuln',
      info: { name: 'Test RCE', severity: 'critical', tags: ['rce'] },
    });
    const result = parseNuclei(input);
    const host = result.nodes.find(n => n.type === 'host');
    expect(host).toBeDefined();
    expect(host!.id).toBe('host-2001-db8--1');
    expect(host!.ip).toBe('2001:db8::1');
    // Service ID should use dashes, not colons
    const svc = result.nodes.find(n => n.type === 'service');
    expect(svc).toBeDefined();
    expect(svc!.id).toBe('svc-2001-db8--1-8443');
  });

  it('correctly handles non-HTTP IPv6 host:port (bracketed)', () => {
    const input = JSON.stringify({
      'template-id': 'redis-unauth',
      type: 'tcp',
      host: '[2001:db8::2]:6379',
      'matched-at': '[2001:db8::2]:6379',
      info: { name: 'Redis Unauth', severity: 'high', tags: ['redis'] },
    });
    const result = parseNuclei(input);
    const svc = result.nodes.find(n => n.type === 'service');
    expect(svc).toBeDefined();
    expect(svc!.id).toBe('svc-2001-db8--2-6379');
  });

  it('does not truncate IPv6 address at first colon', () => {
    // Before the fix, split(':')[0] on "http://[2001:db8::1]:8443" would yield "[2001"
    const input = JSON.stringify({
      'template-id': 'test-detect',
      type: 'http',
      host: 'http://[::1]:80',
      'matched-at': 'http://[::1]:80/',
      info: { name: 'Test', severity: 'info', tags: [] },
    });
    const result = parseNuclei(input);
    const host = result.nodes.find(n => n.type === 'host');
    expect(host).toBeDefined();
    // Should be "host---1" (::1 with colons replaced by dashes), not something like "host-[2001"
    expect(host!.id).toBe('host---1');
    expect(host!.label).not.toContain('[');
  });
});
