import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { GraphEngine } from '../graph-engine.js';
import { isUrlInScope, isCloudResourceInScope } from '../cidr.js';
import { inferProfile } from '../../types.js';
import type { EngagementConfig } from '../../types.js';
import { unlinkSync, existsSync } from 'fs';

const TEST_STATE_FILE = './state-test-sprint8.json';

function makeConfig(overrides: Partial<EngagementConfig> = {}): EngagementConfig {
  return {
    id: 'test-s8',
    name: 'Sprint 8 Test',
    created_at: '2026-03-20T00:00:00Z',
    scope: {
      cidrs: ['10.10.10.0/28'],
      domains: ['test.local'],
      exclusions: ['10.10.10.14'],
    },
    objectives: [{
      id: 'obj-1',
      description: 'Test objective',
      target_node_type: 'credential',
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

// ============================================================
// 8.4: URL scope matching (glob-like)
// ============================================================
describe('isUrlInScope', () => {
  it('matches wildcard subdomain pattern', () => {
    expect(isUrlInScope('https://app.example.com', ['*.example.com'])).toBe(true);
    expect(isUrlInScope('https://deep.sub.example.com', ['*.example.com'])).toBe(true); // single * matches any non-slash chars including dots
    expect(isUrlInScope('https://other.com', ['*.example.com'])).toBe(false);
  });

  it('single * does not match path separators', () => {
    expect(isUrlInScope('https://app.corp.io/api/v1/deep', ['app.corp.io/api/*'])).toBe(false);
  });

  it('matches exact hostname', () => {
    expect(isUrlInScope('https://app.corp.io', ['app.corp.io'])).toBe(true);
    expect(isUrlInScope('https://other.corp.io', ['app.corp.io'])).toBe(false);
  });

  it('matches path pattern', () => {
    expect(isUrlInScope('https://app.corp.io/api/v1', ['app.corp.io/api/*'])).toBe(true);
    expect(isUrlInScope('https://app.corp.io/admin', ['app.corp.io/api/*'])).toBe(false);
  });

  it('matches deep path with **', () => {
    expect(isUrlInScope('https://app.corp.io/api/v1/users/123', ['app.corp.io/api/**'])).toBe(true);
  });

  it('strips protocol for matching', () => {
    expect(isUrlInScope('http://app.corp.io', ['app.corp.io'])).toBe(true);
    expect(isUrlInScope('https://app.corp.io', ['https://app.corp.io'])).toBe(true);
  });

  it('returns false when no patterns match', () => {
    expect(isUrlInScope('https://evil.com', ['*.example.com', 'app.corp.io'])).toBe(false);
  });

  it('case-insensitive matching', () => {
    expect(isUrlInScope('https://APP.EXAMPLE.COM', ['*.example.com'])).toBe(true);
  });
});

// ============================================================
// 8.4: Cloud resource scope matching
// ============================================================
describe('isCloudResourceInScope', () => {
  describe('AWS ARN', () => {
    it('matches in-scope account', () => {
      const result = isCloudResourceInScope(
        'arn:aws:s3:us-east-1:123456789012:mybucket',
        { aws_accounts: ['123456789012'] }
      );
      expect(result.in_scope).toBe(true);
    });

    it('rejects out-of-scope account', () => {
      const result = isCloudResourceInScope(
        'arn:aws:ec2:us-west-2:999999999999:instance/i-abc',
        { aws_accounts: ['123456789012'] }
      );
      expect(result.in_scope).toBe(false);
      expect(result.reason).toContain('999999999999');
    });

    it('rejects when no aws_accounts defined', () => {
      const result = isCloudResourceInScope(
        'arn:aws:s3:us-east-1:123456789012:mybucket',
        {}
      );
      expect(result.in_scope).toBe(false);
      expect(result.reason).toContain('no aws_accounts');
    });
  });

  describe('Azure subscription', () => {
    it('matches in-scope subscription', () => {
      const result = isCloudResourceInScope(
        '/subscriptions/abc-123-def/resourceGroups/myGroup',
        { azure_subscriptions: ['abc-123-def'] }
      );
      expect(result.in_scope).toBe(true);
    });

    it('case-insensitive subscription match', () => {
      const result = isCloudResourceInScope(
        '/subscriptions/ABC-123-DEF/resourceGroups/myGroup',
        { azure_subscriptions: ['abc-123-def'] }
      );
      expect(result.in_scope).toBe(true);
    });

    it('rejects out-of-scope subscription', () => {
      const result = isCloudResourceInScope(
        '/subscriptions/other-sub/resourceGroups/myGroup',
        { azure_subscriptions: ['abc-123-def'] }
      );
      expect(result.in_scope).toBe(false);
    });
  });

  describe('GCP project', () => {
    it('matches in-scope project', () => {
      const result = isCloudResourceInScope(
        'projects/my-project/zones/us-central1-a/instances/vm-1',
        { gcp_projects: ['my-project'] }
      );
      expect(result.in_scope).toBe(true);
    });

    it('rejects out-of-scope project', () => {
      const result = isCloudResourceInScope(
        'projects/other-project/zones/us-central1-a/instances/vm-1',
        { gcp_projects: ['my-project'] }
      );
      expect(result.in_scope).toBe(false);
    });
  });

  it('rejects unrecognized format', () => {
    const result = isCloudResourceInScope('random-string', {});
    expect(result.in_scope).toBe(false);
    expect(result.reason).toContain('Unrecognized');
  });
});

// ============================================================
// 8.4: validateAction with target_url and cloud_resource
// ============================================================
describe('validateAction scope expansion', () => {
  afterEach(cleanup);

  it('validates target_url against url_patterns', () => {
    const engine = new GraphEngine(makeConfig({
      scope: {
        cidrs: [], domains: [], exclusions: [],
        url_patterns: ['*.example.com', 'app.corp.io/api/*'],
      },
    }), TEST_STATE_FILE);

    const valid = engine.validateAction({ target_url: 'https://sub.example.com' });
    expect(valid.valid).toBe(true);

    const invalid = engine.validateAction({ target_url: 'https://evil.com' });
    expect(invalid.valid).toBe(false);
    expect(invalid.errors[0]).toContain('out of scope');
  });

  it('warns when target_url provided but no url_patterns defined', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const result = engine.validateAction({ target_url: 'https://app.example.com' });
    expect(result.valid).toBe(true);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain('no url_patterns');
  });

  it('validates cloud_resource against aws_accounts', () => {
    const engine = new GraphEngine(makeConfig({
      scope: {
        cidrs: [], domains: [], exclusions: [],
        aws_accounts: ['123456789012'],
      },
    }), TEST_STATE_FILE);

    const valid = engine.validateAction({
      cloud_resource: 'arn:aws:s3:us-east-1:123456789012:mybucket',
    });
    expect(valid.valid).toBe(true);

    const invalid = engine.validateAction({
      cloud_resource: 'arn:aws:s3:us-east-1:999999999999:mybucket',
    });
    expect(invalid.valid).toBe(false);
    expect(invalid.errors[0]).toContain('out of scope');
  });

  it('rejects unrecognized cloud resource format', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    const result = engine.validateAction({ cloud_resource: 'random-string' });
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain('Unrecognized');
  });
});

// ============================================================
// 8.5: Profile inference
// ============================================================
describe('inferProfile', () => {
  it('returns explicit profile when set', () => {
    expect(inferProfile(makeConfig({ profile: 'network' }))).toBe('network');
  });

  it('infers goad_ad from domains', () => {
    expect(inferProfile(makeConfig({ scope: { cidrs: [], domains: ['corp.local'], exclusions: [] } }))).toBe('goad_ad');
  });

  it('infers web_app from url_patterns', () => {
    expect(inferProfile(makeConfig({
      scope: { cidrs: [], domains: [], exclusions: [], url_patterns: ['*.example.com'] },
    }))).toBe('web_app');
  });

  it('infers cloud from aws_accounts', () => {
    expect(inferProfile(makeConfig({
      scope: { cidrs: [], domains: [], exclusions: [], aws_accounts: ['123456789012'] },
    }))).toBe('cloud');
  });

  it('infers cloud from azure_subscriptions', () => {
    expect(inferProfile(makeConfig({
      scope: { cidrs: [], domains: [], exclusions: [], azure_subscriptions: ['abc-def'] },
    }))).toBe('cloud');
  });

  it('infers cloud from gcp_projects', () => {
    expect(inferProfile(makeConfig({
      scope: { cidrs: [], domains: [], exclusions: [], gcp_projects: ['my-project'] },
    }))).toBe('cloud');
  });

  it('infers hybrid from domains + cloud accounts', () => {
    expect(inferProfile(makeConfig({
      scope: { cidrs: [], domains: ['corp.local'], exclusions: [], aws_accounts: ['123456789012'] },
    }))).toBe('hybrid');
  });

  it('falls back to single_host with no scope signals', () => {
    expect(inferProfile(makeConfig({
      scope: { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [] },
    }))).toBe('single_host');
  });
});

// ============================================================
// 8.1: Frontier declarative REQUIRED_PROPERTIES
// ============================================================
describe('frontier REQUIRED_PROPERTIES', () => {
  afterEach(cleanup);

  it('identifies missing properties for host nodes (alive, os, services)', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding({
      id: 'f1', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [{ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), confidence: 1.0 }],
      edges: [],
    });

    const frontier = engine.computeFrontier();
    const hostItem = frontier.find(f => f.node_id === 'host-10-10-10-1');
    expect(hostItem).toBeDefined();
    expect(hostItem!.missing_properties).toContain('alive');
  });

  it('identifies missing version for service nodes', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding({
      id: 'f2', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [
        { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', alive: true, os: 'Linux', discovered_at: new Date().toISOString(), confidence: 1.0 },
        { id: 'svc-10-10-10-1-80', type: 'service', label: 'http', service_name: 'http', port: 80, protocol: 'tcp', discovered_at: new Date().toISOString(), confidence: 1.0 },
      ],
      edges: [{ source: 'host-10-10-10-1', target: 'svc-10-10-10-1-80', properties: { type: 'RUNS', confidence: 1.0, discovered_at: new Date().toISOString() } }],
    });

    const frontier = engine.computeFrontier();
    const svcItem = frontier.find(f => f.node_id === 'svc-10-10-10-1-80');
    expect(svcItem).toBeDefined();
    expect(svcItem!.missing_properties).toContain('version');
  });

  it('identifies missing privilege_level for user nodes', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding({
      id: 'f3', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [{ id: 'user-test-local-admin', type: 'user', label: 'admin@test.local', username: 'admin', domain_name: 'test.local', discovered_at: new Date().toISOString(), confidence: 1.0 }],
      edges: [],
    });

    const frontier = engine.computeFrontier();
    const userItem = frontier.find(f => f.type === 'incomplete_node' && f.missing_properties?.includes('privilege_level'));
    expect(userItem).toBeDefined();
  });

  it('does not flag types without a REQUIRED_PROPERTIES entry', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding({
      id: 'f4', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [{ id: 'share-1', type: 'share', label: 'ADMIN$' }],
      edges: [],
    });

    const frontier = engine.computeFrontier();
    const shareItem = frontier.find(f => f.node_id === 'share-1' && f.type === 'incomplete_node');
    expect(shareItem).toBeUndefined();
  });
});

// ============================================================
// 8.2: Session → graph integration
// ============================================================
describe('ingestSessionResult', () => {
  afterEach(cleanup);

  it('creates HAS_SESSION edge when principal_node is known user', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding({
      id: 'f-setup', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [
        { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), confidence: 1.0 },
        { id: 'user-root', type: 'user', label: 'root', discovered_at: new Date().toISOString(), confidence: 1.0 },
      ],
      edges: [],
    });

    engine.ingestSessionResult({
      success: true,
      target_node: 'host-10-10-10-1',
      principal_node: 'user-root',
      session_id: 'sess-1',
    });

    const graph = engine.exportGraph();
    const sessionEdge = graph.edges.find(e => e.properties.type === 'HAS_SESSION');
    expect(sessionEdge).toBeDefined();
    expect(sessionEdge!.source).toBe('user-root');
    expect(sessionEdge!.target).toBe('host-10-10-10-1');
    expect(sessionEdge!.properties.confidence).toBe(1.0);
    expect(sessionEdge!.properties.tested).toBe(true);
  });

  it('does NOT create HAS_SESSION when principal_node is absent', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding({
      id: 'f-setup', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [{ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), confidence: 1.0 }],
      edges: [],
    });

    engine.ingestSessionResult({
      success: true,
      target_node: 'host-10-10-10-1',
      session_id: 'sess-2',
    });

    const graph = engine.exportGraph();
    const sessionEdge = graph.edges.find(e => e.properties.type === 'HAS_SESSION');
    expect(sessionEdge).toBeUndefined();
  });

  it('does NOT create HAS_SESSION when principal_node is unknown in graph', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding({
      id: 'f-setup', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [{ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), confidence: 1.0 }],
      edges: [],
    });

    engine.ingestSessionResult({
      success: true,
      target_node: 'host-10-10-10-1',
      principal_node: 'user-nonexistent',
      session_id: 'sess-3',
    });

    const graph = engine.exportGraph();
    const sessionEdge = graph.edges.find(e => e.properties.type === 'HAS_SESSION');
    expect(sessionEdge).toBeUndefined();
  });

  it('does NOT create HAS_SESSION when principal_node is wrong type (e.g. host)', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding({
      id: 'f-setup', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [
        { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), confidence: 1.0 },
        { id: 'host-10-10-10-2', type: 'host', label: '10.10.10.2', ip: '10.10.10.2', discovered_at: new Date().toISOString(), confidence: 1.0 },
      ],
      edges: [],
    });

    engine.ingestSessionResult({
      success: true,
      target_node: 'host-10-10-10-1',
      principal_node: 'host-10-10-10-2',
      session_id: 'sess-4',
    });

    const graph = engine.exportGraph();
    const sessionEdge = graph.edges.find(e => e.properties.type === 'HAS_SESSION');
    expect(sessionEdge).toBeUndefined();
  });

  it('marks specific frontier edge as tested on success', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding({
      id: 'f-setup', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [
        { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), confidence: 1.0 },
        { id: 'user-root', type: 'user', label: 'root', discovered_at: new Date().toISOString(), confidence: 1.0 },
      ],
      edges: [{
        source: 'user-root', target: 'host-10-10-10-1',
        properties: { type: 'POTENTIAL_AUTH', confidence: 0.5, discovered_at: new Date().toISOString(), discovered_by: 'inference' },
      }],
    });

    // Find the edge ID
    const graph = engine.exportGraph();
    const inferredEdge = graph.edges.find(e => e.properties.type === 'POTENTIAL_AUTH');
    expect(inferredEdge).toBeDefined();

    engine.ingestSessionResult({
      success: true,
      target_node: 'host-10-10-10-1',
      principal_node: 'user-root',
      frontier_item_id: `frontier-edge-${inferredEdge!.id}`,
    });

    // Check the edge is now marked as tested
    const updatedGraph = engine.exportGraph();
    const updated = updatedGraph.edges.find(e => e.id === inferredEdge!.id);
    expect(updated!.properties.tested).toBe(true);
    expect(updated!.properties.test_result).toBe('success');
  });

  it('marks specific frontier edge as failed on session failure', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding({
      id: 'f-setup', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [
        { id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), confidence: 1.0 },
        { id: 'user-root', type: 'user', label: 'root', discovered_at: new Date().toISOString(), confidence: 1.0 },
      ],
      edges: [{
        source: 'user-root', target: 'host-10-10-10-1',
        properties: { type: 'POTENTIAL_AUTH', confidence: 0.5, discovered_at: new Date().toISOString(), discovered_by: 'inference' },
      }],
    });

    const graph = engine.exportGraph();
    const inferredEdge = graph.edges.find(e => e.properties.type === 'POTENTIAL_AUTH');
    expect(inferredEdge).toBeDefined();

    engine.ingestSessionResult({
      success: false,
      target_node: 'host-10-10-10-1',
      principal_node: 'user-root',
      frontier_item_id: `frontier-edge-${inferredEdge!.id}`,
    });

    const updatedGraph = engine.exportGraph();
    const updated = updatedGraph.edges.find(e => e.id === inferredEdge!.id);
    expect(updated!.properties.tested).toBe(true);
    expect(updated!.properties.test_result).toBe('failure');
  });

  it('logs session_access_confirmed event', () => {
    const engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
    engine.ingestFinding({
      id: 'f-setup', agent_id: 'test', timestamp: new Date().toISOString(),
      nodes: [{ id: 'host-10-10-10-1', type: 'host', label: '10.10.10.1', ip: '10.10.10.1', discovered_at: new Date().toISOString(), confidence: 1.0 }],
      edges: [],
    });

    engine.ingestSessionResult({
      success: true,
      target_node: 'host-10-10-10-1',
      session_id: 'sess-log',
    });

    const history = engine.getFullHistory();
    const sessionEvent = history.find(e => e.event_type === 'session_access_confirmed');
    expect(sessionEvent).toBeDefined();
    expect(sessionEvent!.description).toContain('host-10-10-10-1');
    expect(sessionEvent!.description).toContain('succeeded');
  });
});

// ============================================================
// 8.5: Zod schema accepts new profiles
// ============================================================
describe('engagementConfigSchema new profiles', () => {
  afterEach(cleanup);

  it('accepts web_app profile', () => {
    const engine = new GraphEngine(makeConfig({ profile: 'web_app' }), TEST_STATE_FILE);
    expect(engine.getConfig().profile).toBe('web_app');
  });

  it('accepts cloud profile', () => {
    const engine = new GraphEngine(makeConfig({ profile: 'cloud' }), TEST_STATE_FILE);
    expect(engine.getConfig().profile).toBe('cloud');
  });

  it('accepts hybrid profile', () => {
    const engine = new GraphEngine(makeConfig({ profile: 'hybrid' }), TEST_STATE_FILE);
    expect(engine.getConfig().profile).toBe('hybrid');
  });

  it('accepts scope with cloud fields', () => {
    const engine = new GraphEngine(makeConfig({
      scope: {
        cidrs: [], domains: [], exclusions: [],
        aws_accounts: ['123456789012'],
        azure_subscriptions: ['sub-1'],
        gcp_projects: ['proj-1'],
        url_patterns: ['*.example.com'],
      },
    }), TEST_STATE_FILE);
    const scope = engine.getConfig().scope;
    expect(scope.aws_accounts).toEqual(['123456789012']);
    expect(scope.azure_subscriptions).toEqual(['sub-1']);
    expect(scope.gcp_projects).toEqual(['proj-1']);
    expect(scope.url_patterns).toEqual(['*.example.com']);
  });
});
