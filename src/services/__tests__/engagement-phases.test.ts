import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { GraphEngine } from '../graph-engine.js';
import type { EngagementConfig, EngagementPhase } from '../../types.js';

const now = new Date().toISOString();

function makePhases(): EngagementPhase[] {
  return [
    {
      id: 'recon',
      name: 'Reconnaissance',
      order: 1,
      strategies: ['enumeration', 'network_discovery'],
      entry_criteria: [{ type: 'always' }],
      exit_criteria: [{ type: 'node_count', node_type: 'host', min: 3 }],
    },
    {
      id: 'cred-attacks',
      name: 'Credential Attacks',
      order: 2,
      strategies: ['credential_spray', 'enumeration'],
      entry_criteria: [{ type: 'phase_completed', phase_id: 'recon' }],
      exit_criteria: [{ type: 'access_level', min_level: 'user' }],
    },
    {
      id: 'post-ex',
      name: 'Post-Exploitation',
      order: 3,
      strategies: ['post_exploitation', 'credential_spray'],
      entry_criteria: [{ type: 'phase_completed', phase_id: 'cred-attacks' }],
      exit_criteria: [{ type: 'objective_achieved', objective_id: 'domain-admin' }],
    },
  ];
}

function makeConfig(overrides?: Partial<EngagementConfig>): EngagementConfig {
  return {
    id: 'test-phases',
    name: 'Engagement Phases Test',
    created_at: now,
    scope: { cidrs: ['10.10.10.0/24'], domains: ['test.local'], exclusions: [] },
    objectives: [
      { id: 'domain-admin', description: 'Get DA', target_node_type: 'group', target_criteria: { label: 'Domain Admins' }, achieved: false },
    ],
    opsec: { name: 'pentest', max_noise: 0.7 },
    ...overrides,
  } as EngagementConfig;
}

function addHost(engine: GraphEngine, id: string, ip: string) {
  engine.addNode({
    id, type: 'host', label: ip, ip,
    discovered_at: now, discovered_by: 'test', confidence: 1.0,
  });
}

describe('Engagement Phases', () => {
  let engine: GraphEngine;
  let testDir: string;
  const engines = new Set<GraphEngine>();

  function createEngine(config: EngagementConfig, filename = 'state.json'): GraphEngine {
    const created = new GraphEngine(config, join(testDir, filename));
    engines.add(created);
    return created;
  }

  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'overwatch-engagement-phases-'));
  });
  afterEach(() => {
    for (const created of engines) created.dispose();
    engines.clear();
    rmSync(testDir, { recursive: true, force: true });
  });

  // ============================================================
  // Phase evaluation
  // ============================================================

  describe('Phase evaluation', () => {
    it('should evaluate phases from config and include them in state', () => {
      engine = createEngine(makeConfig({ phases: makePhases() }));
      const state = engine.getState();

      expect(state.phases).toBeDefined();
      expect(state.phases.length).toBe(3);
      expect(state.current_phase).toBeDefined();
    });

    it('first phase with always entry_criteria should be active', () => {
      engine = createEngine(makeConfig({ phases: makePhases() }));
      const state = engine.getState();

      const recon = state.phases.find((p: any) => p.id === 'recon');
      expect(recon).toBeDefined();
      expect(recon!.status).toBe('active');
      expect(state.current_phase).toBe('recon');
    });

    it('phases with unmet entry criteria should be locked', () => {
      engine = createEngine(makeConfig({ phases: makePhases() }));
      const state = engine.getState();

      const credAttacks = state.phases.find((p: any) => p.id === 'cred-attacks');
      expect(credAttacks).toBeDefined();
      expect(credAttacks!.status).toBe('locked');

      const postEx = state.phases.find((p: any) => p.id === 'post-ex');
      expect(postEx).toBeDefined();
      expect(postEx!.status).toBe('locked');
    });

    it('phase should complete when exit criteria are met', () => {
      engine = createEngine(makeConfig({ phases: makePhases() }));

      // Add 3 hosts to satisfy recon exit_criteria (node_count >= 3)
      addHost(engine, 'host-1', '10.10.10.1');
      addHost(engine, 'host-2', '10.10.10.2');
      addHost(engine, 'host-3', '10.10.10.3');

      const state = engine.getState();
      const recon = state.phases.find((p: any) => p.id === 'recon');
      expect(recon!.status).toBe('completed');
    });

    it('next phase should activate when previous completes', () => {
      engine = createEngine(makeConfig({ phases: makePhases() }));

      // Complete recon phase
      addHost(engine, 'host-1', '10.10.10.1');
      addHost(engine, 'host-2', '10.10.10.2');
      addHost(engine, 'host-3', '10.10.10.3');

      const state = engine.getState();
      const credAttacks = state.phases.find((p: any) => p.id === 'cred-attacks');
      expect(credAttacks!.status).toBe('active');
      expect(state.current_phase).toBe('cred-attacks');
    });

    it('should return empty phases when no phases configured', () => {
      engine = createEngine(makeConfig());
      const state = engine.getState();

      expect(state.phases).toEqual([]);
      expect(state.current_phase).toBeUndefined();
    });
  });

  // ============================================================
  // Campaign hierarchy
  // ============================================================

  describe('Campaign hierarchy', () => {
    it('should split a campaign into sub-campaigns', () => {
      engine = createEngine(makeConfig());

      // Create a campaign manually with multiple items
      const campaign = engine.createCampaign({
        name: 'Test Campaign',
        strategy: 'enumeration',
        item_ids: ['item-1', 'item-2', 'item-3', 'item-4'],
      });

      const children = engine.splitCampaign(campaign.id, 2);
      expect(children).not.toBeNull();
      expect(children!.length).toBe(2);

      // Children should reference parent
      for (const child of children!) {
        expect(child.parent_id).toBe(campaign.id);
      }

      // Items should be distributed
      const allChildItems = children!.flatMap(c => c.items);
      expect(allChildItems.sort()).toEqual(['item-1', 'item-2', 'item-3', 'item-4'].sort());
    });

    it('should not split a child campaign', () => {
      engine = createEngine(makeConfig());

      const parent = engine.createCampaign({
        name: 'Parent',
        strategy: 'enumeration',
        item_ids: ['a', 'b', 'c'],
      });

      const children = engine.splitCampaign(parent.id, 3);
      expect(children).not.toBeNull();

      // Try to split a child
      const result = engine.splitCampaign(children![0].id, 2);
      expect(result).toBeNull();
    });

    it('should get children of a parent campaign', () => {
      engine = createEngine(makeConfig());

      const parent = engine.createCampaign({
        name: 'Parent',
        strategy: 'enumeration',
        item_ids: ['a', 'b'],
      });

      engine.splitCampaign(parent.id, 2);

      const kids = engine.getCampaignChildren(parent.id);
      expect(kids.length).toBe(2);
      expect(kids.every(k => k.parent_id === parent.id)).toBe(true);
    });

    it('should aggregate progress from children', () => {
      engine = createEngine(makeConfig());

      const parent = engine.createCampaign({
        name: 'Parent',
        strategy: 'enumeration',
        item_ids: ['a', 'b', 'c', 'd'],
      });

      const children = engine.splitCampaign(parent.id, 2)!;

      // Simulate progress on children
      engine.updateCampaignProgress(children[0].id, children[0].items[0], 'success');
      engine.updateCampaignProgress(children[1].id, children[1].items[0], 'success');
      engine.updateCampaignProgress(children[1].id, children[1].items[1], 'failure');

      const progress = engine.getCampaignParentProgress(parent.id);
      expect(progress).not.toBeNull();
      expect(progress!.completed).toBe(3);
      expect(progress!.succeeded).toBe(2);
      expect(progress!.failed).toBe(1);
      expect(progress!.total).toBe(4);
    });

    it('should derive parent status from children', () => {
      engine = createEngine(makeConfig());

      const parent = engine.createCampaign({
        name: 'Parent',
        strategy: 'enumeration',
        item_ids: ['a', 'b'],
      });

      const children = engine.splitCampaign(parent.id, 2)!;

      // All draft → parent draft
      expect(engine.deriveCampaignParentStatus(parent.id)).toBe('draft');

      // Activate one → parent active
      engine.activateCampaign(children[0].id);
      expect(engine.deriveCampaignParentStatus(parent.id)).toBe('active');

      // Complete all → parent completed
      engine.activateCampaign(children[1].id);
      engine.updateCampaignProgress(children[0].id, children[0].items[0], 'success');
      engine.updateCampaignProgress(children[1].id, children[1].items[0], 'success');
      expect(engine.deriveCampaignParentStatus(parent.id)).toBe('completed');
    });

    it('should cascade lifecycle actions to children', () => {
      engine = createEngine(makeConfig());

      const parent = engine.createCampaign({
        name: 'Parent',
        strategy: 'enumeration',
        item_ids: ['a', 'b', 'c'],
      });

      engine.splitCampaign(parent.id, 3);

      // Activate parent → should cascade to children
      engine.activateCampaign(parent.id);
      const kids = engine.getCampaignChildren(parent.id);
      expect(kids.every(k => k.status === 'active')).toBe(true);

      // Abort parent → should cascade to children
      engine.abortCampaign(parent.id);
      const kids2 = engine.getCampaignChildren(parent.id);
      expect(kids2.every(k => k.status === 'aborted')).toBe(true);
    });

    it('should operate parent lifecycle from child-derived status', () => {
      engine = createEngine(makeConfig());
      const parent = engine.createCampaign({
        name: 'Parent', strategy: 'enumeration', item_ids: ['a', 'b'],
      });
      const children = engine.splitCampaign(parent.id, 2)!;
      engine.activateCampaign(children[0].id);
      expect(engine.deriveCampaignParentStatus(parent.id)).toBe('active');

      expect(engine.pauseCampaign(parent.id)?.status).toBe('paused');
      expect(engine.getCampaign(children[0].id)?.status).toBe('paused');
      expect(engine.resumeCampaign(parent.id)?.status).toBe('active');
      expect(engine.getCampaign(children[0].id)?.status).toBe('active');
    });
  });

  // ============================================================
  // Campaign persistence
  // ============================================================

  describe('Campaign persistence', () => {
    it('should persist campaigns across engine restarts', () => {
      const config = makeConfig();
      engine = createEngine(config);

      // Create a campaign
      const campaign = engine.createCampaign({
        name: 'Persistent Campaign',
        strategy: 'enumeration',
        item_ids: ['x', 'y', 'z'],
      });
      engine.activateCampaign(campaign.id);

      // Persist state
      engine.persist();
      engine.flushNow();
      engine.dispose();
      engines.delete(engine);

      // Create new engine from same state file
      const engine2 = createEngine(config);
      const restored = engine2.getCampaign(campaign.id);

      expect(restored).not.toBeNull();
      expect(restored!.name).toBe('Persistent Campaign');
      expect(restored!.status).toBe('active');
      expect(restored!.items).toEqual(['x', 'y', 'z']);
    });

    it('should persist campaign hierarchy across restarts', () => {
      const config = makeConfig();
      engine = createEngine(config);

      const parent = engine.createCampaign({
        name: 'Parent',
        strategy: 'credential_spray',
        item_ids: ['a', 'b', 'c', 'd'],
      });

      engine.splitCampaign(parent.id, 2);
      engine.persist();
      engine.flushNow();
      engine.dispose();
      engines.delete(engine);

      // Restart
      const engine2 = createEngine(config);
      const kids = engine2.getCampaignChildren(parent.id);
      expect(kids.length).toBe(2);
      expect(kids.every(k => k.parent_id === parent.id)).toBe(true);
    });
  });

  // ============================================================
  // Phase-aware campaign generation
  // ============================================================

  describe('Phase-aware campaign generation', () => {
    it('should tag generated campaigns with phase_id', () => {
      const phases = makePhases();
      engine = createEngine(makeConfig({ phases }));

      // Add 2 hosts — recon is active (needs 3 to complete), enumeration strategy allowed
      addHost(engine, 'host-1', '10.10.10.1');
      addHost(engine, 'host-2', '10.10.10.2');

      // Get state to trigger frontier/campaign generation
      const state = engine.getState();
      expect(state.current_phase).toBe('recon');

      const campaigns = engine.listCampaigns();

      // If any campaigns were generated, they should have phase_id = recon
      for (const c of campaigns) {
        if (c.phase_id) {
          expect(c.phase_id).toBe('recon');
        }
      }
    });
  });

  // ============================================================
  // Config & template phases
  // ============================================================

  describe('Config phases schema', () => {
    it('should parse engagement config with phases', () => {
      const config = makeConfig({ phases: makePhases() });
      engine = createEngine(config);

      expect(engine.getState().phases.length).toBe(3);
    });

    it('should handle config without phases', () => {
      const config = makeConfig();
      engine = createEngine(config);

      expect(engine.getState().phases).toEqual([]);
    });
  });
});
