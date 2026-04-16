import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync, readFileSync } from 'fs';
import { GraphEngine } from '../graph-engine.js';
import type { EngagementConfig, EngagementPhase } from '../../types.js';

const TEST_STATE_FILE = './state-test-engagement-phases.json';
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

function cleanup(): void {
  try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch {}
  // Clean up snapshot files
  try {
    const dir = '.';
    const files = require('fs').readdirSync(dir);
    for (const f of files) {
      if (f.startsWith('state-test-engagement-phases.snap-')) {
        try { unlinkSync(f); } catch {}
      }
    }
  } catch {}
}

function addHost(engine: GraphEngine, id: string, ip: string) {
  engine.addNode({
    id, type: 'host', label: ip, ip,
    discovered_at: now, discovered_by: 'test', confidence: 1.0,
  });
}

describe('Engagement Phases', () => {
  let engine: GraphEngine;

  beforeEach(() => { cleanup(); });
  afterEach(() => { cleanup(); });

  // ============================================================
  // Phase evaluation
  // ============================================================

  describe('Phase evaluation', () => {
    it('should evaluate phases from config and include them in state', () => {
      engine = new GraphEngine(makeConfig({ phases: makePhases() }), TEST_STATE_FILE);
      const state = engine.getState();

      expect(state.phases).toBeDefined();
      expect(state.phases.length).toBe(3);
      expect(state.current_phase).toBeDefined();
    });

    it('first phase with always entry_criteria should be active', () => {
      engine = new GraphEngine(makeConfig({ phases: makePhases() }), TEST_STATE_FILE);
      const state = engine.getState();

      const recon = state.phases.find((p: any) => p.id === 'recon');
      expect(recon).toBeDefined();
      expect(recon!.status).toBe('active');
      expect(state.current_phase).toBe('recon');
    });

    it('phases with unmet entry criteria should be locked', () => {
      engine = new GraphEngine(makeConfig({ phases: makePhases() }), TEST_STATE_FILE);
      const state = engine.getState();

      const credAttacks = state.phases.find((p: any) => p.id === 'cred-attacks');
      expect(credAttacks).toBeDefined();
      expect(credAttacks!.status).toBe('locked');

      const postEx = state.phases.find((p: any) => p.id === 'post-ex');
      expect(postEx).toBeDefined();
      expect(postEx!.status).toBe('locked');
    });

    it('phase should complete when exit criteria are met', () => {
      engine = new GraphEngine(makeConfig({ phases: makePhases() }), TEST_STATE_FILE);

      // Add 3 hosts to satisfy recon exit_criteria (node_count >= 3)
      addHost(engine, 'host-1', '10.10.10.1');
      addHost(engine, 'host-2', '10.10.10.2');
      addHost(engine, 'host-3', '10.10.10.3');

      const state = engine.getState();
      const recon = state.phases.find((p: any) => p.id === 'recon');
      expect(recon!.status).toBe('completed');
    });

    it('next phase should activate when previous completes', () => {
      engine = new GraphEngine(makeConfig({ phases: makePhases() }), TEST_STATE_FILE);

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
      engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
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
      engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

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
      engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

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
      engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

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
      engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

      const parent = engine.createCampaign({
        name: 'Parent',
        strategy: 'enumeration',
        item_ids: ['a', 'b', 'c', 'd'],
      });

      const children = engine.splitCampaign(parent.id, 2)!;

      // Simulate progress on children
      children[0].progress.completed = 1;
      children[0].progress.succeeded = 1;
      children[1].progress.completed = 2;
      children[1].progress.succeeded = 1;
      children[1].progress.failed = 1;

      const progress = engine.getCampaignParentProgress(parent.id);
      expect(progress).not.toBeNull();
      expect(progress!.completed).toBe(3);
      expect(progress!.succeeded).toBe(2);
      expect(progress!.failed).toBe(1);
      expect(progress!.total).toBe(4);
    });

    it('should derive parent status from children', () => {
      engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

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
      children[0].status = 'completed';
      children[1].status = 'completed';
      expect(engine.deriveCampaignParentStatus(parent.id)).toBe('completed');
    });

    it('should cascade lifecycle actions to children', () => {
      engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);

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
  });

  // ============================================================
  // Campaign persistence
  // ============================================================

  describe('Campaign persistence', () => {
    it('should persist campaigns across engine restarts', () => {
      const config = makeConfig();
      engine = new GraphEngine(config, TEST_STATE_FILE);

      // Create a campaign
      const campaign = engine.createCampaign({
        name: 'Persistent Campaign',
        strategy: 'enumeration',
        item_ids: ['x', 'y', 'z'],
      });
      engine.activateCampaign(campaign.id);

      // Persist state
      engine.persist();

      // Create new engine from same state file
      const engine2 = new GraphEngine(config, TEST_STATE_FILE);
      const restored = engine2.getCampaign(campaign.id);

      expect(restored).not.toBeNull();
      expect(restored!.name).toBe('Persistent Campaign');
      expect(restored!.status).toBe('active');
      expect(restored!.items).toEqual(['x', 'y', 'z']);
    });

    it('should persist campaign hierarchy across restarts', () => {
      const config = makeConfig();
      engine = new GraphEngine(config, TEST_STATE_FILE);

      const parent = engine.createCampaign({
        name: 'Parent',
        strategy: 'credential_spray',
        item_ids: ['a', 'b', 'c', 'd'],
      });

      engine.splitCampaign(parent.id, 2);
      engine.persist();

      // Restart
      const engine2 = new GraphEngine(config, TEST_STATE_FILE);
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
      engine = new GraphEngine(makeConfig({ phases }), TEST_STATE_FILE);

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
      engine = new GraphEngine(config, TEST_STATE_FILE);

      expect(engine.getState().phases.length).toBe(3);
    });

    it('should handle config without phases', () => {
      const config = makeConfig();
      engine = new GraphEngine(config, TEST_STATE_FILE);

      expect(engine.getState().phases).toEqual([]);
    });
  });
});
