import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { EngagementConfig } from '../../types.js';
import {
  CampaignCommandError,
  CampaignCommandService,
} from '../campaign-command-service.js';
import { GraphEngine } from '../graph-engine.js';

function config(): EngagementConfig {
  return {
    id: 'campaign-command-test',
    name: 'campaign command test',
    created_at: new Date().toISOString(),
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'test', enabled: false, max_noise: 1 },
  } as EngagementConfig;
}

describe('CampaignCommandService', () => {
  let dir: string;
  let stateFile: string;
  let engine: GraphEngine;
  let service: CampaignCommandService;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'overwatch-campaign-command-'));
    stateFile = join(dir, 'state.json');
    engine = new GraphEngine(config(), stateFile);
    service = new CampaignCommandService(engine);
  });

  afterEach(() => {
    engine.dispose();
    rmSync(dir, { recursive: true, force: true });
  });

  it('replays create without producing a duplicate campaign', () => {
    const metadata = {
      transport: 'dashboard' as const,
      command_id: 'campaign-create-command',
      idempotency_key: 'campaign-create-attempt',
    };
    const input = {
      name: 'Enumerate targets',
      strategy: 'enumeration',
      item_ids: ['frontier-a', 'frontier-b'],
    };
    const first = service.create(input, metadata);
    const replay = service.create(input, metadata);

    expect(replay.replayed).toBe(true);
    expect(replay.result).toEqual(first.result);
    expect(engine.listCampaigns()).toHaveLength(1);
  });

  it('preserves update/action/clone/delete idempotency', () => {
    const created = service.create({
      name: 'Campaign',
      strategy: 'custom',
      item_ids: ['frontier-a', 'frontier-b'],
    }, {
      transport: 'mcp',
      command_id: 'create-command',
      idempotency_key: 'create-command',
    }).result!.campaign;
    const updated = service.update(created.id, {
      name: 'Updated campaign',
    }, {
      transport: 'mcp',
      command_id: 'update-command',
      idempotency_key: 'update-command',
    });
    expect(updated.result?.campaign.name).toBe('Updated campaign');
    expect(service.action(created.id, { action: 'activate' }, {
      transport: 'dashboard',
      command_id: 'activate-command',
      idempotency_key: 'activate-command',
    }).result?.campaign.status).toBe('active');
    expect(service.action(created.id, { action: 'pause' }, {
      transport: 'dashboard',
      command_id: 'pause-command',
      idempotency_key: 'pause-command',
    }).result?.campaign.status).toBe('paused');
    const clone = service.clone(created.id, {
      transport: 'dashboard',
      command_id: 'clone-command',
      idempotency_key: 'clone-command',
    });
    const cloneReplay = service.clone(created.id, {
      transport: 'dashboard',
      command_id: 'clone-command',
      idempotency_key: 'clone-command',
    });
    expect(cloneReplay.result?.campaign.id).toBe(clone.result?.campaign.id);
    const cloneId = clone.result!.campaign.id;
    service.delete(cloneId, {
      transport: 'dashboard',
      command_id: 'delete-command',
      idempotency_key: 'delete-command',
    });
    expect(service.delete(cloneId, {
      transport: 'dashboard',
      command_id: 'delete-command',
      idempotency_key: 'delete-command',
    }).replayed).toBe(true);
  });

  it('splits once and replays the same children', () => {
    const campaign = service.create({
      name: 'Split campaign',
      strategy: 'custom',
      item_ids: ['frontier-a', 'frontier-b', 'frontier-c'],
    }, {
      transport: 'dashboard',
      command_id: 'split-create',
      idempotency_key: 'split-create',
    }).result!.campaign;
    const metadata = {
      transport: 'dashboard' as const,
      command_id: 'split-command',
      idempotency_key: 'split-command',
    };
    const first = service.split(campaign.id, 2, metadata);
    const replay = service.split(campaign.id, 2, metadata);
    expect(replay.replayed).toBe(true);
    expect(replay.result?.children.map(child => child.id))
      .toEqual(first.result?.children.map(child => child.id));
    expect(engine.getCampaignChildren(campaign.id)).toHaveLength(2);
  });

  it('rejects invalid lifecycle transitions with a durable failure', () => {
    const campaign = service.create({
      name: 'Draft campaign',
      strategy: 'custom',
      item_ids: ['frontier-a'],
    }, {
      transport: 'dashboard',
      command_id: 'invalid-create',
      idempotency_key: 'invalid-create',
    }).result!.campaign;
    expect(() => service.action(campaign.id, { action: 'resume' }, {
      transport: 'dashboard',
      command_id: 'invalid-resume',
      idempotency_key: 'invalid-resume',
    })).toThrowError(CampaignCommandError);
    expect(engine.getApplicationCommandById('invalid-resume')).toMatchObject({
      status: 'failed',
      error: { code: 'CAMPAIGN_ACTION_NOT_APPLICABLE' },
    });
  });
});
