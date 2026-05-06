import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import { GraphEngine } from '../graph-engine.js';
import {
  deterministicActionId,
  deterministicEventId,
  actionIdOrUuid,
  eventIdOrUuid,
} from '../deterministic-id.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-deterministic-id.json';

const NONCE = 'a'.repeat(64);

function makeConfig(overrides: Partial<EngagementConfig> = {}): EngagementConfig {
  return {
    id: 'det-test',
    name: 'deterministic-id test',
    created_at: '2026-05-06T17:00:00.000Z',
    scope: { cidrs: ['10.10.10.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
    ...overrides,
  };
}

function cleanup(): void {
  try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch {}
}

describe('deterministic-id (P1.2)', () => {
  describe('deterministicActionId', () => {
    it('returns null when nonce is absent', () => {
      expect(deterministicActionId(null)).toBeNull();
      expect(deterministicActionId(undefined)).toBeNull();
    });

    it('returns the same id for identical inputs', () => {
      const inputs = {
        engagement_nonce: NONCE,
        agent_id: 'a1',
        timestamp: '2026-05-06T17:00:00.000Z',
        command_signature: 'nmap -sV 10.10.10.5',
        sequence: 1,
      };
      expect(deterministicActionId(inputs)).toBe(deterministicActionId(inputs));
    });

    it('different agent_id → different id', () => {
      const base = {
        engagement_nonce: NONCE,
        timestamp: '2026-05-06T17:00:00.000Z',
        command_signature: 'cmd',
        sequence: 1,
      };
      const a = deterministicActionId({ ...base, agent_id: 'a1' })!;
      const b = deterministicActionId({ ...base, agent_id: 'a2' })!;
      expect(a).not.toBe(b);
    });

    it('different sequence → different id', () => {
      const base = {
        engagement_nonce: NONCE,
        agent_id: 'a',
        timestamp: '2026-05-06T17:00:00.000Z',
        command_signature: 'cmd',
      };
      expect(deterministicActionId({ ...base, sequence: 1 }))
        .not.toBe(deterministicActionId({ ...base, sequence: 2 }));
    });

    it('action_id and event_id derived from same inputs differ', () => {
      const inputs = {
        engagement_nonce: NONCE,
        agent_id: 'a',
        timestamp: '2026-05-06T17:00:00.000Z',
        command_signature: 'cmd',
        sequence: 1,
      };
      expect(deterministicActionId(inputs)).not.toBe(deterministicEventId(inputs));
    });

    it('format is `act_<16hex>` / `evt_<16hex>`', () => {
      const a = deterministicActionId({
        engagement_nonce: NONCE, agent_id: 'a',
        timestamp: 't', command_signature: 'c', sequence: 1,
      })!;
      const e = deterministicEventId({
        engagement_nonce: NONCE, agent_id: 'a',
        timestamp: 't', command_signature: 'c', sequence: 1,
      })!;
      expect(a).toMatch(/^act_[0-9a-f]{16}$/);
      expect(e).toMatch(/^evt_[0-9a-f]{16}$/);
    });
  });

  describe('actionIdOrUuid / eventIdOrUuid', () => {
    it('falls back to uuidv4 when nonce absent', () => {
      const id = actionIdOrUuid(null);
      // uuidv4 is 36 chars with dashes; act_ form is 16 hex with prefix.
      expect(id).toMatch(/^[0-9a-f-]{36}$/);
      const id2 = eventIdOrUuid(null);
      expect(id2).toMatch(/^[0-9a-f-]{36}$/);
    });
  });
});

describe('engine-context clock injection (P1.3)', () => {
  let engine: GraphEngine;

  beforeEach(() => {
    cleanup();
    engine = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE_FILE);
  });

  afterEach(() => {
    cleanup();
  });

  it('engine.now() honors withClock injection', () => {
    const pinned = '2026-05-06T17:00:00.000Z';
    const observed = engine.withClock(pinned, () => engine.now());
    expect(observed).toBe(pinned);
    // After withClock, falls back to wall-clock.
    expect(engine.now()).not.toBe(pinned);
  });

  it('logActionEvent inside withClock uses the pinned timestamp', () => {
    const pinned = '2026-05-06T17:00:00.000Z';
    engine.withClock(pinned, () => {
      engine.logActionEvent({ description: 'pinned', event_type: 'system', provenance: 'system' });
    });
    const found = engine.getFullHistory().find(e => e.description === 'pinned');
    expect(found?.timestamp).toBe(pinned);
  });

  it('event_ids are deterministic when nonce + pinned clock are both present', () => {
    cleanup();
    const pinned = '2026-05-06T17:00:00.000Z';
    const eng1 = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE_FILE);
    const idA = eng1.withClock(pinned, () => {
      const e = eng1.logActionEvent({
        description: 'identical event', event_type: 'system', provenance: 'system',
      });
      return e.event_id;
    });

    cleanup();
    const eng2 = new GraphEngine(makeConfig({ engagement_nonce: NONCE }), TEST_STATE_FILE);
    const idB = eng2.withClock(pinned, () => {
      const e = eng2.logActionEvent({
        description: 'identical event', event_type: 'system', provenance: 'system',
      });
      return e.event_id;
    });

    expect(idA).toBe(idB);
    expect(idA).toMatch(/^evt_[0-9a-f]{16}$/);
  });

  it('legacy engagements (no nonce) keep uuidv4 event_ids', () => {
    cleanup();
    const eng = new GraphEngine(makeConfig(), TEST_STATE_FILE); // no nonce
    const e = eng.logActionEvent({
      description: 'legacy event',
      event_type: 'system',
      provenance: 'system',
    });
    expect(e.event_id).toMatch(/^[0-9a-f-]{36}$/);
  });
});
