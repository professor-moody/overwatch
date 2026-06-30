import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, unlinkSync, rmSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerStateTools } from '../../tools/state.js';
import { registerTranscriptTools } from '../../tools/transcripts.js';
import { verifyChain, computeEventHash, GENESIS_HASH, shouldChainEntry } from '../activity-chain.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-activity-chain.json';

function makeConfig(hash_chain_enabled: boolean): EngagementConfig {
  return {
    id: 'test-activity-chain',
    name: 'activity-chain test',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: ['test.local'], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
    hash_chain_enabled,
  };
}

function cleanup(): void {
  try { if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE); } catch {}
  try { rmSync('./evidence-test-activity-chain', { recursive: true, force: true }); } catch {}
}

describe('activity-chain (Phase 6)', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;

  beforeEach(() => {
    cleanup();
    engine = new GraphEngine(makeConfig(true), TEST_STATE_FILE);
    handlers = {};
    const fakeServer = {
      registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
        handlers[name] = handler;
      },
    } as unknown as McpServer;
    registerStateTools(fakeServer, engine);
    registerTranscriptTools(fakeServer, engine);
  });

  afterEach(() => {
    cleanup();
  });

  it('shouldChainEntry rule matches plan: agent/system non-thought participate; ingested/inferred/thought excluded', () => {
    expect(shouldChainEntry({ event_id: 'a', timestamp: 't', description: 'x', provenance: 'agent', event_type: 'action_started' })).toBe(true);
    expect(shouldChainEntry({ event_id: 'b', timestamp: 't', description: 'x', provenance: 'system', event_type: 'instrumentation_warning' })).toBe(true);
    expect(shouldChainEntry({ event_id: 'c', timestamp: 't', description: 'x', provenance: 'agent', event_type: 'thought' })).toBe(false);
    expect(shouldChainEntry({ event_id: 'd', timestamp: 't', description: 'x', provenance: 'ingested', event_type: 'transcript_turn_ingested' })).toBe(false);
    expect(shouldChainEntry({ event_id: 'e', timestamp: 't', description: 'x', provenance: 'inferred', event_type: 'inference_generated' })).toBe(false);
  });

  it('writes prev_hash + event_hash on chained entries; no hash on excluded', () => {
    const baseline = engine.getFullHistory().length;
    engine.logActionEvent({ description: 'agent action 1', event_type: 'action_started', provenance: 'agent' });
    engine.logActionEvent({ description: 'a thought', event_type: 'thought', provenance: 'agent' });
    engine.logActionEvent({ description: 'agent action 2', event_type: 'action_completed', provenance: 'agent' });

    const log = engine.getFullHistory();
    const a = log[baseline];
    const b = log[baseline + 1];
    const c = log[baseline + 2];
    expect(a.event_hash).toBeTruthy();
    expect(b.chain_excluded).toBe(true);
    expect(b.event_hash).toBeUndefined();
    expect(c.prev_hash).toBe(a.event_hash);
    expect(c.event_hash).toBeTruthy();
    expect(c.event_hash).not.toBe(a.event_hash);
  });

  it('verifyChain returns valid for an untampered chain', () => {
    const baselineChained = verifyChain(engine.getFullHistory()).chained_count;
    for (let i = 0; i < 10; i++) {
      engine.logActionEvent({
        description: `event ${i}`,
        event_type: i % 2 === 0 ? 'action_started' : 'action_completed',
        provenance: 'agent',
      });
    }
    const result = verifyChain(engine.getFullHistory());
    expect(result.valid).toBe(true);
    expect(result.chained_count).toBe(baselineChained + 10);
    expect(result.breaks.length).toBe(0);
  });

  it('detects tamper: mutating description breaks event_hash', () => {
    engine.logActionEvent({ description: 'first', event_type: 'action_started', provenance: 'agent' });
    engine.logActionEvent({ description: 'second', event_type: 'action_completed', provenance: 'agent' });
    engine.logActionEvent({ description: 'third', event_type: 'finding_reported', provenance: 'agent' });

    // Tamper in-memory
    const log = engine.getFullHistory();
    log[1].description = 'TAMPERED';

    const result = verifyChain(log);
    expect(result.valid).toBe(false);
    // The mutated entry's recomputed hash won't match its stored hash, AND
    // the next entry's prev_hash points to the (now-stale) stored hash so
    // it still chains correctly. So we expect exactly one break on entry 1.
    expect(result.breaks.length).toBeGreaterThanOrEqual(1);
    expect(result.breaks.some(b => b.reason === 'event_hash_mismatch' && b.index === 1)).toBe(true);
  });

  it('thought + ingested events are counted as excluded but never break the chain', async () => {
    const baseline = verifyChain(engine.getFullHistory());
    engine.logActionEvent({ description: 'a1', event_type: 'action_started', provenance: 'agent' });
    engine.logActionEvent({ description: 'reasoning', event_type: 'thought', provenance: 'agent' });
    await handlers.ingest_transcript({
      transcript_jsonl: '{"role":"user","content":"hi"}\n{"role":"assistant","content":"hello"}\n',
      session_id: 'chain-test',
    });
    engine.logActionEvent({ description: 'a2', event_type: 'action_completed', provenance: 'agent' });

    const result = verifyChain(engine.getFullHistory());
    expect(result.valid).toBe(true);
    expect(result.chained_count).toBe(baseline.chained_count + 2);
    expect(result.excluded_count).toBeGreaterThanOrEqual(baseline.excluded_count + 3);
  });

  it('survives save/reload: chain tail is rebuilt', () => {
    engine.logActionEvent({ description: 'before-restart-1', event_type: 'action_started', provenance: 'agent' });
    engine.logActionEvent({ description: 'before-restart-2', event_type: 'action_completed', provenance: 'agent' });

    // Force persistence then reload
    engine.persist();
    const engine2 = new GraphEngine(makeConfig(true), TEST_STATE_FILE);

    // Engine init logs a 'Resumed engagement from persisted state' system event;
    // it is itself part of the chain. We just need the chain to remain valid and
    // for the new event to extend whatever the latest hash is post-restart.
    const tailBefore = engine2.getFullHistory().slice(-1)[0].event_hash;
    expect(tailBefore).toBeTruthy();

    engine2.logActionEvent({ description: 'after-restart', event_type: 'action_started', provenance: 'agent' });
    const newest = engine2.getFullHistory().slice(-1)[0];
    expect(newest.prev_hash).toBe(tailBefore);

    const result = verifyChain(engine2.getFullHistory());
    expect(result.valid).toBe(true);
  });

  it('hash_chain_enabled=false: no hashes emitted, verify_activity_chain reports chain_disabled', async () => {
    cleanup();
    const e2 = new GraphEngine(makeConfig(false), TEST_STATE_FILE);
    const h2: Record<string, any> = {};
    const fakeServer = {
      registerTool(name: string, _c: unknown, handler: any) { h2[name] = handler; },
    } as unknown as McpServer;
    registerStateTools(fakeServer, e2);

    e2.logActionEvent({ description: 'no chain', event_type: 'action_started', provenance: 'agent' });
    expect(e2.getFullHistory()[0].event_hash).toBeUndefined();
    expect(e2.getFullHistory()[0].chain_excluded).toBeUndefined();

    const result = await h2.verify_activity_chain({});
    const payload = JSON.parse(result.content[0].text);
    expect(payload.chain_disabled).toBe(true);
    expect(payload.valid).toBe(true);
  });

  it('verify_activity_chain tool returns isError=true on tamper', async () => {
    engine.logActionEvent({ description: 'one', event_type: 'action_started', provenance: 'agent' });
    engine.logActionEvent({ description: 'two', event_type: 'action_completed', provenance: 'agent' });
    engine.getFullHistory()[0].description = 'TAMPER';

    const result = await handlers.verify_activity_chain({});
    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.valid).toBe(false);
    expect(payload.breaks.length).toBeGreaterThan(0);
  });

  it('run_graph_health surfaces activity_chain when enabled', async () => {
    engine.logActionEvent({ description: 'hp-1', event_type: 'action_started', provenance: 'agent' });
    const result = await handlers.run_graph_health({});
    const payload = JSON.parse(result.content[0].text);
    expect(payload.activity_chain).toBeDefined();
    expect(payload.activity_chain.enabled).toBe(true);
    expect(payload.activity_chain.valid).toBe(true);
    expect(payload.activity_chain.chained_count).toBeGreaterThanOrEqual(1);
  });

  it('computeEventHash is deterministic for the same canonical entry + prev', () => {
    const entry = {
      event_id: 'fixed',
      timestamp: '2026-05-04T00:00:00.000Z',
      description: 'x',
      provenance: 'agent' as const,
      event_type: 'action_started' as const,
    };
    const h1 = computeEventHash(entry, GENESIS_HASH);
    const h2 = computeEventHash(entry, GENESIS_HASH);
    expect(h1).toBe(h2);
    const h3 = computeEventHash(entry, 'a'.repeat(64));
    expect(h3).not.toBe(h1);
  });
});

// ============================================================
// P0.2: signed checkpoints
// ============================================================

import { shouldEmitCheckpoint, buildCheckpoint, verifyCheckpoints } from '../activity-chain.js';

describe('activity-chain P0.2 (checkpoints)', () => {
  it('shouldEmitCheckpoint emits the first checkpoint as soon as any chained event exists', () => {
    expect(shouldEmitCheckpoint({
      chained_events_since_previous: 1,
      seconds_since_previous_checkpoint: 0,
      has_previous_checkpoint: false,
    })).toBe(true);
  });

  it('shouldEmitCheckpoint waits for the events threshold by default', () => {
    expect(shouldEmitCheckpoint({
      chained_events_since_previous: 100,
      seconds_since_previous_checkpoint: 60,
      has_previous_checkpoint: true,
    })).toBe(false);
    expect(shouldEmitCheckpoint({
      chained_events_since_previous: 500,
      seconds_since_previous_checkpoint: 60,
      has_previous_checkpoint: true,
    })).toBe(true);
  });

  it('shouldEmitCheckpoint also fires on the time-based ceiling', () => {
    expect(shouldEmitCheckpoint({
      chained_events_since_previous: 5,
      seconds_since_previous_checkpoint: 30 * 60,
      has_previous_checkpoint: true,
    })).toBe(true);
  });

  it('engine emits a checkpoint after first chained event when chain is enabled', () => {
    cleanup();
    const eng = new GraphEngine(makeConfig(true), TEST_STATE_FILE);
    // The engine may already have emitted the first checkpoint from init-time
    // chained events (engagement creation logs a system event). What we
    // assert is that AT LEAST ONE checkpoint exists once the chain is non-empty.
    eng.logActionEvent({ description: 'first', event_type: 'action_started', provenance: 'agent' });
    const checkpoints = (eng as any).ctx.chainCheckpoints as ReturnType<typeof buildCheckpoint>[];
    expect(checkpoints.length).toBeGreaterThanOrEqual(1);
    expect(checkpoints[0].event_hash).toBeTruthy();
    // The checkpoint references an event that exists in the log with the
    // matching hash.
    const log = eng.getFullHistory();
    const referenced = log[checkpoints[0].event_index];
    expect(referenced).toBeDefined();
    expect(referenced.event_hash).toBe(checkpoints[0].event_hash);
  });

  it('verifyCheckpoints flags mismatches against tampered events', () => {
    cleanup();
    const eng = new GraphEngine(makeConfig(true), TEST_STATE_FILE);
    eng.logActionEvent({ description: 'first', event_type: 'action_started', provenance: 'agent' });
    const log = eng.getFullHistory();
    const checkpoints = (eng as any).ctx.chainCheckpoints as ReturnType<typeof buildCheckpoint>[];
    // Tamper with the event the checkpoint references.
    log[checkpoints[0].event_index].event_hash = 'bad';
    const result = verifyCheckpoints(log, checkpoints);
    expect(result.valid).toBe(false);
    expect(result.mismatches.length).toBe(1);
  });

  it('verifyChain accepts a starting point so it does not have to walk from genesis', () => {
    cleanup();
    const eng = new GraphEngine(makeConfig(true), TEST_STATE_FILE);
    for (let i = 0; i < 5; i++) {
      eng.logActionEvent({
        description: `e${i}`,
        event_type: i % 2 === 0 ? 'action_started' : 'action_completed',
        provenance: 'agent',
      });
    }
    const log = eng.getFullHistory();
    const checkpoints = (eng as any).ctx.chainCheckpoints as ReturnType<typeof buildCheckpoint>[];
    const cp = checkpoints[checkpoints.length - 1];
    const result = verifyChain(log, { event_index: cp.event_index, event_hash: cp.event_hash });
    expect(result.valid).toBe(true);
  });
});

describe('checkpoint signing (Ed25519)', () => {
  const baseCp = (): import('../activity-chain.js').ChainCheckpoint => ({
    event_index: 7, event_id: 'evt-7', event_hash: 'deadbeef', events_since_previous: 7, emitted_at: '2026-06-30T00:00:00.000Z',
  });

  it('generateCheckpointKeypair produces a stable key id + sign/verify roundtrip', async () => {
    const { generateCheckpointKeypair, checkpointKeyId, signCheckpoint, verifyCheckpointSignature } = await import('../activity-chain.js');
    const kp = generateCheckpointKeypair();
    expect(kp.keyId).toMatch(/^ed25519:[0-9a-f]{16}$/);
    expect(checkpointKeyId(kp.publicKeyPem)).toBe(kp.keyId); // stable
    const signed = signCheckpoint(baseCp(), kp.privateKeyPem, kp.keyId);
    expect(signed.signing_key_id).toBe(kp.keyId);
    expect(typeof signed.signature).toBe('string');
    expect(verifyCheckpointSignature(signed, kp.publicKeyPem)).toBe(true);
  });

  it('detects tamper and wrong-key; unsigned verifies false', async () => {
    const { generateCheckpointKeypair, signCheckpoint, verifyCheckpointSignature } = await import('../activity-chain.js');
    const kp = generateCheckpointKeypair();
    const other = generateCheckpointKeypair();
    const signed = signCheckpoint(baseCp(), kp.privateKeyPem, kp.keyId);
    expect(verifyCheckpointSignature({ ...signed, event_hash: 'tampered' }, kp.publicKeyPem)).toBe(false); // tamper
    expect(verifyCheckpointSignature(signed, other.publicKeyPem)).toBe(false); // wrong key
    expect(verifyCheckpointSignature(baseCp(), kp.publicKeyPem)).toBe(false);  // unsigned
  });

  it('verifyCheckpointSignatures: batch report (verified / unverifiable / failed; unsigned ignored)', async () => {
    const { generateCheckpointKeypair, signCheckpoint, verifyCheckpointSignatures } = await import('../activity-chain.js');
    const kp = generateCheckpointKeypair();
    const ok = signCheckpoint({ ...baseCp(), event_index: 1 }, kp.privateKeyPem, kp.keyId);
    const tampered = { ...signCheckpoint({ ...baseCp(), event_index: 2 }, kp.privateKeyPem, kp.keyId), event_hash: 'x' };
    const unknownKey = signCheckpoint({ ...baseCp(), event_index: 3 }, generateCheckpointKeypair().privateKeyPem, 'ed25519:unknownkeyid000');
    const unsigned = { ...baseCp(), event_index: 4 };
    const rep = verifyCheckpointSignatures([ok, tampered, unknownKey, unsigned], { [kp.keyId]: kp.publicKeyPem });
    expect(rep.total).toBe(4);
    expect(rep.signed).toBe(3);          // unsigned ignored
    expect(rep.verified).toBe(1);        // ok
    expect(rep.failed).toEqual([2]);     // tampered
    expect(rep.unverifiable).toEqual([3]); // unknown key id
  });

  it('loadCheckpointSigningKey / loadCheckpointKeyring read env (base64 PEM); unset → null/{}', async () => {
    const { generateCheckpointKeypair, loadCheckpointSigningKey, loadCheckpointKeyring } = await import('../activity-chain.js');
    const kp = generateCheckpointKeypair();
    const b64 = (pem: string) => Buffer.from(pem, 'utf8').toString('base64');
    expect(loadCheckpointSigningKey({})).toBeNull();
    expect(loadCheckpointKeyring({})).toEqual({});
    const loaded = loadCheckpointSigningKey({ OVERWATCH_CHECKPOINT_SIGNING_KEY: b64(kp.privateKeyPem) } as NodeJS.ProcessEnv);
    expect(loaded?.keyId).toBe(kp.keyId);
    // Signer + independent verifier derive the SAME key id from the same key (symmetry).
    const ring = loadCheckpointKeyring({ OVERWATCH_CHECKPOINT_PUBLIC_KEY: b64(kp.publicKeyPem) } as NodeJS.ProcessEnv);
    expect(ring[kp.keyId]).toContain('BEGIN PUBLIC KEY');
    expect(loadCheckpointSigningKey({ OVERWATCH_CHECKPOINT_SIGNING_KEY: 'not-a-key' } as NodeJS.ProcessEnv)).toBeNull(); // malformed → null
  });

  it('attestCheckpointSignatures is STRICT: unsigned / failed / unverifiable all fail', async () => {
    const { attestCheckpointSignatures } = await import('../activity-chain.js');
    expect(attestCheckpointSignatures({ total: 3, signed: 3, verified: 3, failed: [], unverifiable: [] }).ok).toBe(true);
    expect(attestCheckpointSignatures({ total: 3, signed: 2, verified: 2, failed: [], unverifiable: [] }).ok).toBe(false); // one unsigned
    expect(attestCheckpointSignatures({ total: 2, signed: 2, verified: 1, failed: [1], unverifiable: [] }).ok).toBe(false); // one failed
    expect(attestCheckpointSignatures({ total: 2, signed: 2, verified: 1, failed: [], unverifiable: [1] }).ok).toBe(false); // forged/unknown key
    expect(attestCheckpointSignatures({ total: 0, signed: 0, verified: 0, failed: [], unverifiable: [] }).ok).toBe(true);  // nothing to attest
  });

  it('engine signs emitted checkpoints when a signing key is configured', async () => {
    const { generateCheckpointKeypair, verifyCheckpointSignature } = await import('../activity-chain.js');
    const kp = generateCheckpointKeypair();
    const prev = process.env.OVERWATCH_CHECKPOINT_SIGNING_KEY;
    process.env.OVERWATCH_CHECKPOINT_SIGNING_KEY = Buffer.from(kp.privateKeyPem, 'utf8').toString('base64');
    const stateFile = './state-test-activity-chain-signed.json';
    try {
      const signedEngine = new GraphEngine(makeConfig(true), stateFile);
      signedEngine.logActionEvent({ description: 'agent action', event_type: 'action_started', provenance: 'agent' });
      const cps = signedEngine.getChainCheckpoints();
      expect(cps.length).toBeGreaterThan(0);
      const cp = cps[0];
      expect(cp.signature).toBeTruthy();
      expect(cp.signing_key_id).toBe(kp.keyId);
      expect(verifyCheckpointSignature(cp, kp.publicKeyPem)).toBe(true);
    } finally {
      if (prev === undefined) delete process.env.OVERWATCH_CHECKPOINT_SIGNING_KEY; else process.env.OVERWATCH_CHECKPOINT_SIGNING_KEY = prev;
      try { if (existsSync(stateFile)) unlinkSync(stateFile); } catch {}
    }
  });
});
