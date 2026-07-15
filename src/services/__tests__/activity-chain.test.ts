import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerStateTools } from '../../tools/state.js';
import { registerTranscriptTools } from '../../tools/transcripts.js';
import { verifyChain, computeEventHash, GENESIS_HASH, shouldChainEntry } from '../activity-chain.js';
import type { EngagementConfig } from '../../types.js';

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

let testDir: string;
const engines = new Set<GraphEngine>();

function createEngine(config: EngagementConfig, filename = 'state.json'): GraphEngine {
  const engine = new GraphEngine(config, join(testDir, filename));
  engines.add(engine);
  return engine;
}

beforeEach(() => {
  testDir = mkdtempSync(join(tmpdir(), 'overwatch-activity-chain-'));
});

afterEach(() => {
  for (const engine of engines) engine.dispose();
  engines.clear();
  rmSync(testDir, { recursive: true, force: true });
});

describe('activity-chain (Phase 6)', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;

  beforeEach(() => {
    engine = createEngine(makeConfig(true));
    handlers = {};
    const fakeServer = {
      registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
        handlers[name] = handler;
      },
    } as unknown as McpServer;
    registerStateTools(fakeServer, engine);
    registerTranscriptTools(fakeServer, engine);
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
    engine.flushNow();
    engine.dispose();
    engines.delete(engine);
    const engine2 = createEngine(makeConfig(true));

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
    const e2 = createEngine(makeConfig(false), 'disabled.json');
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
    // Public read surfaces are detached so callers cannot mutate durable state.
    // Reach through the test-only internal context to simulate on-disk/runtime
    // corruption for the verifier itself.
    (engine as any).ctx.activityLog[0].description = 'TAMPER';

    const result = await handlers.verify_activity_chain({});
    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.valid).toBe(false);
    expect(payload.breaks.length).toBeGreaterThan(0);
  });

  it('verify_activity_chain hard-fails when a verifier key is configured but checkpoints were STRIPPED', async () => {
    const { generateCheckpointKeypair } = await import('../activity-chain.js');
    const kp = generateCheckpointKeypair();
    const prev = process.env.OVERWATCH_CHECKPOINT_PUBLIC_KEY;
    process.env.OVERWATCH_CHECKPOINT_PUBLIC_KEY = Buffer.from(kp.publicKeyPem, 'utf8').toString('base64');
    const e3 = createEngine(makeConfig(true), 'empty.json');
    const h3: Record<string, any> = {};
    registerStateTools({ registerTool(n: string, _c: unknown, fn: any) { h3[n] = fn; } } as unknown as McpServer, e3);
    try {
      e3.logActionEvent({ description: 'a', event_type: 'action_started', provenance: 'agent' });
      // Attacker strips every checkpoint from the (signed) run to dodge attestation.
      e3.getChainCheckpoints().length = 0;
      const payload = JSON.parse((await h3.verify_activity_chain({})).content[0].text);
      expect(payload.checkpoint_attestation).toMatchObject({ configured: true, ok: false });
      expect(payload.checkpoint_attestation.reason).toMatch(/no checkpoints/i);
    } finally {
      if (prev === undefined) delete process.env.OVERWATCH_CHECKPOINT_PUBLIC_KEY; else process.env.OVERWATCH_CHECKPOINT_PUBLIC_KEY = prev;
    }
  });

  it('tieredTruncate bounds the log AND keeps the surviving chain contiguous + verifiable', async () => {
    const { tieredTruncate } = await import('../engine-context.js');
    const { verifyChain, computeEventHash, GENESIS_HASH } = await import('../activity-chain.js');
    // Build a long, fully-chained log (every entry chains) exceeding the budget.
    const log: any[] = [];
    let prev = GENESIS_HASH;
    for (let i = 0; i < 50; i += 1) {
      const e: any = { event_id: `e${i}`, event_type: 'action_started', timestamp: `2026-06-30T00:00:${String(i).padStart(2, '0')}.000Z`, provenance: 'agent', description: `d${i}`, prev_hash: prev };
      e.event_hash = computeEventHash(e, prev);
      prev = e.event_hash;
      log.push(e);
    }
    const budget = 20;
    const out = tieredTruncate(log, budget);
    expect(out.length).toBeLessThanOrEqual(budget);       // bounded (was unbounded before)
    expect(out.length).toBeGreaterThan(0);
    // Kept entries are the most-recent, contiguous, in original order.
    expect(out[out.length - 1].event_id).toBe('e49');
    // Seed verify from the window's first prev_hash → the surviving sub-chain verifies clean.
    const seed = { event_index: -1, event_hash: out[0].prev_hash! };
    const r = verifyChain(out, seed);
    expect(r.breaks).toHaveLength(0);
  });

  it('OVERWATCH_CHECKPOINT_ENGAGEMENT_NONCE external anchor is authoritative and rejects a config-nonce mismatch', async () => {
    const { generateCheckpointKeypair } = await import('../activity-chain.js');
    const kp = generateCheckpointKeypair();
    const prevPub = process.env.OVERWATCH_CHECKPOINT_PUBLIC_KEY;
    const prevSign = process.env.OVERWATCH_CHECKPOINT_SIGNING_KEY;
    const prevNonce = process.env.OVERWATCH_CHECKPOINT_ENGAGEMENT_NONCE;
    process.env.OVERWATCH_CHECKPOINT_SIGNING_KEY = Buffer.from(kp.privateKeyPem, 'utf8').toString('base64');
    process.env.OVERWATCH_CHECKPOINT_PUBLIC_KEY = Buffer.from(kp.publicKeyPem, 'utf8').toString('base64');
    // Engagement with a specific nonce; the external anchor will DISAGREE (splice).
    const cfg = makeConfig(true);
    (cfg as any).engagement_nonce = 'engagement-A';
    const eA = createEngine(cfg, 'anchor.json');
    const hA: Record<string, any> = {};
    registerStateTools({ registerTool(n: string, _c: unknown, fn: any) { hA[n] = fn; } } as unknown as McpServer, eA);
    try {
      eA.logActionEvent({ description: 'x', event_type: 'action_started', provenance: 'agent' });
      // Verifier expects engagement-B out-of-band → config/checkpoints are A → reject.
      process.env.OVERWATCH_CHECKPOINT_ENGAGEMENT_NONCE = 'engagement-B';
      const bad = JSON.parse((await hA.verify_activity_chain({})).content[0].text);
      expect(bad.checkpoint_attestation.ok).toBe(false);
      expect(bad.checkpoint_attestation.reason).toMatch(/anchor|nonce/i);
      // Correct anchor → attests.
      process.env.OVERWATCH_CHECKPOINT_ENGAGEMENT_NONCE = 'engagement-A';
      const good = JSON.parse((await hA.verify_activity_chain({})).content[0].text);
      expect(good.checkpoint_attestation.ok).toBe(true);
    } finally {
      const restore = (k: string, v: string | undefined) => { if (v === undefined) delete process.env[k]; else process.env[k] = v; };
      restore('OVERWATCH_CHECKPOINT_PUBLIC_KEY', prevPub);
      restore('OVERWATCH_CHECKPOINT_SIGNING_KEY', prevSign);
      restore('OVERWATCH_CHECKPOINT_ENGAGEMENT_NONCE', prevNonce);
    }
  });

  it('verify_activity_chain attests + binds a signed run with a matching verifier key', async () => {
    const { generateCheckpointKeypair } = await import('../activity-chain.js');
    const kp = generateCheckpointKeypair();
    const prevSign = process.env.OVERWATCH_CHECKPOINT_SIGNING_KEY;
    const prevPub = process.env.OVERWATCH_CHECKPOINT_PUBLIC_KEY;
    process.env.OVERWATCH_CHECKPOINT_SIGNING_KEY = Buffer.from(kp.privateKeyPem, 'utf8').toString('base64');
    process.env.OVERWATCH_CHECKPOINT_PUBLIC_KEY = Buffer.from(kp.publicKeyPem, 'utf8').toString('base64');
    const e4 = createEngine(makeConfig(true), 'signed-verify.json');
    const h4: Record<string, any> = {};
    registerStateTools({ registerTool(n: string, _c: unknown, fn: any) { h4[n] = fn; } } as unknown as McpServer, e4);
    try {
      e4.logActionEvent({ description: 'a', event_type: 'action_started', provenance: 'agent' });
      e4.logActionEvent({ description: 'b', event_type: 'action_completed', provenance: 'agent' });
      expect(e4.getChainCheckpoints().length).toBeGreaterThan(0);
      const res = await h4.verify_activity_chain({});
      const payload = JSON.parse(res.content[0].text);
      expect(payload.valid).toBe(true);
      expect(payload.checkpoint_binding.valid).toBe(true);
      expect(payload.checkpoint_attestation).toMatchObject({ configured: true, ok: true });
      expect(res.isError).toBeFalsy();
    } finally {
      if (prevSign === undefined) delete process.env.OVERWATCH_CHECKPOINT_SIGNING_KEY; else process.env.OVERWATCH_CHECKPOINT_SIGNING_KEY = prevSign;
      if (prevPub === undefined) delete process.env.OVERWATCH_CHECKPOINT_PUBLIC_KEY; else process.env.OVERWATCH_CHECKPOINT_PUBLIC_KEY = prevPub;
    }
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
    const eng = createEngine(makeConfig(true));
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
    const eng = createEngine(makeConfig(true));
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
    const eng = createEngine(makeConfig(true));
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
    schema_version: 1, event_index: 7, event_id: 'evt-7', event_hash: 'deadbeef',
    events_since_previous: 7, emitted_at: '2026-06-30T00:00:00.000Z', engagement_nonce: null,
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

  it('verifyCheckpoints binds by event_id and survives log reindexing (truncation)', async () => {
    const { verifyCheckpoints } = await import('../activity-chain.js');
    // Log where the checkpointed event_id 'evt-7' has moved to a DIFFERENT index
    // (as tieredTruncate would do). Index-based lookup would validate the wrong
    // entry; event_id lookup finds it.
    const log = [
      { event_id: 'evt-3', event_hash: 'h3' },
      { event_id: 'evt-5', event_hash: 'h5' },
      { event_id: 'evt-7', event_hash: 'deadbeef' }, // index 2, but cp.event_index says 7
    ] as any[];
    const cp = baseCp(); // event_index: 7, event_id: 'evt-7', event_hash: 'deadbeef'
    expect(verifyCheckpoints(log, [cp]).valid).toBe(true);
    // Tamper the log entry's hash → binding fails (present event, wrong hash).
    const tamperedLog = [{ event_id: 'evt-7', event_hash: 'REHASHED' }] as any[];
    const r = verifyCheckpoints(tamperedLog, [cp]);
    expect(r.valid).toBe(false);
    expect(r.mismatches).toHaveLength(1);
    // Checkpointed event no longer in the (bounded) log → AGED-OUT, not a tamper:
    // a malicious drop+rehash is caught by later checkpoints / verifyChain, and
    // flagging it here would false-positive on the rolling window + legacy state.
    const aged = verifyCheckpoints([{ event_id: 'evt-9', event_hash: 'h9' }] as any[], [cp]);
    expect(aged.valid).toBe(true);
    expect(aged.aged_out).toHaveLength(1);
    expect(aged.mismatches).toHaveLength(0);
  });

  it('checkpointsBindToEngagement rejects a spliced (wrong-nonce) or wrong-schema checkpoint', async () => {
    const { checkpointsBindToEngagement } = await import('../activity-chain.js');
    const cpA = { ...baseCp(), engagement_nonce: 'nonce-A' };
    expect(checkpointsBindToEngagement([cpA], 'nonce-A').ok).toBe(true);
    // Spliced into engagement B (same operator key, different engagement) → rejected.
    expect(checkpointsBindToEngagement([cpA], 'nonce-B').ok).toBe(false);
    // Downgrade / unknown schema → rejected.
    expect(checkpointsBindToEngagement([{ ...cpA, schema_version: 0 }], 'nonce-A').ok).toBe(false);
    // Legacy (null nonce) matches a legacy engagement.
    expect(checkpointsBindToEngagement([{ ...baseCp(), engagement_nonce: null }], null).ok).toBe(true);
  });

  it('a checkpoint signed for engagement A verifies its OWN bytes but does not bind to B (anti-splice)', async () => {
    const { generateCheckpointKeypair, signCheckpoint, verifyCheckpointSignature, checkpointsBindToEngagement } = await import('../activity-chain.js');
    const kp = generateCheckpointKeypair();
    const cpA = signCheckpoint({ ...baseCp(), engagement_nonce: 'engagement-A' }, kp.privateKeyPem, kp.keyId);
    // The signature is valid over its own (nonce-bound) canonical bytes...
    expect(verifyCheckpointSignature(cpA, kp.publicKeyPem)).toBe(true);
    // ...but the engagement-binding check rejects reuse in engagement B.
    expect(checkpointsBindToEngagement([cpA], 'engagement-B').ok).toBe(false);
    expect(checkpointsBindToEngagement([cpA], 'engagement-A').ok).toBe(true);
  });

  it('engine signs emitted checkpoints when a signing key is configured', async () => {
    const { generateCheckpointKeypair, verifyCheckpointSignature } = await import('../activity-chain.js');
    const kp = generateCheckpointKeypair();
    const prev = process.env.OVERWATCH_CHECKPOINT_SIGNING_KEY;
    process.env.OVERWATCH_CHECKPOINT_SIGNING_KEY = Buffer.from(kp.privateKeyPem, 'utf8').toString('base64');
    try {
      const signedEngine = createEngine(makeConfig(true), 'signed.json');
      signedEngine.logActionEvent({ description: 'agent action', event_type: 'action_started', provenance: 'agent' });
      const cps = signedEngine.getChainCheckpoints();
      expect(cps.length).toBeGreaterThan(0);
      const cp = cps[0];
      expect(cp.signature).toBeTruthy();
      expect(cp.signing_key_id).toBe(kp.keyId);
      expect(verifyCheckpointSignature(cp, kp.publicKeyPem)).toBe(true);
    } finally {
      if (prev === undefined) delete process.env.OVERWATCH_CHECKPOINT_SIGNING_KEY; else process.env.OVERWATCH_CHECKPOINT_SIGNING_KEY = prev;
    }
  });
});
