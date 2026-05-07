import { describe, it, expect, afterEach } from 'vitest';
import { existsSync, unlinkSync, readFileSync, writeFileSync, rmSync } from 'fs';
import { join } from 'path';
import { GraphEngine } from '../../services/graph-engine.js';
import { replayTape, rerecordTape, hashGraph, type GoldenTape } from '../../services/golden-replay.js';
import type { EngagementConfig } from '../../types.js';

const FIXTURES_DIR = join(__dirname, 'fixtures');

function tapePath(name: string): string {
  return join(FIXTURES_DIR, `${name}.json`);
}

function loadTape(name: string): GoldenTape {
  return JSON.parse(readFileSync(tapePath(name), 'utf-8'));
}

function freshEngine(config: EngagementConfig, stateFile: string): GraphEngine {
  return new GraphEngine(config, stateFile);
}

function cleanup(stateFile: string): void {
  for (const f of [stateFile, stateFile + '.journal.jsonl']) {
    try { if (existsSync(f)) unlinkSync(f); } catch {}
  }
  try { rmSync('./.snapshots', { recursive: true, force: true }); } catch {}
}

describe('Golden-master replay (P2.2)', () => {
  const stateFile = './state-test-golden-master.json';

  afterEach(() => cleanup(stateFile));

  it('replays the small-recon tape deterministically', () => {
    const tape = loadTape('small-recon');
    cleanup(stateFile);
    const eng1 = freshEngine(tape.config, stateFile);
    const r1 = replayTape(eng1, tape);

    cleanup(stateFile);
    const eng2 = freshEngine(tape.config, stateFile);
    const r2 = replayTape(eng2, tape);

    // Two replays of the same tape against fresh engines produce the
    // same canonical state hash. This is the core determinism contract
    // P1.2 + P1.3 deliver.
    expect(r1.graph_hash).toBe(r2.graph_hash);
    expect(r1.activity_digest).toBe(r2.activity_digest);
  });

  it('matches the stored expected hashes (fails loudly when behavior drifts)', () => {
    const tape = loadTape('small-recon');
    cleanup(stateFile);
    const eng = freshEngine(tape.config, stateFile);
    const result = replayTape(eng, tape);

    if (tape.expected_graph_hash == null) { // treat both null and undefined as "not yet recorded"
      // First run: re-record. Real CI runs always have a stored hash;
      // this branch is a developer-convenience for tape authoring.
      const updated = rerecordTape(tape, result);
      writeFileSync(tapePath('small-recon'), JSON.stringify(updated, null, 2) + '\n');
      // The act of recording counts as a pass in the bootstrap run.
      return;
    }

    if (!result.matches_expected) {
      // Surface the actual hashes so re-recording is a one-line update.
      const msg = [
        `Golden-master drift detected for tape '${tape.name}':`,
        `  expected graph_hash: ${tape.expected_graph_hash}`,
        `  actual   graph_hash: ${result.graph_hash}`,
        `  expected activity_digest: ${tape.expected_activity_digest}`,
        `  actual   activity_digest: ${result.activity_digest}`,
        '',
        'If this drift is intentional, re-record the tape by clearing',
        'the expected_* fields in the fixture file and re-running the test.',
      ].join('\n');
      throw new Error(msg);
    }

    expect(result.matches_expected).toBe(true);
  });

  it('legacy engagement (no nonce) replays the tape but hashes are NOT promised stable', () => {
    // Strip the nonce to simulate a legacy engagement. We don't assert
    // determinism — UUIDs and Date.now() leak in. We just assert the
    // replay completes without error and produces SOMETHING.
    const tape = loadTape('small-recon');
    const legacyConfig = { ...tape.config };
    delete (legacyConfig as { engagement_nonce?: string }).engagement_nonce;
    cleanup(stateFile);
    const eng = freshEngine(legacyConfig, stateFile);
    const result = replayTape(eng, { ...tape, config: legacyConfig });
    expect(result.graph_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(result.graph.nodes.length).toBeGreaterThan(0);
  });

  it('hashGraph is independent of node/edge insertion order', () => {
    const tape = loadTape('small-recon');
    cleanup(stateFile);
    const eng = freshEngine(tape.config, stateFile);
    replayTape(eng, tape);
    const graph = eng.exportGraph();

    // Reverse the arrays — hash should still match because hashGraph
    // sorts internally before canonicalization.
    const shuffled = {
      ...graph,
      nodes: [...graph.nodes].reverse(),
      edges: [...graph.edges].reverse(),
    };
    expect(hashGraph(graph)).toBe(hashGraph(shuffled));
  });
});
