// ============================================================
// Orchestration eval — pipeline plumbing smoke (fake)
// ============================================================
// Validates the orchestration eval end-to-end deterministically: a fake PRIMARY
// (no archetype → orchestrate) dispatches a child, which runs as a fake 'auto'
// child (has an archetype → lands type-matched findings), and the result maps into
// an OrchRunRecord the rubric grades. fake-claude is scripted + emits no tool_use
// stream-json, so the tool-call criteria (orients / externalizes / synthesizes)
// need a real model and are NOT asserted here — this proves the dispatch→child→
// findings→record→grade PIPELINE, like the sub-agent plumbing smoke.
import { describe, it, expect, afterEach, beforeAll } from 'vitest';
import { join, resolve } from 'path';
import { chmodSync, mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { createServer } from 'net';
import { runOrchestrationScenario, type OrchEvalResult } from '../test-support/eval-run.js';
import { gradeOrchestration, ORCH_CRITERIA } from '../services/eval-orchestration-rubric.js';

const supportsLocalListen = await new Promise<boolean>((res) => {
  const srv = createServer();
  srv.on('error', () => { srv.close(); res(false); });
  srv.listen(0, '127.0.0.1', () => { srv.close(); res(true); });
});

describe.skipIf(!supportsLocalListen)('orchestration eval pipeline smoke (fake)', () => {
  let last: OrchEvalResult | null = null;
  beforeAll(() => { chmodSync(resolve('./src/test-support/fake-claude.mjs'), 0o755); });
  afterEach(async () => { if (last) await last.cleanup(); last = null; });

  it('a fake primary dispatches a matched child that lands findings; the record grades', async () => {
    last = await runOrchestrationScenario();
    // Pipeline (one chain): the primary dispatched >= 1 child...
    expect(last.record.dispatches.length).toBeGreaterThanOrEqual(1);
    // ...with a typed, non-default archetype. (The fake primary dispatches without a
    // frontier_item_id, so matchedFrontier here is the "picked a real specialty"
    // heuristic; the frontierType+nodeType resolution path is exercised by the real run.)
    expect(last.record.dispatches.every(d => d.matchedFrontier)).toBe(true);
    // ...which landed findings into the graph. The fake primary writes NO nodes itself
    // (it only orchestrates), so newNodeCount > 0 can ONLY come from the dispatched
    // child — i.e. this asserts the child actually ran end-to-end, not just that a
    // dispatch record exists.
    expect(last.record.newNodeCount).toBeGreaterThan(0);

    const g = gradeOrchestration(last.record);
    expect(g.criteria).toHaveLength(ORCH_CRITERIA.length);
    expect(g.criteria.find(c => c.criterion === 'dispatches')!.score).toBe(1);
    expect(g.criteria.find(c => c.criterion === 'archetype_match')!.score).toBe(1);
    expect(g.criteria.find(c => c.criterion === 'objective_progress')!.score).toBe(1);
  }, 45000);

  it('uses the same explicit artifact finalization path as prompt evaluation', async () => {
    const sandbox = mkdtempSync(join(tmpdir(), 'ow-orch-eval-artifact-smoke-'));
    try {
      last = await runOrchestrationScenario({
        preserveArtifacts: true,
        artifactRoot: join(sandbox, 'artifacts'),
      });
      const grade = gradeOrchestration(last.record);
      const manifest = last.finalizeArtifacts({ grade });
      expect(manifest).toMatchObject({
        evaluation_kind: 'orchestration',
        outcome: 'completed',
        eligible_for_baseline: true,
      });
      expect(JSON.parse(readFileSync(join(last.artifactDirectory!, 'grade.json'), 'utf8')))
        .toMatchObject({ outcome: 'completed', grade: { overall: grade.overall } });
    } finally {
      if (last) await last.cleanup();
      last = null;
      rmSync(sandbox, { recursive: true, force: true });
    }
  }, 45000);
});
