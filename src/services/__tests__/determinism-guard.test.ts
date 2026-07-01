import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

// ============================================================
// Determinism guard: no raw wall-clock in the engine mutation / inference paths.
//
// A `new Date()` / `Date.now()` that lands in a node/edge property (or any
// persisted/exported state) leaks wall-clock time into exportGraph → hashGraph,
// breaking the deterministic-replay / golden-master invariant. Mutation and
// inference code MUST read the injected clock via `ctx.nowIso()` instead.
//
// Legitimately-transient uses (cache TTLs, elapsed-time windows, real-time OPSEC
// checks, approval timing, read-only query filters, parsing a stored timestamp)
// are allowed by tagging the line with a `clock-ok:` marker + reason. This test
// fails on any UNTAGGED wall-clock read in the guarded files, so future drift is
// caught mechanically (without masking real state via hash-field stripping).
// ============================================================

const here = dirname(fileURLToPath(import.meta.url));
const srcRoot = resolve(here, '../..'); // .../src

// The mutation / inference / ingest surface where a clock leak corrupts the
// golden hash. NB the parser layer (bloodhound-ingest etc.) stamps discovered_at
// too, but those are pure parsers without engine-clock access — their ingest
// determinism is handled where the parser is threaded a clock (Batch 6), so they
// are intentionally not guarded here yet.
const GUARDED_FILES = [
  'services/graph-engine.ts',
  'services/engine-context.ts',
  'services/inference-engine.ts',
  'services/cross-tier-inference.ts',
  'services/cross-tier-correlator.ts',
  'services/builtin-inference-rules.ts',
  'tools/ingest-json.ts',
];

const CLOCK_RE = /\bnew Date\s*\(|\bDate\.now\s*\(/;

function isCommentLine(line: string): boolean {
  const t = line.trimStart();
  return t.startsWith('//') || t.startsWith('*') || t.startsWith('/*');
}

describe('determinism guard — no untagged wall-clock in engine mutation/inference paths', () => {
  for (const file of GUARDED_FILES) {
    it(`${file} has no untagged new Date()/Date.now()`, () => {
      const src = readFileSync(resolve(srcRoot, file), 'utf8').split('\n');
      const offenders: string[] = [];
      src.forEach((line, i) => {
        if (!CLOCK_RE.test(line)) return;
        if (isCommentLine(line)) return;          // a comment mentioning it is fine
        if (line.includes('clock-ok')) return;    // explicitly allowed transient use
        offenders.push(`${file}:${i + 1}: ${line.trim()}`);
      });
      expect(offenders, `Use ctx.nowIso() or tag the line "clock-ok: <reason>":\n${offenders.join('\n')}`).toEqual([]);
    });
  }

  it('the guard regex actually catches a raw wall-clock read', () => {
    expect(CLOCK_RE.test('const x = new Date().toISOString();')).toBe(true);
    expect(CLOCK_RE.test('const x = Date.now();')).toBe(true);
    expect(CLOCK_RE.test('const x = ctx.nowIso();')).toBe(false);
  });
});
