import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';

const ATOMIC_ARTIFACT_PRODUCERS = [
  'src/services/report-archive.ts',
  'src/services/bundle-builder.ts',
  'src/services/http-session-jar.ts',
  'src/services/artifact-generation.ts',
  'src/services/evidence-store.ts',
  'src/services/state-artifacts.ts',
  'src/services/tape-recorder.ts',
  'src/services/in-process-tape.ts',
  'src/tools/reporting.ts',
  'src/tools/retrospective.ts',
];

const STREAMING_PRIMITIVE_ALLOWLIST: Record<string, Partial<Record<string, number>>> = {
  // Evidence uses one fd-backed atomic helper and one private streaming stage;
  // neither name is operator-visible until its fsync/descriptor boundary.
  'src/services/evidence-store.ts': { 'writeFileSync(': 1, 'createWriteStream(': 1 },
  // Tape is append-only by design and owns one O_NOFOLLOW/fd-backed stream.
  'src/services/tape-recorder.ts': { 'createWriteStream(': 1 },
};

describe('artifact publication architecture', () => {
  it('keeps completed artifact writers behind the durable publication boundary', () => {
    const violations: string[] = [];
    for (const file of ATOMIC_ARTIFACT_PRODUCERS) {
      const source = readFileSync(resolve(file), 'utf8');
      for (const primitive of ['writeFileSync(', 'createWriteStream(']) {
        const count = source.split(primitive).length - 1;
        const allowed = STREAMING_PRIMITIVE_ALLOWLIST[file]?.[primitive] ?? 0;
        if (count !== allowed) violations.push(`${file} uses ${primitive} ${count} times (allowed ${allowed})`);
      }
    }
    expect(violations).toEqual([]);
  });

  it('spools and validates dashboard bundles before committing HTTP success', () => {
    const source = readFileSync(resolve('src/services/dashboard-server.ts'), 'utf8');
    expect(source).toContain('await buildBundle(this.engine');
    expect(source.indexOf('await buildBundle(this.engine')).toBeLessThan(
      source.indexOf("'Content-Type': 'application/gzip'"),
    );
    expect(source).not.toContain('pipeTarGzToStream(res');
  });
});
