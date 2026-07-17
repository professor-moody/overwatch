import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  publishArtifactGenerationDurable,
  readCurrentArtifactGeneration,
  repairArtifactGenerationMirrors,
} from '../artifact-generation.js';
import { GraphEngine } from '../graph-engine.js';
import type { EngagementConfig } from '../../types.js';

let root: string;

beforeEach(() => { root = mkdtempSync(join(tmpdir(), 'ow-artifact-generation-')); });
afterEach(() => { rmSync(root, { recursive: true, force: true }); });

describe('artifact generation publication', () => {
  it('commits one checksummed generation before refreshing fixed-name mirrors', () => {
    const publication = publishArtifactGenerationDurable({
      root,
      namespace: 'report',
      files: {
        'report.md': { content: '# report', media_type: 'text/markdown' },
        'attack-navigator.json': { content: '{}\n', media_type: 'application/json' },
      },
      legacy_names: ['report.md', 'attack-navigator.json'],
    });
    expect(publication).toMatchObject({
      generation_committed: true,
      legacy_mirror_complete: true,
    });
    const current = readCurrentArtifactGeneration(root, 'report');
    expect(current?.manifest.files.map(file => file.path)).toEqual([
      'attack-navigator.json', 'report.md',
    ]);
    expect(readFileSync(join(root, 'report.md'), 'utf8')).toBe('# report');
  });

  it('makes optional-file removal part of the new authoritative generation', () => {
    publishArtifactGenerationDurable({
      root, namespace: 'report',
      files: {
        'report.md': { content: 'first' },
        'attack-navigator.json': { content: 'stale' },
      },
      legacy_names: ['report.md', 'attack-navigator.json'],
    });
    publishArtifactGenerationDurable({
      root, namespace: 'report',
      files: { 'report.md': { content: 'second' } },
      legacy_names: ['report.md', 'attack-navigator.json'],
    });
    expect(readCurrentArtifactGeneration(root, 'report')?.manifest.files.map(file => file.path))
      .toEqual(['report.md']);
    expect(existsSync(join(root, 'attack-navigator.json'))).toBe(false);
  });

  it('returns committed success when a post-pointer legacy mirror cannot be repaired', () => {
    writeFileSync(join(root, 'blocked'), 'not a directory');
    const publication = publishArtifactGenerationDurable({
      root,
      namespace: 'retrospective',
      files: { 'blocked/report.md': { content: 'committed bytes' } },
      legacy_names: ['blocked/report.md'],
    });
    expect(publication).toMatchObject({
      generation_committed: true,
      legacy_mirror_complete: false,
      warning: expect.stringContaining('legacy fixed-name mirrors'),
    });
    expect(readCurrentArtifactGeneration(root, 'retrospective')?.manifest.files[0]).toMatchObject({
      path: 'blocked/report.md',
    });
  });

  it('repairs mixed fixed-name mirrors from the authoritative generation after restart', () => {
    publishArtifactGenerationDurable({
      root,
      namespace: 'report',
      files: {
        'report.md': { content: 'authoritative report' },
        'attack-navigator.json': { content: '{"current":true}\n' },
      },
      legacy_names: ['report.md', 'attack-navigator.json', 'report.html'],
    });
    writeFileSync(join(root, 'report.md'), 'stale report');
    rmSync(join(root, 'attack-navigator.json'));
    writeFileSync(join(root, 'report.html'), 'obsolete optional mirror');

    expect(repairArtifactGenerationMirrors(root, 'report', [
      'report.md', 'attack-navigator.json', 'report.html',
    ])).toBe(true);
    expect(readFileSync(join(root, 'report.md'), 'utf8')).toBe('authoritative report');
    expect(readFileSync(join(root, 'attack-navigator.json'), 'utf8')).toBe('{"current":true}\n');
    expect(existsSync(join(root, 'report.html'))).toBe(false);
  });

  it('repairs a registered post-pointer mirror interruption during engine startup', () => {
    const statePath = join(root, 'state.json');
    const outputRoot = join(root, 'operator-reports');
    const config: EngagementConfig = {
      id: 'artifact-recovery',
      name: 'Artifact recovery',
      created_at: '2026-07-17T00:00:00.000Z',
      scope: { cidrs: [], domains: [], exclusions: [] },
      objectives: [],
      opsec: { name: 'pentest', enabled: false, max_noise: 0.5 },
    };
    const first = new GraphEngine(config, statePath);
    first.registerArtifactGenerationRecovery({
      root: outputRoot,
      namespace: 'report',
      legacy_names: ['report.md', 'attack-navigator.json'],
    });
    // The recovery registry is explicit durable state, not bounded audit-log
    // truth. Simulate every prior activity entry aging out before checkpoint.
    const context = (first as unknown as { ctx: { activityLog: unknown[] } }).ctx;
    context.activityLog = [];
    first.persistImmediate();
    publishArtifactGenerationDurable({
      root: outputRoot,
      namespace: 'report',
      files: {
        'report.md': { content: 'authoritative restart report' },
        'attack-navigator.json': { content: '{"current":true}\n' },
      },
      legacy_names: ['report.md', 'attack-navigator.json'],
    });
    first.dispose();

    writeFileSync(join(outputRoot, 'report.md'), 'mixed pre-crash report');
    rmSync(join(outputRoot, 'attack-navigator.json'));

    const restarted = new GraphEngine(config, statePath);
    try {
      expect(readFileSync(join(outputRoot, 'report.md'), 'utf8'))
        .toBe('authoritative restart report');
      expect(readFileSync(join(outputRoot, 'attack-navigator.json'), 'utf8'))
        .toBe('{"current":true}\n');
      expect(restarted.getPersistenceRecoveryStatus().artifact_recovery?.generation_warnings)
        .toBeUndefined();
    } finally {
      restarted.dispose();
    }
  });

  it('rejects unsafe members before publishing a pointer', () => {
    expect(() => publishArtifactGenerationDurable({
      root,
      namespace: 'report',
      files: { '../escape': { content: 'no' } },
    })).toThrow(/invalid artifact generation path/i);
    expect(readCurrentArtifactGeneration(root, 'report')).toBeNull();
  });

  it('rejects a pointer whose declared manifest path disagrees with its generation', () => {
    const publication = publishArtifactGenerationDurable({
      root, namespace: 'report', files: { 'report.md': { content: 'report' } },
    });
    const pointer = JSON.parse(readFileSync(publication.pointer_path, 'utf8'));
    pointer.manifest_path = '../wrong-manifest.json';
    writeFileSync(publication.pointer_path, JSON.stringify(pointer));
    expect(() => readCurrentArtifactGeneration(root, 'report')).toThrow(/wrong manifest path/i);
  });

  it('retains a bounded set of superseded immutable generations', () => {
    for (let index = 0; index < 8; index++) {
      publishArtifactGenerationDurable({
        root, namespace: 'report', files: { 'report.md': { content: `report ${index}` } },
      });
    }
    const generations = readdirSync(join(root, '.overwatch-generations', 'report'))
      .filter(name => /^[0-9a-f-]{36}$/i.test(name));
    expect(generations.length).toBeLessThanOrEqual(5);
    expect(readCurrentArtifactGeneration(root, 'report')).not.toBeNull();
  });
});
