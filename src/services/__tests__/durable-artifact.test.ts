import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  DurableArtifactPublicationError,
  publishArtifactFileDurable,
  writeArtifactAtomicDurable,
} from '../durable-artifact.js';

let root: string;

beforeEach(() => { root = mkdtempSync(join(tmpdir(), 'ow-durable-artifact-')); });
afterEach(() => { rmSync(root, { recursive: true, force: true }); });

describe('durable artifact publication', () => {
  it('reports a visible replacement when the post-rename directory fsync fails', () => {
    const destination = join(root, 'artifact.json');
    let caught: unknown;
    try {
      writeArtifactAtomicDurable(destination, '{"committed":true}\n', {
        syncDirectory: () => { throw new Error('injected directory fsync failure'); },
      });
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(DurableArtifactPublicationError);
    expect(caught).toMatchObject({
      publication_visible: true,
      durability_confirmed: false,
      destination_path: destination,
    });
    expect(readFileSync(destination, 'utf8')).toBe('{"committed":true}\n');
  });

  it('reports a visible exclusive publication when the post-link directory fsync fails', () => {
    const staged = join(root, '.artifact.stage');
    const destination = join(root, 'artifact.bin');
    writeFileSync(staged, 'committed bytes');

    expect(() => publishArtifactFileDurable(staged, destination, {
      overwrite: false,
      syncDirectory: () => { throw new Error('injected directory fsync failure'); },
    })).toThrow(expect.objectContaining({
      publication_visible: true,
      durability_confirmed: false,
      destination_path: destination,
    }));
    expect(readFileSync(destination, 'utf8')).toBe('committed bytes');
    expect(existsSync(staged)).toBe(true);
  });

  it('distinguishes committed publication from uncertain staging cleanup durability', () => {
    const staged = join(root, '.artifact.stage');
    const destination = join(root, 'artifact.bin');
    writeFileSync(staged, 'committed bytes');
    let syncCount = 0;
    let caught: unknown;
    try {
      publishArtifactFileDurable(staged, destination, {
        overwrite: false,
        syncDirectory: () => {
          syncCount += 1;
          if (syncCount === 2) throw new Error('injected cleanup fsync failure');
        },
      });
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(DurableArtifactPublicationError);
    expect(caught).toMatchObject({
      publication_visible: true,
      durability_confirmed: true,
      destination_path: destination,
    });
    expect(readFileSync(destination, 'utf8')).toBe('committed bytes');
    expect(existsSync(staged)).toBe(false);
  });
});
