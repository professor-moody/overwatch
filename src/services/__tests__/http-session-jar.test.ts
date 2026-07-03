import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, existsSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { isValidSessionJarId, sessionJarsDir, sessionJarPath, listSessionJars, clearSessionJar } from '../http-session-jar.js';

let dir: string;
let statePath: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'ow-sjar-'));
  statePath = join(dir, 'state-test.json');
});
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

describe('http-session-jar', () => {
  it('validates ids: alnum/dash/underscore only, 1–64 chars', () => {
    expect(isValidSessionJarId('sess-1')).toBe(true);
    expect(isValidSessionJarId('A_b-9')).toBe(true);
    expect(isValidSessionJarId('a'.repeat(64))).toBe(true);
    expect(isValidSessionJarId('')).toBe(false);
    expect(isValidSessionJarId('a'.repeat(65))).toBe(false);
    expect(isValidSessionJarId('has space')).toBe(false);
    expect(isValidSessionJarId('dot.name')).toBe(false);
  });

  it('rejects path-traversal / separator ids (the id becomes a filename)', () => {
    for (const bad of ['../evil', 'a/b', 'a\\b', '..', '.', 'x\0y', '/etc/passwd', 'a/../../b']) {
      expect(isValidSessionJarId(bad)).toBe(false);
      expect(() => sessionJarPath(statePath, bad)).toThrow(/Invalid session_jar_id/);
    }
  });

  it('sessionJarPath places <id>.jar under <stateDir>/session-jars and creates the dir', () => {
    const p = sessionJarPath(statePath, 'sess-1');
    expect(p).toBe(join(dir, 'session-jars', 'sess-1.jar'));
    expect(existsSync(sessionJarsDir(statePath))).toBe(true); // dir created
    expect(existsSync(p)).toBe(false); // file itself is not pre-created
  });

  it('listSessionJars returns existing jar names (sorted, suffix stripped)', () => {
    expect(listSessionJars(statePath)).toEqual([]); // no dir yet
    sessionJarPath(statePath, 'b-sess'); // creates dir
    writeFileSync(join(sessionJarsDir(statePath), 'b-sess.jar'), '# Netscape cookie file\n');
    writeFileSync(join(sessionJarsDir(statePath), 'a-sess.jar'), '# Netscape cookie file\n');
    writeFileSync(join(sessionJarsDir(statePath), 'notes.txt'), 'ignore me');
    expect(listSessionJars(statePath)).toEqual(['a-sess', 'b-sess']);
  });

  it('clearSessionJar removes an existing jar, false otherwise', () => {
    const p = sessionJarPath(statePath, 'sess-1');
    writeFileSync(p, '# cookies');
    expect(clearSessionJar(statePath, 'sess-1')).toBe(true);
    expect(existsSync(p)).toBe(false);
    expect(clearSessionJar(statePath, 'sess-1')).toBe(false); // already gone
    expect(clearSessionJar(statePath, '../evil')).toBe(false); // unsafe id
  });

  it('the jar dir is a sibling of evidence under the state dir', () => {
    expect(sessionJarsDir(statePath)).toBe(join(dirname(statePath), 'session-jars'));
  });
});
