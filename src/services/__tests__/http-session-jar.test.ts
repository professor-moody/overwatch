import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, existsSync, readFileSync, statSync, symlinkSync, truncateSync, utimesSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import {
  beginSessionJarTransaction,
  isValidSessionJarId,
  sessionJarsDir,
  sessionJarPath,
  listSessionJars,
  clearSessionJar,
} from '../http-session-jar.js';

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

  it('publishes a validated staged jar atomically with private permissions', async () => {
    const transaction = await beginSessionJarTransaction(statePath, 'sess-1');
    writeFileSync(transaction.writePath, '# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tFALSE\t0\tsession\tnew\n');
    transaction.commit();
    expect(readFileSync(transaction.readPath, 'utf8')).toContain('\tsession\tnew');
    expect(statSync(transaction.readPath).mode & 0o777).toBe(0o600);
  });

  it('preserves the prior jar when curl produces only a header', async () => {
    const canonical = sessionJarPath(statePath, 'sess-1');
    const original = '# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tFALSE\t0\tsession\told\n';
    writeFileSync(canonical, original);
    const transaction = await beginSessionJarTransaction(statePath, 'sess-1');
    writeFileSync(transaction.writePath, '# Netscape HTTP Cookie File\n');
    expect(transaction.commit()).toEqual({ published: false, durability_confirmed: true });
    expect(readFileSync(canonical, 'utf8')).toBe(original);
  });

  it('can seed the explicitly tested cookie when curl returns no Set-Cookie', async () => {
    const transaction = await beginSessionJarTransaction(statePath, 'sess-1');
    writeFileSync(transaction.writePath, '# Netscape HTTP Cookie File\n');
    expect(transaction.commit({
      url: 'https://app.example.test/login',
      name: 'session',
      value: 'tested-value',
    })).toEqual({ published: true, durability_confirmed: true });
    const jar = readFileSync(transaction.readPath, 'utf8');
    expect(jar).toContain('app.example.test\tFALSE\t/\tTRUE\t0\tsession\ttested-value');
  });

  it('preserves the prior jar when a request aborts or stages malformed bytes', async () => {
    const canonical = sessionJarPath(statePath, 'sess-1');
    const original = '# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tFALSE\t0\tsession\told\n';
    writeFileSync(canonical, original);

    const aborted = await beginSessionJarTransaction(statePath, 'sess-1');
    writeFileSync(aborted.writePath, 'partial');
    aborted.abort();
    expect(readFileSync(canonical, 'utf8')).toBe(original);

    const malformed = await beginSessionJarTransaction(statePath, 'sess-1');
    writeFileSync(malformed.writePath, 'not a netscape jar');
    expect(() => malformed.commit()).toThrow(/valid Netscape cookie jar/i);
    expect(readFileSync(canonical, 'utf8')).toBe(original);
    expect(existsSync(malformed.writePath)).toBe(false);
  });

  it('rejects a symbolic-link canonical jar', async () => {
    const directory = sessionJarsDir(statePath);
    sessionJarPath(statePath, 'seed');
    const outside = join(dir, 'outside.jar');
    writeFileSync(outside, '# Netscape HTTP Cookie File\n');
    symlinkSync(outside, join(directory, 'linked.jar'));
    await expect(beginSessionJarTransaction(statePath, 'linked')).rejects.toThrow(/regular file/i);
  });

  it('serializes same-process writers and rejects a stale cross-boundary replacement', async () => {
    const canonical = sessionJarPath(statePath, 'sess-1');
    writeFileSync(canonical, '# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tFALSE\t0\tsession\told\n');
    const first = await beginSessionJarTransaction(statePath, 'sess-1');
    let secondAcquired = false;
    const secondPromise = beginSessionJarTransaction(statePath, 'sess-1').then(value => {
      secondAcquired = true;
      return value;
    });
    await Promise.resolve();
    expect(secondAcquired).toBe(false);
    writeFileSync(first.writePath, '# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tFALSE\t0\tsession\tfirst\n');
    first.commit();
    const second = await secondPromise;
    writeFileSync(second.writePath, '# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tFALSE\t0\tsession\tsecond\n');
    writeFileSync(canonical, '# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tFALSE\t0\tsession\texternal\n');
    expect(() => second.commit()).toThrow(/changed while authentication was in flight/i);
    expect(readFileSync(canonical, 'utf8')).toContain('\tsession\texternal');
  });

  it('rejects a symlinked jar root before changing the target directory mode', () => {
    const outside = join(dir, 'outside-dir');
    const root = sessionJarsDir(statePath);
    mkdirSync(outside);
    chmodSync(outside, 0o755);
    symlinkSync(outside, root);
    expect(() => sessionJarPath(statePath, 'sess-1')).toThrow(/private regular directory/i);
    expect(statSync(outside).mode & 0o777).toBe(0o755);
    expect(() => clearSessionJar(statePath, 'sess-1')).toThrow(/private regular directory/i);
  });

  it('reclaims only old staging files owned by a dead process', () => {
    sessionJarPath(statePath, 'seed');
    const directory = sessionJarsDir(statePath);
    const dead = join(directory, '.sess-1.jar.tmp-999999-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
    const live = join(directory, `.sess-1.jar.tmp-${process.pid}-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb`);
    writeFileSync(dead, 'sensitive partial cookies');
    writeFileSync(live, 'live partial cookies');
    const old = new Date(Date.now() - 2 * 60 * 60 * 1000);
    utimesSync(dead, old, old);
    utimesSync(live, old, old);
    sessionJarPath(statePath, 'sess-1');
    expect(existsSync(dead)).toBe(false);
    expect(existsSync(live)).toBe(true);
  });

  it('reclaims an old stage when a live PID has a different start identity', () => {
    sessionJarPath(statePath, 'seed');
    const directory = sessionJarsDir(statePath);
    const reused = join(
      directory,
      `.sess-1.jar.tmp-${process.pid}-v0000000000000000-cccccccc-cccc-4ccc-8ccc-cccccccccccc`,
    );
    writeFileSync(reused, 'orphaned from an older process incarnation');
    const old = new Date(Date.now() - 2 * 60 * 60 * 1000);
    utimesSync(reused, old, old);
    listSessionJars(statePath);
    expect(existsSync(reused)).toBe(false);
  });

  it('rejects an oversized canonical jar before transaction hashing', async () => {
    const canonical = sessionJarPath(statePath, 'sess-1');
    writeFileSync(canonical, '# Netscape HTTP Cookie File\n');
    truncateSync(canonical, 10 * 1024 * 1024 + 1);
    await expect(beginSessionJarTransaction(statePath, 'sess-1')).rejects.toThrow(/10 MiB safety limit/i);
  });
});
