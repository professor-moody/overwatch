// ============================================================
// HTTP session jar — named curl cookie-jar files.
//
// In this architecture every target-facing HTTP request is a `curl` spawned
// through the instrumented runner (scope + approval + OPSEC gate). So a "web
// session" is persisted the way curl persists one: a Netscape cookie-jar FILE
// that `curl -c <jar>` writes and `curl -b <jar>` reads. This module manages
// those files under the engagement state dir — it does NOT parse cookies (curl
// owns that), it only resolves/creates/lists/clears the jar paths.
//
// A login via `test_webapp_credential` with a `session_jar_id` writes its
// Set-Cookie into the named jar; the authenticated-crawl tool then reads the
// same jar to crawl with that session. The jar holds a live session cookie (a
// secret), so it lives beside evidence in the operator-local state dir and is
// never logged.
//
// Caveats: (1) the id is used verbatim as a filename, so on a case-insensitive
// filesystem (default macOS/Windows) `Sess` and `sess` alias to one jar while
// on Linux they are two — prefer lowercase ids for portability. (2) There is no
// file locking: two agents writing the same jar id concurrently race, and
// `curl -c` full-overwrites at completion (last-writer-wins) — give concurrent
// logins distinct ids.
// ============================================================

import { dirname, join } from 'path';
import { existsSync, mkdirSync, readdirSync, rmSync } from 'fs';

// The id becomes a filename, so it must be a strict safe token — this is the
// path-traversal guard (no `/`, `\`, `..`, NUL, etc.).
const SAFE_ID = /^[A-Za-z0-9_-]{1,64}$/;

export function isValidSessionJarId(id: string): boolean {
  return typeof id === 'string' && SAFE_ID.test(id);
}

/** Directory holding the jar files, alongside `evidence/` under the state dir. */
export function sessionJarsDir(stateFilePath: string): string {
  return join(dirname(stateFilePath), 'session-jars');
}

/**
 * Absolute path of the named cookie jar, creating the parent dir if needed.
 * Throws on an unsafe id (the id is used as a filename). The file itself need
 * not exist yet — `curl -b <missing>` simply sends no cookies, `curl -c` creates it.
 */
export function sessionJarPath(stateFilePath: string, id: string): string {
  if (!isValidSessionJarId(id)) {
    throw new Error(`Invalid session_jar_id '${id}': must be 1–64 chars of [A-Za-z0-9_-].`);
  }
  const dir = sessionJarsDir(stateFilePath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return join(dir, `${id}.jar`);
}

/** Names of the jars that currently exist (the `.jar` suffix stripped). */
export function listSessionJars(stateFilePath: string): string[] {
  const dir = sessionJarsDir(stateFilePath);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter(f => f.endsWith('.jar'))
    .map(f => f.slice(0, -'.jar'.length))
    .sort();
}

/** Delete a named jar. Returns true if a file was removed. */
export function clearSessionJar(stateFilePath: string, id: string): boolean {
  if (!isValidSessionJarId(id)) return false;
  const p = join(sessionJarsDir(stateFilePath), `${id}.jar`);
  if (existsSync(p)) { rmSync(p); return true; }
  return false;
}
