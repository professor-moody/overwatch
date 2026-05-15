// ============================================================
// Overwatch — BundleBuilder
// Gathers all engagement artefacts into a single .tar.gz archive.
// Used by both the MCP tool and the dashboard HTTP endpoint.
// ============================================================

import { spawn } from 'child_process';
import { existsSync, statSync, mkdirSync, writeFileSync, unlinkSync } from 'fs';
import { join, dirname, basename } from 'path';
import type { GraphEngine } from './graph-engine.js';

export interface BundleOptions {
  /** Include .snapshots/ directory (can be large). Default false. */
  includeSnapshots?: boolean;
  /** Attempt to copy registered tape files into a tapes/ subdir. Default true. */
  includeTapes?: boolean;
}

export interface BundleManifest {
  engagement_id: string;
  created_at: string;
  state_file: string;
  sections: Array<{ path: string; size_bytes: number; description: string }>;
  tape_paths: string[];
}

/** Derive registered tape file paths from the activity log. */
export function extractTapePaths(engine: GraphEngine): string[] {
  const paths: string[] = [];
  const seen = new Set<string>();
  for (const entry of engine.getFullHistory()) {
    if ((entry as Record<string, unknown>).event_type !== 'tape_session_started') continue;
    const det = (entry as Record<string, unknown>).details as Record<string, unknown> | undefined;
    const tp = typeof det?.tape_path === 'string' ? det.tape_path : undefined;
    if (tp && !seen.has(tp)) { seen.add(tp); paths.push(tp); }
  }
  return paths;
}

/** Resolve which entries exist and should be included in the tar. */
export function gatherBundleEntries(
  stateFilePath: string,
  opts: BundleOptions = {},
): { stateDir: string; entries: string[] } {
  const stateDir = dirname(stateFilePath);
  const entries: string[] = [basename(stateFilePath)];

  // Include WAL journal alongside the state file — captures any mutations not
  // yet folded into a snapshot, so the archive is complete even under load.
  const journalFile = basename(stateFilePath, '.json') + '.journal.jsonl';
  if (existsSync(join(stateDir, journalFile))) entries.push(journalFile);

  for (const sub of ['evidence', 'reports']) {
    if (existsSync(join(stateDir, sub))) entries.push(sub);
  }
  if (opts.includeSnapshots && existsSync(join(stateDir, '.snapshots'))) {
    entries.push('.snapshots');
  }

  return { stateDir, entries };
}

/**
 * Spawn `tar czf outPath -C stateDir [entries...]` and wait for completion.
 * Returns the byte size of the resulting file.
 */
export function createTarGz(
  outPath: string,
  stateDir: string,
  entries: string[],
): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn('tar', ['czf', outPath, '-C', stateDir, ...entries], {
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
    child.on('close', (code) => {
      if (code !== 0) return reject(new Error(`tar exited ${code}: ${stderr.trim()}`));
      try {
        resolve(statSync(outPath).size);
      } catch {
        resolve(0);
      }
    });
    child.on('error', (err) => reject(new Error(`tar spawn failed: ${err.message}`)));
  });
}

/**
 * Pipe `tar czf - -C stateDir [entries...]` to a writable stream.
 * Used by the HTTP endpoint to stream the archive directly to the browser.
 *
 * Resolves only after the tar process exits with code 0 so the caller can
 * be sure the archive is complete before ending the HTTP response. Errors
 * from the destination stream (e.g. client disconnect) kill the child.
 */
export function pipeTarGzToStream(
  dest: NodeJS.WritableStream,
  stateDir: string,
  entries: string[],
): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn('tar', ['czf', '-', '-C', stateDir, ...entries], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stderr = '';
    let settled = false;
    const settle = (err?: Error) => {
      if (settled) return;
      settled = true;
      if (err) reject(err); else resolve();
    };

    child.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
    child.stdout.pipe(dest, { end: false });

    // Resolve/reject only once the process exits — stdout.end fires before
    // close, so hooking it alone masks non-zero exit codes (P2).
    child.on('close', (code) => settle(code !== 0 ? new Error(`tar exited ${code}: ${stderr.trim()}`) : undefined));
    child.on('error', (err) => settle(new Error(`tar spawn failed: ${err.message}`)));

    // If the HTTP client disconnects, kill tar rather than streaming into the void.
    dest.on('error', (err) => { child.kill(); settle(err); });
  });
}

/**
 * Build a bundle: write a manifest JSON alongside the archive,
 * then create the .tar.gz including that manifest.
 * Returns the final archive path and size.
 */
export async function buildBundle(
  engine: GraphEngine,
  opts: BundleOptions & { outputPath?: string } = {},
): Promise<{ archivePath: string; sizeBytes: number; manifest: BundleManifest }> {
  // Flush any pending mutations to disk before archiving so the bundle
  // captures the latest engagement state (P1).
  engine.flushNow();

  const stateFilePath = engine.getStateFilePath();
  const stateDir = dirname(stateFilePath);
  const cfg = engine.getConfig();
  const now = new Date().toISOString();
  const ts = now.slice(0, 19).replace(/[T:]/g, '-');

  const { entries } = gatherBundleEntries(stateFilePath, opts);
  const tapePaths = opts.includeTapes !== false ? extractTapePaths(engine) : [];

  // Build sections metadata
  const sections: BundleManifest['sections'] = entries.map(e => {
    const full = join(stateDir, e);
    let size = 0;
    try {
      const st = statSync(full);
      size = st.isDirectory() ? 0 : st.size; // 0 for dirs (aggregate not needed)
    } catch { /* ignore */ }
    const desc =
      e === basename(stateFilePath) ? 'Engagement state (graph + activity log + config)' :
      e === 'evidence' ? 'Evidence files and manifest' :
      e === 'reports' ? 'Rendered report archive' :
      e === '.snapshots' ? 'Periodic state snapshots' : e;
    return { path: e, size_bytes: size, description: desc };
  });

  const manifest: BundleManifest = {
    engagement_id: cfg.id,
    created_at: now,
    state_file: basename(stateFilePath),
    sections,
    tape_paths: tapePaths.filter(p => existsSync(p)),
  };

  // Write manifest into the state dir temporarily
  const manifestPath = join(stateDir, 'bundle-manifest.json');
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  entries.push('bundle-manifest.json');

  const archivePath = opts.outputPath ?? join(stateDir, `bundle-${cfg.id}-${ts}.tar.gz`);

  // Ensure output directory exists
  mkdirSync(dirname(archivePath), { recursive: true });

  try {
    const sizeBytes = await createTarGz(archivePath, stateDir, entries);
    return { archivePath, sizeBytes, manifest };
  } finally {
    try { unlinkSync(manifestPath); } catch { /* cleanup */ }
  }
}
