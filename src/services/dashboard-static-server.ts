import type { ServerResponse } from 'node:http';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, extname, isAbsolute, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const moduleDir = dirname(fileURLToPath(import.meta.url));

interface CachedStaticAsset {
  content: string | Buffer;
  mtimeMs: number;
  size: number;
}

const MIME_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
};

const TEXT_ASSETS = new Set(['.html', '.css', '.js', '.json', '.svg']);

/** Owns dashboard bundle resolution, SPA fallback, and mtime-aware asset cache. */
export class DashboardStaticServer {
  dashboardDir: string | null = null;
  readonly fileCache = new Map<string, CachedStaticAsset>();

  clear(): void {
    this.fileCache.clear();
  }

  serve(url: string, res: ServerResponse): void {
    const pathname = url.split('?')[0];
    const hasExt = extname(pathname) !== '';
    const filePath = hasExt ? pathname : '/index.html';

    let decoded: string;
    try {
      decoded = decodeURIComponent(filePath);
    } catch {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Bad request');
      return;
    }
    if (filePath.includes('..') || decoded.includes('..')) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden');
      return;
    }

    const cleanPath = filePath.replace(/^\//, '').split('?')[0];
    const ext = extname(cleanPath);
    const mime = MIME_TYPES[ext] || 'application/octet-stream';

    try {
      const dashboardDir = this.resolveDashboardDir();
      const fullPath = join(dashboardDir, cleanPath);
      const rel = relative(dashboardDir, fullPath);
      if (rel.startsWith('..') || isAbsolute(rel)) {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Forbidden');
        return;
      }

      const stat = statSync(fullPath);
      const cached = this.fileCache.get(cleanPath);
      if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
        res.writeHead(200, { 'Content-Type': mime, 'Cache-Control': 'no-cache' });
        res.end(cached.content);
        return;
      }

      const content = TEXT_ASSETS.has(ext)
        ? readFileSync(fullPath, 'utf8')
        : readFileSync(fullPath);
      this.fileCache.set(cleanPath, {
        content,
        mtimeMs: stat.mtimeMs,
        size: stat.size,
      });
      res.writeHead(200, { 'Content-Type': mime, 'Cache-Control': 'no-cache' });
      res.end(content);
    } catch {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
    }
  }

  private resolveDashboardDir(): string {
    if (this.dashboardDir) return this.dashboardDir;
    const candidates = [
      join(moduleDir, '..', '..', 'dist', 'dashboard-next'),
      join(moduleDir, '..', 'dashboard-next'),
    ];
    for (const dir of candidates) {
      if (existsSync(join(dir, 'index.html')) && existsSync(join(dir, 'assets'))) {
        this.dashboardDir = dir;
        return dir;
      }
    }
    for (const dir of candidates) {
      if (existsSync(join(dir, 'index.html'))) {
        this.dashboardDir = dir;
        return dir;
      }
    }

    const sourceDir = join(moduleDir, '..', '..', 'src', 'dashboard-next');
    if (existsSync(join(sourceDir, 'index.html'))) {
      this.dashboardDir = sourceDir;
      return sourceDir;
    }
    const compiledSourceDir = join(moduleDir, '..', 'dashboard-next');
    if (existsSync(join(compiledSourceDir, 'index.html'))) {
      this.dashboardDir = compiledSourceDir;
      return compiledSourceDir;
    }
    throw new Error(
      'Dashboard build not found. Run `npm run build:dashboard-next` (or `npm run build`) before starting the server.',
    );
  }
}
