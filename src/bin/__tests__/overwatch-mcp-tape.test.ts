import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawn, type ChildProcess } from 'child_process';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve as resolvePath } from 'path';

const PROXY = resolvePath(__dirname, '../../bin/overwatch-mcp-tape.ts');

function childIsRunning(child: ChildProcess): boolean {
  return child.exitCode === null && child.signalCode === null;
}

function childTreeIsRunning(child: ChildProcess): boolean {
  if (!child.pid) return false;
  if (process.platform === 'win32') return childIsRunning(child);
  try {
    process.kill(-child.pid, 0);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ESRCH') return false;
    if ((error as NodeJS.ErrnoException).code === 'EPERM') return true;
    throw error;
  }
}

function signalChildTree(child: ChildProcess, signal: NodeJS.Signals): void {
  if (!child.pid || !childTreeIsRunning(child)) return;
  if (process.platform !== 'win32') {
    try {
      process.kill(-child.pid, signal);
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ESRCH') return;
      throw error;
    }
  }
  child.kill(signal);
}

function waitForChildExit(child: ChildProcess, timeoutMs: number): Promise<boolean> {
  if (!childTreeIsRunning(child)) return Promise.resolve(true);
  return new Promise(resolveWait => {
    const deadline = Date.now() + timeoutMs;
    const poll = () => {
      if (!childTreeIsRunning(child)) resolveWait(true);
      else if (Date.now() >= deadline) resolveWait(false);
      else setTimeout(poll, 25);
    };
    poll();
  });
}

async function terminateChild(child: ChildProcess): Promise<void> {
  if (!childTreeIsRunning(child)) return;
  signalChildTree(child, 'SIGTERM');
  if (await waitForChildExit(child, 2_000)) return;
  signalChildTree(child, 'SIGKILL');
  if (!await waitForChildExit(child, 2_000)) {
    throw new Error(`Tape proxy ${child.pid ?? 'unknown'} did not exit after SIGKILL`);
  }
}

/**
 * Integration test for `overwatch-mcp-tape`.
 *
 * Strategy:
 * - Build a tiny Node script that acts as the upstream MCP server: it reads
 *   newline-delimited JSON from stdin and echoes a response per request.
 * - Spawn the proxy (via tsx) wrapping the fake upstream.
 * - Send 3 client frames; expect 3 responses on the proxy's stdout AND
 *   6 records (3 client + 3 server) in the tape JSONL.
 */
describe('overwatch-mcp-tape proxy (integration)', () => {
  let tmp: string;
  let tapePath: string;
  let upstreamPath: string;
  let proxy: ChildProcess | undefined;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'overwatch-tape-int-'));
    tapePath = join(tmp, 'tape.jsonl');
    upstreamPath = join(tmp, 'fake-upstream.mjs');
    // Fake upstream: parse each JSON-RPC line and echo a result with the same id.
    writeFileSync(upstreamPath, `
let buf = '';
process.stdin.setEncoding('utf-8');
process.stdin.on('data', (chunk) => {
  buf += chunk;
  let idx;
  while ((idx = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, idx);
    buf = buf.slice(idx + 1);
    if (!line) continue;
    try {
      const req = JSON.parse(line);
      const resp = { jsonrpc: '2.0', id: req.id, result: { method: req.method, ok: true } };
      process.stdout.write(JSON.stringify(resp) + '\\n');
    } catch {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', error: 'bad' }) + '\\n');
    }
  }
});
process.stdin.on('end', () => process.exit(0));
`);
  });

  afterEach(async () => {
    if (proxy) await terminateChild(proxy);
    proxy = undefined;
    rmSync(tmp, { recursive: true, force: true });
  });

  it('captures 3 client frames + 3 server responses', async () => {
    const child = spawn(process.execPath, ['--import', 'tsx', PROXY, '--tape', tapePath, '--quiet', '--', 'node', upstreamPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      detached: process.platform !== 'win32',
    });
    proxy = child;

    const responses: string[] = [];
    let stdoutBuf = '';
    child.stdout.setEncoding('utf-8');
    child.stdout.on('data', (chunk: string) => {
      stdoutBuf += chunk;
      let idx;
      while ((idx = stdoutBuf.indexOf('\n')) >= 0) {
        const line = stdoutBuf.slice(0, idx);
        stdoutBuf = stdoutBuf.slice(idx + 1);
        if (line) responses.push(line);
      }
    });

    // Send 3 frames
    child.stdin.write('{"jsonrpc":"2.0","method":"a","id":1}\n');
    child.stdin.write('{"jsonrpc":"2.0","method":"b","id":2}\n');
    child.stdin.write('{"jsonrpc":"2.0","method":"c","id":3}\n');

    // Wait for 3 responses (poll)
    const deadline = Date.now() + 15_000;
    while (responses.length < 3 && Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 50));
    }

    child.stdin.end();
    const exitCode: number = await new Promise((resolve) => {
      child.on('exit', (code) => resolve(code ?? 0));
    });
    expect(exitCode).toBe(0);
    expect(responses.length).toBe(3);

    const tape = readFileSync(tapePath, 'utf-8').trim().split('\n').map(l => JSON.parse(l));
    const c2s = tape.filter(r => r.direction === 'client_to_server');
    const s2c = tape.filter(r => r.direction === 'server_to_client');
    expect(c2s.length).toBe(3);
    expect(s2c.length).toBe(3);
    expect(c2s[0].parsed.method).toBe('a');
    expect(s2c[0].parsed.result.method).toBe('a');
    expect(s2c[2].parsed.id).toBe(3);
  }, 30_000);
});

// Track A regression: --out is accepted as an alias for --tape.
// Earlier docs referenced --out; the proxy parser only accepted --tape,
// so anyone copying the doc snippet hit a silent flag-not-recognized.
describe('overwatch-mcp-tape arg parsing', () => {
  it('accepts --out as an alias for --tape', async () => {
    const { parseArgs } = await import('../overwatch-mcp-tape.js');
    const aliased = parseArgs(['--out', '/tmp/x.jsonl', '--', 'node', 'srv.js']);
    expect(aliased.tapePath).toBe('/tmp/x.jsonl');
    expect(aliased.upstream).toEqual(['node', 'srv.js']);
    const canonical = parseArgs(['--tape', '/tmp/y.jsonl', '--', 'node', 'srv.js']);
    expect(canonical.tapePath).toBe('/tmp/y.jsonl');
  });
});
