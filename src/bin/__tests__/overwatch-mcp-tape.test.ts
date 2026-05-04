import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawn } from 'child_process';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve as resolvePath } from 'path';

const PROXY = resolvePath(__dirname, '../../bin/overwatch-mcp-tape.ts');

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

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('captures 3 client frames + 3 server responses', async () => {
    const proxy = spawn('npx', ['tsx', PROXY, '--tape', tapePath, '--quiet', '--', 'node', upstreamPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const responses: string[] = [];
    let stdoutBuf = '';
    proxy.stdout.setEncoding('utf-8');
    proxy.stdout.on('data', (chunk: string) => {
      stdoutBuf += chunk;
      let idx;
      while ((idx = stdoutBuf.indexOf('\n')) >= 0) {
        const line = stdoutBuf.slice(0, idx);
        stdoutBuf = stdoutBuf.slice(idx + 1);
        if (line) responses.push(line);
      }
    });

    // Send 3 frames
    proxy.stdin.write('{"jsonrpc":"2.0","method":"a","id":1}\n');
    proxy.stdin.write('{"jsonrpc":"2.0","method":"b","id":2}\n');
    proxy.stdin.write('{"jsonrpc":"2.0","method":"c","id":3}\n');

    // Wait for 3 responses (poll)
    const deadline = Date.now() + 15_000;
    while (responses.length < 3 && Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 50));
    }

    proxy.stdin.end();
    const exitCode: number = await new Promise((resolve) => {
      proxy.on('exit', (code) => resolve(code ?? 0));
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
