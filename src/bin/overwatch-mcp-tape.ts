#!/usr/bin/env node
// ============================================================
// overwatch-mcp-tape — stdio JSON-RPC capture proxy
//
// Wrap an Overwatch MCP server and capture every newline-delimited
// JSON-RPC frame in both directions to a JSONL tape file. Lives outside
// the main server so its bugs do NOT crash live engagements.
//
// Usage:
//   overwatch-mcp-tape --tape ./tapes/session.jsonl -- node ./dist/index.js [server-args...]
//   overwatch-mcp-tape --tape-dir ./tapes -- node ./dist/index.js
//
// Flags:
//   --tape <file>     explicit tape path (overrides --tape-dir)
//   --tape-dir <dir>  directory; tape file becomes <dir>/tape-<iso>.jsonl
//   --session <id>    optional human-readable session id (embedded in
//                     auto-generated tape file name)
//   --quiet           suppress proxy stderr diagnostics
//   --                everything after this is the upstream server argv
// ============================================================

import { spawn } from 'child_process';
import { fileURLToPath } from 'node:url';
import { processChunk, TapeWriter } from '../services/tape-recorder.js';

interface ParsedArgs {
  tapePath?: string;
  tapeDir?: string;
  sessionId?: string;
  quiet: boolean;
  upstream: string[];
}

export function parseArgs(argv: string[]): ParsedArgs {
  const out: ParsedArgs = { quiet: false, upstream: [] };
  let i = 0;
  while (i < argv.length) {
    const arg = argv[i];
    if (arg === '--') { out.upstream = argv.slice(i + 1); break; }
    // `--tape` is the canonical flag; `--out` is accepted as an alias
    // because earlier docs referenced it. Both behave identically.
    if (arg === '--tape' || arg === '--out') { out.tapePath = argv[++i]; }
    else if (arg === '--tape-dir') { out.tapeDir = argv[++i]; }
    else if (arg === '--session') { out.sessionId = argv[++i]; }
    else if (arg === '--quiet') { out.quiet = true; }
    else if (arg === '-h' || arg === '--help') {
      printUsage();
      process.exit(0);
    } else {
      // Unknown flag before --: treat the rest as upstream argv (lenient mode)
      out.upstream = argv.slice(i);
      break;
    }
    i++;
  }
  return out;
}

function printUsage(): void {
  process.stderr.write(`overwatch-mcp-tape — stdio JSON-RPC capture proxy

Usage:
  overwatch-mcp-tape [options] -- <upstream-cmd> [upstream-args...]

Options:
  --tape <file>      Explicit tape file path (JSONL).
  --tape-dir <dir>   Directory for auto-named tape file. Defaults to ./tapes.
  --session <id>     Optional session id baked into auto-generated file name.
  --quiet            Suppress proxy diagnostics on stderr.
  -h, --help         Show this help.
`);
}

function resolveTapePath(args: ParsedArgs): string {
  if (args.tapePath) return args.tapePath;
  const dir = args.tapeDir ?? './tapes';
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const sid = args.sessionId ? `${args.sessionId}-` : '';
  return `${dir}/tape-${sid}${ts}.jsonl`;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.upstream.length === 0) {
    process.stderr.write('error: missing upstream command (use `-- <cmd> [args...]`)\n');
    printUsage();
    process.exit(2);
  }

  const tapePath = resolveTapePath(args);
  const writer = new TapeWriter(tapePath);
  const log = (msg: string): void => {
    if (!args.quiet) process.stderr.write(`[overwatch-mcp-tape] ${msg}\n`);
  };
  log(`recording to ${tapePath}`);
  log(`spawning upstream: ${args.upstream.join(' ')}`);

  const child = spawn(args.upstream[0], args.upstream.slice(1), {
    stdio: ['pipe', 'pipe', 'inherit'],
  });

  let clientBuffer = '';
  let serverBuffer = '';

  // client (us) -> upstream stdin
  process.stdin.setEncoding('utf-8');
  process.stdin.on('data', (chunk: string) => {
    clientBuffer = processChunk(writer, 'client_to_server', clientBuffer, chunk);
    if (!child.stdin.destroyed) child.stdin.write(chunk);
  });
  process.stdin.on('end', () => {
    if (!child.stdin.destroyed) child.stdin.end();
  });

  // upstream stdout -> client (us)
  child.stdout.setEncoding('utf-8');
  child.stdout.on('data', (chunk: string) => {
    serverBuffer = processChunk(writer, 'server_to_client', serverBuffer, chunk);
    process.stdout.write(chunk);
  });

  const shutdown = async (code: number): Promise<void> => {
    // Flush any partial-frame remainders as raw records (best-effort).
    if (clientBuffer.length > 0) {
      writer.write({ ts: new Date().toISOString(), direction: 'client_to_server', raw: clientBuffer, parse_error: 'unterminated_frame_at_close' });
    }
    if (serverBuffer.length > 0) {
      writer.write({ ts: new Date().toISOString(), direction: 'server_to_client', raw: serverBuffer, parse_error: 'unterminated_frame_at_close' });
    }
    log(`captured ${writer.count} frames`);
    await writer.close();
    process.exit(code);
  };

  child.on('exit', (code, signal) => {
    log(`upstream exited (code=${code}, signal=${signal})`);
    void shutdown(code ?? (signal ? 1 : 0));
  });

  child.on('error', (err) => {
    log(`upstream error: ${err.message}`);
    void shutdown(1);
  });

  process.on('SIGINT', () => { if (!child.killed) child.kill('SIGINT'); });
  process.on('SIGTERM', () => { if (!child.killed) child.kill('SIGTERM'); });
}

// Only run main when invoked directly. The test harness imports this
// module to exercise parseArgs in isolation; running main() at import
// time spawns a child and exits on missing args.
const isDirect = (() => {
  if (typeof require !== 'undefined' && (require as any).main === module) return true;
  try {
    const here = fileURLToPath(import.meta.url);
    const argv1 = process.argv[1];
    return !!argv1 && (here === argv1 || here.endsWith(argv1));
  } catch {
    return false;
  }
})();

if (isDirect) {
  main().catch((err) => {
    process.stderr.write(`[overwatch-mcp-tape] fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
    process.exit(1);
  });
}
