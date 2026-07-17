// ============================================================
// Overwatch — register_tape_session tool
// Inform the engagement that an external `overwatch-mcp-tape` proxy is
// recording the live JSON-RPC stream. The tape file itself is owned by
// the proxy (out-of-server, file-backed). This tool only registers a
// pointer + manifest summary into the activity log so retrospectives
// can find it.
// ============================================================

import { z } from 'zod';
import { createReadStream, lstatSync, existsSync } from 'fs';
import { createHash } from 'crypto';
import { resolve as resolvePath } from 'path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';

/**
 * Stream the tape file and count non-empty newline-delimited lines without
 * loading it into memory. Tapes can be hundreds of MB; the previous
 * `readFileSync` blew up the heap for large captures.
 */
async function streamTapeStats(absPath: string): Promise<{ line_count: number; sha256: string }> {
  return new Promise((resolve, reject) => {
    let lineCount = 0;
    const hash = createHash('sha256');
    let pendingNonEmpty = false; // true once we have seen non-newline bytes for the current line
    const stream = createReadStream(absPath, { highWaterMark: 64 * 1024 });
    stream.on('data', (chunk: Buffer | string) => {
      const buf = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
      hash.update(buf);
      for (let i = 0; i < buf.length; i++) {
        const b = buf[i];
        if (b === 0x0a /* \n */) {
          if (pendingNonEmpty) lineCount++;
          pendingNonEmpty = false;
        } else if (b !== 0x0d /* \r */) {
          pendingNonEmpty = true;
        }
      }
    });
    stream.on('end', () => {
      if (pendingNonEmpty) lineCount++; // trailing line without final newline
      resolve({ line_count: lineCount, sha256: hash.digest('hex') });
    });
    stream.on('error', reject);
  });
}

/**
 * Compute a sha256 over the first and last `windowBytes` of the tape so the
 * manifest pins which file we registered without loading the whole tape.
 */
async function tapeFingerprint(absPath: string, size: number, windowBytes = 4096): Promise<string> {
  const hash = createHash('sha256');
  if (size === 0) return hash.digest('hex');
  const head = await readRange(absPath, 0, Math.min(windowBytes, size));
  hash.update(head);
  if (size > windowBytes) {
    const tailStart = Math.max(windowBytes, size - windowBytes);
    const tail = await readRange(absPath, tailStart, size);
    hash.update(tail);
  }
  return hash.digest('hex');
}

function readRange(absPath: string, start: number, end: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    // end is exclusive in fs terms via { start, end: end - 1 }
    const stream = createReadStream(absPath, { start, end: end - 1 });
    stream.on('data', (c: Buffer | string) => chunks.push(typeof c === 'string' ? Buffer.from(c) : c));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

export function registerTapeTools(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'register_tape_session',
    {
      title: 'Register Tape Session',
      description: `Register an external JSON-RPC tape (produced by \`overwatch-mcp-tape\`) with this engagement.

The tape itself is captured by the standalone proxy binary and lives on disk
as JSONL outside the server. This tool only records a pointer + small manifest
(file size, line count, full-file sha256, and a compatibility head/tail fingerprint) into the activity log
so retrospectives can locate it. The tape's contents are NOT loaded into the
graph by this call.

Inputs:
- \`tape_path\` (required): absolute or workspace-relative path to the tape JSONL.
- \`session_id\` (required): human-readable identifier for the captured session.
- \`upstream_command\` (optional): the upstream argv that was wrapped, for context.
- \`notes\` (optional): operator-supplied free text.

Emits a \`tape_session_started\` event (provenance='operator', category='system').`,
      inputSchema: {
        tape_path: z.string().min(1),
        session_id: z.string().min(1),
        upstream_command: z.string().optional(),
        notes: z.string().optional(),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('register_tape_session', async (args) => {
      const { tape_path, session_id, upstream_command, notes } = args;
      const absPath = resolvePath(tape_path);

      if (!existsSync(absPath)) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              registered: false,
              error: 'tape_not_found',
              tape_path: absPath,
            }, null, 2),
          }],
          isError: true,
        };
      }

      const stat = lstatSync(absPath);
      if (stat.isSymbolicLink() || !stat.isFile()) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              registered: false,
              error: 'tape_not_regular_file',
              tape_path: absPath,
            }, null, 2),
          }],
          isError: true,
        };
      }
      // Stream-count lines so multi-hundred-MB tapes don't OOM the server,
      // and fingerprint via head+tail windows only.
      const { line_count: lineCount, sha256 } = await streamTapeStats(absPath);
      const fingerprint = await tapeFingerprint(absPath, stat.size);
      const after = lstatSync(absPath);
      if (
        after.isSymbolicLink()
        || !after.isFile()
        || after.dev !== stat.dev
        || after.ino !== stat.ino
        || after.size !== stat.size
        || after.mtimeMs !== stat.mtimeMs
      ) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              registered: false,
              error: 'tape_changed_during_registration',
              tape_path: absPath,
            }, null, 2),
          }],
          isError: true,
        };
      }

      const event = engine.logActionEvent({
        description: `Tape session registered: ${session_id} (${lineCount} frames, ${stat.size} bytes)`,
        event_type: 'tape_session_started',
        category: 'system',
        provenance: 'operator',
        details: {
          session_id,
          tape_path: absPath,
          tape_size_bytes: stat.size,
          tape_line_count: lineCount,
          tape_sha256: sha256,
          tape_fingerprint_sha256: fingerprint,
          upstream_command,
          notes,
          captured_at: stat.mtime.toISOString(),
        },
      });

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            registered: true,
            event_id: event.event_id,
            tape_path: absPath,
            session_id,
            tape_size_bytes: stat.size,
            tape_line_count: lineCount,
            tape_sha256: sha256,
            tape_fingerprint_sha256: fingerprint,
          }, null, 2),
        }],
      };
    }),
  );
}
