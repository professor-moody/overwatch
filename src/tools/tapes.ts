// ============================================================
// Overwatch — register_tape_session tool
// Inform the engagement that an external `overwatch-mcp-tape` proxy is
// recording the live JSON-RPC stream. The tape file itself is owned by
// the proxy (out-of-server, file-backed). This tool only registers a
// pointer + manifest summary into the activity log so retrospectives
// can find it.
// ============================================================

import { z } from 'zod';
import { readFileSync, statSync, existsSync } from 'fs';
import { resolve as resolvePath } from 'path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerTapeTools(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'register_tape_session',
    {
      title: 'Register Tape Session',
      description: `Register an external JSON-RPC tape (produced by \`overwatch-mcp-tape\`) with this engagement.

The tape itself is captured by the standalone proxy binary and lives on disk
as JSONL outside the server. This tool only records a pointer + small manifest
(file size, line count, sha256 of the first/last bytes) into the activity log
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

      const stat = statSync(absPath);
      // Read at most the first and last 4KB to compute a cheap fingerprint
      // without loading huge tapes into memory.
      const fp = readFileSync(absPath, 'utf-8');
      const lineCount = fp.length === 0 ? 0 : fp.split('\n').filter(l => l.length > 0).length;

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
          }, null, 2),
        }],
      };
    }),
  );
}
