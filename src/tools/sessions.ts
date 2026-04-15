// ============================================================
// Overwatch — Session Tools
// MCP tools for persistent interactive session management
// ============================================================

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SessionManager } from '../services/session-manager.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';
import { isIpInScope, isHostnameInScope, isIPv6 } from '../services/cidr.js';

function isRemoteScopedSession(kind: 'ssh' | 'local_pty' | 'socket', mode?: 'connect' | 'listen'): boolean {
  return kind === 'ssh' || (kind === 'socket' && mode !== 'listen');
}

function isHostInScope(host: string, engine: GraphEngine): boolean {
  const scope = engine.getConfig().scope;
  return isIpInScope(host, scope.cidrs, scope.exclusions)
    || isHostnameInScope(host, scope.domains, scope.exclusions);
}

export function registerSessionTools(server: McpServer, sessionManager: SessionManager, engine: GraphEngine): void {

  // ============================================================
  // Tool: open_session
  // ============================================================
  server.registerTool(
    'open_session',
    {
      title: 'Open Session',
      description: `Create a new persistent interactive session.

Supports three session kinds:
- **ssh**: SSH connection via node-pty (full PTY, resize, signals)
- **local_pty**: Local shell via node-pty (full PTY)
- **socket**: TCP socket for bind/reverse shells (dumb TTY, upgradeable)

Sessions persist across MCP tool calls. Use write_session/read_session for I/O.
Remote target sessions (SSH and socket connect mode) are scope-enforced and fail closed for out-of-scope hosts.
The session is claimed by the opening agent — other agents can read but not write without force.`,
      inputSchema: {
        kind: z.enum(['ssh', 'local_pty', 'socket']).describe('Session transport type'),
        title: z.string().describe('Human-readable session label'),
        host: z.string().optional().describe('Target host (required for ssh and socket connect mode)'),
        port: z.number().int().optional().describe('Target port (required for socket, optional for ssh)'),
        user: z.string().optional().describe('SSH username'),
        key_path: z.string().optional().describe('Path to SSH private key'),
        password: z.string().optional().describe('SSH password (used via sshpass — prefer keys)'),
        ssh_options: z.array(z.string()).optional().describe('Additional SSH -o options'),
        shell: z.string().optional().describe('Shell path for local_pty (default: $SHELL or /bin/bash)'),
        cwd: z.string().optional().describe('Working directory for local_pty'),
        mode: z.enum(['connect', 'listen']).optional().describe('Socket mode: connect to target or listen for incoming'),
        cols: z.number().int().optional().describe('Terminal columns (default: 120)'),
        rows: z.number().int().optional().describe('Terminal rows (default: 30)'),
        agent_id: z.string().optional().describe('Agent that owns this session'),
        target_node: z.string().optional().describe('Graph node ID this session targets'),
        principal_node: z.string().optional().describe('Graph node ID of the authenticating user/group/credential (enables HAS_SESSION edge creation on success)'),
        credential_node: z.string().optional().describe('Graph node ID of the credential used for authentication'),
        action_id: z.string().optional().describe('Action ID to correlate session result with planned action'),
        frontier_item_id: z.string().optional().describe('Frontier item this session attempt came from'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorBoundary('open_session', async (params) => {
      const warnings: string[] = [];
      if (params.host && isRemoteScopedSession(params.kind, params.mode)) {
        if (isIPv6(params.host)) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: `IPv6 targets are not supported (scope is IPv4-only): "${params.host}"`,
                host: params.host,
                kind: params.kind,
                mode: params.mode ?? 'connect',
                scope_reason: 'ipv6_unsupported',
              }, null, 2),
            }],
            isError: true,
          };
        }
        if (!isHostInScope(params.host, engine)) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: `Refusing to open remote session to out-of-scope host "${params.host}"`,
                host: params.host,
                kind: params.kind,
                mode: params.mode ?? 'connect',
                scope_reason: 'host_out_of_scope',
              }, null, 2),
            }],
            isError: true,
          };
        }
      }

      const result = await sessionManager.create({
        kind: params.kind,
        title: params.title,
        host: params.host,
        user: params.user,
        port: params.port,
        key_path: params.key_path,
        password: params.password,
        ssh_options: params.ssh_options,
        shell: params.shell,
        cwd: params.cwd,
        mode: params.mode,
        cols: params.cols,
        rows: params.rows,
        agent_id: params.agent_id,
        target_node: params.target_node,
        principal_node: params.principal_node,
        credential_node: params.credential_node,
        action_id: params.action_id,
        frontier_item_id: params.frontier_item_id,
      });

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            session: result.metadata,
            initial_output: result.initial,
            ...(warnings.length > 0 ? { warnings } : {}),
          }, null, 2),
        }],
      };
    }),
  );

  // ============================================================
  // Tool: write_session
  // ============================================================
  server.registerTool(
    'write_session',
    {
      title: 'Write to Session',
      description: `Write raw bytes to a session. This is the I/O primitive.

No implicit newline — use append_newline for convenience.
Works for shells, password prompts, REPLs, menus, and partial input.
Only the claiming agent can write (use force to override).`,
      inputSchema: {
        session_id: z.string().describe('Session ID to write to'),
        data: z.string().describe('Data to write to the session'),
        append_newline: z.boolean().default(false).describe('Append \\n after data'),
        agent_id: z.string().optional().describe('Agent performing the write (checked against claimed_by)'),
        force: z.boolean().default(false).describe('Override ownership check'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorBoundary('write_session', async ({ session_id, data, append_newline, agent_id, force }) => {
      const payload = append_newline ? data + '\n' : data;
      const result = sessionManager.write(session_id, payload, agent_id, force);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2),
        }],
      };
    }),
  );

  // ============================================================
  // Tool: read_session
  // ============================================================
  server.registerTool(
    'read_session',
    {
      title: 'Read Session Output',
      description: `Read output from a session buffer using cursor-based positioning.

Provide from_pos to read incrementally (returns everything since that position).
Omit from_pos to read the last tail_chars of output.
Returns start_pos/end_pos for stable cursor tracking across reads.
truncated=true means the buffer wrapped past your requested from_pos.`,
      inputSchema: {
        session_id: z.string().describe('Session ID to read from'),
        from_pos: z.number().int().optional().describe('Absolute buffer position to read from (for incremental reads)'),
        tail_chars: z.number().int().optional().describe('Characters to read from tail when from_pos is omitted (default 4096)'),
        tail_bytes: z.number().int().optional().describe('Alias for tail_chars'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('read_session', async ({ session_id, from_pos, tail_chars, tail_bytes }) => {
      const effectiveTailChars = tail_chars ?? tail_bytes ?? 4096;
      const result = sessionManager.read(session_id, from_pos, effectiveTailChars);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2),
        }],
      };
    }),
  );

  // ============================================================
  // Tool: send_to_session (experimental convenience)
  // ============================================================
  server.registerTool(
    'send_to_session',
    {
      title: 'Send Command to Session',
      description: `[Experimental] Convenience wrapper: write command + wait for output to settle + return captured output.

Implemented on top of write_session + read_session. Uses idle timeout to detect when output has stopped.
For password prompts, REPLs, partial input, or streaming tools (tail -f, tcpdump), use write_session + read_session directly.

idle_ms: return after this much silence (default 500ms)
timeout_ms: max wait time (default 10s)
wait_for: regex — return immediately when matched in output`,
      inputSchema: {
        session_id: z.string().describe('Session ID'),
        command: z.string().describe('Command to send (newline appended automatically)'),
        timeout_ms: z.number().int().default(10000).describe('Max wait time in ms'),
        idle_ms: z.number().int().default(500).describe('Return after this many ms of silence'),
        wait_for: z.string().optional().describe('Regex pattern — return immediately when matched'),
        agent_id: z.string().optional().describe('Agent performing the send'),
        force: z.boolean().default(false).describe('Override ownership check'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorBoundary('send_to_session', async ({ session_id, command, timeout_ms, idle_ms, wait_for, agent_id, force }) => {
      const result = await sessionManager.sendCommand(session_id, command, {
        timeout_ms,
        idle_ms,
        wait_for,
        claimedBy: agent_id,
        force,
      });

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2),
        }],
      };
    }),
  );

  // ============================================================
  // Tool: list_sessions
  // ============================================================
  server.registerTool(
    'list_sessions',
    {
      title: 'List Sessions',
      description: `List all sessions with metadata (no output buffers).
Always returns an envelope shaped like { total, active, sessions }.
Use session_id to get details for a specific session.`,
      inputSchema: {
        active_only: z.boolean().default(false).describe('Only show pending/connected sessions'),
        session_id: z.string().optional().describe('Get details for a specific session'),
        agent_id: z.string().optional().describe('Filter to sessions claimed by this agent (or unclaimed)'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('list_sessions', async ({ active_only, session_id, agent_id }) => {
      if (session_id) {
        const session = sessionManager.getSession(session_id);
        if (!session) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: `Session not found: ${session_id}`,
                session_id,
              }, null, 2),
            }],
            isError: true,
          };
        }
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              total: 1,
              active: session.state === 'connected' || session.state === 'pending' ? 1 : 0,
              sessions: [session],
            }, null, 2),
          }],
        };
      }

      let sessions = sessionManager.list(active_only);
      if (agent_id) {
        sessions = sessions.filter(s => !s.claimed_by || s.claimed_by === agent_id);
      }
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            total: sessions.length,
            active: sessions.filter(s => s.state === 'connected' || s.state === 'pending').length,
            sessions,
          }, null, 2),
        }],
      };
    }),
  );

  // ============================================================
  // Tool: update_session
  // ============================================================
  server.registerTool(
    'update_session',
    {
      title: 'Update Session',
      description: `Update session metadata: capabilities, title, notes, or ownership.

Use this to:
- Record a shell upgrade (tty_quality: 'dumb' → 'partial' → 'full')
- Transfer ownership to another agent
- Add operational notes`,
      inputSchema: {
        session_id: z.string().describe('Session ID to update'),
        tty_quality: z.enum(['none', 'dumb', 'partial', 'full']).optional()
          .describe('Updated TTY quality after shell upgrade'),
        supports_resize: z.boolean().optional().describe('Whether session now supports resize'),
        supports_signals: z.boolean().optional().describe('Whether session now supports signals'),
        title: z.string().optional().describe('New session title'),
        claimed_by: z.string().optional().describe('Transfer ownership to this agent_id'),
        notes: z.string().optional().describe('Operational notes'),
        agent_id: z.string().optional().describe('Agent performing the update (checked against claimed_by)'),
        force: z.boolean().default(false).describe('Override ownership check'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('update_session', async ({ session_id, tty_quality, supports_resize, supports_signals, title, claimed_by, notes, agent_id, force }) => {
      const capabilities: Record<string, unknown> = {};
      if (tty_quality !== undefined) capabilities.tty_quality = tty_quality;
      if (supports_resize !== undefined) capabilities.supports_resize = supports_resize;
      if (supports_signals !== undefined) capabilities.supports_signals = supports_signals;

      const updated = sessionManager.update(session_id, {
        capabilities: Object.keys(capabilities).length > 0 ? capabilities as any : undefined,
        title,
        claimed_by,
        notes,
      }, agent_id, force);

      return {
        content: [{ type: 'text', text: JSON.stringify(updated, null, 2) }],
      };
    }),
  );

  // ============================================================
  // Tool: resize_session
  // ============================================================
  server.registerTool(
    'resize_session',
    {
      title: 'Resize Session',
      description: `Resize terminal dimensions. Only works for PTY-backed sessions (ssh, local_pty, or upgraded socket).`,
      inputSchema: {
        session_id: z.string().describe('Session ID'),
        cols: z.number().int().describe('New column count'),
        rows: z.number().int().describe('New row count'),
        agent_id: z.string().optional().describe('Agent performing the resize (checked against claimed_by)'),
        force: z.boolean().default(false).describe('Override ownership check'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('resize_session', async ({ session_id, cols, rows, agent_id, force }) => {
      sessionManager.resize(session_id, cols, rows, agent_id, force);
      return {
        content: [{ type: 'text', text: JSON.stringify({ session_id, cols, rows, resized: true }, null, 2) }],
      };
    }),
  );

  // ============================================================
  // Tool: signal_session
  // ============================================================
  server.registerTool(
    'signal_session',
    {
      title: 'Signal Session',
      description: `Send a signal to the session process. Only works for PTY-backed sessions.
Use SIGINT to cancel a running command, SIGTERM/SIGKILL to force-terminate.`,
      inputSchema: {
        session_id: z.string().describe('Session ID'),
        signal: z.string().describe('Signal to send (SIGINT, SIGTERM, SIGKILL, SIGTSTP, SIGCONT)'),
        agent_id: z.string().optional().describe('Agent performing the signal (checked against claimed_by)'),
        force: z.boolean().default(false).describe('Override ownership check'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('signal_session', async ({ session_id, signal: rawSignal, agent_id, force }) => {
      const validSignals = ['SIGINT', 'SIGTERM', 'SIGKILL', 'SIGTSTP', 'SIGCONT'] as const;
      const normalized = rawSignal.toUpperCase().startsWith('SIG') ? rawSignal.toUpperCase() : `SIG${rawSignal.toUpperCase()}`;
      const signal = normalized as typeof validSignals[number];
      if (!validSignals.includes(signal)) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: `Unknown signal: ${rawSignal}. Valid: ${validSignals.join(', ')}` }, null, 2) }],
          isError: true,
        };
      }
      sessionManager.signal(session_id, signal, agent_id, force);
      return {
        content: [{ type: 'text', text: JSON.stringify({ session_id, signal, sent: true }, null, 2) }],
      };
    }),
  );

  // ============================================================
  // Tool: close_session
  // ============================================================
  server.registerTool(
    'close_session',
    {
      title: 'Close Session',
      description: `Close and destroy a session. Returns final output snapshot and session summary.`,
      inputSchema: {
        session_id: z.string().describe('Session ID to close'),
        agent_id: z.string().optional().describe('Agent performing the close (checked against claimed_by)'),
        force: z.boolean().default(false).describe('Override ownership check'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('close_session', async ({ session_id, agent_id, force }) => {
      const result = sessionManager.close(session_id, agent_id, force);
      const duration = result.metadata.started_at && result.metadata.closed_at
        ? (new Date(result.metadata.closed_at).getTime() - new Date(result.metadata.started_at).getTime()) / 1000
        : 0;

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            session: result.metadata,
            final_output: result.final,
            summary: {
              duration_seconds: duration,
              total_output_bytes: result.final.end_pos,
            },
          }, null, 2),
        }],
      };
    }),
  );
}
