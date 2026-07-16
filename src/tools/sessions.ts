// ============================================================
// Overwatch — Session Tools
// MCP tools for persistent interactive session management
// ============================================================

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SessionManager } from '../services/session-manager.js';
import type { GraphEngine } from '../services/graph-engine.js';
import type { SessionDefaultValidation } from '../types.js';
import { withErrorBoundary } from './error-boundary.js';
import { isHostInScope as isScopedHostInScope, isIPv6, isIPv4 } from '../services/cidr.js';
import { registerMockServiceCore } from './operator-infra.js';
import { actionIdOrUuid } from '../services/deterministic-id.js';
import {
  SESSION_COMMAND_TERMINAL,
  SessionCommandService,
  buildSessionRequestFingerprint,
} from '../services/session-command-service.js';

const defaultValidationSchema = z.object({
  technique: z.string().min(1).describe('Technique label applied to every send_to_session call (e.g. "lateral_movement", "post_exploit").'),
  target_ip: z.string().min(1).optional().describe('Target IP or hostname for scope checks (defaults to session host when omitted).'),
  target_url: z.string().min(1).optional().describe('Target URL for scope checks (web sessions).'),
  target_node: z.string().min(1).optional().describe('Graph node ID this session targets.'),
  allow_unverified_scope: z.boolean().optional().describe('Skip the fail-closed check for unverified host/service/share targets.'),
  agent_id: z.string().min(1).optional().describe('Agent attributed to instrumented sends from this session.'),
});

/**
 * Resolve the default target_ip for a session: use the explicit value if
 * given, otherwise fall back to the session host (which may be an IPv4 or
 * a hostname — `validateAction` accepts both).
 */
function deriveDefaultTarget(host: string | undefined, dv: SessionDefaultValidation): SessionDefaultValidation {
  if (dv.target_ip || dv.target_url || dv.target_node) return dv;
  if (!host) return dv;
  // Hostnames and IPv4 both go through target_ip; isHostInScope handles both.
  if (isIPv4(host) || !isIPv6(host)) {
    return { ...dv, target_ip: host };
  }
  return dv;
}

function isRemoteScopedSession(kind: 'ssh' | 'local_pty' | 'socket', mode?: 'connect' | 'listen'): boolean {
  return kind === 'ssh' || (kind === 'socket' && mode !== 'listen');
}

function isHostInScope(host: string, engine: GraphEngine): boolean {
  const scope = engine.getConfig().scope;
  return isScopedHostInScope(host, scope);
}

export function registerSessionTools(
  server: McpServer,
  sessionManager: SessionManager,
  engine: GraphEngine,
  sessionCommands = new SessionCommandService(engine),
): void {

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
        title: z.string().min(1).describe('Human-readable session label'),
        host: z.string().min(1).optional().describe('Target host (required for ssh and socket connect mode)'),
        bind_host: z.string().min(1).optional().describe('Socket listen bind address. Alias for host in listen mode; prefer this for reverse-shell catchers.'),
        advertise_host: z.string().min(1).optional().describe('Callback address the target should use to reach this listener. Display-only metadata for payload construction.'),
        port: z.number().int().min(0).max(65_535).optional().describe('Target port (required for socket, optional for ssh; 0 requests an ephemeral listener port)'),
        user: z.string().min(1).optional().describe('SSH username'),
        key_path: z.string().min(1).optional().describe('Path to SSH private key'),
        password: z.string().optional().describe('SSH password (used via sshpass — prefer keys)'),
        ssh_options: z.array(z.string()).optional().describe('Additional SSH -o options'),
        shell: z.string().min(1).optional().describe('Shell path for local_pty (default: $SHELL or /bin/bash)'),
        cwd: z.string().min(1).optional().describe('Working directory for local_pty'),
        mode: z.enum(['connect', 'listen']).optional().describe('Socket mode: connect to target or listen for incoming'),
        accept_mode: z.enum(['single', 'rearm']).optional().describe('Socket listener accept behavior. reverse_shell_catcher defaults to rearm; generic listeners default to single.'),
        cols: z.number().int().optional().describe('Terminal columns (default: 120)'),
        rows: z.number().int().optional().describe('Terminal rows (default: 30)'),
        agent_id: z.string().min(1).optional().describe('Owning task_id (preferred); a unique legacy agent label is accepted'),
        target_node: z.string().min(1).optional().describe('Graph node ID this session targets'),
        principal_node: z.string().min(1).optional().describe('Graph node ID of the authenticating user/group/credential (enables HAS_SESSION edge creation on success)'),
        credential_node: z.string().min(1).optional().describe('Graph node ID of the credential used for authentication'),
        action_id: z.string().min(1).optional().describe('Action ID to correlate session result with planned action'),
        frontier_item_id: z.string().min(1).optional().describe('Frontier item this session attempt came from'),
        mock_service_purpose: z.enum([
          'fake_ldap', 'responder', 'ntlmrelayx', 'redirector',
          'reverse_shell_catcher', 'http_capture', 'smb_capture', 'other',
        ]).optional().describe('When opening a socket listener, auto-register this session as an operator-controlled mock_service of the given purpose. Adds a mock_service node + RUNS_ON/OPERATED_BY edges and stamps serves_mock_service_id back onto the session capabilities.'),
        mock_service_protocol: z.string().optional().describe('Wire protocol of the mock service (defaults to the socket protocol).'),
        mock_service_notes: z.string().optional(),
        default_validation: defaultValidationSchema.optional().describe(
          'Baseline scope/technique for the session. When set, every send_to_session inherits this and runs validateAction (per-call overrides apply). Highly recommended for SSH and remote sessions.',
        ),
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
      const ownerResolution = params.agent_id
        ? engine.resolveAgentTaskReference(params.agent_id)
        : { status: 'missing' as const };
      if (ownerResolution.status === 'ambiguous_legacy_label') {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              error: `Agent label is ambiguous: ${params.agent_id}`,
              candidate_task_ids: ownerResolution.candidate_task_ids,
              hint: 'Pass the exact task_id as agent_id for this compatibility input.',
            }, null, 2),
          }],
          isError: true,
        };
      }
      const ownerTask = ownerResolution.status === 'exact'
        || ownerResolution.status === 'unique_legacy_label'
        ? ownerResolution.task
        : undefined;
      const ownerTaskId = ownerTask?.task_id ?? ownerTask?.id;
      const ownerAgentLabel = ownerTask?.agent_label ?? ownerTask?.agent_id ?? params.agent_id;
      const effectiveMode = params.mode ?? (params.kind === 'socket' ? 'connect' : undefined);
      const isSocketListener = params.kind === 'socket' && effectiveMode === 'listen';
      const bindHost = isSocketListener ? (params.bind_host ?? params.host ?? '127.0.0.1') : undefined;
      const acceptMode = params.accept_mode
        ?? (isSocketListener && params.mock_service_purpose === 'reverse_shell_catcher' ? 'rearm' : 'single');
      if (isSocketListener && (bindHost === '127.0.0.1' || bindHost === 'localhost')) {
        warnings.push(params.advertise_host
          ? `Listener is bound to ${bindHost}; targets cannot reach ${params.advertise_host} unless a bridge/forwarder is running.`
          : `Listener is bound to ${bindHost}; pass bind_host/advertise_host or run a bridge if targets must call back from another host.`);
      }
      if (isSocketListener && !params.advertise_host && bindHost === '0.0.0.0') {
        warnings.push('Listener binds all interfaces but no advertise_host was provided; payload callback address is ambiguous.');
      }

      if (params.host && isRemoteScopedSession(params.kind, effectiveMode)) {
        if (isIPv6(params.host)) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: `IPv6 targets are not supported (scope is IPv4-only): "${params.host}"`,
                host: params.host,
                kind: params.kind,
                mode: effectiveMode ?? 'connect',
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
                mode: effectiveMode ?? 'connect',
                scope_reason: 'host_out_of_scope',
              }, null, 2),
            }],
            isError: true,
          };
        }
      }

      // If the caller declared a target_node, ensure that node exists and
      // matches the host they're actually connecting to. Otherwise a
      // successful SSH to host A could be recorded as a HAS_SESSION edge
      // against host B due to an operator/agent metadata bug.
      if (params.target_node && params.host && isRemoteScopedSession(params.kind, effectiveMode)) {
        const node = engine.getNode(params.target_node);
        if (!node) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: `target_node "${params.target_node}" does not exist in the graph`,
                target_node: params.target_node,
                host: params.host,
                scope_reason: 'target_node_missing',
              }, null, 2),
            }],
            isError: true,
          };
        }
        const candidates = [
          (node as { ip?: string }).ip,
          (node as { hostname?: string }).hostname,
          (node as { fqdn?: string }).fqdn,
          (node as { label?: string }).label,
        ].filter((v): v is string => typeof v === 'string' && v.length > 0);
        const matches = candidates.some(c => c === params.host);
        if (!matches) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: `target_node "${params.target_node}" does not match host "${params.host}" (node has: ${candidates.join(', ') || '<no host fields>'})`,
                target_node: params.target_node,
                host: params.host,
                node_host_fields: candidates,
                scope_reason: 'target_node_host_mismatch',
              }, null, 2),
            }],
            isError: true,
          };
        }
      }

      // Resolve effective default_validation. If an explicit one was passed,
      // fill in target_ip from session host when omitted; otherwise synthesize
      // a sensible default for remote-scoped sessions so every send is still
      // instrumented (technique falls back to "session_command").
      let defaultValidation: SessionDefaultValidation | undefined = params.default_validation
        ? deriveDefaultTarget(params.host, { ...params.default_validation, agent_id: params.default_validation.agent_id ?? ownerAgentLabel })
        : undefined;
      if (!defaultValidation && params.host && isRemoteScopedSession(params.kind, effectiveMode)) {
        defaultValidation = deriveDefaultTarget(params.host, {
          technique: 'session_command',
          target_node: params.target_node,
          agent_id: ownerAgentLabel,
        });
      }

      // If the operator declared a default_validation (or one was synthesized
      // for a remote session), run validateAction once so technique-level
      // OPSEC checks gate the open. The per-host scope check above already
      // catches out-of-scope hosts; this picks up blacklisted techniques and
      // similar policy denials when OPSEC is enabled.
      if (defaultValidation) {
        const v = engine.validateAction({
          technique: defaultValidation.technique,
          target_ip: defaultValidation.target_ip,
          target_url: defaultValidation.target_url,
          target_node: defaultValidation.target_node,
          allow_unverified_scope: defaultValidation.allow_unverified_scope,
        });
        if (!v.valid) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: `Refusing to open session: validateAction denied (${v.errors.join('; ')})`,
                host: params.host,
                kind: params.kind,
                technique: defaultValidation.technique,
                validation_errors: v.errors,
                validation_warnings: v.warnings,
                scope_reason: 'default_validation_denied',
              }, null, 2),
            }],
            isError: true,
          };
        }
        if (v.warnings.length > 0) warnings.push(...v.warnings);
      }

      const result = await sessionManager.create({
        kind: params.kind,
        title: params.title,
        host: isSocketListener ? bindHost : params.host,
        bind_host: bindHost,
        advertise_host: params.advertise_host,
        user: params.user,
        port: params.port,
        key_path: params.key_path,
        password: params.password,
        ssh_options: params.ssh_options,
        shell: params.shell,
        cwd: params.cwd,
        mode: effectiveMode,
        accept_mode: acceptMode,
        reachability_warnings: warnings.length > 0 ? warnings : undefined,
        cols: params.cols,
        rows: params.rows,
        owner_task_id: ownerTaskId,
        agent_id: ownerAgentLabel,
        target_node: params.target_node,
        principal_node: params.principal_node,
        credential_node: params.credential_node,
        action_id: params.action_id,
        frontier_item_id: params.frontier_item_id,
        default_validation: defaultValidation,
      });

      // Operator-infra integration: when a socket listener is opened with
      // `mock_service_purpose`, auto-register the listener as a
      // mock_service node and stamp serves_mock_service_id back onto the
      // session capabilities so the dashboard can pivot session ↔ listener.
      let mock_service: { mock_service_id: string; new: boolean } | undefined;
      if (
        params.mock_service_purpose
        && params.kind === 'socket'
        && effectiveMode === 'listen'
        && typeof result.metadata.port === 'number'
      ) {
        const reg = registerMockServiceCore(engine, {
          purpose: params.mock_service_purpose,
          protocol: params.mock_service_protocol ?? 'tcp',
          bind_host: bindHost ?? '127.0.0.1',
          bind_port: result.metadata.port,
          notes: params.mock_service_notes,
          bound_session_id: result.metadata.id,
          target_node: params.target_node,
          agent_id: ownerAgentLabel,
          action_id: params.action_id,
          frontier_item_id: params.frontier_item_id,
        });
        sessionManager.update(result.metadata.id, {
          capabilities: { serves_mock_service_id: reg.mock_service_id },
        });
        result.metadata.capabilities.serves_mock_service_id = reg.mock_service_id;
        mock_service = { mock_service_id: reg.mock_service_id, new: reg.is_new };
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            session: result.metadata,
            initial_output: result.initial,
            ...(mock_service ? { mock_service } : {}),
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
        connection_id: z.string().optional().describe('Expected live connection generation ID; rejects if the listener reconnected.'),
        connection_generation: z.number().int().nonnegative().optional().describe('Expected connection generation number.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorBoundary('write_session', async ({
      session_id,
      data,
      append_newline,
      agent_id,
      force,
      connection_id,
      connection_generation,
    }) => {
      const payload = append_newline ? data + '\n' : data;
      const result = sessionManager.write(
        session_id,
        payload,
        agent_id,
        force,
        { connection_id, connection_generation },
      );

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
truncated=true means the buffer wrapped past your requested from_pos.
Pass the connection_id/generation returned by the prior read to reject stale-generation cursors.`,
      inputSchema: {
        session_id: z.string().describe('Session ID to read from'),
        from_pos: z.number().int().optional().describe('Absolute buffer position to read from (for incremental reads)'),
        tail_chars: z.number().int().optional().describe('Characters to read from tail when from_pos is omitted (default 4096)'),
        tail_bytes: z.number().int().optional().describe('Alias for tail_chars'),
        connection_id: z.string().optional().describe('Expected live connection generation ID.'),
        connection_generation: z.number().int().nonnegative().optional().describe('Expected connection generation number.'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('read_session', async ({
      session_id,
      from_pos,
      tail_chars,
      tail_bytes,
      connection_id,
      connection_generation,
    }) => {
      const effectiveTailChars = tail_chars ?? tail_bytes ?? 4096;
      const result = sessionManager.read(
        session_id,
        from_pos,
        effectiveTailChars,
        { connection_id, connection_generation },
      );

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2),
        }],
      };
    }),
  );

  // ============================================================
  // Tool: send_to_session (instrumented command execution)
  // ============================================================
  server.registerTool(
    'send_to_session',
    {
      title: 'Send Command to Session',
      description: `Run a command in a persistent session with full action-lifecycle instrumentation.

Each call:
- runs validateAction against the merged metadata (per-call override > session default_validation),
- emits action_started / action_completed (or action_failed) on the activity log,
- persists the captured output window as evidence,
- records OPSEC noise when an estimate is supplied or OPSEC enforcement is on.

Sessions opened with default_validation inherit it on every send, so most calls only need (session_id, command). For partial input, password prompts, REPLs, or streaming tools (tail -f, tcpdump), use write_session + read_session — those are the lower-level primitives and intentionally bypass the lifecycle.

idle_ms: return after this much silence (default 500ms)
timeout_ms: max wait time (default 10s)
wait_for: regex — return immediately when matched in output

Result fields include action_id, evidence_id, validation_result, plus completion_reason:
- 'wait_for'       — wait_for regex matched
- 'idle'           — output went quiet for idle_ms
- 'timeout'        — hit timeout_ms before settling (timed_out: true)
- 'session_closed' — session went away mid-command`,
      inputSchema: {
        session_id: z.string().describe('Session ID'),
        command: z.string().describe('Command to send (newline appended automatically)'),
        timeout_ms: z.number().int().default(10000).describe('Max wait time in ms'),
        idle_ms: z.number().int().default(500).describe('Return after this many ms of silence'),
        wait_for: z.string().optional().describe('Regex pattern — return immediately when matched'),
        agent_id: z.string().optional().describe('Agent performing the send'),
        force: z.boolean().default(false).describe('Override ownership check'),
        // Per-call validation override (merged over session default_validation)
        technique: z.string().optional().describe('Override technique for this command (defaults to session default_validation.technique).'),
        target_ip: z.string().optional().describe('Override target IP/hostname for this command (defaults to session default_validation.target_ip or session host).'),
        target_url: z.string().optional().describe('Override target URL for this command.'),
        target_node: z.string().optional().describe('Override target node for this command.'),
        allow_unverified_scope: z.boolean().optional().describe('Override allow_unverified_scope for this command.'),
        noise_estimate: z.number().optional().describe('Per-command noise estimate (records OPSEC noise; enforced only when OPSEC is enabled).'),
        action_id: z.string().min(1).optional().describe('Stable action ID for this instrumented session command.'),
        command_id: z.string().min(1).optional().describe('Stable application-command ID for status correlation and safe retries.'),
        idempotency_key: z.string().min(1).optional().describe('Stable retry key. Identical retries return the original captured result without sending again.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorBoundary('send_to_session', async (params) => {
      const {
        session_id, command, timeout_ms, idle_ms, wait_for, agent_id, force,
        technique: callTechnique, target_ip: callTargetIp, target_url: callTargetUrl,
        target_node: callTargetNode, allow_unverified_scope: callAllowUnverified,
        noise_estimate, action_id, command_id, idempotency_key,
      } = params;
      const actorResolution = agent_id
        ? engine.resolveAgentTaskReference(agent_id)
        : undefined;
      const actorTaskId = actorResolution?.status === 'exact'
        || actorResolution?.status === 'unique_legacy_label'
        ? actorResolution.task.task_id ?? actorResolution.task.id
        : null;
      const descriptor = {
        session_id,
        action_id,
        agent_id,
        command_length: command.length,
        request_fingerprint: buildSessionRequestFingerprint({
          session_id,
          command,
          wait_for,
          timeout_ms,
          idle_ms,
          force,
          technique: callTechnique,
          target_ip: callTargetIp,
          target_url: callTargetUrl,
          target_node: callTargetNode,
          allow_unverified_scope: callAllowUnverified === true,
          noise_estimate,
        }),
        timeout_ms,
        idle_ms,
        has_wait_for: wait_for !== undefined,
        force,
        technique: callTechnique,
        target_ip: callTargetIp,
        has_target_url: callTargetUrl !== undefined,
        target_node: callTargetNode,
        allow_unverified_scope: callAllowUnverified === true,
        noise_estimate,
      };

      return sessionCommands.execute(descriptor, async (bindActionId) => {
      const session = sessionManager.getSession(session_id);
      if (!session) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: `Session not found: ${session_id}`, session_id }, null, 2) }],
          isError: true,
        };
      }
      const connectionId = session.connection_id;
      const connectionGeneration = session.connection_generation;
      const generationDetails = {
        session_id,
        connection_id: connectionId,
        connection_generation: connectionGeneration,
      };

      // Merge per-call override > session default > session host fallback.
      // When neither yields a technique, fall back to a generic
      // `session_command` label so the lifecycle still runs (the action
      // gets logged + evidence persisted). Operators with scope concerns
      // should pass default_validation at open_session — otherwise
      // local_pty sessions and similar no-scope-concern uses don't need
      // any per-call ceremony.
      //
      // F8: previously a remote session opened with `host` but no
      // explicit default_validation.target_ip would validate against an
      // empty target — every send logged as a generic session_command
      // with no scope attribution. Now we fall back to `session.host`
      // for target_ip, which validateAction accepts as either an IPv4
      // or hostname (isHostInScope handles both).
      const sessionDefault = session.default_validation;
      const technique = callTechnique ?? sessionDefault?.technique ?? 'session_command';
      const fallbackTargetIp =
        callTargetIp
        ?? sessionDefault?.target_ip
        // Only fall back to session.host for kinds that actually point at
        // a remote target — local_pty's host field is irrelevant for
        // scope, and a socket-listener's "host" is the bind address.
        ?? (session.kind === 'ssh' || (session.kind === 'socket' && session.host && (!('mode' in session) || (session as { mode?: string }).mode !== 'listen'))
            ? session.host
            : undefined);
      const effective: SessionDefaultValidation = {
        technique,
        target_ip: fallbackTargetIp,
        target_url: callTargetUrl ?? sessionDefault?.target_url,
        target_node: callTargetNode ?? sessionDefault?.target_node,
        allow_unverified_scope: callAllowUnverified ?? sessionDefault?.allow_unverified_scope,
        agent_id: agent_id ?? sessionDefault?.agent_id,
      };

      // Compute deterministic action_id when the engagement carries a nonce.
      const cfg = engine.getConfig();
      const normalizedActionId = action_id || actionIdOrUuid(
        cfg.engagement_nonce
          ? {
            engagement_nonce: cfg.engagement_nonce,
            agent_id: effective.agent_id,
            timestamp: engine.now(),
            command_signature: command,
            sequence: engine.nextDeterministicSeq(),
          }
          : null,
      );
      bindActionId(normalizedActionId);

      // ---- 1. Validation ----
      const v = engine.validateAction({
        technique: effective.technique,
        target_ip: effective.target_ip,
        target_url: effective.target_url,
        target_node: effective.target_node,
        allow_unverified_scope: effective.allow_unverified_scope,
      });
      const validationResult = !v.valid ? 'invalid' : v.warnings.length > 0 ? 'warning_only' : 'valid';
      const targetIpsForEvent = effective.target_ip ? [effective.target_ip] : undefined;
      const targetNodeIdsForEvent = effective.target_node ? [effective.target_node] : undefined;

      engine.logActionEvent({
        description: `send_to_session: ${command}`,
        agent_id: effective.agent_id,
        action_id: normalizedActionId,
        event_type: 'action_validated',
        category: 'frontier',
        tool_name: 'send_to_session',
        technique: effective.technique,
        target_node_ids: targetNodeIdsForEvent,
        target_ips: targetIpsForEvent,
        validation_result: validationResult,
        result_classification: !v.valid ? 'failure' : v.warnings.length > 0 ? 'partial' : 'success',
        details: { ...generationDetails, errors: v.errors, warnings: v.warnings, opsec_context: v.opsec_context, opsec_skipped: v.opsec_skipped },
      });

      if (!v.valid) {
        const terminalActionInput: Parameters<GraphEngine['logActionEvent']>[0] = {
          description: `Refused to send to session: ${command}`,
          agent_id: effective.agent_id,
          action_id: normalizedActionId,
          event_type: 'action_failed',
          category: 'frontier',
          tool_name: 'send_to_session',
          technique: effective.technique,
          target_node_ids: targetNodeIdsForEvent,
          target_ips: targetIpsForEvent,
          result_classification: 'failure',
          details: { ...generationDetails, reason: 'validation_failed', validation_errors: v.errors },
        };
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              action_id: normalizedActionId,
              ...generationDetails,
              executed: false,
              validation_result: 'invalid',
              errors: v.errors,
              warnings: v.warnings,
            }, null, 2),
          }],
          isError: true,
          [SESSION_COMMAND_TERMINAL]: terminalActionInput,
        };
      }

      // ---- 2. action_started ----
      engine.logActionEvent({
        description: `send_to_session: ${command}`,
        agent_id: effective.agent_id,
        action_id: normalizedActionId,
        event_type: 'action_started',
        category: 'frontier',
        tool_name: 'send_to_session',
        technique: effective.technique,
        target_node_ids: targetNodeIdsForEvent,
        target_ips: targetIpsForEvent,
        noise_estimate,
        details: { ...generationDetails, command, timeout_ms, idle_ms, wait_for, invoking_tool: 'send_to_session' },
      });
      if (typeof noise_estimate === 'number') {
        engine.recordOpsecNoise({
          action_id: normalizedActionId,
          host_id: effective.target_node,
          agent_id: effective.agent_id,
          noise_estimate,
        });
      }
      engine.persist();

      // ---- 3. Execute ----
      let sendResult: Awaited<ReturnType<typeof sessionManager.sendCommand>>;
      let spawnError: string | undefined;
      let spawnErrorCode: string | undefined;
      try {
        sendResult = await sessionManager.sendCommand(session_id, command, {
          timeout_ms,
          idle_ms,
          wait_for,
          claimedBy: agent_id,
          force,
          connection_id: connectionId,
          connection_generation: connectionGeneration,
        });
      } catch (err) {
        spawnError = err instanceof Error ? err.message : String(err);
        spawnErrorCode = err && typeof err === 'object' && 'code' in err
          ? String((err as { code?: unknown }).code ?? '')
          : undefined;
        const terminalActionInput: Parameters<GraphEngine['logActionEvent']>[0] = {
          description: `send_to_session failed: ${command}`,
          agent_id: effective.agent_id,
          action_id: normalizedActionId,
          event_type: 'action_failed',
          category: 'frontier',
          tool_name: 'send_to_session',
          technique: effective.technique,
          target_node_ids: targetNodeIdsForEvent,
          target_ips: targetIpsForEvent,
          result_classification: 'failure',
          details: {
            ...generationDetails,
            reason: 'spawn_error',
            spawn_error: spawnError,
            ...(spawnErrorCode ? { code: spawnErrorCode } : {}),
          },
        };
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              action_id: normalizedActionId,
              ...generationDetails,
              executed: false,
              spawn_error: spawnError,
              ...(spawnErrorCode ? { code: spawnErrorCode } : {}),
            }, null, 2),
          }],
          isError: true,
          [SESSION_COMMAND_TERMINAL]: terminalActionInput,
        };
      }

      // ---- 4. Persist evidence ----
      let evidence_id: string | undefined;
      if (sendResult.text && sendResult.text.length > 0) {
        try {
          evidence_id = engine.getEvidenceStore().store({
            action_id: normalizedActionId,
            evidence_type: 'command_output',
            filename: 'session_output',
            raw_output: sendResult.text,
          });
        } catch {
          // Evidence persistence must not fail the command — record absence on the event.
        }
      }

      // ---- 5. Terminal lifecycle event ----
      const terminalReason = sendResult.completion_reason;
      const succeeded = terminalReason !== 'timeout' && terminalReason !== 'session_closed';
      const terminalEventType = succeeded ? 'action_completed' as const : 'action_failed' as const;
      const terminalGenerationDetails = {
        session_id,
        connection_id: sendResult.connection_id,
        connection_generation: sendResult.connection_generation,
      };
      const terminalActionInput: Parameters<GraphEngine['logActionEvent']>[0] = {
        description: `send_to_session: ${command}`,
        agent_id: effective.agent_id,
        action_id: normalizedActionId,
        event_type: terminalEventType,
        category: 'frontier',
        tool_name: 'send_to_session',
        technique: effective.technique,
        target_node_ids: targetNodeIdsForEvent,
        target_ips: targetIpsForEvent,
        result_classification: succeeded ? 'success' : 'failure',
        details: {
          ...terminalGenerationDetails,
          completion_reason: terminalReason,
          timed_out: sendResult.timed_out,
          captured_bytes: sendResult.text?.length ?? 0,
          evidence_id,
          start_pos: sendResult.start_pos,
          end_pos: sendResult.end_pos,
          truncated: sendResult.truncated,
          reason: !succeeded ? terminalReason : undefined,
          invoking_tool: 'send_to_session',
        },
      };

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ...sendResult,
            action_id: normalizedActionId,
            evidence_id,
            validation_result: validationResult,
            warnings: v.warnings.length > 0 ? v.warnings : undefined,
          }, null, 2),
        }],
        [SESSION_COMMAND_TERMINAL]: terminalActionInput,
      };
      }, {
        command_id,
        idempotency_key,
        actor_task_id: actorTaskId,
        action_id,
      });
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
        agent_id: z.string().optional().describe('Filter to sessions claimed by this task_id (unique legacy label accepted)'),
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
        const resolution = engine.resolveAgentTaskReference(agent_id);
        if (resolution.status === 'ambiguous_legacy_label') {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: `Agent label is ambiguous: ${agent_id}`,
                candidate_task_ids: resolution.candidate_task_ids,
              }, null, 2),
            }],
            isError: true,
          };
        }
        const taskId = resolution.status === 'exact' || resolution.status === 'unique_legacy_label'
          ? resolution.task.task_id ?? resolution.task.id
          : agent_id;
        sessions = sessions.filter(s => !s.claimed_by || s.claimed_by === taskId);
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
  // Tool: resume_session
  // ============================================================
  server.registerTool(
    'resume_session',
    {
      title: 'Resume Session Listener',
      description: `Explicitly rebind a recovered rearm socket listener.

The listener keeps its stable session/listener ID and generation counter, but
does not become connected and does not create HAS_SESSION access until a new
target connection is accepted.`,
      inputSchema: {
        session_id: z.string().describe('Recovered listener session ID'),
        agent_id: z.string().optional().describe('Task resuming the listener (checked against claimed_by)'),
        force: z.boolean().default(false).describe('Override ownership check'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('resume_session', async ({ session_id, agent_id, force }) => {
      const actorResolution = agent_id
        ? engine.resolveAgentTaskReference(agent_id)
        : { status: 'missing' as const };
      if (actorResolution.status === 'ambiguous_legacy_label') {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              error: `Agent label is ambiguous: ${agent_id}`,
              candidate_task_ids: actorResolution.candidate_task_ids,
            }, null, 2),
          }],
          isError: true,
        };
      }
      const actorTaskId = actorResolution.status === 'exact'
        || actorResolution.status === 'unique_legacy_label'
        ? actorResolution.task.task_id ?? actorResolution.task.id
        : agent_id;
      try {
        const result = await sessionManager.resume(session_id, actorTaskId, force);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              resumed: true,
              session: result.metadata,
            }, null, 2),
          }],
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        const code = error && typeof error === 'object' && 'code' in error
          ? String((error as { code?: unknown }).code ?? '')
          : '';
        const notFound = /not found/i.test(message);
        if (
          code === 'SESSION_NOT_RESUMABLE'
          || code === 'SESSION_RESUME_CONFLICT'
          || notFound
        ) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: message,
                session_id,
                code: code || 'SESSION_NOT_FOUND',
                error_type: notFound
                  ? 'not_found'
                  : code === 'SESSION_RESUME_CONFLICT'
                    ? 'conflict'
                    : 'validation_error',
              }, null, 2),
            }],
            isError: true,
          };
        }
        throw error;
      }
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
        claimed_by: z.string().optional().describe('Transfer ownership to this task_id (unique legacy agent label accepted)'),
        notes: z.string().optional().describe('Operational notes'),
        agent_id: z.string().optional().describe('Task performing the update (unique legacy agent label accepted; checked against claimed_by)'),
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

      const claimedResolution = claimed_by
        ? engine.resolveAgentTaskReference(claimed_by)
        : { status: 'missing' as const };
      if (claimedResolution.status === 'ambiguous_legacy_label') {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              error: `Agent label is ambiguous: ${claimed_by}`,
              candidate_task_ids: claimedResolution.candidate_task_ids,
            }, null, 2),
          }],
          isError: true,
        };
      }
      const claimedTaskId = claimedResolution.status === 'exact'
        || claimedResolution.status === 'unique_legacy_label'
        ? claimedResolution.task.task_id ?? claimedResolution.task.id
        : claimed_by;
      const actorResolution = agent_id
        ? engine.resolveAgentTaskReference(agent_id)
        : { status: 'missing' as const };
      if (actorResolution.status === 'ambiguous_legacy_label') {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              error: `Agent label is ambiguous: ${agent_id}`,
              candidate_task_ids: actorResolution.candidate_task_ids,
            }, null, 2),
          }],
          isError: true,
        };
      }
      const actorTaskId = actorResolution.status === 'exact'
        || actorResolution.status === 'unique_legacy_label'
        ? actorResolution.task.task_id ?? actorResolution.task.id
        : agent_id;
      const updated = sessionManager.update(session_id, {
        capabilities: Object.keys(capabilities).length > 0 ? capabilities as any : undefined,
        title,
        claimed_by: claimedTaskId,
        notes,
      }, actorTaskId, force);

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

      // If this session was bound to a mock_service, stamp stopped_at on
      // the listener node so the dashboard / retrospective know it is no
      // longer live.
      const mockId = result.metadata.capabilities.serves_mock_service_id;
      if (mockId) {
        const node = engine.getNode(mockId);
        if (node && node.type === 'mock_service') {
          engine.addNode({
            ...node,
            stopped_at: result.metadata.closed_at ?? new Date().toISOString(),
          });
        }
      }

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
