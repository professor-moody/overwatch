// ============================================================
// Overwatch — run_bash tool
// Shell-form alias around the shared instrumented process runner.
// Use this when you need shell features (pipes, redirects, globs,
// expansions). For a binary + argv invocation, prefer `run_tool`.
// ============================================================

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';
import { getSupportedParsers } from '../services/parsers/index.js';
import { ParserContextSchema } from '../types.js';
import {
  runInstrumentedProcess,
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
} from './_process-runner.js';

export function registerRunBashTool(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'run_bash',
    {
      title: 'Run Bash Command',
      description: `Execute a shell command via \`bash -c\` with full action-lifecycle instrumentation.

Use this when you need shell features (pipes, redirects, globs, env expansion).
For straight binary + argv execution, prefer \`run_tool\` — it avoids shell
parsing pitfalls and injection risk.

Overwatch will automatically:
1. Run scope/OPSEC validation (unless validate=false)
2. Wait for operator approval if approval_mode requires it
3. Log action_started → execute → log action_completed/action_failed
4. Store full stdout/stderr in the evidence store (linked by action_id)
5. Optionally parse the output via a built-in parser (parse_with) and ingest findings

Returns inline stdout/stderr (capped at 256 KiB per stream; full output via get_evidence).

For interactive or long-lived shells use \`open_session\` + \`send_to_session\`.
Managed one-shot commands may not request backgrounding or daemonization.
Known detach forms are rejected before launch, and descendants left in the
managed process group are terminated with a precise failure. Tools that
internally self-daemonize are unsupported: launch them through your operator
terminal, then register the PID with \`track_process\`.`,
      inputSchema: {
        command: z.string().min(1).describe('Shell command to execute via `bash -c`'),
        cwd: z.string().optional().describe('Working directory for the command'),
        env: z.record(z.string()).optional().describe('Extra environment variables to set on the child process'),
        timeout_ms: z.number().int().min(100).max(MAX_TIMEOUT_MS).optional()
          .describe(`Hard timeout in milliseconds (default ${DEFAULT_TIMEOUT_MS}, max ${MAX_TIMEOUT_MS})`),
        action_id: z.string().optional().describe('Stable action ID. Auto-generated if omitted.'),
        frontier_item_id: z.string().optional().describe('Frontier item this action came from'),
        agent_id: z.string().optional().describe('Agent or session responsible for the action'),
        description: z.string().optional().describe('Human-readable description of the action (defaults to the command)'),
        tool_name: z.string().optional().describe('Tool name for attribution (defaults to first command token)'),
        technique: z.string().optional().describe('Technique label (e.g. portscan, kerberoast)'),
        target_node: z.string().optional().describe('Primary target node ID for scope validation'),
        target_node_ids: z.array(z.string()).optional().describe('All target node IDs'),
        target_ip: z.string().optional().describe('Raw target IP for pre-discovery scope validation'),
        target_ips: z.array(z.string()).optional().describe('All raw target IPs'),
        target_cidr: z.string().optional().describe('Raw target CIDR for scanner/subnet scope validation'),
        target_cidrs: z.array(z.string()).optional().describe('All raw target CIDRs'),
        target_url: z.string().optional().describe('Target URL for url-pattern scope validation'),
        cloud_resource: z.string().optional().describe('Cloud resource identifier for cloud-scope validation'),
        validate: z.boolean().default(true).describe('Run scope/OPSEC validation before executing (default true)'),
        allow_unverified_scope: z.boolean().optional().describe('Operator override: skip the fail-closed check for host/service/share targets that cannot be verified against the engagement scope. Use only with explicit operator intent.'),
        operator_infra: z.boolean().optional().describe('Mark this as local operator infrastructure setup (listeners, bridges, port cleanup). Local bind IPs in argv are not treated as target scan scope.'),
        parse_with: z.string().optional().describe(`Built-in parser to apply to stdout on success. Supported: ${getSupportedParsers().join(', ')}`),
        parser_context: ParserContextSchema.optional().describe('Optional credential, tenant, repository, branch, cloud, target, domain, host, or provider-specific parser context'),
        parse_stream: z.enum(['stdout', 'stderr', 'combined', 'auto']).optional().describe("Which captured stream feeds the parser. 'stdout' (default), 'stderr' for tools that emit on stderr, 'combined' to concat, 'auto' to pick stdout if non-empty else stderr."),
        noise_estimate: z.number().min(0).max(1).optional().describe('Predicted noise level (overrides validation estimate when present)'),
        command_id: z.string().min(1).optional().describe('Stable application-command ID for status correlation and safe retries.'),
        idempotency_key: z.string().min(1).optional().describe('Stable retry key. Reusing it with identical input returns the original result without executing again.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorBoundary('run_bash', async (params, extra) => {
      return runInstrumentedProcess(engine, {
        binary: 'bash',
        args: ['-c', params.command],
        command_repr: params.command,
        cwd: params.cwd,
        env: params.env,
        timeout_ms: params.timeout_ms,
        action_id: params.action_id,
        frontier_item_id: params.frontier_item_id,
        agent_id: params.agent_id,
        description: params.description,
        tool_name: params.tool_name,
        technique: params.technique,
        target_node: params.target_node,
        target_node_ids: params.target_node_ids,
        target_ip: params.target_ip,
        target_ips: params.target_ips,
        target_cidr: params.target_cidr,
        target_cidrs: params.target_cidrs,
        target_url: params.target_url,
        cloud_resource: params.cloud_resource,
        validate: params.validate,
        allow_unverified_scope: params.allow_unverified_scope,
        operator_infra: params.operator_infra,
        parse_with: params.parse_with,
        parser_context: params.parser_context,
        parse_stream: params.parse_stream,
        noise_estimate: params.noise_estimate,
        invoking_tool: 'run_bash',
        command_id: params.command_id,
        idempotency_key: params.idempotency_key,
        abortSignal: extra?.signal,
      });
    }),
  );
}
