// ============================================================
// Overwatch — run_tool tool
// Argv-form companion to `run_bash`. Spawns a binary directly with
// an argument array — no shell parsing, no injection vectors. Use
// this for straight tool invocations (nmap, nxc, curl, etc.).
// ============================================================

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';
import { getSupportedParsers } from '../services/parsers/index.js';
import {
  runInstrumentedProcess,
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
} from './_process-runner.js';

function shellQuote(s: string): string {
  // Lightweight pretty-printer for the description / evidence "command_repr".
  // Not for actual shell execution — the runner uses argv directly.
  if (/^[A-Za-z0-9_./:=@%+-]+$/.test(s)) return s;
  return `'${s.replace(/'/g, "'\\''")}'`;
}

export function registerRunToolTool(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'run_tool',
    {
      title: 'Run Tool (argv form)',
      description: `Execute a binary with an explicit argv array, fully instrumented like \`run_bash\`.

Prefer this over \`run_bash\` whenever you have a binary + arguments to pass —
no shell parsing means no injection risk and no escaping headaches.
Reach for \`run_bash\` only when you genuinely need shell features (pipes,
redirects, globs, expansions).

Lifecycle (identical to \`run_bash\`):
1. Scope/OPSEC validation (unless validate=false)
2. Operator approval if required
3. action_started → spawn → action_completed/action_failed
4. Stdout/stderr stored in evidence (linked by action_id)
5. Optional inline parse_with → ingest

Returns inline stdout/stderr (capped at 256 KiB per stream; full output via get_evidence).`,
      inputSchema: {
        binary: z.string().min(1).describe('Path or name of the binary to execute (resolved via PATH if not absolute).'),
        args: z.array(z.string()).default([]).describe('Argument vector passed directly to the binary (no shell parsing).'),
        cwd: z.string().optional().describe('Working directory for the command'),
        env: z.record(z.string()).optional().describe('Extra environment variables to set on the child process'),
        timeout_ms: z.number().int().min(100).max(MAX_TIMEOUT_MS).optional()
          .describe(`Hard timeout in milliseconds (default ${DEFAULT_TIMEOUT_MS}, max ${MAX_TIMEOUT_MS})`),
        action_id: z.string().optional().describe('Stable action ID. Auto-generated if omitted.'),
        frontier_item_id: z.string().optional().describe('Frontier item this action came from'),
        agent_id: z.string().optional().describe('Agent or session responsible for the action'),
        description: z.string().optional().describe('Human-readable description of the action (defaults to binary + args)'),
        tool_name: z.string().optional().describe('Tool name for attribution (defaults to the binary basename)'),
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
        parser_context: z.object({
          domain: z.string().optional(),
          source_host: z.string().optional(),
        }).optional().describe('Optional context passed to the parser'),
        parse_stream: z.enum(['stdout', 'stderr', 'combined', 'auto']).optional().describe("Which captured stream feeds the parser. 'stdout' (default), 'stderr' for tools that emit on stderr, 'combined' to concat, 'auto' to pick stdout if non-empty else stderr."),
        noise_estimate: z.number().min(0).max(1).optional().describe('Predicted noise level (overrides validation estimate when present)'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorBoundary('run_tool', async (params, extra) => {
      const args = params.args ?? [];
      const command_repr = [params.binary, ...args].map(shellQuote).join(' ');
      // Default tool_name to the binary basename for cleaner attribution.
      const default_tool_name = params.tool_name
        || params.binary.split('/').pop()
        || params.binary;
      return runInstrumentedProcess(engine, {
        binary: params.binary,
        args,
        command_repr,
        cwd: params.cwd,
        env: params.env,
        timeout_ms: params.timeout_ms,
        action_id: params.action_id,
        frontier_item_id: params.frontier_item_id,
        agent_id: params.agent_id,
        description: params.description,
        tool_name: default_tool_name,
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
        invoking_tool: 'run_tool',
        abortSignal: extra?.signal,
      });
    }),
  );
}
