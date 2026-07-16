import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { toolText } from './_tool-output.js';
import { withErrorBoundary } from './error-boundary.js';

const sha256Schema = z.string().regex(/^[0-9a-f]{64}$/);

export function registerRecoveryTools(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'get_recovery_status',
    {
      title: 'Get Recovery Status',
      description: 'Inspect WAL/state recovery and active file/runtime/state configuration convergence. This remains available in degraded read-only mode.',
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    withErrorBoundary('get_recovery_status', async () => toolText({
      recovery: engine.getPersistenceRecoveryStatus(),
    })),
  );

  server.registerTool(
    'resolve_config_divergence',
    {
      title: 'Resolve Config Divergence',
      description: 'Explicitly choose file or durable-state authority when active configuration representations diverge. Requires the exact hashes returned by get_recovery_status.',
      inputSchema: {
        resolution: z.enum(['use_file', 'use_state']),
        expected_file_hash: sha256Schema,
        expected_state_hash: sha256Schema,
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    },
    withErrorBoundary('resolve_config_divergence', async params => toolText(
      engine.resolveConfigDivergence({
        mode: params.resolution,
        expected_file_hash: params.expected_file_hash,
        expected_state_hash: params.expected_state_hash,
      }),
    )),
  );
}
