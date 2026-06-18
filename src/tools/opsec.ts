import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerOpsecTools(server: McpServer, engine: GraphEngine): void {

  // ============================================================
  // Tool: get_opsec_status
  // Read-only OPSEC posture for the opsec_sentinel archetype + any operator/agent.
  // ============================================================
  server.registerTool(
    'get_opsec_status',
    {
      title: 'Get OPSEC Status',
      description: `Read the engagement's OPSEC posture: noise budget spent, the recommended approach (quiet/normal/loud), and any defensive signals observed (lockouts, rate limits, honeypots, connection resets, blocks). Optionally scope the noise/recommendation to a host or domain. Read-only — never mutates state.`,
      inputSchema: {
        host_id: z.string().optional().describe('Scope the noise estimate + recommendation to a host node'),
        domain: z.string().optional().describe('Scope the noise estimate + recommendation to a domain'),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    withErrorBoundary('get_opsec_status', async ({ host_id, domain }) => {
      const tracker = engine.getOpsecTracker();
      const context = engine.getOpsecContext({ host_id, domain });
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            enforcement: engine.getOpsecStatus(),       // { enabled, configured_fields, inert }
            global_noise_spent: tracker.getGlobalNoise(),
            context,                                     // scoped: noise + budget remaining + recommended_approach + recent signals
            all_defensive_signals: tracker.getAllDefensiveSignals(),  // full history (context.defensive_signals is recent + scoped)
          }, null, 2),
        }],
      };
    }),
  );
}
