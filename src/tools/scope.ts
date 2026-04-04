import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerScopeTools(server: McpServer, engine: GraphEngine): void {

  // ============================================================
  // Tool: update_scope
  // Confirmation-gated runtime scope expansion/contraction.
  // ============================================================
  server.registerTool(
    'update_scope',
    {
      title: 'Update Engagement Scope',
      description: `Expand or contract the engagement scope at runtime.

Use this when a pivot network, new domain, or additional target is discovered that was not
in the original engagement config. Scope changes are persisted immediately and affect
frontier generation, filtering, and action validation.

**Confirmation gate**: Set \`confirm: true\` to apply the change. When \`confirm\` is false
(default), returns a dry-run preview showing:
- Current vs proposed scope
- How many graph nodes would enter or leave scope
- Which pending scope suggestions would be resolved

Scope suggestions are automatically surfaced in \`get_state()\` when out-of-scope host nodes
exist in the graph. Use this tool to approve them after review.

Examples:
- Add a pivot network: \`{ add_cidrs: ["172.16.1.0/24"], reason: "Pivot network via 10.10.110.100", confirm: true }\`
- Add a domain: \`{ add_domains: ["internal.corp"], reason: "Discovered AD domain", confirm: true }\`
- Exclude a host: \`{ add_exclusions: ["172.16.1.1"], reason: "Production gateway — do not touch", confirm: true }\``,
      inputSchema: {
        add_cidrs: z.array(z.string()).optional()
          .describe('CIDRs to add to scope (e.g. ["172.16.1.0/24"])'),
        remove_cidrs: z.array(z.string()).optional()
          .describe('CIDRs to remove from scope'),
        add_domains: z.array(z.string()).optional()
          .describe('Domains to add to scope (e.g. ["internal.corp"])'),
        remove_domains: z.array(z.string()).optional()
          .describe('Domains to remove from scope'),
        add_exclusions: z.array(z.string()).optional()
          .describe('IPs or CIDRs to add to exclusion list'),
        remove_exclusions: z.array(z.string()).optional()
          .describe('IPs or CIDRs to remove from exclusion list'),
        reason: z.string()
          .describe('Operator-provided reason for the scope change (required)'),
        confirm: z.boolean().default(false)
          .describe('Set to true to apply the change. False (default) returns a dry-run preview.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('update_scope', async ({ add_cidrs, remove_cidrs, add_domains, remove_domains, add_exclusions, remove_exclusions, reason, confirm }) => {
      const changes = { add_cidrs, remove_cidrs, add_domains, remove_domains, add_exclusions, remove_exclusions };

      if (!confirm) {
        const preview = engine.previewScopeChange(changes);
        const warnings: string[] = [];
        if (preview.nodes_entering_scope > 0) {
          warnings.push(`SCOPE EXPANSION: ${preview.nodes_entering_scope} existing node(s) will enter scope.`);
        }
        if ((add_cidrs && add_cidrs.length > 0) || (add_domains && add_domains.length > 0)) {
          const newCidrs = add_cidrs?.filter(c => !preview.before.cidrs.includes(c)) || [];
          const newDomains = add_domains?.filter(d => !preview.before.domains.includes(d)) || [];
          if (newCidrs.length > 0 || newDomains.length > 0) {
            warnings.push(`New scope entries: ${[...newCidrs, ...newDomains].join(', ')}. Future discovered hosts in these ranges will be in-scope.`);
          }
        }
        if (preview.nodes_leaving_scope > 0) {
          warnings.push(`SCOPE CONTRACTION: ${preview.nodes_leaving_scope} node(s) will leave scope.`);
        }
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              mode: 'preview',
              message: 'Dry-run preview. Set confirm: true to apply this scope change.',
              ...(warnings.length > 0 ? { scope_expansion_warning: warnings } : {}),
              reason,
              ...preview,
            }, null, 2),
          }],
        };
      }

      // Apply the scope change
      const result = engine.updateScope({ ...changes, reason });

      if (!result.applied) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              mode: 'error',
              errors: result.errors,
            }, null, 2),
          }],
        };
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            mode: 'applied',
            reason,
            before: result.before,
            after: result.after,
            affected_node_count: result.affected_node_count,
          }, null, 2),
        }],
      };
    }),
  );
}
