import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { nodeTypeSchema, edgeTypeSchema } from '../types.js';
import type { InferenceRule } from '../types.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerInferenceTools(server: McpServer, engine: GraphEngine): void {

  // ============================================================
  // Tool: suggest_inference_rule
  // LLM proposes new inference rules during engagement
  // ============================================================
  server.registerTool(
    'suggest_inference_rule',
    {
      title: 'Suggest Inference Rule',
      description: `Propose a new inference rule to add to the engagement's active rule set.

Inference rules fire automatically when matching nodes are ingested or updated.
They produce new edges (hypotheses) that expand the attack graph.

Example: "If a host has port 3389 open, create a CAN_RDPINTO edge from all users with valid creds."

The rule will be validated for correct node/edge types and selectors.
Optionally backfill against all existing matching nodes.

Valid selectors for source/target:
- trigger_node: the node that matched the trigger
- parent_host: host that RUNS the trigger service
- domain_nodes: all domain nodes in the graph
- domain_credentials: all credential nodes
- domain_users: all user nodes
- all_compromised: nodes with HAS_SESSION or ADMIN_TO edges
- compatible_services: services matching the credential type
- enrollable_users: users that can enroll in certificates
- trigger_service: the service node itself`,
      inputSchema: {
        name: z.string().describe('Human-readable name for the rule'),
        description: z.string().describe('What this rule detects and why it matters'),
        trigger_node_type: nodeTypeSchema.describe('Node type that triggers this rule'),
        trigger_properties: z.record(z.unknown()).optional()
          .describe('Property values the trigger node must match, e.g. {"service_name": "rdp"}'),
        produces: z.array(z.object({
          edge_type: edgeTypeSchema.describe('Type of edge to create'),
          source_selector: z.string().describe('How to resolve the source node'),
          target_selector: z.string().describe('How to resolve the target node'),
          confidence: z.number().min(0).max(1).default(0.7).describe('Confidence of the inferred edge'),
        })).min(1).describe('Edges this rule produces when triggered'),
        backfill: z.boolean().default(false)
          .describe('Run this rule against all existing matching nodes immediately'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      }
    },
    withErrorBoundary('suggest_inference_rule', async ({ name, description, trigger_node_type, trigger_properties, produces, backfill }) => {
      // Validate selectors
      const validSelectors = new Set([
        'trigger_node', 'parent_host', 'domain_nodes', 'domain_credentials',
        'domain_users', 'all_compromised', 'compatible_services',
        'enrollable_users', 'trigger_service',
      ]);
      const errors: string[] = [];
      for (const prod of produces) {
        if (!validSelectors.has(prod.source_selector)) {
          errors.push(`Invalid source_selector: '${prod.source_selector}'`);
        }
        if (!validSelectors.has(prod.target_selector)) {
          errors.push(`Invalid target_selector: '${prod.target_selector}'`);
        }
      }

      if (errors.length > 0) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              valid: false,
              errors,
              valid_selectors: [...validSelectors],
            }, null, 2)
          }],
          isError: true,
        };
      }

      const rule: InferenceRule = {
        id: `rule-custom-${Date.now()}`,
        name,
        description,
        trigger: {
          node_type: trigger_node_type,
          property_match: trigger_properties,
        },
        produces: produces.map(p => ({
          edge_type: p.edge_type,
          source_selector: p.source_selector,
          target_selector: p.target_selector,
          confidence: p.confidence,
        })),
      };

      engine.addInferenceRule(rule);

      let backfillResult: { inferred_edges: number } | undefined;
      if (backfill) {
        const inferred = engine.backfillRule(rule);
        backfillResult = { inferred_edges: inferred.length };
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            rule_id: rule.id,
            name: rule.name,
            added: true,
            backfill: backfillResult,
            message: `Inference rule '${name}' added${backfillResult ? ` (backfilled ${backfillResult.inferred_edges} edges)` : ''}`,
          }, null, 2)
        }]
      };
    })
  );
}
