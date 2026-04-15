import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerScoringTools(server: McpServer, engine: GraphEngine): void {

  // ============================================================
  // Tool: next_task
  // Returns the filtered frontier for LLM scoring.
  // ============================================================
  server.registerTool(
    'next_task',
    {
      title: 'Get Next Tasks',
      description: `Returns frontier items (candidate next actions) with graph context attached.

The deterministic layer has already filtered out:
- Out-of-scope targets
- Duplicate/already-tested actions
- Actions exceeding OPSEC hard noise limits
- Dead hosts

Everything else passes through for YOUR analysis. Each item includes graph metrics
(hops to objective, fan-out estimate, node degree, confidence, OPSEC noise rating).

YOUR job is to:
1. Score and rank these by overall value
2. Spot multi-step attack chains across items
3. Consider sequencing (what should happen first)
4. Assess likely defenses and risks
5. Recommend specific actions for the top items

Returns: Array of FrontierItem objects with graph metrics, plus any items that were filtered and why.`,
      inputSchema: {
        max_items: z.number().int().min(1).max(50)
          .default(20)
          .describe('Maximum frontier items to return'),
        include_filtered: z.boolean()
          .default(false)
          .describe('Also return items that were filtered out, with reasons'),
        group_by: z.enum(['individual', 'campaign'])
          .default('individual')
          .describe('Return individual frontier items or group them into campaigns (credential spray, enumeration, post-exploitation)')
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      }
    },
    withErrorBoundary('next_task', async ({ max_items, include_filtered, group_by }) => {
      const frontier = engine.computeFrontier();
      const { passed, filtered } = engine.filterFrontier(frontier);

      const result: Record<string, unknown> = {
        candidate_count: passed.length,
        candidates: passed.slice(0, max_items)
      };

      if (group_by === 'campaign') {
        const campaigns = engine.getCampaigns();
        result.campaigns = campaigns;
        result.campaign_count = campaigns.length;
      }

      if (include_filtered) {
        result.filtered_count = filtered.length;
        result.filtered = filtered.slice(0, 20);
      }

      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
      };
    })
  );

  // ============================================================
  // Tool: validate_action
  // Pre-execution sanity check against graph + OPSEC policy.
  // ============================================================
  server.registerTool(
    'validate_action',
    {
      title: 'Validate Action',
      description: `Validate a proposed action against the graph state and OPSEC policy BEFORE executing it.

Checks:
- Do referenced nodes actually exist in the graph?
- Is the target in scope (not excluded)?
- Is the technique blacklisted by OPSEC profile?
- Is the action within the approved time window?
- Adaptive OPSEC: noise budget remaining, recommended approach, defensive signals

When approval_mode is 'approve-critical' or 'approve-all', this tool may block while awaiting operator approval. The response will include an 'approval' field with the operator's decision.

Call this before every significant action. Returns valid/invalid with specific errors and warnings.`,
      inputSchema: {
        target_node: z.string().optional().describe('Node ID being targeted'),
        target_ip: z.string().optional().describe('Raw IP address to validate against scope (pre-discovery, no graph node required)'),
        edge_source: z.string().optional().describe('Source node of the edge being tested'),
        edge_target: z.string().optional().describe('Target node of the edge being tested'),
        technique: z.string().optional().describe('Technique name (e.g. kerberoast, ntlmrelay, portscan)'),
        target_url: z.string().optional().describe('URL to validate against scope url_patterns (e.g. https://app.corp.io/api/v1)'),
        cloud_resource: z.string().optional().describe('Cloud resource identifier to validate against scope (AWS ARN, Azure subscription path, GCP project path)'),
        action_id: z.string().optional().describe('Stable action ID to correlate validation with execution and findings'),
        tool_name: z.string().optional().describe('Tool expected to be used for this action'),
        tool: z.string().optional().describe('Alias for tool_name'),
        frontier_item_id: z.string().optional().describe('Frontier item this action came from'),
        description: z.string().optional().describe('Human-readable description of the planned action')
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      }
    },
    withErrorBoundary('validate_action', async ({ target_node, target_ip, edge_source, edge_target, technique, target_url, cloud_resource, action_id, tool_name: rawToolName, tool, frontier_item_id, description }) => {
      const tool_name = rawToolName || tool;
      const normalizedActionId = action_id || uuidv4();
      const result = engine.validateAction({ target_node, target_ip, edge_source, edge_target, technique, target_url, cloud_resource });
      const validationResult = !result.valid
        ? 'invalid'
        : result.warnings.length > 0
          ? 'warning_only'
          : 'valid';
      const targetNodeIds = [target_node, edge_source, edge_target].filter((value): value is string => !!value);
      const targetIps = target_ip ? [target_ip] : undefined;
      const frontierType = frontier_item_id ? engine.getFrontierItem(frontier_item_id)?.type : undefined;

      const resolvedDescription = description || 'Validate action';
      engine.logActionEvent({
        description: resolvedDescription,
        action_id: normalizedActionId,
        event_type: 'action_validated',
        category: 'frontier',
        frontier_type: frontierType,
        tool_name,
        technique,
        target_node_ids: targetNodeIds.length > 0 ? [...new Set(targetNodeIds)] : undefined,
        target_ips: targetIps,
        target_edge: edge_source && edge_target ? { source: edge_source, target: edge_target } : undefined,
        frontier_item_id,
        validation_result: validationResult,
        noise_estimate: result.opsec_context.global_noise_spent,
        result_classification: !result.valid ? 'failure' : result.warnings.length > 0 ? 'partial' : 'success',
        details: {
          errors: result.errors,
          warnings: result.warnings,
          opsec_context: result.opsec_context,
        },
      });
      engine.persist();

      // --- Approval gate ---
      // If validation passed (not invalid) and approval mode requires it,
      // block until the operator approves, denies, or timeout fires.
      const queue = engine.getPendingActionQueue();
      let approval: import('../services/pending-action-queue.js').ActionResolution | undefined;
      if (validationResult !== 'invalid' && queue.needsApproval(result.opsec_context, technique)) {
        approval = await queue.submit({
          action_id: normalizedActionId,
          technique,
          target_node,
          target_ip,
          description: resolvedDescription,
          opsec_context: result.opsec_context,
          validation_result: validationResult as 'valid' | 'warning_only',
          frontier_item_id,
        });

        // Log the approval resolution
        engine.logActionEvent({
          description: `Action ${approval.status}: ${resolvedDescription}`,
          action_id: normalizedActionId,
          event_type: 'action_validated',
          category: 'frontier',
          frontier_item_id,
          result_classification: approval.status === 'denied' ? 'failure' : 'success',
          details: {
            approval_status: approval.status,
            operator_notes: approval.operator_notes,
            reason: approval.reason,
          },
        });
        engine.persist();
      }

      const responseObj: Record<string, unknown> = {
        action_id: normalizedActionId,
        action: resolvedDescription,
        frontier_item_id: frontier_item_id || undefined,
        frontier_type: frontierType || undefined,
        validation_result: validationResult,
        ...result,
      };

      if (approval) {
        responseObj.approval = {
          status: approval.status,
          operator_notes: approval.operator_notes,
          reason: approval.reason,
        };
        // If denied, override validation_result so the model knows to abort
        if (approval.status === 'denied') {
          responseObj.validation_result = 'invalid';
          responseObj.errors = [...(result.errors || []), `Operator denied: ${approval.reason || 'no reason given'}`];
        }
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(responseObj, null, 2)
        }]
      };
    })
  );

  // ============================================================
  // Tool: manage_campaign
  // Campaign lifecycle control and CRUD.
  // ============================================================
  server.registerTool(
    'manage_campaign',
    {
      title: 'Manage Campaign',
      description: `Create, control, and manage campaigns.

**Lifecycle actions** (require campaign_id):
- activate, pause, resume, abort, status, check_abort

**CRUD actions**:
- **create** — Create a new campaign from frontier items (requires name, strategy, item_ids)
- **update** — Modify name, abort_conditions, or items on draft/paused campaigns (requires campaign_id)
- **clone** — Duplicate a campaign as a new draft (requires campaign_id)
- **delete** — Remove a draft campaign (requires campaign_id)

Campaigns can be auto-generated or manually composed from frontier items.
Use next_task(group_by="campaign") to see available campaigns.`,
      inputSchema: {
        campaign_id: z.string().optional().describe('Campaign ID (required for all actions except create)'),
        action: z.enum(['activate', 'pause', 'resume', 'abort', 'status', 'check_abort', 'create', 'update', 'clone', 'delete'])
          .describe('Action to perform'),
        name: z.string().optional().describe('Campaign name (required for create, optional for update)'),
        strategy: z.enum(['credential_spray', 'enumeration', 'post_exploitation', 'network_discovery', 'custom'])
          .optional().describe('Campaign strategy (required for create)'),
        item_ids: z.array(z.string()).optional().describe('Frontier item IDs (required for create)'),
        abort_conditions: z.array(z.object({
          type: z.enum(['consecutive_failures', 'total_failures_pct', 'opsec_noise_ceiling', 'time_limit_seconds']),
          threshold: z.number(),
        })).optional().describe('Abort conditions (optional for create/update)'),
        add_items: z.array(z.string()).optional().describe('Item IDs to add (for update)'),
        remove_items: z.array(z.string()).optional().describe('Item IDs to remove (for update)'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      }
    },
    withErrorBoundary('manage_campaign', async ({ campaign_id, action, name, strategy, item_ids, abort_conditions, add_items, remove_items }) => {
      let campaign;
      let extra: Record<string, unknown> = {};

      switch (action) {
        case 'create': {
          if (!name) return { content: [{ type: 'text', text: JSON.stringify({ error: 'name is required for create' }) }] };
          if (!strategy) return { content: [{ type: 'text', text: JSON.stringify({ error: 'strategy is required for create' }) }] };
          if (!item_ids || item_ids.length === 0) return { content: [{ type: 'text', text: JSON.stringify({ error: 'item_ids (non-empty) is required for create' }) }] };
          campaign = engine.createCampaign({ name, strategy, item_ids, abort_conditions });
          break;
        }
        case 'update': {
          if (!campaign_id) return { content: [{ type: 'text', text: JSON.stringify({ error: 'campaign_id is required for update' }) }] };
          try {
            campaign = engine.updateCampaign(campaign_id, { name, abort_conditions, add_items, remove_items });
          } catch (err: any) {
            return { content: [{ type: 'text', text: JSON.stringify({ error: err.message }) }] };
          }
          break;
        }
        case 'clone': {
          if (!campaign_id) return { content: [{ type: 'text', text: JSON.stringify({ error: 'campaign_id is required for clone' }) }] };
          campaign = engine.cloneCampaign(campaign_id);
          break;
        }
        case 'delete': {
          if (!campaign_id) return { content: [{ type: 'text', text: JSON.stringify({ error: 'campaign_id is required for delete' }) }] };
          try {
            const deleted = engine.deleteCampaign(campaign_id);
            if (!deleted) return { content: [{ type: 'text', text: JSON.stringify({ error: `Campaign ${campaign_id} not found` }) }] };
            return { content: [{ type: 'text', text: JSON.stringify({ deleted: true, campaign_id }) }] };
          } catch (err: any) {
            return { content: [{ type: 'text', text: JSON.stringify({ error: err.message }) }] };
          }
        }
        case 'activate':
          if (!campaign_id) return { content: [{ type: 'text', text: JSON.stringify({ error: 'campaign_id is required' }) }] };
          campaign = engine.activateCampaign(campaign_id);
          break;
        case 'pause':
          if (!campaign_id) return { content: [{ type: 'text', text: JSON.stringify({ error: 'campaign_id is required' }) }] };
          campaign = engine.pauseCampaign(campaign_id);
          break;
        case 'resume':
          if (!campaign_id) return { content: [{ type: 'text', text: JSON.stringify({ error: 'campaign_id is required' }) }] };
          campaign = engine.resumeCampaign(campaign_id);
          break;
        case 'abort':
          if (!campaign_id) return { content: [{ type: 'text', text: JSON.stringify({ error: 'campaign_id is required' }) }] };
          campaign = engine.abortCampaign(campaign_id);
          break;
        case 'status':
          if (!campaign_id) return { content: [{ type: 'text', text: JSON.stringify({ error: 'campaign_id is required' }) }] };
          campaign = engine.getCampaign(campaign_id);
          break;
        case 'check_abort':
          if (!campaign_id) return { content: [{ type: 'text', text: JSON.stringify({ error: 'campaign_id is required' }) }] };
          campaign = engine.getCampaign(campaign_id);
          extra = engine.checkCampaignAbortConditions(campaign_id);
          break;
      }

      if (!campaign) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: `Campaign ${campaign_id} not found or action not applicable` }) }]
        };
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ campaign, ...extra }, null, 2)
        }]
      };
    })
  );
}
