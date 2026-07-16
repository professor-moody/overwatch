import { z } from 'zod';
import { resolve } from 'path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import type { EngagementManager, CreateEngagementInput } from '../services/engagement-manager.js';
import { buildEngagementConfig } from '../services/engagement-builder.js';
import { withErrorBoundary } from './error-boundary.js';
import { toolText } from './_tool-output.js';
import { EngagementCommandService } from '../services/engagement-command-service.js';

// ============================================================
// Engagement setup tools — conversational, no hand-edited JSON
// ============================================================
// create_engagement persists a validated engagements/<id>.json from a name +
// scope + objectives + OPSEC profile. CREATE-THEN-START: the new engagement is
// not live until the server is (re)started pointed at it; the result carries the
// activation steps. No live engine reload (out of scope by design).

export function registerEngagementTools(
  server: McpServer,
  engine: GraphEngine,
  engagementManager: EngagementManager,
  commands: Pick<
    EngagementCommandService,
    'addObjective' | 'updateOpsec'
  > = new EngagementCommandService(engine),
): void {
  server.registerTool(
    'create_engagement',
    {
      title: 'Create Engagement',
      description: `Build + persist a new engagement config so nobody hand-edits engagement.json.

Give a name, scope (CIDRs/domains), objectives, and an OPSEC profile; this writes a
validated engagements/<id>.json and returns how to activate it.

CREATE-THEN-START: the new engagement is NOT live until the server is (re)started
pointed at it — the result includes the exact steps. Use dry_run:true to preview
the built config without writing. Does not touch the currently running engagement.`,
      inputSchema: {
        name: z.string().min(1).describe('Engagement name (also seeds the id)'),
        template: z.string().optional().describe('Template id to base it on (e.g. ctf, internal-pentest, external-assessment, red-team, cloud-assessment, assumed-breach)'),
        cidrs: z.array(z.string()).optional().describe('In-scope CIDRs, e.g. ["10.10.10.0/24"]'),
        domains: z.array(z.string()).optional().describe('In-scope domains'),
        exclusions: z.array(z.string()).optional().describe('Out-of-scope CIDRs/IPs'),
        objectives: z.array(z.object({ description: z.string().min(1) })).optional().describe('Engagement objectives (goals)'),
        opsec_profile: z.enum(['quiet', 'normal', 'pentest', 'loud']).optional().describe('Named OPSEC noise ceiling: quiet=0.2, normal=0.5, pentest=0.7 (default), loud=1.0'),
        dry_run: z.boolean().default(false).describe('Preview the built config without writing it to disk'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    withErrorBoundary('create_engagement', async (params) => {
      const input: CreateEngagementInput = {
        name: params.name,
        template_id: params.template,
        cidrs: params.cidrs,
        domains: params.domains,
        exclusions: params.exclusions,
        // builder fills a stable id (obj-N) when blank
        objectives: params.objectives?.map(o => ({ id: '', description: o.description })),
        opsec_profile: params.opsec_profile,
      };

      if (params.dry_run) {
        return toolText({ dry_run: true, config: buildEngagementConfig(input) });
      }

      const engagement = engagementManager.createEngagement(input);
      return toolText({
        created: true,
        engagement,
        activation: {
          status: 'not_active',
          note: 'Persisted but NOT live. The running server keeps serving the current engagement until it is restarted pointed at this config (no live reload).',
          steps: [
            `Set OVERWATCH_CONFIG=${resolve(engagement.config_path)} (or copy it to ./engagement.json).`,
            'Restart the Overwatch MCP server / Claude Code session so it re-reads the config.',
            'Confirm with list_engagements — the new id should show is_active: true.',
          ],
        },
      });
    }),
  );

  server.registerTool(
    'list_engagements',
    {
      title: 'List Engagements',
      description: 'List the persisted engagement configs (engagements/*.json) and which one is currently active. Use after create_engagement to confirm activation.',
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    withErrorBoundary('list_engagements', async () => {
      return toolText({
        active_id: engagementManager.getActiveId(),
        engagements: engagementManager.listEngagements(),
      });
    }),
  );

  // --- Configure the ACTIVE engagement (no hand-edited JSON) ---

  server.registerTool(
    'add_objective',
    {
      title: 'Add Objective',
      description: 'Add an objective (goal) to the ACTIVE engagement. Low-risk — declares a goal; authorizes no targets and does not change scope/OPSEC. Persists immediately.',
      inputSchema: {
        description: z.string().min(1).describe('What achieving this objective means (e.g. "Compromise the domain controller")'),
        target_node_type: z.string().optional().describe('Node type that satisfies it (e.g. credential, host)'),
        target_criteria: z.record(z.unknown()).optional().describe('Property match for the target node, e.g. {"privileged": true}'),
        achievement_edge_types: z.array(z.string()).optional().describe('Edge types that count as achieved (default: HAS_SESSION/ADMIN_TO/OWNS_CRED)'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    withErrorBoundary('add_objective', async (params) => {
      const execution = commands.addObjective({
        description: params.description,
        target_node_type: params.target_node_type,
        target_criteria: params.target_criteria,
        achievement_edge_types: params.achievement_edge_types,
      }, { transport: 'mcp' });
      return toolText({
        added: true,
        objective: execution.result!.objective,
        command_id: execution.command_id,
        idempotency_key: execution.idempotency_key,
        replayed: execution.replayed,
      });
    }),
  );

  server.registerTool(
    'set_opsec',
    {
      title: 'Set OPSEC Policy',
      description: `Update the ACTIVE engagement's OPSEC policy (noise ceiling, enforcement, approval mode, time window, technique blacklist) — no hand-edited config.

**Confirmation gate**: confirm:false (default) returns a before/after diff plus warnings for any LOOSENING change (higher max_noise, disabling enforcement, switching to auto-approve). Set confirm:true to apply + persist. This mutates the LIVE engine, so it changes what the running engagement permits.`,
      inputSchema: {
        max_noise: z.number().min(0).max(1).optional().describe('Noise ceiling 0.0–1.0'),
        enabled: z.boolean().optional().describe('Enable/disable OPSEC enforcement'),
        approval_mode: z.enum(['auto-approve', 'approve-critical', 'approve-all']).optional().describe('Operator-approval policy'),
        approval_timeout_ms: z.number().int().min(1000).optional().describe('Approval wait before auto-resolve (ms)'),
        time_window: z.object({ start_hour: z.number().int().min(0).max(23), end_hour: z.number().int().min(0).max(23) }).nullable().optional().describe('Allowed hours window; null clears it'),
        blacklisted_techniques: z.array(z.string()).optional().describe('Techniques that are always vetoed'),
        reason: z.string().min(1).describe('Why (recorded in the activity log for attribution)'),
        confirm: z.boolean().default(false).describe('Set true to apply. False (default) returns a dry-run diff.'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    withErrorBoundary('set_opsec', async (params) => {
      const opsec = engine.getConfig().opsec;
      const before = {
        enabled: opsec.enabled, max_noise: opsec.max_noise, approval_mode: opsec.approval_mode,
        approval_timeout_ms: opsec.approval_timeout_ms, time_window: opsec.time_window,
        blacklisted_techniques: opsec.blacklisted_techniques,
      };

      const after: Record<string, unknown> = { ...before };
      const warnings: string[] = [];
      if (params.max_noise !== undefined) {
        after.max_noise = params.max_noise;
        if (params.max_noise > (before.max_noise ?? 0)) warnings.push(`max_noise raised ${before.max_noise} → ${params.max_noise} (louder ceiling).`);
      }
      if (params.enabled !== undefined) {
        after.enabled = params.enabled;
        if (params.enabled === false && before.enabled !== false) warnings.push('OPSEC enforcement DISABLED — actions will not be noise/scope-vetoed.');
      }
      if (params.approval_mode !== undefined) {
        after.approval_mode = params.approval_mode;
        if (params.approval_mode === 'auto-approve' && before.approval_mode !== 'auto-approve') warnings.push('approval_mode → auto-approve — no operator gate on actions.');
      }
      if (params.approval_timeout_ms !== undefined) after.approval_timeout_ms = params.approval_timeout_ms;
      if (params.time_window !== undefined) after.time_window = params.time_window ?? undefined;
      if (params.blacklisted_techniques !== undefined) after.blacklisted_techniques = params.blacklisted_techniques;

      if (!params.confirm) {
        return toolText({
          mode: 'preview',
          message: 'Dry-run. Set confirm: true to apply this OPSEC change.',
          reason: params.reason,
          before,
          after,
          ...(warnings.length ? { weakening_warnings: warnings } : {}),
        });
      }

      const execution = commands.updateOpsec({
        max_noise: params.max_noise,
        enabled: params.enabled,
        approval_mode: params.approval_mode,
        approval_timeout_ms: params.approval_timeout_ms,
        time_window: params.time_window,
        blacklisted_techniques: params.blacklisted_techniques,
      }, params.reason, {
        transport: 'mcp',
      });
      return toolText({
        ...execution.result,
        command_id: execution.command_id,
        idempotency_key: execution.idempotency_key,
        replayed: execution.replayed,
      });
    }),
  );
}
