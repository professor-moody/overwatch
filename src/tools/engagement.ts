import { z } from 'zod';
import { resolve } from 'path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { EngagementManager, CreateEngagementInput } from '../services/engagement-manager.js';
import { buildEngagementConfig } from '../services/engagement-builder.js';
import { withErrorBoundary } from './error-boundary.js';
import { toolText } from './_tool-output.js';

// ============================================================
// Engagement setup tools — conversational, no hand-edited JSON
// ============================================================
// create_engagement persists a validated engagements/<id>.json from a name +
// scope + objectives + OPSEC profile. CREATE-THEN-START: the new engagement is
// not live until the server is (re)started pointed at it; the result carries the
// activation steps. No live engine reload (out of scope by design).

export function registerEngagementTools(server: McpServer, engagementManager: EngagementManager): void {
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
}
