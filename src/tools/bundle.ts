// ============================================================
// Overwatch — bundle_engagement MCP tool
// ============================================================

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { buildBundle } from '../services/bundle-builder.js';
import { validateFilePath } from '../utils/path-validation.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerBundleTools(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'bundle_engagement',
    {
      title: 'Bundle Engagement',
      description: `Package all engagement artefacts into a single portable .tar.gz archive.

The bundle includes:
- **state file** — full graph, activity log, and config (the source of truth)
- **evidence/** — all captured evidence files and the manifest
- **reports/** — every rendered report in the archive
- **bundle-manifest.json** — index of included files, state/journal format versions, tape paths, and metadata

Optionally includes .snapshots/ (periodic state snapshots; can add significant size).

Registered tape files (captured by \`overwatch-mcp-tape\`) are external and not
copied into the bundle, but their paths are listed in bundle-manifest.json so they
can be located manually.

Use this to:
- Archive a completed engagement for long-term storage
- Transfer engagement data to another machine or operator
- Share a reproducible state with the team

Returns the absolute path to the created archive and its size.`,

      inputSchema: {
        output_path: z.string().optional()
          .describe('Absolute path for the output .tar.gz file. Defaults to bundle-<id>-<timestamp>.tar.gz alongside the state file.'),
        include_snapshots: z.boolean().default(false)
          .describe('Include .snapshots/ directory (periodic state snapshots). Can add significant size.'),
        include_tapes: z.boolean().default(true)
          .describe('List registered tape file paths in the bundle manifest (tapes are not copied, only referenced).'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    withErrorBoundary('bundle_engagement', async ({ output_path, include_snapshots, include_tapes }) => {
      const resolvedOutputPath = output_path ? validateFilePath(output_path) : undefined;

      const { archivePath, sizeBytes, manifest } = await buildBundle(engine, {
        includeSnapshots: include_snapshots,
        includeTapes: include_tapes,
        outputPath: resolvedOutputPath,
      });

      engine.logActionEvent({
        description: `Engagement bundle created: ${archivePath} (${(sizeBytes / 1024 / 1024).toFixed(1)} MB, ${manifest.sections.length} sections)`,
        event_type: 'system',
        category: 'system',
      });
      // Persist so the audit event above is durable — logActionEvent only
      // mutates in-memory state; without a flush the event can be lost if
      // the process exits before the next debounced write (P3).
      engine.flushNow();

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            bundle_path: archivePath,
            size_bytes: sizeBytes,
            size_mb: parseFloat((sizeBytes / 1024 / 1024).toFixed(2)),
            engagement_id: manifest.engagement_id,
            state_version: manifest.state_version,
            journal_version: manifest.journal_version,
            sections: manifest.sections.map(s => s.path),
            tape_paths_referenced: manifest.tape_paths,
            created_at: manifest.created_at,
          }, null, 2),
        }],
      };
    }),
  );
}
