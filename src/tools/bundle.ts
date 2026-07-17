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
- **active-engagement-config.json** — converged active config when the engagement is file-managed
- **recovery-artifacts/** — active intents, conflicts, migration backups, rollback markers, and preserved recovery authorities when present
- **tapes/** — registered MCP tapes when requested
- **bundle-manifest.json** — V2 index with checkpoint/config identity, recovery status, authority inventory, and per-file sizes and SHA-256 digests

Optionally includes .snapshots/ (periodic state snapshots; can add significant size).

Registered tape files (captured by \`overwatch-mcp-tape\`) are copied into the
bundle when requested; their original paths remain listed for provenance.

Use this to:
- Archive a completed engagement for long-term storage
- Transfer engagement data to another machine or operator
- Share a reproducible state with the team

The capture is staged privately, validated, fsynced, and atomically published;
failed replacements leave a prior destination intact. Live state/WAL/config and
artifact-store path collisions are rejected.

Returns the absolute path, bundle id, size, SHA-256, publication status, and
whether its durable state reference was persisted.`,

      inputSchema: {
        output_path: z.string().optional()
          .describe('Absolute path for the output .tar.gz file. Defaults alongside writable state, or in the OS temp directory during degraded read-only recovery.'),
        include_snapshots: z.boolean().default(false)
          .describe('Include .snapshots/ directory (periodic state snapshots). Can add significant size.'),
        include_tapes: z.boolean().default(true)
          .describe('Copy registered tape files into the bundle and retain their original paths in the manifest.'),
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

      const { archivePath, sizeBytes, sha256, bundleId, manifest, durabilityConfirmed } = await buildBundle(engine, {
        includeSnapshots: include_snapshots,
        includeTapes: include_tapes,
        outputPath: resolvedOutputPath,
      });

      let referencePersisted = false;
      if (engine.isPersistenceWritable()) {
        try {
          engine.logActionEvent({
            description: `Engagement bundle created: ${archivePath} (${(sizeBytes / 1024 / 1024).toFixed(1)} MB, ${manifest.sections.length} sections)`,
            event_type: 'system',
            category: 'system',
            details: {
              bundle_path: archivePath,
              bundle_id: bundleId,
              size_bytes: sizeBytes,
              sha256,
              manifest_version: manifest.manifest_version,
            },
          });
          engine.flushNow();
          referencePersisted = true;
        } catch (error) {
          // The archive has already crossed its fsync + atomic-rename boundary.
          // Return that truthful outcome instead of encouraging a duplicate
          // bundle because an independent audit mutation failed afterward.
          console.error(`[bundle] archive published but durable reference failed: ${error instanceof Error ? error.message : String(error)}`);
        }
      }

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            bundle_path: archivePath,
            bundle_id: bundleId,
            size_bytes: sizeBytes,
            sha256,
            published: true,
            durability_confirmed: durabilityConfirmed,
            reference_persisted: referencePersisted,
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
