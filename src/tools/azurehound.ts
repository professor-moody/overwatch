import { z } from 'zod';
import { readFileSync, existsSync, readdirSync, statSync } from 'fs';
import { resolve, join, extname } from 'path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { parseAzureHoundFile } from '../services/azurehound-ingest.js';
import { prepareFindingForIngest } from '../services/finding-validation.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerAzureHoundTools(server: McpServer, engine: GraphEngine): void {

  server.registerTool(
    'ingest_azurehound',
    {
      title: 'Ingest AzureHound / ROADtools Data',
      description: `Parse and ingest AzureHound or ROADtools JSON output into the engagement graph.

Accepts either:
- A directory path containing AzureHound JSON files (users.json, groups.json, etc.)
- A single JSON file path

Maps Azure AD objects to Overwatch graph nodes and edges:
- Users → cloud_identity (provider: azure, principal_type: user)
- Groups → group (provider: azure)
- Apps → cloud_identity (principal_type: app)
- Service Principals → cloud_identity (principal_type: service_account)
- Role Assignments → cloud_policy + HAS_POLICY edges
- App Role Assignments → ASSUMES_ROLE edges

After ingestion, inference rules fire on all new nodes.`,
      inputSchema: {
        path: z.string().describe('Path to AzureHound JSON file or directory containing JSON files'),
        max_files: z.number().int().min(1).max(50).default(20)
          .describe('Maximum number of JSON files to process from a directory'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      }
    },
    withErrorBoundary('ingest_azurehound', async ({ path: inputPath, max_files }) => {
      const resolvedPath = resolve(inputPath);

      if (!existsSync(resolvedPath)) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: `Path not found: ${resolvedPath}` }, null, 2) }],
          isError: true
        };
      }

      const stat = statSync(resolvedPath);
      const files: string[] = [];

      if (stat.isDirectory()) {
        const entries = readdirSync(resolvedPath)
          .filter(f => extname(f).toLowerCase() === '.json')
          .sort()
          .slice(0, max_files);
        files.push(...entries.map(f => join(resolvedPath, f)));
      } else {
        files.push(resolvedPath);
      }

      if (files.length === 0) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: 'No JSON files found in directory' }, null, 2) }],
          isError: true
        };
      }

      let totalNodes = 0;
      let totalEdges = 0;
      const errors: string[] = [];
      const processedFiles: string[] = [];

      for (const filePath of files) {
        try {
          const content = readFileSync(filePath, 'utf-8');
          const filename = filePath.split('/').pop() || filePath;
          const finding = parseAzureHoundFile(content, filename);

          if (finding.nodes.length === 0 && finding.edges.length === 0) {
            continue;
          }

          const prepared = prepareFindingForIngest(finding, nodeId => engine.getNode(nodeId));
          if (prepared.errors.length > 0) {
            errors.push(`${filename}: ${prepared.errors.map(e => e.message).join(', ')}`);
            continue;
          }

          engine.ingestFinding(prepared.finding);
          totalNodes += finding.nodes.length;
          totalEdges += finding.edges.length;
          processedFiles.push(filename);
        } catch (err: any) {
          errors.push(`${filePath}: ${err.message}`);
        }
      }

      const result = {
        files_processed: processedFiles.length,
        total_nodes: totalNodes,
        total_edges: totalEdges,
        files: processedFiles,
        errors: errors.length > 0 ? errors : undefined,
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    })
  );
}
