import { z } from 'zod';
import { readFileSync, existsSync, readdirSync } from 'fs';
import { resolve, join, extname } from 'path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { parseBloodHoundFile } from '../services/bloodhound-ingest.js';

export function registerBloodHoundTools(server: McpServer, engine: GraphEngine): void {

  // ============================================================
  // Tool: ingest_bloodhound
  // Parse and ingest SharpHound/bloodhound-python JSON output
  // ============================================================
  server.registerTool(
    'ingest_bloodhound',
    {
      title: 'Ingest BloodHound Data',
      description: `Parse and ingest SharpHound or bloodhound-python JSON output into the engagement graph.

Accepts either:
- A directory path containing BloodHound JSON files (computers.json, users.json, etc.)
- A single JSON file path

Maps BloodHound objects to Overwatch graph nodes and edges:
- Computer → host, User → user, Group → group, Domain → domain, OU → ou, GPO → gpo
- ACEs, Members, Sessions, LocalAdmins → corresponding edge types

After ingestion, inference rules fire on all new nodes. This is the fastest way to
populate the graph with Active Directory structure.`,
      inputSchema: {
        path: z.string().describe('Path to BloodHound JSON file or directory containing JSON files'),
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
    async ({ path: inputPath, max_files }) => {
      const resolvedPath = resolve(inputPath);

      if (!existsSync(resolvedPath)) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: `Path not found: ${resolvedPath}` }, null, 2) }],
          isError: true
        };
      }

      const filesToProcess: Array<{ path: string; name: string }> = [];
      const stat = await import('fs').then(fs => fs.statSync(resolvedPath));

      if (stat.isDirectory()) {
        const entries = readdirSync(resolvedPath)
          .filter(f => extname(f).toLowerCase() === '.json')
          .slice(0, max_files);
        for (const entry of entries) {
          filesToProcess.push({ path: join(resolvedPath, entry), name: entry });
        }
      } else {
        filesToProcess.push({ path: resolvedPath, name: resolvedPath.split('/').pop() || 'unknown.json' });
      }

      if (filesToProcess.length === 0) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: 'No JSON files found at the specified path' }, null, 2) }],
          isError: true
        };
      }

      let totalNodes = 0;
      let totalEdges = 0;
      let totalInferred = 0;
      const allErrors: string[] = [];
      const fileResults: Array<{ file: string; nodes: number; edges: number; inferred: number }> = [];

      for (const file of filesToProcess) {
        try {
          const raw = readFileSync(file.path, 'utf-8');
          const result = parseBloodHoundFile(raw, file.name);

          if (!result) {
            allErrors.push(`${file.name}: no data extracted`);
            continue;
          }

          if (result.errors.length > 0) {
            allErrors.push(...result.errors);
          }

          if (result.finding && (result.finding.nodes.length > 0 || result.finding.edges.length > 0)) {
            const ingestResult = engine.ingestFinding(result.finding);
            const nodeCount = ingestResult.new_nodes.length;
            const edgeCount = ingestResult.new_edges.length;
            const inferredCount = ingestResult.inferred_edges.length;
            totalNodes += nodeCount;
            totalEdges += edgeCount;
            totalInferred += inferredCount;
            fileResults.push({ file: file.name, nodes: nodeCount, edges: edgeCount, inferred: inferredCount });
          }
        } catch (err) {
          allErrors.push(`${file.name}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            files_processed: fileResults.length,
            total_new_nodes: totalNodes,
            total_new_edges: totalEdges,
            total_inferred_edges: totalInferred,
            per_file: fileResults,
            errors: allErrors.length > 0 ? allErrors : undefined,
            message: `BloodHound ingestion complete: ${totalNodes} nodes, ${totalEdges} edges, ${totalInferred} inferred from ${fileResults.length} files`
          }, null, 2)
        }]
      };
    }
  );
}
