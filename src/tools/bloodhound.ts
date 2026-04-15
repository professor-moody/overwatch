import { z } from 'zod';
import { readFileSync, existsSync, readdirSync, statSync } from 'fs';
import { resolve, join, extname } from 'path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { buildBloodHoundSidMap, parseBloodHoundFile } from '../services/bloodhound-ingest.js';
import { prepareFindingForIngest } from '../services/finding-validation.js';
import { withErrorBoundary } from './error-boundary.js';

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
    withErrorBoundary('ingest_bloodhound', async ({ path: inputPath, max_files }) => {
      const resolvedPath = resolve(inputPath);

      if (!existsSync(resolvedPath)) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: `Path not found: ${resolvedPath}` }, null, 2) }],
          isError: true
        };
      }

      const filesToProcess: Array<{ path: string; name: string; raw?: string }> = [];
      const stat = statSync(resolvedPath);

      if (stat.isDirectory()) {
        const entries = readdirSync(resolvedPath)
          .filter(f => extname(f).toLowerCase() === '.json')
          .sort()
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
      const filePayloads: Array<{ raw: string; filename: string }> = [];
      const parsedFindings: Array<{ file: string; finding: NonNullable<ReturnType<typeof parseBloodHoundFile>['finding']> }> = [];

      for (const file of filesToProcess) {
        try {
          const raw = readFileSync(file.path, 'utf-8');
          file.raw = raw;
          filePayloads.push({ raw, filename: file.name });
        } catch (err) {
          allErrors.push(`${file.name}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }

      const { sidMap, errors: sidMapErrors } = buildBloodHoundSidMap(filePayloads);
      allErrors.push(...sidMapErrors);

      for (const file of filesToProcess) {
        try {
          if (file.raw === undefined) continue;
          const result = parseBloodHoundFile(file.raw, file.name, { sidMap });

          if (result.errors.length > 0) {
            allErrors.push(...result.errors);
          }

          if (result.finding && (result.finding.nodes.length > 0 || result.finding.edges.length > 0)) {
            parsedFindings.push({ file: file.name, finding: result.finding });
          }
        } catch (err) {
          allErrors.push(`${file.name}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }

      const parsedNodeLookup = new Map<string, NonNullable<ReturnType<typeof parseBloodHoundFile>['finding']>['nodes'][number]>();
      for (const parsed of parsedFindings) {
        for (const node of parsed.finding.nodes) {
          if (!parsedNodeLookup.has(node.id)) {
            parsedNodeLookup.set(node.id, node);
          }
        }
      }

      for (const parsed of parsedFindings) {
        const prepared = prepareFindingForIngest(parsed.finding, nodeId => (parsedNodeLookup.get(nodeId) as any) || engine.getNode(nodeId));

        // Separate fatal node errors from recoverable edge errors
        const nodeErrors = prepared.errors.filter(e => e.code !== 'edge_type_constraint' && e.code !== 'missing_node_reference');
        const edgeErrors = prepared.errors.filter(e => e.code === 'edge_type_constraint' || e.code === 'missing_node_reference');

        if (nodeErrors.length > 0) {
          allErrors.push(`${parsed.file}: invalid graph mutation (${nodeErrors.map(error => error.message).join('; ')})`);
          continue;
        }

        if (edgeErrors.length > 0) {
          allErrors.push(...edgeErrors.map(e => `${parsed.file}: skipped edge: ${e.message}`));
          // Remove invalid edges and continue with the rest of the file
          const badEdgeKeys = new Set(edgeErrors.map(e => `${e.source_id}--${e.edge_type}--${e.target_id}`));
          prepared.finding.edges = prepared.finding.edges.filter(e => {
            const key = `${e.source}--${e.properties.type}--${e.target}`;
            return !badEdgeKeys.has(key);
          });
        }

        const ingestResult = engine.ingestFinding(prepared.finding);
        const nodeCount = ingestResult.new_nodes.length;
        const edgeCount = ingestResult.new_edges.length;
        const inferredCount = ingestResult.inferred_edges.length;
        totalNodes += nodeCount;
        totalEdges += edgeCount;
        totalInferred += inferredCount;
        fileResults.push({ file: parsed.file, nodes: nodeCount, edges: edgeCount, inferred: inferredCount });
      }

      // Post-ingest enrichment: identify HVTs and pre-compute attack paths
      const enrichment = engine.enrichBloodHoundPaths();

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            files_processed: fileResults.length,
            total_new_nodes: totalNodes,
            total_new_edges: totalEdges,
            total_inferred_edges: totalInferred,
            hvts_identified: enrichment.hvts.length,
            attack_paths_computed: enrichment.paths.length,
            per_file: fileResults,
            errors: allErrors.length > 0 ? allErrors : undefined,
            message: `BloodHound ingestion complete: ${totalNodes} nodes, ${totalEdges} edges, ${totalInferred} inferred from ${fileResults.length} files. ${enrichment.hvts.length} HVTs identified, ${enrichment.paths.length} attack paths pre-computed.`
          }, null, 2)
        }]
      };
    })
  );
}
