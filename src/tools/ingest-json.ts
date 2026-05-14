// ============================================================
// Overwatch — ingest_json
// Generic JSON / JSONL → engagement graph ingest.
// No dedicated parser required; operator supplies a field mapping.
// ============================================================

import { z } from 'zod';
import { readFileSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { nodeTypeSchema, edgeTypeSchema, NODE_TYPES, EDGE_TYPES } from '../types.js';
import type { NodeType, EdgeType } from '../types.js';
import { validateFilePath } from '../utils/path-validation.js';
import { withErrorBoundary } from './error-boundary.js';

// ---- Helpers ----------------------------------------------------------------

/**
 * Resolve a dot-notation path against an object.
 * Supports array indexing: "results[0].ip"
 * Returns undefined if any segment is missing or null.
 */
function getPath(obj: unknown, path: string): unknown {
  const parts = path.replace(/\[(\d+)\]/g, '.$1').split('.');
  let cur: unknown = obj;
  for (const part of parts) {
    if (cur == null || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

/** Sanitize a raw ID value for use in a node ID. */
function sanitizeId(raw: string): string {
  return raw.replace(/[^a-zA-Z0-9._:-]/g, '-');
}

/**
 * Parse a string as JSON array, JSONL, or single JSON object.
 * Always returns an array of parsed items.
 */
function parseContent(content: string): unknown[] {
  const trimmed = content.trim();

  if (trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);
      return Array.isArray(parsed) ? parsed : [parsed];
    } catch { /* fall through */ }
  }

  if (trimmed.startsWith('{')) {
    try {
      return [JSON.parse(trimmed)];
    } catch { /* fall through */ }
  }

  // JSONL — one JSON value per non-empty line
  const lines = trimmed.split('\n').map(l => l.trim()).filter(Boolean);
  const items: unknown[] = [];
  let parseErrors = 0;
  for (const line of lines) {
    // Skip comment lines some tools emit (# ...)
    if (line.startsWith('#')) continue;
    try {
      items.push(JSON.parse(line));
    } catch {
      parseErrors++;
    }
  }
  if (items.length > 0) return items;
  if (parseErrors > 0) throw new Error(`Content appears to be JSONL but ${parseErrors} lines failed to parse.`);
  throw new Error('Content is not valid JSON, JSON array, or JSONL.');
}

// ---- Schema -----------------------------------------------------------------

const propertyFieldSchema = z.union([
  z.string().describe('Field name to copy as-is (dot-path supported)'),
  z.object({
    from: z.string().describe('Source field (dot-path)'),
    to: z.string().describe('Destination property name'),
  }).describe('Rename: copy field "from" into property "to"'),
]);

const mappingSchema = z.object({
  node_type: z.string().describe(`Graph node type. Valid: ${NODE_TYPES.join(', ')}`),
  array_path: z.string().optional()
    .describe('Dot-path to a nested array of items within each parsed object (e.g. "results", "data.findings"). When set, each element of that array becomes one candidate item for this mapping.'),
  id_field: z.string()
    .describe('Dot-path to the field used as the node ID (e.g. "ip", "host.address", "url").'),
  id_prefix: z.string().optional()
    .describe('Prefix prepended to the sanitized ID value. Defaults to "json-<node_type>-". The same prefix must be used in parent_field references to reconstruct IDs.'),
  label_field: z.string().optional()
    .describe('Dot-path to the node label field. Defaults to the raw ID value.'),
  property_fields: z.array(propertyFieldSchema).optional()
    .describe('Fields to copy as node properties. Use "field" to copy as-is, or {from: "src", to: "dest"} to rename.'),
  parent_field: z.string().optional()
    .describe('Dot-path to the full parent node ID. When present, an edge is created: parent → this node.'),
  parent_edge_type: z.string().optional()
    .describe(`Edge type for the parent → this node edge. Defaults to "RUNS". Valid: ${EDGE_TYPES.slice(0, 8).join(', ')}, …`),
});

// ---- Tool registration ------------------------------------------------------

export function registerIngestJsonTools(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'ingest_json',
    {
      title: 'Ingest JSON / JSONL',
      description: `Ingest tool output in JSON or JSONL format directly into the engagement graph without a dedicated parser.

Accepts any of:
- A JSON array: \`[{"ip": "10.0.0.1"}, ...]\`
- JSONL (newline-delimited JSON, one object per line)
- A single JSON object
- A file path pointing to any of the above

Provide one or more \`mappings\` that each describe how to translate objects into graph nodes.
Multiple mappings applied to the same input let you create several node types from one item.

**ID construction:** \`<id_prefix><sanitized(id_field value)>\`
Default prefix is \`json-<node_type>-\` so a host at 10.0.0.1 becomes \`json-host-10.0.0.1\`.

**Edge creation:** If \`parent_field\` is set, the tool creates a \`parent_edge_type\` edge
(default: RUNS) from the parent node ID to this node. The parent node must already exist
in the graph or be created by an earlier mapping in the same call.

---

**Examples**

*trufflehog JSONL (credentials):*
\`\`\`json
{"mappings": [{
  "node_type": "credential",
  "id_field": "SourceMetadata.Data.Git.commit",
  "id_prefix": "trufflehog-",
  "label_field": "DetectorName",
  "property_fields": ["DetectorName", "Verified", {"from": "Raw", "to": "cred_value"}]
}]}
\`\`\`

*subfinder JSON (domains):*
\`\`\`json
{"mappings": [{"node_type": "domain", "id_field": "host", "label_field": "host",
  "property_fields": ["ip_addresses", "sources"]}]}
\`\`\`

*feroxbuster JSONL (web endpoints + parent host):*
\`\`\`json
{"mappings": [{
  "node_type": "api_endpoint",
  "id_field": "url",
  "label_field": "url",
  "property_fields": ["status", "content_length", "words", "lines"],
  "parent_field": "url",
  "parent_edge_type": "HAS_ENDPOINT"
}]}
\`\`\`

*trivy JSON (vulnerabilities nested under Results[]):*
\`\`\`json
{"mappings": [{
  "node_type": "vulnerability",
  "array_path": "Results",
  "id_field": "VulnerabilityID",
  "label_field": "Title",
  "property_fields": ["Severity", {"from": "CVSS.nvd.V3Score", "to": "cvss"}, "PkgName"]
}]}
\`\`\`

*Custom scan: host + service from same object:*
\`\`\`json
{"mappings": [
  {"node_type": "host", "id_field": "ip", "id_prefix": "json-host-"},
  {"node_type": "service", "id_field": "port", "id_prefix": "json-svc-",
   "label_field": "service", "property_fields": ["port", "protocol", "banner"],
   "parent_field": "ip", "parent_edge_type": "RUNS"}
]}
\`\`\`
> Note: \`parent_field\` here gives the raw IP. You must reconstruct the parent ID
> manually: since the host mapping used prefix \`json-host-\`, set \`parent_field\` to
> return the full ID, or set the host's \`id_prefix\` to \`""\` and reference the raw IP.
> The simplest approach: use \`report_finding\` for cross-node edges after ingest.`,

      inputSchema: {
        content: z.string().optional()
          .describe('Raw JSON, JSON array, or JSONL string. Mutually exclusive with file_path.'),
        file_path: z.string().optional()
          .describe('Absolute path to a JSON or JSONL file. Mutually exclusive with content.'),
        mappings: z.array(mappingSchema).min(1)
          .describe('One or more mapping definitions. Applied in order; earlier mappings run before later ones (relevant for parent_field edges).'),
        agent_id: z.string().optional()
          .describe('Agent ID credited for this ingest.'),
        label: z.string().optional()
          .describe('Human-readable description that appears in the activity log (defaults to a generated summary).'),
      },
    },
    withErrorBoundary('ingest_json', async ({ content, file_path, mappings, agent_id, label }) => {
      if (!content && !file_path) {
        throw new Error('Provide either content or file_path.');
      }
      if (content && file_path) {
        throw new Error('Provide only one of content or file_path, not both.');
      }

      let rawContent = content!;
      if (file_path) {
        const safePath = validateFilePath(file_path);
        rawContent = readFileSync(safePath, 'utf-8');
      }

      const topLevelItems = parseContent(rawContent);
      if (topLevelItems.length === 0) {
        return {
          content: [{
            type: 'text' as const,
            text: JSON.stringify({ items_parsed: 0, nodes_upserted: 0, edges_created: 0, message: 'No items found.' }, null, 2),
          }],
        };
      }

      const now = new Date().toISOString();
      const allNodeIds: string[] = [];
      let edgesCreated = 0;
      const warnings: string[] = [];
      const mappingErrors: string[] = [];

      for (const rawMapping of mappings) {
        // Validate node_type
        const typeResult = nodeTypeSchema.safeParse(rawMapping.node_type);
        if (!typeResult.success) {
          mappingErrors.push(`Invalid node_type "${rawMapping.node_type}". Valid types: ${NODE_TYPES.join(', ')}`);
          continue;
        }
        const nodeType: NodeType = typeResult.data;
        const defaultPrefix = `json-${nodeType}-`;
        const idPrefix = rawMapping.id_prefix ?? defaultPrefix;

        // Validate parent edge type if specified
        let parentEdgeType: EdgeType = 'RUNS';
        if (rawMapping.parent_edge_type) {
          const edgeResult = edgeTypeSchema.safeParse(rawMapping.parent_edge_type);
          if (!edgeResult.success) {
            warnings.push(`Invalid parent_edge_type "${rawMapping.parent_edge_type}" in mapping for ${nodeType} — defaulting to RUNS`);
          } else {
            parentEdgeType = edgeResult.data;
          }
        }

        // Resolve items for this mapping
        let items: unknown[] = topLevelItems;
        if (rawMapping.array_path) {
          const nested: unknown[] = [];
          for (const item of topLevelItems) {
            const val = getPath(item, rawMapping.array_path);
            if (Array.isArray(val)) nested.push(...val);
            else if (val != null) nested.push(val);
          }
          items = nested;
        }

        for (const item of items) {
          const rawId = String(getPath(item, rawMapping.id_field) ?? '').trim();
          if (!rawId) continue;

          const nodeId = `${idPrefix}${sanitizeId(rawId)}`;

          const rawLabel = rawMapping.label_field ? getPath(item, rawMapping.label_field) : undefined;
          const nodeLabel = rawLabel != null ? String(rawLabel) : rawId;

          // Collect properties
          const props: Record<string, unknown> = {};
          for (const pf of rawMapping.property_fields ?? []) {
            if (typeof pf === 'string') {
              const val = getPath(item, pf);
              if (val != null) props[pf.split('.').pop()!] = val;
            } else {
              const val = getPath(item, pf.from);
              if (val != null) props[pf.to] = val;
            }
          }

          engine.addNode({
            id: nodeId,
            type: nodeType,
            label: nodeLabel,
            ...props,
            discovered_at: now,
            discovered_by: agent_id || 'json-ingest',
            confidence: 0.9,
          });
          allNodeIds.push(nodeId);

          // Create parent edge if specified
          if (rawMapping.parent_field) {
            const rawParentId = String(getPath(item, rawMapping.parent_field) ?? '').trim();
            if (rawParentId) {
              try {
                engine.addEdge(rawParentId, nodeId, {
                  type: parentEdgeType,
                  confidence: 0.9,
                  discovered_at: now,
                  discovered_by: agent_id || 'json-ingest',
                });
                edgesCreated++;
              } catch {
                // Parent node may not exist yet; skip silently
              }
            }
          }
        }
      }

      if (mappingErrors.length > 0 && allNodeIds.length === 0) {
        throw new Error(mappingErrors.join('; '));
      }

      const description = label || `json ingest: ${topLevelItems.length} item${topLevelItems.length !== 1 ? 's' : ''} → ${allNodeIds.length} node${allNodeIds.length !== 1 ? 's' : ''}${file_path ? ` (${file_path.split('/').pop()})` : ''}`;

      engine.logActionEvent({
        description,
        agent_id,
        event_type: 'parse_output',
        category: 'finding',
        target_node_ids: allNodeIds.slice(0, 50),
      });
      engine.persist();

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            items_parsed: topLevelItems.length,
            nodes_upserted: allNodeIds.length,
            edges_created: edgesCreated,
            mappings_applied: mappings.length - mappingErrors.length,
            ...(warnings.length > 0 ? { warnings } : {}),
            ...(mappingErrors.length > 0 ? { mapping_errors: mappingErrors } : {}),
            sample_node_ids: allNodeIds.slice(0, 5),
          }, null, 2),
        }],
      };
    }),
  );
}
