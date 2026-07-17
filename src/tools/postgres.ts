// ============================================================
// Overwatch — Postgres ingest tools
// Read-only ingest from an operator-controlled postgres database.
// ============================================================

import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';
import { PostgresSource, redactDsn } from '../services/postgres-source.js';
import { nodeTypeSchema, NODE_TYPES } from '../types.js';
import type { NodeType, Finding } from '../types.js';
import { prepareFindingForIngest } from '../services/finding-validation.js';
import { EngagementCommandService } from '../services/engagement-command-service.js';
import { createHash } from 'node:crypto';

// Per-engagement connection pool — keyed by engagement ID to support multi-engagement servers.
const sourcesById = new Map<string, PostgresSource>();

function getSource(engagementId: string): PostgresSource {
  const src = sourcesById.get(engagementId);
  if (!src) throw new Error('No postgres connection active for this engagement. Call connect_postgres first.');
  return src;
}

export function registerPostgresTools(server: McpServer, engine: GraphEngine): void {
  const engagementCommands = new EngagementCommandService(engine);

  // ---- connect_postgres ----
  server.registerTool(
    'connect_postgres',
    {
      title: 'Connect to Postgres',
      description: `Establish a read-only connection to an operator-controlled PostgreSQL database.

The connection is **session-scoped** — it lives only for the current server process.
You must call connect_postgres again after an MCP server restart. A redacted form of
the DSN is recorded in engagement config for display purposes, but credentials are
not persisted and cannot be automatically reconnected.

On success returns the list of tables in the public schema.

Example: connect_postgres("postgresql://user:pass@localhost:5432/msf")`,
      inputSchema: {
        connection_string: z.string().min(5).describe('postgres:// or postgresql:// connection string'),
        schema: z.string().default('public').describe('Schema to introspect (default: public)'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorBoundary('connect_postgres', async ({ connection_string, schema }) => {
      engine.assertPersistenceWritable();
      const engagementId = engine.getConfig().id;

      // Test and store
      const src = new PostgresSource(connection_string);
      try {
        await src.testConnection();
      } catch (err) {
        await src.end();
        throw new Error(`Failed to connect: ${err instanceof Error ? err.message : String(err)}`);
      }

      // The connection check is asynchronous. Re-check before publishing the
      // live handle or changing durable configuration in case persistence
      // degraded while the target connection was in flight.
      try {
        engine.assertPersistenceWritable();
      } catch (error) {
        await src.end().catch(() => {});
        throw error;
      }

      // Replace any existing source for this engagement
      const existing = sourcesById.get(engagementId);
      if (existing) await existing.end().catch(() => {});
      sourcesById.set(engagementId, src);

      // Record a redacted DSN in engagement config for display only.
      // Credentials are never stored — operators must reconnect after restart.
      const redactedDsn = redactDsn(connection_string);
      const dsnIdentity = createHash('sha256')
        .update(redactedDsn)
        .digest('hex');
      engagementCommands.patchConfig(
        { postgres_dsn: redactedDsn },
        {
          command_id: `postgres-dsn:${dsnIdentity}`,
          idempotency_key: `postgres-dsn:${dsnIdentity}`,
          transport: 'system',
          actor_task_id: null,
        },
      );

      const tables = await src.discoverTables(schema);
      const summary = tables.map(t => `${t.schema_name}.${t.table_name} (${t.columns.length} columns)`).join('\n');

      engine.logActionEvent({ description: `Postgres connected: ${redactedDsn} — ${tables.length} tables in schema "${schema}"`, event_type: 'system', category: 'system' });

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            connected: true,
            dsn_redacted: redactedDsn,
            schema,
            table_count: tables.length,
            tables: summary,
          }, null, 2),
        }],
      };
    }),
  );

  // ---- list_postgres_tables ----
  server.registerTool(
    'list_postgres_tables',
    {
      title: 'List Postgres Tables',
      description: 'List tables and columns in the connected postgres database. Requires connect_postgres first.',
      inputSchema: {
        schema: z.string().default('public').describe('Schema to list (default: public)'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorBoundary('list_postgres_tables', async ({ schema }) => {
      const src = getSource(engine.getConfig().id);
      const tables = await src.discoverTables(schema);
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({ schema, tables }, null, 2),
        }],
      };
    }),
  );

  // ---- ingest_postgres_table ----
  server.registerTool(
    'ingest_postgres_table',
    {
      title: 'Ingest Postgres Table',
      description: `Read rows from a postgres table and ingest them into the engagement graph.

You must specify a \`mapping\` that describes how to translate rows into graph nodes.

\`mapping\` fields:
- \`node_type\` (required): graph node type — "host", "user", "credential", "service", etc.
- \`id_column\` (required): column whose value becomes the node ID prefix (e.g. "address", "ip")
- \`label_column\` (optional): column used as the node label
- \`property_columns\` (optional): list of columns to copy as node properties

Examples:
  Metasploit hosts table:
    { "node_type": "host", "id_column": "address", "label_column": "name",
      "property_columns": ["os_name", "os_flavor", "purpose"] }

  Custom vulns table:
    { "node_type": "vulnerability", "id_column": "cve_id", "label_column": "title",
      "property_columns": ["cvss", "description"] }`,
      inputSchema: {
        table: z.string().describe('Table name (optionally schema-qualified, e.g. "public.hosts")'),
        mapping: z.object({
          node_type: z.string().describe('Graph node type: host, user, credential, service, vulnerability, etc.'),
          id_column: z.string().describe('Column whose value forms the node ID'),
          label_column: z.string().optional().describe('Column used as the node display label'),
          property_columns: z.array(z.string()).optional().describe('Columns to copy as node properties'),
        }).describe('Column → graph node mapping'),
        filter: z.string().optional().describe('SQL WHERE clause (without the WHERE keyword)'),
        limit: z.number().int().min(1).max(50000).default(1000).describe('Maximum rows to ingest (default 1000)'),
        agent_id: z.string().optional().describe('Agent performing the ingest'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorBoundary('ingest_postgres_table', async ({ table, mapping, filter, limit, agent_id }) => {
      const typeResult = nodeTypeSchema.safeParse(mapping.node_type);
      if (!typeResult.success) {
        throw new Error(`Invalid node_type "${mapping.node_type}". Valid types: ${NODE_TYPES.join(', ')}`);
      }
      const nodeType: NodeType = typeResult.data;

      const src = getSource(engine.getConfig().id);
      const rows = await src.queryTable(table, filter, limit);

      if (rows.length === 0) {
        return {
          content: [{
            type: 'text' as const,
            text: JSON.stringify({ table, rows_read: 0, nodes_upserted: 0, message: 'No rows matched.' }, null, 2),
          }],
        };
      }

      const now = new Date().toISOString();
      const discoveredBy = agent_id || 'postgres-ingest';
      const findingNodes: Finding['nodes'] = [];
      const seenIds = new Set<string>();

      for (const row of rows) {
        const rawId = String(row[mapping.id_column] ?? '').trim();
        if (!rawId) continue;

        const nodeId = `pg-${nodeType}-${rawId.replace(/[^a-zA-Z0-9._-]/g, '-')}`;
        if (seenIds.has(nodeId)) continue;
        seenIds.add(nodeId);

        const label = mapping.label_column ? String(row[mapping.label_column] ?? rawId) : rawId;

        const extraProps: Record<string, unknown> = {};
        for (const col of mapping.property_columns ?? []) {
          if (row[col] !== undefined && row[col] !== null) {
            extraProps[col] = row[col];
          }
        }

        findingNodes.push({
          id: nodeId,
          type: nodeType,
          label,
          ...extraProps,
          discovered_at: now,
          discovered_by: discoveredBy,
          confidence: 0.9,
        });
      }

      const finding: Finding = {
        id: uuidv4(),
        agent_id: discoveredBy,
        timestamp: now,
        nodes: findingNodes,
        edges: [],
      };

      const prepared = prepareFindingForIngest(finding, id => engine.getNode(id));

      if (prepared.errors.length > 0) {
        throw new Error(`Ingest validation failed: ${prepared.errors.map(e => e.message).join('; ')}`);
      }

      const ingestResult = engine.ingestFinding(prepared.finding);
      const allNodeIds = [...ingestResult.new_nodes, ...ingestResult.updated_nodes];

      engine.logActionEvent({
        description: `postgres ingest: ${rows.length} rows from ${table} → ${ingestResult.new_nodes.length} new + ${ingestResult.updated_nodes.length} updated ${nodeType} nodes`,
        agent_id,
        event_type: 'parse_output',
        category: 'finding',
        target_node_ids: allNodeIds.slice(0, 50),
      });

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            table,
            rows_read: rows.length,
            new_nodes: ingestResult.new_nodes.length,
            updated_nodes: ingestResult.updated_nodes.length,
            node_type: nodeType,
            sample_node_ids: allNodeIds.slice(0, 5),
          }, null, 2),
        }],
      };
    }),
  );
}
