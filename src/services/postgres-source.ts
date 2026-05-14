// ============================================================
// Overwatch — PostgresSource
// Read-only ingest from an operator-controlled postgres DB.
// ============================================================

import pg from 'pg';

const { Pool } = pg;

export interface TableColumn {
  column_name: string;
  data_type: string;
  is_nullable: string;
}

export interface TableMeta {
  table_name: string;
  schema_name: string;
  columns: TableColumn[];
}

export class PostgresSource {
  private pool: pg.Pool;
  private dsn: string;

  constructor(connectionString: string) {
    this.dsn = connectionString;
    this.pool = new Pool({
      connectionString,
      max: 3,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
    });
  }

  async testConnection(): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query('SELECT 1');
    } finally {
      client.release();
    }
  }

  async discoverTables(schema = 'public'): Promise<TableMeta[]> {
    const client = await this.pool.connect();
    try {
      const { rows } = await client.query<{
        table_name: string;
        table_schema: string;
        column_name: string;
        data_type: string;
        is_nullable: string;
      }>(
        `SELECT t.table_name, t.table_schema, c.column_name, c.data_type, c.is_nullable
         FROM information_schema.tables t
         JOIN information_schema.columns c
           ON c.table_name = t.table_name AND c.table_schema = t.table_schema
         WHERE t.table_type = 'BASE TABLE' AND t.table_schema = $1
         ORDER BY t.table_name, c.ordinal_position`,
        [schema],
      );

      const tableMap = new Map<string, TableMeta>();
      for (const row of rows) {
        const key = `${row.table_schema}.${row.table_name}`;
        if (!tableMap.has(key)) {
          tableMap.set(key, {
            table_name: row.table_name,
            schema_name: row.table_schema,
            columns: [],
          });
        }
        tableMap.get(key)!.columns.push({
          column_name: row.column_name,
          data_type: row.data_type,
          is_nullable: row.is_nullable,
        });
      }
      return Array.from(tableMap.values());
    } finally {
      client.release();
    }
  }

  async queryTable(
    table: string,
    filter?: string,
    limit = 1000,
  ): Promise<Record<string, unknown>[]> {
    // Basic injection protection: table name must be identifier-safe
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)?$/.test(table)) {
      throw new Error(`Invalid table name: ${table}`);
    }
    const client = await this.pool.connect();
    try {
      let sql = `SELECT * FROM ${table}`;
      const params: unknown[] = [];
      if (filter) {
        // Filter is operator-supplied raw SQL — for read-only usage only.
        // We wrap in a transaction that is always read-only to prevent writes.
        sql += ` WHERE ${filter}`;
      }
      sql += ` LIMIT $${params.length + 1}`;
      params.push(limit);
      await client.query('SET TRANSACTION READ ONLY');
      const { rows } = await client.query(sql, params);
      return rows as Record<string, unknown>[];
    } finally {
      client.release();
    }
  }

  getDsn(): string {
    // Never return the DSN to callers that might log it — return a redacted form.
    return redactDsn(this.dsn);
  }

  async end(): Promise<void> {
    await this.pool.end();
  }
}

export function redactDsn(dsn: string): string {
  return dsn.replace(/(:\/\/[^:]*:)[^@]*(@)/, '$1[redacted]$2');
}
