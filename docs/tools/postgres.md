# PostgreSQL Tools

Session-scoped PostgreSQL connection and ingestion helpers.

## Tools

| Tool | Read-only | Purpose |
|------|-----------|---------|
| `connect_postgres` | No | Open an in-process PostgreSQL connection for this server session. |
| `list_postgres_tables` | Yes | List schemas/tables visible to the active connection. |
| `ingest_postgres_table` | No | Query rows from a table and ingest them as graph nodes. |

## Persistence Model

PostgreSQL connections are runtime-only. The live DSN and credentials are not persisted, and the server does not reconnect automatically after restart.

The engagement config may retain a redacted `postgres_dsn` display value after validation/reload. That value is for operator visibility only and is not enough to reconnect.

## Usage Notes

- Call `connect_postgres` again after an MCP server restart.
- Use `list_postgres_tables` to confirm visibility before ingestion.
- Keep mappings explicit when ingesting tables so downstream graph output remains predictable.
