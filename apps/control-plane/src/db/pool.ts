import { Pool, type PoolClient, type QueryResult, type QueryResultRow } from "pg";
import type { DatabaseConfig } from "@reconnexus/configuration";

/** Anything that can run parameterized SQL: either the pool or a transaction client. */
export interface Queryable {
  query<R extends QueryResultRow = QueryResultRow>(sql: string, params?: unknown[]): Promise<QueryResult<R>>;
}

export interface Db extends Queryable {
  withTransaction<T>(fn: (client: Queryable) => Promise<T>): Promise<T>;
  close(): Promise<void>;
  raw(): Pool;
}

export function createDb(config: DatabaseConfig): Db {
  const pool = new Pool({
    connectionString: config.url,
    max: config.poolSize,
    statement_timeout: config.statementTimeoutMs,
  });

  return {
    async query<R extends QueryResultRow = QueryResultRow>(sql: string, params: unknown[] = []): Promise<QueryResult<R>> {
      return pool.query<R>(sql, params as never[]);
    },
    async withTransaction<T>(fn: (client: Queryable) => Promise<T>): Promise<T> {
      const client: PoolClient = await pool.connect();
      try {
        await client.query("BEGIN");
        const result = await fn(client as unknown as Queryable);
        await client.query("COMMIT");
        return result;
      } catch (err) {
        try {
          await client.query("ROLLBACK");
        } catch {
          /* connection may be gone */
        }
        throw err;
      } finally {
        client.release();
      }
    },
    async close(): Promise<void> {
      await pool.end();
    },
    raw(): Pool {
      return pool;
    },
  };
}
