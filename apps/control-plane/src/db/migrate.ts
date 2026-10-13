import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Db } from "./pool.js";

export interface MigrationFile {
  version: string;
  name: string;
  filename: string;
  sql: string;
}

const ADVISORY_LOCK_KEY = 0x5ec07e51; // arbitrary, stable within this app

export async function listMigrations(dir: string): Promise<MigrationFile[]> {
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch (err) {
    throw new Error(`cannot read migrations directory '${dir}': ${(err as Error).message}`);
  }
  const files = entries.filter((f) => /^\d{4}_.+\.sql$/.test(f)).sort();
  const out: MigrationFile[] = [];
  for (const filename of files) {
    const version = filename.slice(0, 4);
    const name = filename.slice(5, -4);
    const sql = await readFile(join(dir, filename), "utf8");
    out.push({ version, name, filename, sql });
  }
  return out;
}

export async function ensureMigrationsTable(db: Db): Promise<void> {
  await db.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version    text PRIMARY KEY,
      name       text NOT NULL,
      applied_at timestamptz NOT NULL DEFAULT now()
    )`);
}

export async function appliedVersions(db: Db): Promise<Set<string>> {
  await ensureMigrationsTable(db);
  const res = await db.query<{ version: string }>("SELECT version FROM schema_migrations");
  return new Set(res.rows.map((r) => r.version));
}

export interface MigrateResult {
  applied: string[];
  skipped: string[];
}

/**
 * Apply pending migrations in ascending version order inside a transaction, guarded by a
 * Postgres advisory lock so concurrent runners cannot interleave. Idempotent: applied
 * versions are skipped on re-run.
 */
export async function migrate(db: Db, dir: string): Promise<MigrateResult> {
  const migrations = await listMigrations(dir);

  // Duplicate version detection.
  const seen = new Set<string>();
  for (const m of migrations) {
    if (seen.has(m.version)) throw new Error(`duplicate migration version ${m.version}`);
    seen.add(m.version);
  }

  return db.withTransaction(async (client) => {
    await client.query("SELECT pg_advisory_xact_lock($1)", [ADVISORY_LOCK_KEY]);
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version    text PRIMARY KEY,
        name       text NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now()
      )`);
    const existing = await client.query<{ version: string }>("SELECT version FROM schema_migrations");
    const applied = new Set(existing.rows.map((r) => r.version));

    const result: MigrateResult = { applied: [], skipped: [] };
    for (const m of migrations) {
      if (applied.has(m.version)) {
        result.skipped.push(m.version);
        continue;
      }
      await client.query(m.sql);
      await client.query("INSERT INTO schema_migrations (version, name) VALUES ($1, $2)", [m.version, m.name]);
      result.applied.push(m.version);
    }
    return result;
  });
}

export interface MigrationStatusRow {
  version: string;
  name: string;
  applied: boolean;
}

export async function migrationStatus(db: Db, dir: string): Promise<MigrationStatusRow[]> {
  const migrations = await listMigrations(dir);
  const applied = await appliedVersions(db);
  return migrations.map((m) => ({ version: m.version, name: m.name, applied: applied.has(m.version) }));
}
