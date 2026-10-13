import { describe, expect, it } from "vitest";
import { createDb, migrate, migrationStatus } from "@reconnexus/control-plane";
import { loadConfig } from "@reconnexus/configuration";

const config = loadConfig({ cwd: process.cwd() });

async function probe(): Promise<boolean> {
  const db = createDb(config.database);
  try {
    await db.query("SELECT 1");
    return true;
  } catch {
    return false;
  } finally {
    await db.close();
  }
}

const available = await probe();

describe.skipIf(!available)("database migrations", () => {
  it("applies all migrations and is idempotent", async () => {
    const db = createDb(config.database);
    try {
      const first = await migrate(db, config.migrationsDir);
      expect(first.applied.length + first.skipped.length).toBeGreaterThanOrEqual(2);

      const second = await migrate(db, config.migrationsDir);
      expect(second.applied).toEqual([]);
      expect(second.skipped.length).toBeGreaterThanOrEqual(2);

      const status = await migrationStatus(db, config.migrationsDir);
      expect(status.every((s) => s.applied)).toBe(true);

      const tables = await db.query<{ table_name: string }>(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
      );
      const names = tables.rows.map((r) => r.table_name);
      for (const t of ["projects", "scope_policies", "scan_runs", "jobs", "assets", "observations", "findings", "coverage_records", "audit_events"]) {
        expect(names, `missing table ${t}`).toContain(t);
      }
    } finally {
      await db.close();
    }
  });

  it("enforces the finding confidence check constraint", async () => {
    const db = createDb(config.database);
    const name = `ck-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
    let projectId: string | undefined;
    try {
      await migrate(db, config.migrationsDir);
      const ws = await db.query<{ id: string }>(
        "INSERT INTO workspaces (name) VALUES ($1) RETURNING id",
        [name],
      );
      const project = await db.query<{ id: string }>(
        "INSERT INTO projects (workspace_id, name, root_domain) VALUES ($1, $2, $3) RETURNING id",
        [ws.rows[0]!.id, name, "ck.example"],
      );
      projectId = project.rows[0]!.id;
      const policy = await db.query<{ id: string }>(
        "INSERT INTO scope_policies (project_id, version, document) VALUES ($1, 1, '{}'::jsonb) RETURNING id",
        [projectId],
      );
      const scan = await db.query<{ id: string }>(
        "INSERT INTO scan_runs (project_id, policy_id, start_url, root_domain) VALUES ($1, $2, $3, $4) RETURNING id",
        [projectId, policy.rows[0]!.id, "https://ck.example/", "ck.example"],
      );
      const insertFinding = (confidence: number): Promise<unknown> =>
        db.query(
          `INSERT INTO findings (project_id, scan_id, category, title, severity, confidence, validation, source_reliability)
           VALUES ($1, $2, 'test', 't', 'LOW', $3, 'SUSPECTED', 'MEDIUM')`,
          [projectId, scan.rows[0]!.id, confidence],
        );
      await expect(insertFinding(1.5)).rejects.toThrow(/confidence/);
      await expect(insertFinding(0.5)).resolves.toBeDefined();
    } finally {
      if (projectId) {
        await db.query("DELETE FROM projects WHERE id = $1", [projectId]).catch(() => undefined);
      }
      await db.query("DELETE FROM workspaces WHERE name = $1", [name]).catch(() => undefined);
      await db.close();
    }
  });
});
