import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { buildReport, createDb, Repository, ScanService } from "@reconnexus/control-plane";
import { ScopePolicySchema } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";

/**
 * Report finalization must be idempotent and must read current persisted state, never a stale
 * coverage snapshot. A transition (e.g. a provider that later reports PARTIAL) must be reflected
 * on regeneration rather than frozen at the first finalization.
 */
const config = loadConfig({ cwd: process.cwd() });
const FROZEN = () => new Date("2026-01-01T00:00:00.000Z");

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

function makePolicy(rootDomain: string): unknown {
  return {
    schemaVersion: 1,
    policyId: randomUUID(),
    projectId: randomUUID(),
    policyVersion: 1,
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "DNS", "ACTIVE_HTTP"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

describe.skipIf(!available)("report finalization", () => {
  it("is idempotent and reflects later state changes (no stale coverage snapshot)", async () => {
    const db = createDb(config.database);
    const repo = new Repository(db);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const workspace = `fin${rand}`;
    try {
      const { scanId } = await new ScanService(db).createScan({
        startUrl: `https://${rootDomain}/`,
        policy: ScopePolicySchema.parse(makePolicy(rootDomain)),
        workspaceName: workspace,
      });

      const setAllSucceeded = async (): Promise<void> => {
        await db.query("UPDATE jobs SET status='SUCCEEDED' WHERE scan_id=$1", [scanId]);
      };
      const persistReport = async (): Promise<void> => {
        const report = await buildReport(repo, scanId, { now: FROZEN() });
        const now = FROZEN();
        await db.withTransaction(async (client) => {
          await client.query("DELETE FROM observations WHERE scan_id=$1 AND kind='report'", [scanId]);
          const a = await client.query<{ id: string }>("INSERT INTO assets (project_id,type,canonical_key,value) VALUES ((SELECT project_id FROM scan_runs WHERE id=$1),'DOMAIN',$2,$2) ON CONFLICT (project_id,type,canonical_key) DO UPDATE SET value=EXCLUDED.value RETURNING id", [scanId, rootDomain]);
          await client.query(
            `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
             VALUES ((SELECT project_id FROM scan_runs WHERE id=$1),$1,$2,'stage-12-reporting','AUTHORITATIVE',$3,'report',$4::jsonb)`,
            [scanId, a.rows[0]!.id, now.toISOString(), JSON.stringify(report)],
          );
        });
      };

      await setAllSucceeded();
      // Finalize twice: exactly one report row survives (idempotent delete+insert).
      await persistReport();
      await persistReport();
      const rows = await db.query<{ n: string }>("SELECT count(*)::text AS n FROM observations WHERE scan_id=$1 AND kind='report'", [scanId]);
      expect(Number(rows.rows[0]!.n)).toBe(1);
      expect((await buildReport(repo, scanId, { now: FROZEN() }))!.reportStatus).toBe("COMPLETE_NO_FINDINGS");

      // A provider later drops to PARTIAL: regeneration must reflect it, not the old snapshot.
      await db.query("UPDATE jobs SET status='PARTIAL' WHERE scan_id=$1 AND job_key='04-http-probe'", [scanId]);
      await db.query("UPDATE coverage_records SET status='PARTIAL' WHERE scan_id=$1 AND stage='04-http-probe'", [scanId]);
      const after = await buildReport(repo, scanId, { now: FROZEN() });
      expect(after!.reportStatus).toBe("PARTIAL");
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
