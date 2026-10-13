import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDb, ScanService } from "@reconnexus/control-plane";
import { ScopePolicySchema } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";
import { loadContext } from "../../apps/cli/src/context.js";
import { correlationsCommand } from "../../apps/cli/src/commands/correlations.js";
import { makeEnvelope } from "../../apps/cli/src/output.js";
import { CliError } from "../../apps/cli/src/errors.js";

const config = loadConfig({ cwd: process.cwd() });
const ctx = loadContext({});

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

function policy(rootDomain: string): unknown {
  return {
    schemaVersion: 1,
    policyId: randomUUID(),
    projectId: randomUUID(),
    policyVersion: 1,
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "ACTIVE_HTTP"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

describe.skipIf(!available)("correlations CLI", () => {
  it("distinguishes not-run, partial, failed, complete-empty and populated states; JSON; missing scan", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const workspace = `corrcli${rand}`;
    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${rootDomain}/`, policy: ScopePolicySchema.parse(policy(rootDomain)), workspaceName: workspace });
      const { scanId, projectId } = created;
      const setCoverage = (status: string): Promise<unknown> =>
        db.query(
          `INSERT INTO coverage_records (project_id, scan_id, stage, status, expected, collected, notes, details)
           VALUES ($1,$2,'11-correlation',$3,0,0,'','{}'::jsonb)
           ON CONFLICT (scan_id, stage) DO UPDATE SET status=EXCLUDED.status, details=EXCLUDED.details`,
          [projectId, scanId, status],
        );

      // 1. Not run.
      const notRun = await correlationsCommand(ctx, scanId, {});
      expect((notRun.data as { stageState: string }).stageState).toBe("NOT_RUN");

      // 2. Partial.
      await setCoverage("PARTIAL");
      const partial = await correlationsCommand(ctx, scanId, {});
      expect((partial.data as { stageState: string }).stageState).toBe("PARTIAL");
      expect(partial.render ? partial.render() : "").toContain("PARTIALLY");

      // 3. Failed (coverage MISSING + job FAILED).
      await setCoverage("MISSING");
      await db.query("UPDATE jobs SET status='FAILED' WHERE scan_id=$1 AND job_key='11-correlation'", [scanId]);
      const failed = await correlationsCommand(ctx, scanId, {});
      expect((failed.data as { stageState: string }).stageState).toBe("FAILED");

      // 4. Complete with no correlations.
      await setCoverage("COLLECTED");
      await db.query("UPDATE jobs SET status='SUCCEEDED' WHERE scan_id=$1 AND job_key='11-correlation'", [scanId]);
      const empty = await correlationsCommand(ctx, scanId, {});
      expect((empty.data as { stageState: string }).stageState).toBe("COMPLETE");
      expect(empty.render ? empty.render() : "").toContain("no correlations found");

      // 5. Populated correlation observation + edge.
      const a = await db.query<{ id: string }>("INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'URL','https://h/a.js','https://h/a.js') RETURNING id", [projectId]);
      const b = await db.query<{ id: string }>("INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'URL','https://h/b.js','https://h/b.js') RETURNING id", [projectId]);
      await db.query(
        `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
         VALUES ($1,$2,$3,'stage-11-correlation','HIGH', now(),'correlation',$4::jsonb)`,
        [projectId, scanId, a.rows[0]!.id, JSON.stringify({ relation: "SHARES_SECRET_FINGERPRINT", status: "OBSERVED", subject: "https://h/a.js", related: ["https://h/b.js"], ruleId: "aws-access-key-id", hmacKeyed: true, correlationGroup: "abcdef0123456789", sourceRecordIds: [], sourceStage: "11-correlation", evidence: "rule x", confidence: 0.9 })],
      );
      await db.query(
        `INSERT INTO asset_relationships (project_id, from_asset_id, to_asset_id, relation, confidence, source)
         VALUES ($1,$2,$3,'shares_secret_fingerprint',0.9,'stage-11-correlation')`,
        [projectId, a.rows[0]!.id, b.rows[0]!.id],
      );
      const populated = await correlationsCommand(ctx, scanId, {});
      expect((populated.data as { correlationObservations: number }).correlationObservations).toBe(1);
      expect((populated.data as { edges: number }).edges).toBe(1);
      const filtered = await correlationsCommand(ctx, scanId, { relation: "MULTI_SOURCE_CORROBORATION" });
      expect((filtered.data as { correlationObservations: number }).correlationObservations).toBe(0);

      const env = JSON.parse(JSON.stringify(makeEnvelope("correlations", populated)));
      expect(env.ok).toBe(true);
      expect(env.exitCode).toBe(0);

      await expect(correlationsCommand(ctx, "00000000-0000-0000-0000-000000000000", {})).rejects.toBeInstanceOf(CliError);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
