import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { buildReport, createDb, Repository, ScanService } from "@reconnexus/control-plane";
import { ScopePolicySchema } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";

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
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "DNS", "ACTIVE_HTTP", "SECURITY_CHECKS"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

describe.skipIf(!available)("security-metadata finding appears in the report", () => {
  it("derives an INSECURE_COOKIE finding and marks the report as having findings", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const workspace = `secf${rand}`;
    try {
      const { scanId, projectId } = await new ScanService(db).createScan({
        startUrl: `https://${rootDomain}/`,
        policy: ScopePolicySchema.parse(makePolicy(rootDomain)),
        workspaceName: workspace,
      });
      const svc = await db.query<{ id: string }>(
        "INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'SERVICE',$2,$2) RETURNING id",
        [projectId, `https://${rootDomain}`],
      );
      await db.query(
        `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
         VALUES ($1,$2,$3,'builtin-security-meta','HIGH', now(),'security-metadata',$4::jsonb)`,
        [projectId, scanId, svc.rows[0]!.id, JSON.stringify({ category: "COOKIE", name: "session", status: "OBSERVED", observed: true, value: "", url: `https://${rootDomain}/`, detail: { secure: false, httpOnly: true, sameSite: "Lax" }, evidence: "Set-Cookie", evidenceType: "HEADER" })],
      );
      await db.query("UPDATE jobs SET status='SUCCEEDED' WHERE scan_id=$1", [scanId]);
      await db.query("UPDATE scan_runs SET status='SUCCEEDED' WHERE id=$1", [scanId]);

      const report = await buildReport(new Repository(db), scanId, { now: FROZEN() });
      expect(report).toBeTruthy();
      const f = report!.findings.find((x) => x.category === "INSECURE_COOKIE");
      expect(f).toBeTruthy();
      expect(f!.severity).toBe("LOW");
      expect(f!.validation).toBe("SUSPECTED");
      expect(report!.findingTotals.total).toBeGreaterThanOrEqual(1);
      expect(report!.reportStatus).toBe("COMPLETE_WITH_FINDINGS");
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });

  it("does not derive a finding from an absent security header", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const workspace = `secn${rand}`;
    try {
      const { scanId, projectId } = await new ScanService(db).createScan({
        startUrl: `https://${rootDomain}/`,
        policy: ScopePolicySchema.parse(makePolicy(rootDomain)),
        workspaceName: workspace,
      });
      const svc = await db.query<{ id: string }>(
        "INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'SERVICE',$2,$2) RETURNING id",
        [projectId, `https://${rootDomain}`],
      );
      await db.query(
        `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
         VALUES ($1,$2,$3,'builtin-security-meta','HIGH', now(),'security-metadata',$4::jsonb)`,
        [projectId, scanId, svc.rows[0]!.id, JSON.stringify({ category: "HEADER", name: "strict-transport-security", status: "NOT_OBSERVED", observed: false, url: `https://${rootDomain}/`, detail: {}, evidence: "absent", evidenceType: "HEADER" })],
      );
      await db.query("UPDATE jobs SET status='SUCCEEDED' WHERE scan_id=$1", [scanId]);
      await db.query("UPDATE scan_runs SET status='SUCCEEDED' WHERE id=$1", [scanId]);

      const report = await buildReport(new Repository(db), scanId, { now: FROZEN() });
      expect(report!.findings.some((x) => x.category === "INSECURE_COOKIE")).toBe(false);
      expect(report!.findingTotals.total).toBe(0);
      expect(report!.reportStatus).toBe("COMPLETE_NO_FINDINGS");
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
