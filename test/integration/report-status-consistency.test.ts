import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { buildReport, createDb, formatReport, renderReportHtml, Repository, ScanService } from "@reconnexus/control-plane";
import { ScopePolicySchema } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";

/**
 * Regression for the observed report contradiction: a report showed `COMPLETE_WITH_FINDINGS`
 * while displaying "0 candidate findings". Root cause: `buildReport` counted correlations (and
 * takeover candidates) into the number it passed to `deriveReportStatus`, while the findings
 * section and `findingTotals` were derived from `buildFindings`. A scan with correlations but no
 * findings was therefore labelled as having findings.
 *
 * These tests force a fully-successful set of stage jobs so the analysis status is SUCCEEDED, then
 * assert the report status agrees with the findings the report actually contains.
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

/** Force every stage job (including reporting) to SUCCEEDED and the scan to SUCCEEDED. */
async function markAllSucceeded(db: ReturnType<typeof createDb>, scanId: string): Promise<void> {
  await db.query("UPDATE jobs SET status='SUCCEEDED' WHERE scan_id=$1", [scanId]);
  await db.query("UPDATE scan_runs SET status='SUCCEEDED' WHERE id=$1", [scanId]);
}

describe.skipIf(!available)("report status agrees with reported findings", () => {
  it("correlations alone (zero findings) yield COMPLETE_NO_FINDINGS, never COMPLETE_WITH_FINDINGS", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const workspace = `rsc${rand}`;
    try {
      const { scanId, projectId } = await new ScanService(db).createScan({
        startUrl: `https://${rootDomain}/`,
        policy: ScopePolicySchema.parse(makePolicy(rootDomain)),
        workspaceName: workspace,
      });
      const asset = await db.query<{ id: string }>(
        "INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'URL',$2,$2) RETURNING id",
        [projectId, `https://${rootDomain}/a.js`],
      );
      const assetId = asset.rows[0]!.id;
      // 3 correlation observations, exactly like the Dunya News report, and zero findings.
      for (let i = 0; i < 3; i++) {
        await db.query(
          `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
           VALUES ($1,$2,$3,'stage-11-correlation','HIGH', now(),'correlation',$4::jsonb)`,
          [projectId, scanId, assetId, JSON.stringify({ relation: "MULTI_SOURCE_CORROBORATION", status: "OBSERVED", subject: `https://${rootDomain}/a.js`, related: ["dns", "crawler"], confidence: 0.6 })],
        );
      }
      await markAllSucceeded(db, scanId);

      const report = await buildReport(new Repository(db), scanId, { now: FROZEN() });
      expect(report).toBeTruthy();
      expect(report!.correlations.length).toBe(3);
      expect(report!.findingTotals.total).toBe(0);
      expect(report!.findings.length).toBe(0);
      // The core invariant: a report with zero findings is never COMPLETE_WITH_FINDINGS.
      expect(report!.reportStatus).toBe("COMPLETE_NO_FINDINGS");
      // Before the fix this rendered `COMPLETE_WITH_FINDINGS` with "0 candidate findings" and the
      // contradictory body text "This assessment is incomplete". Assert the rendered artifacts now
      // agree end to end.
      const html = renderReportHtml(report!);
      expect(html).toContain("Assessment complete — no candidate findings");
      expect(html).not.toContain("COMPLETE_WITH_FINDINGS");
      expect(html).not.toContain("candidate findings to review");
      const human = formatReport(report!, "human");
      expect(human).toContain("Status: COMPLETE_NO_FINDINGS");
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });

  it("a persisted secret candidate makes it COMPLETE_WITH_FINDINGS with a matching total", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const workspace = `rscf${rand}`;
    try {
      const { scanId, projectId } = await new ScanService(db).createScan({
        startUrl: `https://${rootDomain}/`,
        policy: ScopePolicySchema.parse(makePolicy(rootDomain)),
        workspaceName: workspace,
      });
      const asset = await db.query<{ id: string }>(
        "INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'URL',$2,$2) RETURNING id",
        [projectId, `https://${rootDomain}/a.js`],
      );
      const assetId = asset.rows[0]!.id;
      await db.query(
        `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
         VALUES ($1,$2,$3,'builtin-secret-scan','HIGH', now(),'secret-finding',$4::jsonb)`,
        [projectId, scanId, assetId, JSON.stringify({ ruleId: "aws-access-key-id", category: "CLOUD_CREDENTIAL", status: "HIGH_CONFIDENCE", confidence: 0.95, host: rootDomain, location: "1:3", redactedSnippet: "const s='[REDACTED]';" })],
      );
      await markAllSucceeded(db, scanId);

      const report = await buildReport(new Repository(db), scanId, { now: FROZEN() });
      expect(report!.findingTotals.total).toBe(1);
      expect(report!.reportStatus).toBe("COMPLETE_WITH_FINDINGS");
      // Status, headline and totals are internally consistent.
      expect(report!.findings.length).toBe(report!.findingTotals.total);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
