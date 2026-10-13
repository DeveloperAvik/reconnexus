import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { buildReport, createDb, FakeRunner, Repository, ReportRedactionError, ScanOrchestrator, ScanService, type DiscoveryRunner } from "@reconnexus/control-plane";
import { LocalArtifactStore } from "@reconnexus/evidence-contracts";
import { ReportSchema, ScopePolicySchema, type DiscoveryResult } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";
import { Logger } from "@reconnexus/logging";

const config = loadConfig({ cwd: process.cwd() });
const log = new Logger({ level: "error", format: "json", sink: () => undefined });
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

const RAW_MARKER = "AKIAZZZZZZZZZZZZZZZZ";

const emptyRunner: DiscoveryRunner = new FakeRunner((job) => ({ schemaVersion: 1, status: "SUCCEEDED", provider: job.provider, providerVersion: "test", execution: { argv: [], exitCode: 0, exitDescription: "", durationMs: 0, stdoutBytes: 0, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" }, coverage: { attempted: 0, succeeded: 0, failed: 0, skipped: 0, unavailable: 0 }, records: [], diagnostics: [] }) as DiscoveryResult);

function makePolicy(rootDomain: string): unknown {
  return {
    schemaVersion: 1,
    policyId: randomUUID(),
    projectId: randomUUID(),
    policyVersion: 1,
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "DNS", "ACTIVE_HTTP", "SECRET_SCAN", "SECURITY_CHECKS"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

function orch(db: ReturnType<typeof createDb>, runner: DiscoveryRunner, redactor?: (v: unknown) => unknown) {
  return new ScanOrchestrator({ db, runner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config, now: FROZEN, ...(redactor ? { redactor } : {}) });
}

describe.skipIf(!available)("Stage 12 reporting", () => {
  it("generates a redacted report, is idempotent/deterministic, and reflects persistence", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const host = `app.${rootDomain}`;
    const workspace = `rep${rand}`;
    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${host}/`, policy: ScopePolicySchema.parse(makePolicy(rootDomain)), workspaceName: workspace });
      const { scanId, projectId } = created;

      const mkAsset = async (key: string): Promise<string> => {
        const r = await db.query<{ id: string }>("INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'URL',$2,$2) RETURNING id", [projectId, key]);
        return r.rows[0]!.id;
      };
      const obs = (assetId: string, kind: string, data: Record<string, unknown>): Promise<unknown> =>
        db.query(`INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data) VALUES ($1,$2,$3,'builtin-secret-scan','HIGH', now(),$4,$5::jsonb)`, [projectId, scanId, assetId, kind, JSON.stringify(data)]);
      const a = `https://${host}/a.js`;
      const b = `https://${host}/b.js`;
      const aid = await mkAsset(a);
      const bid = await mkAsset(b);
      await obs(aid, "secret-finding", { ruleId: "aws-access-key-id", category: "CLOUD_CREDENTIAL", status: "HIGH_CONFIDENCE", confidence: 0.95, fingerprint: "FP-SHARED", host, location: "1:3", redactedSnippet: `const s='[REDACTED]';` });
      await obs(bid, "secret-finding", { ruleId: "aws-access-key-id", category: "CLOUD_CREDENTIAL", status: "HIGH_CONFIDENCE", confidence: 0.95, fingerprint: "FP-SHARED", host, location: "2:3", redactedSnippet: `const t='[REDACTED]';` });
      await obs(aid, "secret-scan-artifact", { hmacKeyed: true, status: "ANALYZED" });
      await obs(bid, "secret-scan-artifact", { hmacKeyed: true, status: "ANALYZED" });

      // Before running, reporting has not run.
      const repo = new Repository(db);
      const before = await buildReport(repo, scanId, { now: FROZEN() });
      expect(before?.reportStatus).toBe("REPORTING_NOT_RUN");

      const summary = await orch(db, emptyRunner).runScan(scanId);
      expect(summary.stages.find((s) => s.stage === "12-reporting")?.status).toBe("SUCCEEDED");

      const reports = await db.query<{ data: unknown }>("SELECT data FROM observations WHERE scan_id=$1 AND kind='report'", [scanId]);
      expect(reports.rowCount).toBe(1);
      const stored = ReportSchema.parse(reports.rows[0]!.data);
      expect(stored.reportStatus).toBe("PARTIAL"); // scan is partial (skipped stages)
      expect(stored.secretFindings.length).toBe(2);
      expect(stored.correlations.length).toBe(1);
      expect(stored.correlations[0]!.correlationGroup).toMatch(/^[0-9a-f]{16}$/);

      // Redaction regression: no raw marker, no fingerprint (only opaque group).
      const blob = JSON.stringify(stored);
      expect(blob).not.toContain(RAW_MARKER);
      expect(blob).not.toContain("FP-SHARED");
      expect(blob).toContain("[REDACTED");

      // Idempotency + determinism (frozen clock).
      await orch(db, emptyRunner).runScan(scanId);
      const reports2 = await db.query<{ data: unknown }>("SELECT data FROM observations WHERE scan_id=$1 AND kind='report'", [scanId]);
      expect(reports2.rowCount).toBe(1);
      // Normalize through the schema so key ordering does not affect the comparison.
      expect(JSON.stringify(ReportSchema.parse(reports2.rows[0]!.data))).toBe(JSON.stringify(stored));
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });

  it("fails closed on redaction failure: no report persisted, coverage MISSING, REPORTING_FAILED", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const workspace = `repf${rand}`;
    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${rootDomain}/`, policy: ScopePolicySchema.parse(makePolicy(rootDomain)), workspaceName: workspace });
      const { scanId } = created;
      const summary = await orch(db, emptyRunner, () => {
        throw new Error("redactor unavailable");
      }).runScan(scanId);
      expect(summary.stages.find((s) => s.stage === "12-reporting")?.status).toBe("FAILED");

      const reports = await db.query<{ n: string }>("SELECT count(*)::text AS n FROM observations WHERE scan_id=$1 AND kind='report'", [scanId]);
      expect(Number(reports.rows[0]!.n)).toBe(0);
      const cov = await db.query<{ status: string }>("SELECT status FROM coverage_records WHERE scan_id=$1 AND stage='12-reporting'", [scanId]);
      expect(cov.rows[0]?.status).toBe("MISSING");

      const repo = new Repository(db);
      const report = await buildReport(repo, scanId, { now: FROZEN() });
      expect(report?.reportStatus).toBe("REPORTING_FAILED");
      void ReportRedactionError;
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
