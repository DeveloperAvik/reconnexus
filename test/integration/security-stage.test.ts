import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDb, FakeRunner, Repository, ScanOrchestrator, ScanService, type DiscoveryRunner } from "@reconnexus/control-plane";
import { LocalArtifactStore } from "@reconnexus/evidence-contracts";
import { ScopePolicySchema, type DiscoveryJob, type DiscoveryResult } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";
import { Logger } from "@reconnexus/logging";

const config = loadConfig({ cwd: process.cwd() });
const log = new Logger({ level: "error", format: "json", sink: () => undefined });

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

function makeResult(job: DiscoveryJob, partial: Partial<DiscoveryResult>): DiscoveryResult {
  return {
    schemaVersion: 1,
    status: "SUCCEEDED",
    provider: job.provider,
    providerVersion: "test",
    execution: { argv: [job.provider], exitCode: 0, exitDescription: "", durationMs: 1, stdoutBytes: 1, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" },
    coverage: { attempted: 1, succeeded: 1, failed: 0, skipped: 0, unavailable: 0 },
    records: [],
    diagnostics: [],
    ...partial,
  };
}

function makePolicy(rootDomain: string): unknown {
  return {
    schemaVersion: 1,
    policyId: randomUUID(),
    projectId: randomUUID(),
    policyVersion: 1,
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "DNS", "ACTIVE_HTTP", "CRAWL", "JS_ANALYSIS", "API_DISCOVERY", "SECURITY_CHECKS"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

describe.skipIf(!available)("security metadata stage (06 & 10)", () => {
  it("categorizes URLs (stage 06) and persists security metadata (stage 10), idempotently", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const host = `app.${rootDomain}`;
    const origin = `https://${host}`;
    const workspace = `sec${rand}`;
    const sha = "f".repeat(64);

    const runner: DiscoveryRunner = new FakeRunner((job) => {
      if (job.kind === "SECURITY_META") {
        return makeResult(job, {
          records: [
            { type: "SECURITY_METADATA" as const, url: `${origin}/`, host, category: "HSTS", name: "strict-transport-security", status: "OBSERVED", observed: true, value: "", detail: { maxAge: 31536000, includeSubDomains: true, preload: false }, consistent: null, evidence: "HSTS header", evidenceType: "HEADER", provider: job.provider, source: "security-metadata" },
            { type: "SECURITY_METADATA" as const, url: `${origin}/`, host, category: "TLS", name: "certificate", status: "OBSERVED", observed: true, value: "", detail: { sha256: sha, validNow: true, hostnameMatch: true, daysToExpiry: 90 }, consistent: true, evidence: "TLS peer certificate", evidenceType: "TLS", provider: job.provider, source: "security-metadata" },
            { type: "SECURITY_METADATA" as const, url: `${origin}/`, host, category: "HEADER", name: "x-frame-options", status: "NOT_OBSERVED", observed: false, value: "", detail: { limitation: "header absent in this response only" }, consistent: null, evidence: "header not present", evidenceType: "HEADER", provider: job.provider, source: "security-metadata" },
          ],
        });
      }
      return makeResult(job, { records: [] });
    });

    try {
      const created = await new ScanService(db).createScan({ startUrl: `${origin}/`, policy: ScopePolicySchema.parse(makePolicy(rootDomain)), workspaceName: workspace });
      const { scanId, projectId } = created;

      // Stage 05 URL observation (for stage 06) and an HTTP observation (seed for stage 10).
      const urlAsset = await db.query<{ id: string }>("INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'URL',$2,$2) RETURNING id", [projectId, `${origin}/`]);
      await db.query(
        `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
         VALUES ($1,$2,$3,'builtin-crawler','MEDIUM', now(),'url',$4::jsonb)`,
        [projectId, scanId, urlAsset.rows[0]!.id, JSON.stringify({ method: "CRAWL", host, classifications: [{ category: "HTML_PAGE", confidence: 0.4, evidenceType: "PATH", evidence: "x" }], parameters: [] })],
      );
      const svc = await db.query<{ id: string }>("INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'SERVICE',$2,$2) RETURNING id", [projectId, origin]);
      await db.query(
        `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
         VALUES ($1,$2,$3,'builtin-http','HIGH', now(),'http',$4::jsonb)`,
        [projectId, scanId, svc.rows[0]!.id, JSON.stringify({ url: `${origin}/`, finalUrl: `${origin}/`, probeStatus: "OK" })],
      );

      const summary = await new ScanOrchestrator({ db, runner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config }).runScan(scanId);
      expect(summary.stages.find((s) => s.stage === "06-url-categorization")?.status).toBe("SUCCEEDED");
      expect(summary.stages.find((s) => s.stage === "10-security-checks")?.status).toBe("SUCCEEDED");

      const repo = new Repository(db);
      const coverage = await repo.listCoverage(scanId);
      const cat06 = coverage.find((c) => c.stage === "06-url-categorization");
      expect(cat06?.status).toBe("COLLECTED");
      expect(cat06?.expected).toBe(1);
      expect(cat06?.collected).toBe(1);

      const meta = await repo.listSecurityMetadata(scanId);
      expect(meta.length).toBe(3);
      expect(meta.some((m) => (m.data as { category: string }).category === "HSTS")).toBe(true);
      expect(meta.some((m) => (m.data as { status: string }).status === "NOT_OBSERVED")).toBe(true);

      // TLS metadata is correlated to a certificate asset.
      const certs = await repo.listAssets(projectId, ["CERTIFICATE"]);
      expect(certs.some((c) => c.value === sha)).toBe(true);
      const rel = await db.query<{ n: string }>("SELECT count(*)::text AS n FROM asset_relationships WHERE project_id=$1 AND relation='presents_certificate'", [projectId]);
      expect(Number(rel.rows[0]!.n)).toBeGreaterThan(0);

      // Idempotency.
      const before = await db.query<{ n: string }>("SELECT count(*)::text AS n FROM observations WHERE scan_id=$1 AND kind='security-metadata'", [scanId]);
      await new ScanOrchestrator({ db, runner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config }).runScan(scanId);
      const after = await db.query<{ n: string }>("SELECT count(*)::text AS n FROM observations WHERE scan_id=$1 AND kind='security-metadata'", [scanId]);
      expect(after.rows[0]!.n).toBe(before.rows[0]!.n);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
