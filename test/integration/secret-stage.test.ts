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

// Synthetic, non-functional fixture values. They are never written to the database.
const RAW_MARKER = "AKIAABCDEFGHIJKLMNOP";
const RAW_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----";

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
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "DNS", "ACTIVE_HTTP", "CRAWL", "JS_ANALYSIS", "API_DISCOVERY", "SECRET_SCAN", "SECURITY_CHECKS"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

describe.skipIf(!available)("secret detection stage (09)", () => {
  it("persists redacted findings, is idempotent, and never stores a raw secret", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const host = `app.${rootDomain}`;
    const jsUrl = `https://${host}/app.js`;
    const workspace = `sec9${rand}`;

    const runner: DiscoveryRunner = new FakeRunner((job) => {
      if (job.kind === "SECRET_SCAN") {
        return makeResult(job, {
          records: [
            { type: "SECRET_CANDIDATE" as const, ruleId: "aws-access-key-id", category: "CLOUD_CREDENTIAL", status: "HIGH_CONFIDENCE", confidence: 0.95, artifactUrl: jsUrl, host, location: "3:12", redactedSnippet: "const a='[REDACTED]';", fingerprint: "abc123", occurrences: 2, rationale: "matched rule", suppressionReason: "", provider: job.provider, source: "secret-scan" },
            { type: "SECRET_CANDIDATE" as const, ruleId: "private-key", category: "PRIVATE_KEY", status: "HIGH_CONFIDENCE", confidence: 0.95, artifactUrl: jsUrl, host, location: "7:1", redactedSnippet: "[REDACTED:private-key]", fingerprint: "def456", occurrences: 1, rationale: "matched rule", suppressionReason: "", provider: job.provider, source: "secret-scan" },
            { type: "SECRET_SCAN_ARTIFACT" as const, artifactUrl: jsUrl, host, status: "ANALYZED", findingsCount: 2, rawBytes: 200, hmacKeyed: true, error: "", provider: job.provider, source: "secret-scan" },
          ],
        });
      }
      return makeResult(job, { records: [] });
    });

    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${host}/`, policy: ScopePolicySchema.parse(makePolicy(rootDomain)), workspaceName: workspace });
      const { scanId, projectId } = created;

      // Seed a persisted JS artifact so stage 09 has an eligible artifact.
      const a = await db.query<{ id: string }>("INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'JS_ARTIFACT',$2,$2) RETURNING id", [projectId, jsUrl]);
      await db.query(
        `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
         VALUES ($1,$2,$3,'builtin-js','MEDIUM', now(),'js-artifact',$4::jsonb)`,
        [projectId, scanId, a.rows[0]!.id, JSON.stringify({ contentHash: "c".repeat(64), sizeBytes: 10, status: "RETRIEVED" })],
      );

      const summary = await new ScanOrchestrator({ db, runner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config }).runScan(scanId);
      expect(summary.stages.find((s) => s.stage === "09-secret-detection")?.status).toBe("SUCCEEDED");

      const repo = new Repository(db);
      const findings = await repo.listSecretFindings(scanId);
      expect(findings.length).toBe(2);
      expect(findings.every((f) => (f.data as { redactedSnippet: string }).redactedSnippet.includes("[REDACTED"))).toBe(true);
      expect(findings.some((f) => (f.data as { fingerprint: string }).fingerprint === "abc123")).toBe(true);
      const artifacts = await repo.listSecretScanArtifacts(scanId);
      expect(artifacts.length).toBe(1);

      const coverage = (await repo.listCoverage(scanId)).find((c) => c.stage === "09-secret-detection");
      expect(coverage?.status).toBe("COLLECTED");

      // RELEASE GATE (TS side): no raw secret value anywhere in the database.
      for (const needle of [RAW_MARKER, RAW_PRIVATE_KEY, "S3cr3tP4ss"]) {
        const hits = await db.query<{ n: string }>(
          `SELECT (
             (SELECT count(*) FROM observations WHERE data::text LIKE $1) +
             (SELECT count(*) FROM assets WHERE canonical_key LIKE $1 OR value LIKE $1) +
             (SELECT count(*) FROM provider_executions WHERE stderr_excerpt LIKE $1 OR error LIKE $1) +
             (SELECT count(*) FROM audit_events WHERE detail::text LIKE $1) +
             (SELECT count(*) FROM evidence_artifacts WHERE storage_uri LIKE $1)
           )::text AS n`,
          [`%${needle}%`],
        );
        expect(Number(hits.rows[0]!.n), `raw value ${needle} must not be persisted`).toBe(0);
      }

      // Idempotency.
      const before = await db.query<{ n: string }>("SELECT count(*)::text AS n FROM observations WHERE scan_id=$1 AND kind='secret-finding'", [scanId]);
      await new ScanOrchestrator({ db, runner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config }).runScan(scanId);
      const after = await db.query<{ n: string }>("SELECT count(*)::text AS n FROM observations WHERE scan_id=$1 AND kind='secret-finding'", [scanId]);
      expect(after.rows[0]!.n).toBe(before.rows[0]!.n);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
