import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDb, FakeRunner, ingestDiscoveryResult, ScanOrchestrator, ScanService, type DiscoveryRunner } from "@reconnexus/control-plane";
import { LocalArtifactStore } from "@reconnexus/evidence-contracts";
import { ScopePolicySchema, type DiscoveryResult } from "@reconnexus/contracts";
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

const emptyRunner: DiscoveryRunner = new FakeRunner((job) => ({ schemaVersion: 1, status: "SUCCEEDED", provider: job.provider, providerVersion: "test", execution: { argv: [], exitCode: 0, exitDescription: "", durationMs: 0, stdoutBytes: 0, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" }, coverage: { attempted: 0, succeeded: 0, failed: 0, skipped: 0, unavailable: 0 }, records: [], diagnostics: [] }) as DiscoveryResult);

function policy(rootDomain: string): unknown {
  return {
    schemaVersion: 1,
    policyId: randomUUID(),
    projectId: randomUUID(),
    policyVersion: 1,
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "DNS", "ACTIVE_HTTP", "CRAWL", "SECRET_SCAN", "SECURITY_CHECKS"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

describe("failure injection: database", () => {
  it("reports database unavailability honestly instead of a successful run", async () => {
    const bad = loadConfig({ cwd: process.cwd() });
    bad.database.url = "postgres://127.0.0.1:1/reconnexus_nope";
    const db = createDb(bad.database);
    const orchestrator = new ScanOrchestrator({ db, runner: emptyRunner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config });
    await expect(orchestrator.runScan(randomUUID())).rejects.toBeTruthy();
    await db.close().catch(() => undefined);
  });
});

describe.skipIf(!available)("failure injection: transactions and cancellation", () => {
  it("rolls back a failed ingest transaction with no partial rows", async () => {
    const db = createDb(config.database);
    const marker = `rollback-${Math.random().toString(36).slice(2, 10)}`;
    try {
      // A non-existent project id violates the FK; the whole transaction must roll back. The unique
      // marker makes the check deterministic even when other test files run in parallel.
      await expect(
        db.withTransaction((client) =>
          ingestDiscoveryResult(client, new LocalArtifactStore(config.artifacts.root), {
            projectId: randomUUID(),
            scanId: randomUUID(),
            rootDomain: "example.com",
            provider: marker,
            observedAt: new Date(),
            result: { schemaVersion: 1, status: "SUCCEEDED", provider: marker, providerVersion: "t", execution: { argv: [], exitCode: 0, exitDescription: "", durationMs: 0, stdoutBytes: 0, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" }, coverage: { attempted: 1, succeeded: 1, failed: 0, skipped: 0, unavailable: 0 }, records: [{ type: "HOST_OBSERVATION", host: `${marker}.example.com`, source: marker, provider: marker, status: "DISCOVERED", addresses: [], notes: "" }], diagnostics: [] },
          }),
        ),
      ).rejects.toBeTruthy();
      const after = await db.query<{ n: string }>("SELECT count(*)::text AS n FROM observations WHERE data::text LIKE $1 OR source LIKE $1", [`%${marker}%`]);
      expect(Number(after.rows[0]!.n)).toBe(0);
      const assets = await db.query<{ n: string }>("SELECT count(*)::text AS n FROM assets WHERE canonical_key LIKE $1", [`%${marker}%`]);
      expect(Number(assets.rows[0]!.n)).toBe(0);
    } finally {
      await db.query("DELETE FROM observations WHERE data::text LIKE $1 OR source LIKE $1", [`%${marker}%`]).catch(() => undefined);
      await db.close();
    }
  });

  it("cancellation prevents stage execution and never yields SUCCEEDED", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const workspace = `fi${rand}`;
    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${rootDomain}/`, policy: ScopePolicySchema.parse(policy(rootDomain)), workspaceName: workspace });
      const controller = new AbortController();
      controller.abort();
      let calls = 0;
      const runner: DiscoveryRunner = new FakeRunner((job) => {
        calls++;
        return { schemaVersion: 1, status: "SUCCEEDED", provider: job.provider, providerVersion: "t", execution: { argv: [], exitCode: 0, exitDescription: "", durationMs: 0, stdoutBytes: 0, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" }, coverage: { attempted: 0, succeeded: 0, failed: 0, skipped: 0, unavailable: 0 }, records: [], diagnostics: [] } as DiscoveryResult;
      });
      const summary = await new ScanOrchestrator({ db, runner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config, signal: controller.signal }).runScan(created.scanId);
      expect(calls).toBe(0);
      expect(summary.status).not.toBe("SUCCEEDED");
      // Only the pre-existing Stage 00 (recorded at scan creation) may remain SUCCEEDED.
      const succeededJobs = await db.query<{ job_key: string }>("SELECT job_key FROM jobs WHERE scan_id=$1 AND status='SUCCEEDED'", [created.scanId]);
      expect(succeededJobs.rows.map((r) => r.job_key)).toEqual(["00-input-authorization"]);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
