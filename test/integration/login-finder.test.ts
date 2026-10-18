import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDb, FakeRunner, Repository, ScanOrchestrator, ScanService, type DiscoveryRunner } from "@reconnexus/control-plane";
import { LocalArtifactStore } from "@reconnexus/evidence-contracts";
import { ExitCode, ScopePolicySchema, type DiscoveryJob, type DiscoveryResult } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";
import { Logger } from "@reconnexus/logging";
import { loadContext } from "../../apps/cli/src/context.js";
import { adminCommand, cpanelCommand } from "../../apps/cli/src/commands/finder.js";

const config = loadConfig({ cwd: process.cwd() });
const ctx = loadContext({});
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

function makeResult(job: DiscoveryJob, records: DiscoveryResult["records"] = []): DiscoveryResult {
  return {
    schemaVersion: 1,
    status: "SUCCEEDED",
    provider: job.provider,
    providerVersion: "test",
    execution: { argv: [job.provider], exitCode: 0, exitDescription: "", durationMs: 1, stdoutBytes: 1, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" },
    coverage: { attempted: records.length, succeeded: records.length, failed: 0, skipped: 0, unavailable: 0 },
    records,
    diagnostics: [],
  };
}

function policy(rootDomain: string): unknown {
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

describe.skipIf(!available)("login finder stage (14)", () => {
  it("runs the finder, persists admin/cPanel interfaces, and exposes both CLI commands", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const host = `www.${rootDomain}`;
    const workspace = `lf${rand}`;

    const runner: DiscoveryRunner = new FakeRunner((job) => {
      if (job.kind === "LOGIN_FINDER") {
        return makeResult(job, [
          {
            type: "LOGIN_INTERFACE" as const,
            url: `https://${host}/admin/login`,
            finalUrl: `https://${host}/admin/login`,
            host,
            kind: "ADMIN" as const,
            status: "DETECTED" as const,
            confidence: 0.85,
            httpStatus: 200,
            title: "Admin Login",
            evidence: "HTTP 200; password form present",
            evidenceType: "LOGIN_FORM",
            provider: job.provider,
            source: "login-finder",
          },
          {
            type: "LOGIN_INTERFACE" as const,
            url: `https://${host}:2083/`,
            finalUrl: `https://${host}:2083/`,
            host,
            kind: "CPANEL" as const,
            status: "DETECTED" as const,
            confidence: 0.9,
            httpStatus: 200,
            title: "cPanel Login",
            evidence: "HTTP 200; control-panel title",
            evidenceType: "CPANEL_TITLE",
            provider: job.provider,
            source: "login-finder",
          },
        ]);
      }
      return makeResult(job);
    });

    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${rootDomain}/`, policy: ScopePolicySchema.parse(policy(rootDomain)), workspaceName: workspace });
      const { scanId, projectId } = created;

      // Seed an HTTP observation so the stage has an origin to probe.
      const hostAsset = await db.query<{ id: string }>(
        "INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'HOST',$2,$2) ON CONFLICT (project_id,type,canonical_key) DO UPDATE SET value=EXCLUDED.value RETURNING id",
        [projectId, host],
      );
      await db.query(
        `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
         VALUES ($1,$2,$3,'http','HIGH',now(),'http',$4)`,
        [projectId, scanId, hostAsset.rows[0]!.id, JSON.stringify({ url: `https://${host}/`, finalUrl: `https://${host}/`, probeStatus: "OK", statusCode: 200 })],
      );

      const summary = await new ScanOrchestrator({ db, runner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config }).runScan(scanId);
      expect(summary.stages.find((s) => s.stage === "14-login-finder")?.status).toBe("SUCCEEDED");

      const repo = new Repository(db);
      const records = await repo.listLoginInterfaces(scanId);
      expect(records.length).toBe(2);

      const admin = await adminCommand(ctx, scanId, {});
      expect(admin.exitCode).toBe(ExitCode.SUCCESS);
      expect((admin.data as { total: number; detected: number }).total).toBe(1);
      expect((admin.data as { total: number; detected: number }).detected).toBe(1);

      const cpanel = await cpanelCommand(ctx, scanId, {});
      expect(cpanel.exitCode).toBe(ExitCode.SUCCESS);
      expect((cpanel.data as { total: number }).total).toBe(1);

      const filtered = await adminCommand(ctx, scanId, { status: "POSSIBLE" });
      expect((filtered.data as { total: number }).total).toBe(0);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
