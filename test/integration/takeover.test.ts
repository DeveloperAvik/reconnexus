import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDb, FakeRunner, Repository, ScanOrchestrator, ScanService, type DiscoveryRunner } from "@reconnexus/control-plane";
import { LocalArtifactStore } from "@reconnexus/evidence-contracts";
import { ScopePolicySchema, ExitCode, type DiscoveryJob, type DiscoveryResult } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";
import { Logger } from "@reconnexus/logging";
import { loadContext } from "../../apps/cli/src/context.js";
import { takeoverCommand } from "../../apps/cli/src/commands/takeover.js";
import { makeEnvelope } from "../../apps/cli/src/output.js";

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

function policy(rootDomain: string): unknown {
  return {
    schemaVersion: 1,
    policyId: randomUUID(),
    projectId: randomUUID(),
    policyVersion: 1,
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "DNS", "ACTIVE_HTTP", "TAKEOVER_CHECK"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

describe.skipIf(!available)("subdomain-takeover stage (13)", () => {
  it("runs the takeover stage, persists candidates, and includes them in the report", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const sub = `blog.${rootDomain}`;
    const workspace = `tko${rand}`;

    const runner: DiscoveryRunner = new FakeRunner((job) => {
      if (job.kind === "TAKEOVER") {
        return makeResult(job, {
          records: [
            { type: "TAKEOVER_CANDIDATE" as const, host: sub, cname: "user.github.io", service: "GitHub Pages", status: "SUSPECTED", confidence: 0.8, httpStatus: 404, evidence: "CNAME -> user.github.io; HTTP 404; unmarked", evidenceType: "UNCLAIMED_MARKER", provider: job.provider, source: "takeover" },
          ],
        });
      }
      return makeResult(job, { records: [] });
    });

    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${rootDomain}/`, policy: ScopePolicySchema.parse(policy(rootDomain)), workspaceName: workspace });
      const { scanId, projectId } = created;
      await db.query("INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'SUBDOMAIN',$2,$2) ON CONFLICT DO NOTHING", [projectId, sub]);

      const summary = await new ScanOrchestrator({ db, runner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config }).runScan(scanId);
      const stage = summary.stages.find((s) => s.stage === "13-subdomain-takeover");
      expect(stage?.status).toBe("SUCCEEDED");
      // Reporting must run after takeover (DAG ordering) and succeed.
      expect(summary.stages.find((s) => s.stage === "12-reporting")?.status).toBe("SUCCEEDED");

      const repo = new Repository(db);
      const candidates = await repo.listTakeoverCandidates(scanId);
      expect(candidates.length).toBe(1);
      expect((candidates[0]!.data as { service: string }).service).toBe("GitHub Pages");

      const report = await db.query<{ data: { takeoverCandidates: unknown[] } }>("SELECT data FROM observations WHERE scan_id=$1 AND kind='report'", [scanId]);
      expect(report.rows[0]!.data.takeoverCandidates.length).toBe(1);

      // CLI listing + filters.
      const all = await takeoverCommand(ctx, scanId, {});
      expect(all.exitCode).toBe(ExitCode.SUCCESS);
      expect((all.data as { total: number; actionable: number }).actionable).toBe(1);
      const byService = await takeoverCommand(ctx, scanId, { service: "github" });
      expect((byService.data as { total: number }).total).toBe(1);
      const none = await takeoverCommand(ctx, scanId, { status: "NOT_VULNERABLE" });
      expect((none.data as { total: number }).total).toBe(0);
      const env = JSON.parse(JSON.stringify(makeEnvelope("takeover", all)));
      expect(env.ok).toBe(true);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
