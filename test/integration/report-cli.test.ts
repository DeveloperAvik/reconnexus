import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDb, FakeRunner, ScanOrchestrator, ScanService, type DiscoveryRunner } from "@reconnexus/control-plane";
import { LocalArtifactStore } from "@reconnexus/evidence-contracts";
import { ScopePolicySchema, ExitCode, type DiscoveryResult } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";
import { Logger } from "@reconnexus/logging";
import { loadContext } from "../../apps/cli/src/context.js";
import { reportCommand } from "../../apps/cli/src/commands/report.js";
import { makeEnvelope } from "../../apps/cli/src/output.js";
import { CliError } from "../../apps/cli/src/errors.js";

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

const emptyRunner: DiscoveryRunner = new FakeRunner((job) => ({ schemaVersion: 1, status: "SUCCEEDED", provider: job.provider, providerVersion: "test", execution: { argv: [], exitCode: 0, exitDescription: "", durationMs: 0, stdoutBytes: 0, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" }, coverage: { attempted: 0, succeeded: 0, failed: 0, skipped: 0, unavailable: 0 }, records: [], diagnostics: [] }) as DiscoveryResult);

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

describe.skipIf(!available)("report CLI", () => {
  it("distinguishes not-run, partial; supports formats; missing scan errors", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const workspace = `repcli${rand}`;
    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${rootDomain}/`, policy: ScopePolicySchema.parse(policy(rootDomain)), workspaceName: workspace });
      const { scanId } = created;

      // Not run yet.
      const notRun = await reportCommand(ctx, scanId, {});
      expect(notRun.exitCode).toBe(ExitCode.SUCCESS);
      expect((notRun.data as { reportStatus: string }).reportStatus).toBe("REPORTING_NOT_RUN");
      expect(notRun.render ? notRun.render() : "").toContain("not been run");

      // Run the pipeline (empty results) → reporting runs.
      await new ScanOrchestrator({ db, runner: emptyRunner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config, now: () => new Date("2026-01-01T00:00:00.000Z") }).runScan(scanId);

      const human = await reportCommand(ctx, scanId, {});
      expect((human.data as { reportStatus: string }).reportStatus).toBe("PARTIAL");
      expect(human.render ? human.render() : "").toContain("ReconNexus report");

      const json = await reportCommand(ctx, scanId, { format: "json" });
      expect(JSON.parse(json.render!().toString()).scanId).toBe(scanId);

      const jsonl = await reportCommand(ctx, scanId, { format: "jsonl" });
      expect(JSON.parse(jsonl.render!().toString().split("\n")[0]!).kind).toBe("summary");

      const csv = await reportCommand(ctx, scanId, { format: "csv" });
      expect(csv.render!().toString().split("\n")[0]).toBe("section,type,key,status,detail");

      const sarif = await reportCommand(ctx, scanId, { format: "sarif" });
      const sarifDoc = JSON.parse(sarif.render!().toString());
      expect(sarifDoc.version).toBe("2.1.0");
      expect(sarifDoc.runs[0].tool.driver.name).toBe("ReconNexus");

      const env = JSON.parse(JSON.stringify(makeEnvelope("report", json)));
      expect(env.ok).toBe(true);
      expect(env.exitCode).toBe(0);

      await expect(reportCommand(ctx, "00000000-0000-0000-0000-000000000000", {})).rejects.toBeInstanceOf(CliError);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
