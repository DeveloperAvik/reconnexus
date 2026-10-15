import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDb, FakeRunner, Repository, ScanOrchestrator, ScanService, type DiscoveryRunner } from "@reconnexus/control-plane";
import { LocalArtifactStore } from "@reconnexus/evidence-contracts";
import { ScopePolicySchema, type DiscoveryJob, type DiscoveryResult } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";
import { Logger } from "@reconnexus/logging";

/**
 * Regression: a provider that returns PARTIAL must be visible at the stage and scan level. In the
 * Dunya News report a stage showed builtin-http PARTIAL / builtin-static PARTIAL yet the job was
 * SUCCEEDED and the whole assessment was SUCCEEDED — a partial provider was masked by the
 * aggregate. Stage 02 uses two providers (subfinder, assetfinder) so the masking is reproducible.
 */
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
    providerVersion: "test-1.0",
    execution: { argv: [job.provider], exitCode: 0, exitDescription: "", durationMs: 1, stdoutBytes: 10, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" },
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
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "DNS", "ACTIVE_HTTP"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 1, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

describe.skipIf(!available)("provider-level partial results propagate to stage and scan", () => {
  it("marks the stage PARTIAL when one of two providers returns PARTIAL", async () => {
    const db = createDb(config.database);
    const repo = new Repository(db);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const workspace = `pp${rand}`;
    try {
      const runner: DiscoveryRunner = new FakeRunner((job) => {
        if (job.kind === "SUBDOMAINS") {
          if (job.provider === "assetfinder") {
            return makeResult(job, {
              status: "PARTIAL",
              coverage: { attempted: 2, succeeded: 1, failed: 1, skipped: 0, unavailable: 0 },
              records: [{ type: "HOST_OBSERVATION" as const, host: `p.${rootDomain}`, source: "passive", provider: job.provider, status: "DISCOVERED", addresses: [], notes: "" }],
              diagnostics: ["partial: one source timed out"],
            });
          }
          return makeResult(job, { records: [{ type: "HOST_OBSERVATION" as const, host: `a.${rootDomain}`, source: "passive", provider: job.provider, status: "DISCOVERED", addresses: [], notes: "" }] });
        }
        return makeResult(job, {});
      });

      const { scanId } = await new ScanService(db).createScan({
        startUrl: `https://${rootDomain}/`,
        policy: ScopePolicySchema.parse(makePolicy(rootDomain)),
        workspaceName: workspace,
      });
      const summary = await new ScanOrchestrator({ db, runner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config }).runScan(scanId);

      const stage = summary.stages.find((s) => s.stage === "02-subdomain-discovery");
      expect(stage?.status).toBe("PARTIAL");
      // The sibling success does not mask the partial provider.
      const outcomes = await repo.listProviderOutcomes(scanId);
      expect(outcomes.find((o) => o.provider === "subfinder")!.outcome).toBe("SUCCEEDED");
      expect(outcomes.find((o) => o.provider === "assetfinder")!.outcome).toBe("PARTIAL");

      const coverage = await repo.listCoverage(scanId);
      expect(coverage.find((c) => c.stage === "02-subdomain-discovery")!.status).toBe("PARTIAL");
      // The scan as a whole is not reported SUCCEEDED.
      expect(summary.status).not.toBe("SUCCEEDED");
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
