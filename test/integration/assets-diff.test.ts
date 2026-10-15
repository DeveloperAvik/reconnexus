import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDb, FakeRunner, ScanOrchestrator, ScanService, type DiscoveryRunner } from "@reconnexus/control-plane";
import { LocalArtifactStore } from "@reconnexus/evidence-contracts";
import { ScopePolicySchema, ExitCode, type DiscoveryJob, type DiscoveryResult } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";
import { Logger } from "@reconnexus/logging";
import { loadContext } from "../../apps/cli/src/context.js";
import { assetsDiffCommand } from "../../apps/cli/src/commands/assets.js";
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
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "DNS", "ACTIVE_HTTP"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 1, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

/** A runner that reports a fixed set of subdomains for the SUBDOMAINS stage and nothing else. */
function subdomainRunner(hosts: string[]): DiscoveryRunner {
  return new FakeRunner((job) => {
    if (job.kind === "SUBDOMAINS") {
      return makeResult(job, {
        records: hosts.map((host) => ({ type: "HOST_OBSERVATION" as const, host, source: "passive", provider: job.provider, status: "DISCOVERED", addresses: [], notes: "" })),
        coverage: { attempted: 1, succeeded: 1, failed: 0, skipped: 0, unavailable: 0 },
      });
    }
    return makeResult(job, {});
  });
}

describe.skipIf(!available)("assets diff", () => {
  it("reports added, removed and unchanged observed assets deterministically", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const workspace = `adiff${rand}`;
    try {
      const service = new ScanService(db);
      const orchestrator = (runner: DiscoveryRunner): ScanOrchestrator =>
        new ScanOrchestrator({ db, runner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config });

      const common = `keep.${rootDomain}`;
      // Both scans must share the project's policy identity (same policyId/version) to be scans of
      // the same project; a fresh random policyId per scan is rejected as a version conflict.
      const pol = ScopePolicySchema.parse(policy(rootDomain));
      const first = await service.createScan({ startUrl: `https://${rootDomain}/`, policy: pol, workspaceName: workspace });
      await orchestrator(subdomainRunner([common, `old.${rootDomain}`])).runScan(first.scanId);

      const second = await service.createScan({ startUrl: `https://${rootDomain}/`, policy: pol, workspaceName: workspace });
      await orchestrator(subdomainRunner([common, `new.${rootDomain}`])).runScan(second.scanId);

      const diff = await assetsDiffCommand(ctx, first.scanId, second.scanId, { type: "SUBDOMAIN,HOST" });
      expect(diff.exitCode).toBe(ExitCode.SUCCESS);
      const data = diff.data as {
        counts: { added: number; removed: number; unchanged: number };
        added: Array<{ value: string }>;
        removed: Array<{ value: string }>;
      };
      const addedValues = data.added.map((a) => a.value);
      const removedValues = data.removed.map((a) => a.value);
      expect(addedValues).toContain(`new.${rootDomain}`);
      expect(removedValues).toContain(`old.${rootDomain}`);
      expect(data.counts.unchanged).toBeGreaterThan(0);
      // Deterministic ordering.
      expect(data.added.map((a) => a.value)).toEqual([...data.added.map((a) => a.value)].sort());

      const human = diff.render!();
      expect(human).toContain("Asset changes");
      expect(human).toContain("added");
      expect(human).toContain(`new.${rootDomain}`);
      expect(human).toContain(`old.${rootDomain}`);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });

  it("rejects a comparison across projects and a missing scan", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const workspace = `adiff2${rand}`;
    try {
      const service = new ScanService(db);
      const a = await service.createScan({ startUrl: `https://a-${rand}.example.net/`, policy: ScopePolicySchema.parse(policy(`a-${rand}.example.net`)), workspaceName: `${workspace}a` });
      const b = await service.createScan({ startUrl: `https://b-${rand}.example.net/`, policy: ScopePolicySchema.parse(policy(`b-${rand}.example.net`)), workspaceName: `${workspace}b` });
      await expect(assetsDiffCommand(ctx, a.scanId, b.scanId, {})).rejects.toBeInstanceOf(CliError);
      await expect(assetsDiffCommand(ctx, a.scanId, "00000000-0000-0000-0000-000000000000", {})).rejects.toBeInstanceOf(CliError);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain LIKE $1", [`%-${rand}.example.net`]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name LIKE $1", [`${workspace}%`]).catch(() => undefined);
      await db.close();
    }
  });
});
