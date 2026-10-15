import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { compareScans, createDb, FakeRunner, Repository, ScanOrchestrator, ScanService, type DiscoveryRunner } from "@reconnexus/control-plane";
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

function policy(rootDomain: string): unknown {
  return {
    schemaVersion: 1,
    policyId: randomUUID(),
    projectId: randomUUID(),
    policyVersion: 1,
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "DNS"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 1, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

/** Emits one subdomain plus an A record for it with the given address. */
function runner(tag: string, dnsValue: string): DiscoveryRunner {
  return new FakeRunner((job) => {
    if (job.kind === "SUBDOMAINS") {
      return makeResult(job, { records: [{ type: "HOST_OBSERVATION" as const, host: tag, source: "passive", provider: job.provider, status: "DISCOVERED", addresses: [], notes: "" }] });
    }
    if (job.kind === "DNS") {
      const names = job.inputs.names ?? [];
      return makeResult(job, {
        records: names.map((n) => ({ type: "DNS_RECORD" as const, name: n, recordType: "A" as const, value: dnsValue, ttl: 60, status: "NOERROR", resolver: "test" })),
        coverage: { attempted: names.length, succeeded: names.length, failed: 0, skipped: 0, unavailable: 0 },
      });
    }
    return makeResult(job, {});
  });
}

describe.skipIf(!available)("changes command (integration)", () => {
  it("compares DNS and asset changes between two scans of the same project", async () => {
    const db = createDb(config.database);
    const repo = new Repository(db);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const workspace = `chg${rand}`;
    try {
      const service = new ScanService(db);
      const pol = ScopePolicySchema.parse(policy(rootDomain));
      const orch = (r: DiscoveryRunner): ScanOrchestrator => new ScanOrchestrator({ db, runner: r, store: new LocalArtifactStore(config.artifacts.root), logger: log, config });

      const host = `app.${rootDomain}`;
      const a = await service.createScan({ startUrl: `https://${rootDomain}/`, policy: pol, workspaceName: workspace });
      await orch(runner(host, "203.0.113.10")).runScan(a.scanId);
      const b = await service.createScan({ startUrl: `https://${rootDomain}/`, policy: pol, workspaceName: workspace });
      await orch(runner(host, "203.0.113.99")).runScan(b.scanId);

      const cmp = await compareScans(repo, a.scanId, b.scanId, { categories: ["dns", "assets"] });
      const dns = cmp.categories.find((c) => c.category === "dns")!;
      // The DNS stage must have run fully in both scans for a CHANGED verdict to be supported.
      expect(dns.coverage[0]!.comparable).toBe(true);
      expect(dns.totals.CHANGED).toBe(1);
      expect(dns.changes[0]!.changedFields).toContain("value");
      // Same subdomain observed in both → unchanged, not added/removed.
      const assets = cmp.categories.find((c) => c.category === "assets")!;
      expect(assets.totals.ADDED).toBe(0);
      expect(assets.totals.REMOVED).toBe(0);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
