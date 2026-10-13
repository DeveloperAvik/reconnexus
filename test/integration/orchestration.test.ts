import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createDb,
  FakeRunner,
  Repository,
  ScanOrchestrator,
  ScanService,
  type DiscoveryRunner,
} from "@reconnexus/control-plane";
import { LocalArtifactStore } from "@reconnexus/evidence-contracts";
import { ScopePolicySchema, type DiscoveryJob, type DiscoveryResult } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";
import { Logger } from "@reconnexus/logging";

const config = loadConfig({ cwd: process.cwd() });

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
    authorization: {
      reference: "TEST-AUTH",
      authorizedBy: "test",
      validFrom: "2020-01-01T00:00:00.000Z",
      validUntil: "2999-01-01T00:00:00.000Z",
      capabilities: ["PASSIVE", "DNS", "ACTIVE_HTTP"],
    },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 1, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

async function countAssets(db: ReturnType<typeof createDb>, projectId: string): Promise<number> {
  const r = await db.query<{ n: string }>("SELECT count(*)::text AS n FROM assets WHERE project_id=$1", [projectId]);
  return Number(r.rows[0]!.n);
}

describe.skipIf(!available)("scan orchestration", () => {
  it("runs implemented stages, persists results, reports coverage, and is idempotent", async () => {
    const db = createDb(config.database);
    const repo = new Repository(db);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const workspace = `orch-${rand}`;
    const seenJobs: DiscoveryJob[] = [];

    const runner: DiscoveryRunner = new FakeRunner((job) => {
      seenJobs.push(job);
      if (job.kind === "SUBDOMAINS") {
        const records = [
          { type: "HOST_OBSERVATION" as const, host: `a.${rootDomain}`, source: "passive", provider: job.provider, status: "DISCOVERED", addresses: [], notes: "" },
          { type: "HOST_OBSERVATION" as const, host: `b.${rootDomain}`, source: "passive", provider: job.provider, status: "DISCOVERED", addresses: [], notes: "" },
          { type: "HOST_OBSERVATION" as const, host: "out-of-scope.example.org", source: "passive", provider: job.provider, status: "DISCOVERED", addresses: [], notes: "" },
        ];
        return makeResult(job, { records, coverage: { attempted: 1, succeeded: 1, failed: 0, skipped: 0, unavailable: 0 } });
      }
      if (job.kind === "DNS") {
        const names = job.inputs.names ?? [];
        const records = names.flatMap((n, i) => [
          { type: "DNS_RECORD" as const, name: n, recordType: "A" as const, value: `93.184.216.${i + 1}`, ttl: 60, status: "NOERROR", resolver: "test" },
          { type: "HOST_OBSERVATION" as const, host: n, source: "dns", provider: job.provider, status: "RESOLVED", addresses: [`93.184.216.${i + 1}`], notes: "" },
        ]);
        return makeResult(job, { records, coverage: { attempted: names.length, succeeded: names.length, failed: 0, skipped: 0, unavailable: 0 } });
      }
      // IP_METADATA
      const addrs = job.inputs.addresses ?? [];
      const records = addrs.map((a, i) => ({
        type: "IP_METADATA" as const,
        ip: a.ip,
        prefix: `93.184.216.0/24`,
        asn: 64500 + i,
        asnOrg: "Test Network",
        networkName: "TESTNET",
        country: "ZZ",
        source: "rdap",
        confidence: 0.8,
        limitations: [],
      }));
      return makeResult(job, { records, coverage: { attempted: addrs.length, succeeded: addrs.length, failed: 0, skipped: 0, unavailable: 0 } });
    });

    try {
      const created = await new ScanService(db).createScan({
        startUrl: `https://${rootDomain}/`,
        policy: ScopePolicySchema.parse(makePolicy(rootDomain)),
        workspaceName: workspace,
      });
      const scanId = created.scanId;
      const projectId = created.projectId;

      const orchestrator = new ScanOrchestrator({
        db,
        runner,
        store: new LocalArtifactStore(config.artifacts.root),
        logger: new Logger({ level: "error", format: "json", sink: () => undefined }),
        config,
      });
      const summary = await orchestrator.runScan(scanId);

      expect(summary.status).toBe("PARTIAL"); // stages 04-12 are skipped in Phase 2
      expect(summary.assetsCreated).toBeGreaterThan(0);

      // DNS stage must only ever receive in-scope names.
      const dnsJob = seenJobs.find((j) => j.kind === "DNS");
      expect(dnsJob).toBeTruthy();
      for (const n of dnsJob!.inputs.names ?? []) {
        expect(n === rootDomain || n.endsWith(`.${rootDomain}`)).toBe(true);
      }

      const assets = await repo.listAssets(projectId, ["SUBDOMAIN", "HOST", "IP", "CIDR", "ASN"]);
      const values = assets.map((a) => a.value);
      expect(values).toContain(`a.${rootDomain}`);
      expect(values).toContain(`b.${rootDomain}`);
      expect(values).toContain("93.184.216.1");
      // Discovered but out-of-scope host is recorded as an asset, never resolved.
      expect(values).toContain("out-of-scope.example.org");

      const coverage = await repo.listCoverage(scanId);
      expect(coverage.length).toBeGreaterThan(0);
      const outcomes = await repo.listProviderOutcomes(scanId);
      expect(outcomes.some((o) => o.provider === "subfinder" && o.outcome === "SUCCEEDED")).toBe(true);

      // Idempotency: a second run must not duplicate canonical assets.
      const before = await countAssets(db, projectId);
      const second = await new ScanOrchestrator({
        db,
        runner,
        store: new LocalArtifactStore(config.artifacts.root),
        logger: new Logger({ level: "error", format: "json", sink: () => undefined }),
        config,
      }).runScan(scanId);
      const after = await countAssets(db, projectId);
      expect(after).toBe(before);
      expect(second.assetsCreated).toBe(0);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });

  it("surfaces a provider failure as PARTIAL, not empty success", async () => {
    const db = createDb(config.database);
    const repo = new Repository(db);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const workspace = `orchf-${rand}`;

    const runner: DiscoveryRunner = new FakeRunner((job) => {
      if (job.provider === "subfinder") {
        return makeResult(job, { status: "FAILED", coverage: { attempted: 1, succeeded: 0, failed: 1, skipped: 0, unavailable: 0 }, diagnostics: ["simulated failure"] });
      }
      if (job.kind === "SUBDOMAINS") {
        const records = [{ type: "HOST_OBSERVATION" as const, host: `a.${rootDomain}`, source: "passive", provider: job.provider, status: "DISCOVERED", addresses: [], notes: "" }];
        return makeResult(job, { records });
      }
      return makeResult(job, {});
    });

    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${rootDomain}/`, policy: ScopePolicySchema.parse(makePolicy(rootDomain)), workspaceName: workspace });
      const scanId = created.scanId;
      const summary = await new ScanOrchestrator({
        db,
        runner,
        store: new LocalArtifactStore(config.artifacts.root),
        logger: new Logger({ level: "error", format: "json", sink: () => undefined }),
        config,
        maxAttempts: 1,
      }).runScan(scanId);
      expect(summary.status).toBe("PARTIAL");
      const outcomes = await repo.listProviderOutcomes(scanId);
      expect(outcomes.find((o) => o.provider === "subfinder")!.outcome).toBe("FAILED");
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });

  it("retries a retryable stage failure and then succeeds", async () => {
    const db = createDb(config.database);
    const repo = new Repository(db);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const workspace = `orchr-${rand}`;
    let subfinderCalls = 0;

    const runner: DiscoveryRunner = new FakeRunner((job) => {
      if (job.kind === "SUBDOMAINS") {
        return makeResult(job, { records: [{ type: "HOST_OBSERVATION" as const, host: `a.${rootDomain}`, source: "passive", provider: job.provider, status: "DISCOVERED", addresses: [], notes: "" }] });
      }
      if (job.provider === "builtin-dns") {
        subfinderCalls++;
        if (subfinderCalls === 1) {
          return makeResult(job, { status: "FAILED", coverage: { attempted: 1, succeeded: 0, failed: 1, skipped: 0, unavailable: 0 }, diagnostics: ["transient"] });
        }
        const names = job.inputs.names ?? [];
        return makeResult(job, { records: names.map((n) => ({ type: "HOST_OBSERVATION" as const, host: n, source: "dns", provider: job.provider, status: "RESOLVED", addresses: ["93.184.216.34"], notes: "" })) });
      }
      return makeResult(job, {});
    });

    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${rootDomain}/`, policy: ScopePolicySchema.parse(makePolicy(rootDomain)), workspaceName: workspace });
      const scanId = created.scanId;
      await new ScanOrchestrator({
        db,
        runner,
        store: new LocalArtifactStore(config.artifacts.root),
        logger: new Logger({ level: "error", format: "json", sink: () => undefined }),
        config,
        maxAttempts: 3,
        sleep: () => Promise.resolve(),
      }).runScan(scanId);
      expect(subfinderCalls).toBeGreaterThanOrEqual(2);
      const outcomes = await repo.listProviderOutcomes(scanId);
      expect(outcomes.find((o) => o.provider === "subfinder")!.outcome).toBe("SUCCEEDED");
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });

  it("does not run a cancelled scan", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const workspace = `orchc-${rand}`;
    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${rootDomain}/`, policy: ScopePolicySchema.parse(makePolicy(rootDomain)), workspaceName: workspace });
      const scanId = created.scanId;
      await new Repository(db).updateScanStatus(scanId, "CANCELLED");
      let called = 0;
      const runner = new FakeRunner((job) => {
        called++;
        return makeResult(job, {});
      });
      const summary = await new ScanOrchestrator({
        db,
        runner,
        store: new LocalArtifactStore(config.artifacts.root),
        logger: new Logger({ level: "error", format: "json", sink: () => undefined }),
        config,
      }).runScan(scanId);
      expect(summary.status).toBe("CANCELLED");
      expect(called).toBe(0);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
