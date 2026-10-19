import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createDb,
  FakeRunner,
  isRetryableProviderOutcome,
  Repository,
  ScanOrchestrator,
  ScanService,
  shouldRetryStage,
  type ScanRunSummary,
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

type Status = DiscoveryResult["status"];

function makeResult(job: DiscoveryJob, status: Status, records: DiscoveryResult["records"] = []): DiscoveryResult {
  return {
    schemaVersion: 1,
    status,
    provider: job.provider,
    providerVersion: "test-1.0",
    execution: { argv: [job.provider], exitCode: 0, exitDescription: "", durationMs: 1, stdoutBytes: 10, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" },
    coverage: { attempted: 1, succeeded: status === "SUCCEEDED" ? 1 : 0, failed: status === "FAILED" ? 1 : 0, skipped: 0, unavailable: status === "SOURCE_UNAVAILABLE" ? 1 : 0 },
    records,
    diagnostics: status === "SUCCEEDED" ? [] : [`simulated ${status}`],
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

interface Scenario {
  /** Outcome of subfinder / assetfinder on the n-th call (1-based) of the SUBDOMAINS stage. */
  subfinder: (call: number) => Status;
  assetfinder: (call: number) => Status;
  maxAttempts?: number;
  onSubfinderCall?: (call: number, ctx: { db: ReturnType<typeof createDb>; scanId: string }) => Promise<void>;
}

async function run(sc: Scenario): Promise<{
  summary: ScanRunSummary;
  calls: Record<string, number>;
  sleeps: number[];
  outcomes: Array<{ provider: string; outcome: string; records_count: number }>;
  stageJobStatus: string;
  hostObservations: number;
  distinctHostObservations: number;
}> {
  const db = createDb(config.database);
  const repo = new Repository(db);
  const rand = Math.random().toString(36).slice(2, 8);
  const rootDomain = `rn-${rand}.example.net`;
  const workspace = `retry-${rand}`;
  const calls: Record<string, number> = { subfinder: 0, assetfinder: 0 };
  const sleeps: number[] = [];
  let scanIdRef = "";
  const pending: Array<Promise<void>> = [];

  const runner = new FakeRunner((job) => {
    if (job.kind !== "SUBDOMAINS") return makeResult(job, "SUCCEEDED");
    const n = (calls[job.provider] = (calls[job.provider] ?? 0) + 1);
    const status = job.provider === "subfinder" ? sc.subfinder(n) : sc.assetfinder(n);
    if (job.provider === "subfinder" && sc.onSubfinderCall) pending.push(sc.onSubfinderCall(n, { db, scanId: scanIdRef }));
    const records =
      status === "SUCCEEDED"
        ? [{ type: "HOST_OBSERVATION" as const, host: `${job.provider}.${rootDomain}`, source: "passive", provider: job.provider, status: "DISCOVERED", addresses: [], notes: "" }]
        : [];
    return makeResult(job, status, records);
  });

  try {
    const created = await new ScanService(db).createScan({ startUrl: `https://${rootDomain}/`, policy: ScopePolicySchema.parse(policy(rootDomain)), workspaceName: workspace });
    scanIdRef = created.scanId;
    const summary = await new ScanOrchestrator({
      db,
      runner,
      store: new LocalArtifactStore(config.artifacts.root),
      logger: new Logger({ level: "error", format: "json", sink: () => undefined }),
      config,
      maxAttempts: sc.maxAttempts ?? 3,
      sleep: (ms) => {
        sleeps.push(ms);
        return Promise.resolve();
      },
    }).runScan(created.scanId);
    await Promise.all(pending);
    const outcomes = (await repo.listProviderOutcomes(created.scanId)).filter((o) => o.stage === "02-subdomain-discovery");
    const job = (await repo.getJobRows(created.scanId)).find((j) => j.stage === "02-subdomain-discovery")!;
    const obs = await db.query<{ n: string; d: string }>(
      "SELECT count(*)::text AS n, count(DISTINCT (asset_id, source, data))::text AS d FROM observations WHERE scan_id=$1 AND kind='host'",
      [created.scanId],
    );
    return {
      summary,
      calls,
      sleeps,
      outcomes: outcomes.map((o) => ({ provider: o.provider, outcome: o.outcome, records_count: o.records_count })),
      stageJobStatus: job.status,
      hostObservations: Number(obs.rows[0]!.n),
      distinctHostObservations: Number(obs.rows[0]!.d),
    };
  } finally {
    await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
    await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
    await db.close();
  }
}

const stageOf = (s: ScanRunSummary) => s.stages.find((x) => x.stage === "02-subdomain-discovery")!;
const outcomeOf = (r: { outcomes: Array<{ provider: string; outcome: string }> }, p: string) => r.outcomes.find((o) => o.provider === p)?.outcome;

describe("retry policy (pure)", () => {
  it("retries only FAILED provider outcomes", () => {
    expect(isRetryableProviderOutcome("FAILED")).toBe(true);
    for (const o of ["SUCCEEDED", "PARTIAL", "SKIPPED", "BLOCKED", "SOURCE_UNAVAILABLE", "CANCELLED"]) expect(isRetryableProviderOutcome(o), o).toBe(false);
  });
  it("retries a stage when any provider failed, regardless of siblings", () => {
    expect(shouldRetryStage([])).toBe(false);
    expect(shouldRetryStage([{ outcome: "FAILED" }])).toBe(true);
    expect(shouldRetryStage([{ outcome: "FAILED" }, { outcome: "SOURCE_UNAVAILABLE" }])).toBe(true);
    expect(shouldRetryStage([{ outcome: "FAILED" }, { outcome: "SKIPPED" }])).toBe(true);
    expect(shouldRetryStage([{ outcome: "FAILED" }, { outcome: "SUCCEEDED" }])).toBe(true);
    expect(shouldRetryStage([{ outcome: "SOURCE_UNAVAILABLE" }, { outcome: "SKIPPED" }, { outcome: "PARTIAL" }])).toBe(false);
  });
});

describe.skipIf(!available)("mixed-outcome stage retries", () => {
  it("FAILED + SOURCE_UNAVAILABLE: retries only the failed provider, never the unavailable one", async () => {
    const r = await run({ subfinder: (n) => (n === 1 ? "FAILED" : "SUCCEEDED"), assetfinder: () => "SOURCE_UNAVAILABLE" });
    expect(r.calls).toEqual({ subfinder: 2, assetfinder: 1 });
    expect(outcomeOf(r, "subfinder")).toBe("SUCCEEDED");
    expect(outcomeOf(r, "assetfinder")).toBe("SOURCE_UNAVAILABLE");
    expect(stageOf(r.summary).status).toBe("PARTIAL");
    expect(r.stageJobStatus).toBe("PARTIAL");
    expect(r.sleeps.length).toBe(1);
  });

  it("FAILED + SKIPPED: retries only the failed provider", async () => {
    const r = await run({ subfinder: (n) => (n === 1 ? "FAILED" : "SUCCEEDED"), assetfinder: () => "SKIPPED" });
    expect(r.calls).toEqual({ subfinder: 2, assetfinder: 1 });
    expect(outcomeOf(r, "assetfinder")).toBe("SKIPPED");
    expect(stageOf(r.summary).status).toBe("PARTIAL");
  });

  it("FAILED + SUCCEEDED: retries the failed provider, reuses completed work, adds no duplicate observations", async () => {
    const r = await run({ subfinder: (n) => (n === 1 ? "FAILED" : "SUCCEEDED"), assetfinder: () => "SUCCEEDED" });
    expect(r.calls).toEqual({ subfinder: 2, assetfinder: 1 });
    expect(stageOf(r.summary).status).toBe("SUCCEEDED");
    expect(r.stageJobStatus).toBe("SUCCEEDED");
    expect(r.hostObservations).toBe(2); // one per provider, none repeated
    expect(r.distinctHostObservations).toBe(r.hostObservations);
    const reused = stageOf(r.summary).providers.find((p) => p.provider === "assetfinder")!;
    expect(reused.reason).toContain("reused");
  });

  it("transient failure of every provider is retried and recovers", async () => {
    const r = await run({ subfinder: (n) => (n < 3 ? "FAILED" : "SUCCEEDED"), assetfinder: (n) => (n < 2 ? "FAILED" : "SUCCEEDED") });
    expect(r.calls).toEqual({ subfinder: 3, assetfinder: 2 });
    expect(stageOf(r.summary).status).toBe("SUCCEEDED");
    expect(r.sleeps.length).toBe(2);
    expect(r.sleeps[1]!).toBeGreaterThan(r.sleeps[0]! - 250); // exponential backoff (jitter < 250ms)
  });

  it("retry exhaustion: bounded attempts, backoff between them, FAILED sibling stays FAILED, success kept", async () => {
    const r = await run({ subfinder: () => "FAILED", assetfinder: () => "SUCCEEDED", maxAttempts: 3 });
    expect(r.calls).toEqual({ subfinder: 3, assetfinder: 1 });
    expect(r.sleeps.length).toBe(2);
    expect(outcomeOf(r, "subfinder")).toBe("FAILED");
    expect(outcomeOf(r, "assetfinder")).toBe("SUCCEEDED");
    expect(stageOf(r.summary).status).toBe("PARTIAL"); // data was collected; failure is visible
    expect(r.stageJobStatus).toBe("PARTIAL");
    expect(r.hostObservations).toBe(1);
  });

  it("retry exhaustion with only failures ends FAILED", async () => {
    const r = await run({ subfinder: () => "FAILED", assetfinder: () => "FAILED", maxAttempts: 2 });
    expect(r.calls).toEqual({ subfinder: 2, assetfinder: 2 });
    expect(stageOf(r.summary).status).toBe("FAILED");
    expect(r.stageJobStatus).toBe("FAILED");
  });

  it("does not retry when no provider failed (unavailable / skipped / partial / success)", async () => {
    const a = await run({ subfinder: () => "SOURCE_UNAVAILABLE", assetfinder: () => "SOURCE_UNAVAILABLE" });
    expect(a.calls).toEqual({ subfinder: 1, assetfinder: 1 });
    expect(stageOf(a.summary).status).toBe("SOURCE_UNAVAILABLE");
    expect(a.sleeps).toEqual([]);

    const b = await run({ subfinder: () => "SKIPPED", assetfinder: () => "SOURCE_UNAVAILABLE" });
    expect(b.calls).toEqual({ subfinder: 1, assetfinder: 1 });
    expect(b.sleeps).toEqual([]);

    const c = await run({ subfinder: () => "PARTIAL", assetfinder: () => "SUCCEEDED" });
    expect(c.calls).toEqual({ subfinder: 1, assetfinder: 1 });
    expect(stageOf(c.summary).status).toBe("PARTIAL");
    expect(outcomeOf(c, "subfinder")).toBe("PARTIAL");
  });

  it("a partial provider result is kept, and a failed sibling is retried alone", async () => {
    const r = await run({ subfinder: (n) => (n === 1 ? "FAILED" : "PARTIAL"), assetfinder: () => "PARTIAL" });
    expect(r.calls).toEqual({ subfinder: 2, assetfinder: 1 });
    expect(stageOf(r.summary).status).toBe("PARTIAL");
  });

  it("cancellation during a failed attempt stops retries", async () => {
    const r = await run({
      subfinder: () => "FAILED",
      assetfinder: () => "SUCCEEDED",
      onSubfinderCall: async (_n, { db, scanId }) => {
        await new Repository(db).updateScanStatus(scanId, "CANCELLED");
      },
    });
    expect(r.calls.subfinder).toBe(1);
    expect(r.summary.status).toBe("CANCELLED");
    expect(r.stageJobStatus).toBe("CANCELLED");
  });

  it("maxAttempts=1 disables retries", async () => {
    const r = await run({ subfinder: () => "FAILED", assetfinder: () => "SUCCEEDED", maxAttempts: 1 });
    expect(r.calls).toEqual({ subfinder: 1, assetfinder: 1 });
    expect(r.sleeps).toEqual([]);
    expect(stageOf(r.summary).status).toBe("PARTIAL");
  });
});
