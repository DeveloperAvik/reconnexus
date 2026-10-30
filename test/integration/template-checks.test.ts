import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDb, FakeRunner, loadScanFindings, Repository, ScanOrchestrator, ScanService, type DiscoveryRunner } from "@reconnexus/control-plane";
import { loadContext } from "../../apps/cli/src/context.js";
import { riskCommand } from "../../apps/cli/src/commands/risk.js";
import { LocalArtifactStore } from "@reconnexus/evidence-contracts";
import { ExitCode, ScopePolicySchema, type DiscoveryJob, type DiscoveryResult } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";
import { Logger } from "@reconnexus/logging";

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

function policy(rootDomain: string, capabilities: string[]): unknown {
  return {
    schemaVersion: 1,
    policyId: randomUUID(),
    projectId: randomUUID(),
    policyVersion: 1,
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

describe.skipIf(!available)("template checks, profiles and risk", () => {
  async function setup(db: ReturnType<typeof createDb>, capabilities: string[], profile?: string) {
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const host = `www.${rootDomain}`;
    const workspace = `tc${rand}`;
    const created = await new ScanService(db).createScan({ startUrl: `https://${rootDomain}/`, policy: ScopePolicySchema.parse(policy(rootDomain, capabilities)), workspaceName: workspace, ...(profile ? { profile } : {}) });
    return { ...created, rootDomain, host, workspace };
  }

  async function seedHttp(db: ReturnType<typeof createDb>, projectId: string, scanId: string, host: string): Promise<void> {
    const a = await db.query<{ id: string }>(
      "INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'HOST',$2,$2) ON CONFLICT (project_id,type,canonical_key) DO UPDATE SET value=EXCLUDED.value RETURNING id",
      [projectId, host],
    );
    await db.query(
      `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data) VALUES ($1,$2,$3,'http','HIGH',now(),'http',$4)`,
      [projectId, scanId, a.rows[0]!.id, JSON.stringify({ url: `https://${host}/`, finalUrl: `https://${host}/`, probeStatus: "OK", statusCode: 200 })],
    );
  }

  async function cleanup(db: ReturnType<typeof createDb>, rootDomain: string, workspace: string): Promise<void> {
    await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
    await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
    await db.close();
  }

  const store = () => new LocalArtifactStore(config.artifacts.root);

  it("runs templates, turns non-INFO matches into findings and ranks the host", async () => {
    const db = createDb(config.database);
    const s = await setup(db, ["PASSIVE", "DNS", "ACTIVE_HTTP", "ACTIVE_TEMPLATE_CHECK"]);
    let seen: DiscoveryJob["inputs"] | undefined;
    const match = (templateId: string, severity: "INFO" | "MEDIUM" | "CRITICAL", path: string, provider: string) => ({
      type: "TEMPLATE_FINDING" as const, host: s.host, url: `https://${s.host}${path}`, templateId, name: templateId, severity, description: "d", tags: ["exposure"], references: [],
      matcherName: "", extracted: [], templateType: "http", confidence: 0.7, provider, source: "nuclei",
    });
    const runner: DiscoveryRunner = new FakeRunner((job) => {
      if (job.kind !== "TEMPLATE_CHECK") return makeResult(job);
      seen = job.inputs;
      return makeResult(job, [match("git-config", "MEDIUM", "/.git/config", job.provider), match("tech-detect", "INFO", "/", job.provider), match("big", "CRITICAL", "/big", job.provider)]);
    });
    try {
      await seedHttp(db, s.projectId, s.scanId, s.host);
      const summary = await new ScanOrchestrator({ db, runner, store: store(), logger: log, config, templateTags: "exposure" }).runScan(s.scanId);
      expect(summary.stages.find((x) => x.stage === "16-template-checks")?.status).toBe("SUCCEEDED");
      expect(seen?.urls).toEqual([`https://${s.host}`]);
      expect(seen?.templateTags).toBe("exposure");

      const findings = await loadScanFindings(new Repository(db), s.scanId);
      expect(findings.filter((f) => f.category === "TEMPLATE_MATCH").map((f) => f.severity).sort()).toEqual(["HIGH", "MEDIUM"]);

      const ranked = await riskCommand(ctx, s.scanId, { explain: true });
      expect(ranked.exitCode).toBe(ExitCode.SUCCESS);
      const hosts = (ranked.data as { hosts: Array<{ host: string; level: string; findingCount: number }> }).hosts;
      expect(hosts[0]).toMatchObject({ host: s.host, findingCount: 2 });
      expect(((await riskCommand(ctx, s.scanId, { level: "critical" })).data as { total: number }).total).toBe(0);
      await expect(riskCommand(ctx, s.scanId, { level: "bogus" })).rejects.toThrow(/unknown level/);
    } finally {
      await cleanup(db, s.rootDomain, s.workspace);
    }
  });

  it("plans no template stage without ACTIVE_TEMPLATE_CHECK", async () => {
    const db = createDb(config.database);
    const s = await setup(db, ["PASSIVE", "DNS", "ACTIVE_HTTP"]);
    const kinds: string[] = [];
    const runner: DiscoveryRunner = new FakeRunner((job) => (kinds.push(job.kind), makeResult(job)));
    try {
      await seedHttp(db, s.projectId, s.scanId, s.host);
      const summary = await new ScanOrchestrator({ db, runner, store: store(), logger: log, config }).runScan(s.scanId);
      expect(summary.stages.some((x) => x.stage === "16-template-checks")).toBe(false);
      expect(kinds).not.toContain("TEMPLATE_CHECK");
    } finally {
      await cleanup(db, s.rootDomain, s.workspace);
    }
  });

  it("applies a stealth profile: stages left out, limits tightened, never raised", async () => {
    const db = createDb(config.database);
    const s = await setup(db, ["PASSIVE", "DNS", "ACTIVE_HTTP", "PORT_SCAN", "ACTIVE_TEMPLATE_CHECK"], "stealth");
    const limits: Array<{ kind: string; rps: number; conc: number; depth: number }> = [];
    const runner: DiscoveryRunner = new FakeRunner((job) => (limits.push({ kind: job.kind, rps: job.limits.requestsPerSecond, conc: job.limits.maxConcurrency, depth: job.limits.crawlDepth }), makeResult(job)));
    try {
      await seedHttp(db, s.projectId, s.scanId, s.host);
      const summary = await new ScanOrchestrator({ db, runner, store: store(), logger: log, config }).runScan(s.scanId);
      const stages = summary.stages.map((x) => x.stage);
      for (const gone of ["15-port-scan", "16-template-checks", "14-login-finder"]) expect(stages).not.toContain(gone);
      expect(summary.profile).toBe("stealth");
      expect(limits.length).toBeGreaterThan(0);
      for (const l of limits) {
        expect(l.rps).toBeLessThanOrEqual(2);
        expect(l.conc).toBeLessThanOrEqual(2);
        expect(l.depth).toBeLessThanOrEqual(1);
      }
    } finally {
      await cleanup(db, s.rootDomain, s.workspace);
    }
  });

  it("rejects an unknown profile before persisting anything", async () => {
    const db = createDb(config.database);
    try {
      await expect(setup(db, ["PASSIVE", "DNS", "ACTIVE_HTTP"], "loud")).rejects.toThrow(/unknown scan profile/);
    } finally {
      await db.close();
    }
  });
});
