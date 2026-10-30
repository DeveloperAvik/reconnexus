import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDb, FakeRunner, ScanOrchestrator, ScanService, type DiscoveryRunner } from "@reconnexus/control-plane";
import { loadContext } from "../../apps/cli/src/context.js";
import { portsCommand } from "../../apps/cli/src/commands/ports.js";
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

describe.skipIf(!available)("port scan stage (15)", () => {
  async function setup(db: ReturnType<typeof createDb>, capabilities: string[]) {
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const host = `www.${rootDomain}`;
    const workspace = `ps${rand}`;
    const created = await new ScanService(db).createScan({ startUrl: `https://${rootDomain}/`, policy: ScopePolicySchema.parse(policy(rootDomain, capabilities)), workspaceName: workspace });
    return { ...created, rootDomain, host, workspace };
  }

  async function seedResolution(db: ReturnType<typeof createDb>, projectId: string, host: string, ip: string): Promise<void> {
    const ins = (type: string, v: string) =>
      db.query<{ id: string }>(
        "INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,$2,$3,$3) ON CONFLICT (project_id,type,canonical_key) DO UPDATE SET value=EXCLUDED.value RETURNING id",
        [projectId, type, v],
      );
    const h = await ins("SUBDOMAIN", host);
    const i = await ins("IP", ip);
    await db.query("INSERT INTO asset_relationships (project_id,from_asset_id,to_asset_id,relation,source) VALUES ($1,$2,$3,'resolves_to','test')", [projectId, h.rows[0]!.id, i.rows[0]!.id]);
  }

  async function cleanup(db: ReturnType<typeof createDb>, rootDomain: string, workspace: string): Promise<void> {
    await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
    await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
    await db.close();
  }

  it("scans resolved addresses of in-scope hosts and persists ports as services", async () => {
    const db = createDb(config.database);
    const s = await setup(db, ["PASSIVE", "DNS", "ACTIVE_HTTP", "PORT_SCAN"]);
    let seen: DiscoveryJob["inputs"] | undefined;
    const runner: DiscoveryRunner = new FakeRunner((job) => {
      if (job.kind !== "PORT_SCAN") return makeResult(job);
      seen = job.inputs;
      return makeResult(job, [
        { type: "PORT_OBSERVATION" as const, host: s.host, ip: "93.184.216.34", port: 22, protocol: "tcp" as const, state: "OPEN" as const, service: "ssh", product: "OpenSSH", version: "8.9", extraInfo: "", tls: false, confidence: 1, provider: job.provider, source: "nmap" },
        { type: "PORT_OBSERVATION" as const, host: s.host, ip: "93.184.216.34", port: 443, protocol: "tcp" as const, state: "OPEN" as const, service: "http", product: "nginx", version: "", extraInfo: "", tls: true, confidence: 0.8, provider: job.provider, source: "nmap" },
      ]);
    });
    try {
      await seedResolution(db, s.projectId, s.host, "93.184.216.34");
      const summary = await new ScanOrchestrator({ db, runner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config, portScanPorts: "22,443" }).runScan(s.scanId);
      expect(summary.stages.find((x) => x.stage === "15-port-scan")?.status).toBe("SUCCEEDED");
      expect(seen?.addresses).toEqual([{ ip: "93.184.216.34", viaHost: s.host }]);
      expect(seen?.ports).toBe("22,443");

      const obs = await db.query<{ data: { port: number; product: string } }>("SELECT data FROM observations WHERE scan_id=$1 AND kind='port-observation' ORDER BY (data->>'port')::int", [s.scanId]);
      expect(obs.rows.map((r) => r.data.port)).toEqual([22, 443]);
      expect(obs.rows[0]!.data.product).toBe("OpenSSH");
      const rel = await db.query("SELECT 1 FROM asset_relationships WHERE project_id=$1 AND relation='exposes_port'", [s.projectId]);
      expect(rel.rowCount).toBe(4);

      const listed = await portsCommand(ctx, s.scanId, {});
      expect(listed.exitCode).toBe(ExitCode.SUCCESS);
      expect((listed.data as { total: number; addresses: number }).total).toBe(2);
      expect((listed.data as { addresses: number }).addresses).toBe(1);
      expect(((await portsCommand(ctx, s.scanId, { port: 443 })).data as { total: number }).total).toBe(1);
      expect(((await portsCommand(ctx, s.scanId, { service: "ssh" })).data as { total: number }).total).toBe(1);
    } finally {
      await cleanup(db, s.rootDomain, s.workspace);
    }
  });

  it("plans no port-scan stage and sends no job when the policy does not grant PORT_SCAN", async () => {
    const db = createDb(config.database);
    const s = await setup(db, ["PASSIVE", "DNS", "ACTIVE_HTTP"]);
    const kinds: string[] = [];
    const runner: DiscoveryRunner = new FakeRunner((job) => {
      kinds.push(job.kind);
      return makeResult(job);
    });
    try {
      await seedResolution(db, s.projectId, s.host, "93.184.216.34");
      const summary = await new ScanOrchestrator({ db, runner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config }).runScan(s.scanId);
      expect(summary.stages.some((x) => x.stage === "15-port-scan")).toBe(false);
      expect(kinds).not.toContain("PORT_SCAN");
    } finally {
      await cleanup(db, s.rootDomain, s.workspace);
    }
  });
});
