import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDb, FakeRunner, Repository, ScanOrchestrator, ScanService, type DiscoveryRunner } from "@reconnexus/control-plane";
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
    providerVersion: "test",
    execution: { argv: [job.provider], exitCode: 0, exitDescription: "", durationMs: 1, stdoutBytes: 1, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" },
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
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "DNS", "ACTIVE_HTTP", "CRAWL"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

const log = new Logger({ level: "error", format: "json", sink: () => undefined });

function urlRecord(provider: string, host: string, url: string, category = "HTML_PAGE") {
  return {
    type: "URL_OBSERVATION" as const,
    url,
    canonicalUrl: url,
    host,
    method: "CRAWL" as const,
    depth: 0,
    statusCode: 200,
    source: "crawl",
    provider,
    classifications: [{ category, confidence: 0.6, evidenceType: "PATH", evidence: "test" }],
    parameters: [{ name: "page", roles: [{ role: "pagination", confidence: 0.7, evidence: "parameter name 'page'" }] }],
  };
}

describe.skipIf(!available)("URL collection stage", () => {
  it("collects, deduplicates across providers, preserves provenance, and is idempotent", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const host = `app.${rootDomain}`;
    const workspace = `url-${rand}`;

    const runner: DiscoveryRunner = new FakeRunner((job) => {
      if (job.kind === "URL_COLLECTION") {
        if (job.provider === "builtin-crawler") {
          return makeResult(job, {
            records: [urlRecord(job.provider, host, `https://${host}/`), urlRecord(job.provider, host, `https://${host}/admin`, "ADMIN")],
            coverage: { attempted: 1, succeeded: 2, failed: 0, skipped: 0, unavailable: 0 },
          });
        }
        if (job.provider === "gau") {
          // Same canonical URL from a second provider — must add provenance, not a new asset.
          return makeResult(job, { records: [urlRecord(job.provider, host, `https://${host}/`)] });
        }
        return makeResult(job, { records: [] });
      }
      return makeResult(job, { records: [] });
    });

    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${host}/`, policy: ScopePolicySchema.parse(makePolicy(rootDomain)), workspaceName: workspace });
      const { scanId, projectId } = created;

      // Seed an HTTP observation so the URL stage has a seed (simulates a completed probe).
      const svc = await db.query<{ id: string }>(
        "INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'SERVICE',$2,$2) RETURNING id",
        [projectId, `https://${host}`],
      );
      await db.query(
        `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
         VALUES ($1,$2,$3,'http','HIGH', now(),'http', $4::jsonb)`,
        [projectId, scanId, svc.rows[0]!.id, JSON.stringify({ url: `https://${host}/`, finalUrl: `https://${host}/`, probeStatus: "OK" })],
      );

      const summary = await new ScanOrchestrator({ db, runner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config }).runScan(scanId);
      const urlStage = summary.stages.find((s) => s.stage === "05-url-collection");
      expect(urlStage?.status).toBe("SUCCEEDED");
      expect(urlStage?.providers.some((p) => p.provider === "builtin-crawler" && p.records === 2)).toBe(true);

      const repo = new Repository(db);
      const urls = await repo.listUrlObservations(scanId);
      expect(urls.length).toBe(3); // 2 from crawler + 1 from gau
      const unique = new Set(urls.map((u) => u.url));
      expect(unique.size).toBe(2); // dedup by canonical identity

      const assets = await repo.listAssets(projectId, ["URL"]);
      expect(assets.length).toBe(2);

      const params = urls.flatMap((u) => (u.data as { parameters?: Array<{ name: string }> }).parameters ?? []);
      expect(params.some((p) => p.name === "page")).toBe(true);

      const rels = await db.query<{ n: string }>(
        "SELECT count(*)::text AS n FROM asset_relationships WHERE project_id=$1 AND relation='contains_url'",
        [projectId],
      );
      expect(Number(rels.rows[0]!.n)).toBeGreaterThan(0);

      // Idempotency: a second run must not duplicate assets or observations.
      const before = await db.query<{ n: string }>("SELECT count(*)::text AS n FROM observations WHERE scan_id=$1 AND kind='url'", [scanId]);
      await new ScanOrchestrator({ db, runner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config }).runScan(scanId);
      const after = await db.query<{ n: string }>("SELECT count(*)::text AS n FROM observations WHERE scan_id=$1 AND kind='url'", [scanId]);
      expect(after.rows[0]!.n).toBe(before.rows[0]!.n);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
