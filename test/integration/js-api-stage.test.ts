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
const log = new Logger({ level: "error", format: "json", sink: () => undefined });

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
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "DNS", "ACTIVE_HTTP", "CRAWL", "JS_ANALYSIS", "API_DISCOVERY"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

describe.skipIf(!available)("JS & API intelligence stages", () => {
  it("persists JS artifacts, source maps, endpoints and specs; idempotent", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const host = `app.${rootDomain}`;
    const jsUrl = `https://${host}/app.js`;
    const specUrl = `https://${host}/openapi.json`;
    const workspace = `js${rand}`;

    const runner: DiscoveryRunner = new FakeRunner((job) => {
      if (job.kind === "JS_ANALYSIS") {
        return makeResult(job, {
          records: [
            { type: "JS_ARTIFACT" as const, url: jsUrl, canonicalUrl: jsUrl, contentHash: "b".repeat(64), contentType: "application/javascript", sizeBytes: 10, sourceUrl: `https://${host}/`, discoveryMethod: "stage05", status: "RETRIEVED", error: "", truncated: false, provider: job.provider, source: "js" },
            { type: "SOURCE_MAP" as const, jsUrl, sourceMapUrl: `${jsUrl}.map`, status: "PARSED", sourcesCount: 1, sources: ["src/a.ts"], sourceRoot: "", hasContent: true, error: "", provider: job.provider },
            { type: "API_ENDPOINT" as const, method: "GET", origin: `https://${host}`, path: "/api/users", url: `https://${host}/api/users`, discoveredVia: "JS", documented: false, resolved: true, operationId: "", tags: [], parameters: [{ name: "page", location: "query", required: false, type: "", evidence: "fetch" }], contentTypes: [], authSchemes: [], sourceUrl: jsUrl, evidence: "fetch(/api/users)", evidenceType: "JS_FETCH", provider: job.provider },
            { type: "API_ENDPOINT" as const, method: "GET", origin: `https://${host}`, path: "/api/users/", url: "", discoveredVia: "JS", documented: false, resolved: false, operationId: "", tags: [], parameters: [], contentTypes: [], authSchemes: [], sourceUrl: jsUrl, evidence: "dynamic", evidenceType: "JS_DYNAMIC", provider: job.provider },
          ],
        });
      }
      if (job.kind === "API_SPEC") {
        return makeResult(job, {
          records: [
            { type: "API_SPEC" as const, url: specUrl, specVersion: "openapi:3.0.0", title: "T", format: "JSON", servers: [`https://${host}`], pathCount: 1, operationCount: 1, securitySchemes: ["bearerAuth"], unresolvedRefs: 0, parseStatus: "PARSED", error: "", provider: job.provider },
            { type: "API_ENDPOINT" as const, method: "POST", origin: `https://${host}`, path: "/api/users", url: `https://${host}/api/users`, discoveredVia: "SPEC", documented: true, resolved: true, operationId: "createUser", tags: ["users"], parameters: [{ name: "name", location: "body", required: true, type: "string", evidence: "spec body" }], contentTypes: ["application/json"], authSchemes: ["bearerAuth"], sourceUrl: specUrl, evidence: "declared", evidenceType: "OPENAPI", provider: job.provider },
          ],
        });
      }
      return makeResult(job, { records: [] });
    });

    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${host}/`, policy: ScopePolicySchema.parse(makePolicy(rootDomain)), workspaceName: workspace });
      const { scanId, projectId } = created;

      // Seed stage-05 URL observations so stages 07/08 have eligible inputs.
      const seed = async (url: string, category: string): Promise<void> => {
        const a = await db.query<{ id: string }>("INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'URL',$2,$2) RETURNING id", [projectId, url]);
        await db.query(
          `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
           VALUES ($1,$2,$3,'builtin-crawler','MEDIUM', now(),'url',$4::jsonb)`,
          [projectId, scanId, a.rows[0]!.id, JSON.stringify({ method: "CRAWL", host, classifications: [{ category, confidence: 0.8, evidenceType: "EXTENSION", evidence: "x" }], parameters: [] })],
        );
      };
      await seed(jsUrl, "JAVASCRIPT");
      await seed(specUrl, "API_SPEC");

      const summary = await new ScanOrchestrator({ db, runner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config }).runScan(scanId);
      expect(summary.stages.find((s) => s.stage === "07-js-intelligence")?.status).toBe("SUCCEEDED");
      expect(summary.stages.find((s) => s.stage === "08-api-discovery")?.status).toBe("SUCCEEDED");

      const repo = new Repository(db);
      const artifacts = await repo.listJsArtifacts(scanId);
      expect(artifacts.length).toBe(1);
      expect((artifacts[0]!.data as { contentHash: string }).contentHash).toBe("b".repeat(64));

      const endpoints = await repo.listApiEndpoints(scanId);
      // GET /api/users (JS), GET /api/users/ (JS dynamic), POST /api/users (SPEC) => 3 distinct method-aware.
      expect(endpoints.length).toBe(3);
      const documented = endpoints.filter((e) => (e.data as { documented?: boolean }).documented);
      expect(documented.length).toBe(1);
      const unresolved = endpoints.filter((e) => (e.data as { resolved?: boolean }).resolved === false);
      expect(unresolved.length).toBe(1);

      const specs = await repo.listApiSpecs(scanId);
      expect(specs.length).toBe(1);

      const jsAssets = await repo.listAssets(projectId, ["JS_ARTIFACT", "API_ENDPOINT"]);
      expect(jsAssets.length).toBeGreaterThanOrEqual(4);

      // Idempotency: rerun does not duplicate.
      const before = await db.query<{ n: string }>("SELECT count(*)::text AS n FROM observations WHERE scan_id=$1 AND kind='api-endpoint'", [scanId]);
      await new ScanOrchestrator({ db, runner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config }).runScan(scanId);
      const after = await db.query<{ n: string }>("SELECT count(*)::text AS n FROM observations WHERE scan_id=$1 AND kind='api-endpoint'", [scanId]);
      expect(after.rows[0]!.n).toBe(before.rows[0]!.n);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });

  // Nothing on a target has to reference a specification for one to exist. When JavaScript
  // analysis has already proved an origin serves an API, stage 08 checks that origin's well-known
  // specification paths instead of skipping.
  it("probes well-known specification paths on origins that show evidence of an API", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const host = `app.${rootDomain}`;
    const apiHost = `api.${rootDomain}`;
    const jsUrl = `https://${host}/app.js`;
    const workspace = `probe${rand}`;

    let apiInputs: DiscoveryJob["inputs"] | undefined;
    const runner: DiscoveryRunner = new FakeRunner((job) => {
      if (job.kind === "JS_ANALYSIS") {
        return makeResult(job, {
          records: [
            { type: "JS_ARTIFACT" as const, url: jsUrl, canonicalUrl: jsUrl, contentHash: "c".repeat(64), contentType: "application/javascript", sizeBytes: 10, sourceUrl: `https://${host}/`, discoveryMethod: "stage05", status: "RETRIEVED", error: "", truncated: false, provider: job.provider, source: "js" },
            { type: "API_ENDPOINT" as const, method: "GET", origin: `https://${apiHost}`, path: "/v1/orders", url: `https://${apiHost}/v1/orders`, discoveredVia: "JS", documented: false, resolved: true, operationId: "", tags: [], parameters: [], contentTypes: [], authSchemes: [], sourceUrl: jsUrl, evidence: "fetch(/v1/orders)", evidenceType: "JS_FETCH", provider: job.provider },
          ],
        });
      }
      if (job.kind === "API_SPEC") {
        apiInputs = job.inputs;
        // Every probed path is absent: the stage still did its work.
        return makeResult(job, { coverage: { attempted: job.inputs.specProbeUrls?.length ?? 0, succeeded: job.inputs.specProbeUrls?.length ?? 0, failed: 0, skipped: 0, unavailable: 0 }, records: [] });
      }
      return makeResult(job, { records: [] });
    });

    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${host}/`, policy: ScopePolicySchema.parse(makePolicy(rootDomain)), workspaceName: workspace });
      const { scanId, projectId } = created;

      const a = await db.query<{ id: string }>("INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'URL',$2,$2) RETURNING id", [projectId, jsUrl]);
      await db.query(
        `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
         VALUES ($1,$2,$3,'builtin-crawler','MEDIUM', now(),'url',$4::jsonb)`,
        [projectId, scanId, a.rows[0]!.id, JSON.stringify({ method: "CRAWL", host, classifications: [{ category: "JAVASCRIPT", confidence: 0.8, evidenceType: "EXTENSION", evidence: "x" }], parameters: [] })],
      );

      const summary = await new ScanOrchestrator({ db, runner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config }).runScan(scanId);
      expect(summary.stages.find((s) => s.stage === "08-api-discovery")?.status).toBe("SUCCEEDED");

      expect(apiInputs).toBeDefined();
      expect(apiInputs!.specUrls ?? []).toEqual([]);
      expect(apiInputs!.specProbeUrls ?? []).toContain(`https://${apiHost}/openapi.json`);
      expect(apiInputs!.specProbeUrls ?? []).toContain(`https://${apiHost}/swagger.json`);

      // A probed path that holds nothing is coverage, never an asset.
      const probedAssets = await db.query<{ n: string }>("SELECT count(*)::text AS n FROM assets WHERE project_id=$1 AND value LIKE '%/openapi.json'", [projectId]);
      expect(probedAssets.rows[0]!.n).toBe("0");

      const coverage = await new Repository(db).listCoverage(scanId);
      const apiCoverage = coverage.find((c) => c.stage === "08-api-discovery");
      expect((apiCoverage?.details as { probedWellKnownPaths?: number } | undefined)?.probedWellKnownPaths).toBeGreaterThan(0);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
