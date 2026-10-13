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
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "DNS", "ACTIVE_HTTP"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 1, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

const log = new Logger({ level: "error", format: "json", sink: () => undefined });

describe.skipIf(!available)("HTTP probe stage", () => {
  it("persists services, technologies and certificates with evidence", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const host = `app.${rootDomain}`;
    const workspace = `http-${rand}`;

    const runner: DiscoveryRunner = new FakeRunner((job) => {
      if (job.kind !== "HTTP_PROBE") return makeResult(job, { records: [] });
      const url = `https://${host}/`;
      return makeResult(job, {
        records: [
          {
            type: "HTTP_OBSERVATION" as const,
            url,
            host,
            provider: job.provider,
            source: "http",
            http: {
              finalUrl: url,
              statusCode: 200,
              statusText: "200 OK",
              contentType: "text/html",
              title: "Home",
              headers: { server: "nginx", "content-type": "text/html" },
              redirectChain: [],
              tls: { subject: `CN=${host}`, issuer: "CN=Test CA", notBefore: "2025-01-01T00:00:00Z", notAfter: "2026-01-01T00:00:00Z", sha256: `deadbeef${rand}`, protocol: "TLS 1.3", sans: [host] },
              probeStatus: "OK",
              error: "",
              bodyTruncated: false,
            },
          },
          { type: "TECHNOLOGY" as const, url, host, provider: job.provider, technology: { name: "nginx", category: "WEB_SERVER", evidenceType: "HEADER", evidence: "Server: nginx", confidence: 0.9 } },
          { type: "TECHNOLOGY" as const, url, host, provider: job.provider, technology: { name: "PHP", category: "FRAMEWORK", evidenceType: "HEADER", evidence: "X-Powered-By: PHP/8.1", confidence: 0.95 } },
        ],
        coverage: { attempted: 1, succeeded: 1, failed: 0, skipped: 0, unavailable: 0 },
      });
    });

    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${rootDomain}/`, policy: ScopePolicySchema.parse(makePolicy(rootDomain)), workspaceName: workspace });
      const { scanId, projectId } = created;

      // Seed a resolved in-scope host so the HTTP stage has an eligible target.
      await db.query(
        `INSERT INTO assets (project_id, type, canonical_key, value) VALUES ($1,'SUBDOMAIN',$2,$2) ON CONFLICT DO NOTHING`,
        [projectId, host],
      );
      await db.query(
        `INSERT INTO assets (project_id, type, canonical_key, value) VALUES ($1,'IP','203.0.113.77','203.0.113.77') ON CONFLICT DO NOTHING`,
        [projectId],
      );
      await db.query(
        `INSERT INTO asset_relationships (project_id, from_asset_id, to_asset_id, relation, confidence, source)
         SELECT $1, h.id, i.id, 'resolves_to', 0.9, 'test' FROM assets h, assets i
          WHERE h.project_id=$1 AND h.value=$2 AND i.project_id=$1 AND i.value='203.0.113.77'
         ON CONFLICT DO NOTHING`,
        [projectId, host],
      );

      const summary = await new ScanOrchestrator({
        db,
        runner,
        store: new LocalArtifactStore(config.artifacts.root),
        logger: log,
        config,
      }).runScan(scanId);

      expect(summary.status).toBe("PARTIAL"); // stages 05-12 unimplemented
      const httpStage = summary.stages.find((s) => s.stage === "04-http-probe");
      expect(httpStage?.status).toBe("SUCCEEDED");
      expect(httpStage?.providers.some((p) => p.provider === "builtin-http" && p.outcome === "SUCCEEDED")).toBe(true);

      const repo = new Repository(db);
      const assets = await repo.listAssets(projectId, ["SERVICE", "TECHNOLOGY", "CERTIFICATE"]);
      const values = assets.map((a) => a.value);
      expect(values).toContain(`https://${host}`);
      expect(values).toContain("nginx");
      expect(values).toContain("PHP");
      expect(values.some((v) => v.startsWith("deadbeef"))).toBe(true);

      const probes = await repo.listHttpObservations(scanId);
      expect(probes.length).toBe(1);
      expect(probes[0]!.status_code).toBe(200);
      expect(probes[0]!.server).toBe("nginx");

      const techs = await repo.listTechnologyObservations(scanId);
      expect(techs.map((t) => t.name).sort()).toEqual(["PHP", "nginx"]);
      expect(techs.every((t) => t.evidence.length > 0)).toBe(true);

      // Technology observations must be linked to stored evidence artifacts.
      const links = await db.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM evidence_links el
           JOIN observations o ON o.id = el.observation_id
          WHERE o.scan_id = $1 AND o.kind = 'technology'`,
        [scanId],
      );
      expect(Number(links.rows[0]!.n)).toBeGreaterThan(0);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
