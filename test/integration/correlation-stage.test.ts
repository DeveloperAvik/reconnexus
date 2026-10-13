import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDb, FakeRunner, Repository, ScanOrchestrator, ScanService, type DiscoveryRunner } from "@reconnexus/control-plane";
import { LocalArtifactStore } from "@reconnexus/evidence-contracts";
import { ScopePolicySchema, type DiscoveryResult } from "@reconnexus/contracts";
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

const RAW_SECRET = "AKIAABCDEFGHIJKLMNOP"; // synthetic; must never be persisted

function makePolicy(rootDomain: string): unknown {
  return {
    schemaVersion: 1,
    policyId: randomUUID(),
    projectId: randomUUID(),
    policyVersion: 1,
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "DNS", "ACTIVE_HTTP", "CRAWL", "SECRET_SCAN", "SECURITY_CHECKS"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

const emptyRunner: DiscoveryRunner = new FakeRunner((job) => ({ schemaVersion: 1, status: "SUCCEEDED", provider: job.provider, providerVersion: "test", execution: { argv: [], exitCode: 0, exitDescription: "", durationMs: 0, stdoutBytes: 0, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" }, coverage: { attempted: 0, succeeded: 0, failed: 0, skipped: 0, unavailable: 0 }, records: [], diagnostics: [] }) as DiscoveryResult);

describe.skipIf(!available)("Stage 11 correlation", () => {
  it("correlates shared secret fingerprints and multi-source corroboration, idempotently and safely", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const host = `app.${rootDomain}`;
    const workspace = `corr${rand}`;

    const seedAsset = async (type: string, key: string): Promise<string> => {
      const r = await db.query<{ id: string }>("INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,$2,$3,$3) RETURNING id", [projectId, type, key]);
      return r.rows[0]!.id;
    };
    const seedObs = async (assetId: string, source: string, kind: string, data: Record<string, unknown>): Promise<void> => {
      await db.query(
        `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
         VALUES ($1,$2,$3,$4,'MEDIUM', now(),$5,$6::jsonb)`,
        [projectId, scanId, assetId, source, kind, JSON.stringify(data)],
      );
    };

    let projectId = "";
    let scanId = "";
    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${host}/`, policy: ScopePolicySchema.parse(makePolicy(rootDomain)), workspaceName: workspace });
      scanId = created.scanId;
      projectId = created.projectId;

      const artifactA = `https://${host}/a.js`;
      const artifactB = `https://${host}/b.js`;
      const artifactC = `https://${host}/c.js`;
      const assetA = await seedAsset("URL", artifactA);
      const assetB = await seedAsset("URL", artifactB);
      const assetC = await seedAsset("URL", artifactC);

      // A and B share the same keyed fingerprint for the same rule; C is unkeyed (not comparable).
      await seedObs(assetA, "builtin-secret-scan", "secret-finding", { ruleId: "aws-access-key-id", fingerprint: "FP-SHARED", status: "HIGH_CONFIDENCE", redactedSnippet: "x='[REDACTED]'" });
      await seedObs(assetB, "builtin-secret-scan", "secret-finding", { ruleId: "aws-access-key-id", fingerprint: "FP-SHARED", status: "HIGH_CONFIDENCE", redactedSnippet: "y='[REDACTED]'" });
      await seedObs(assetC, "builtin-secret-scan", "secret-finding", { ruleId: "aws-access-key-id", fingerprint: "FP-SHARED", status: "HIGH_CONFIDENCE", redactedSnippet: "z='[REDACTED]'" });
      await seedObs(assetA, "builtin-secret-scan", "secret-scan-artifact", { hmacKeyed: true, status: "ANALYZED" });
      await seedObs(assetB, "builtin-secret-scan", "secret-scan-artifact", { hmacKeyed: true, status: "ANALYZED" });
      await seedObs(assetC, "builtin-secret-scan", "secret-scan-artifact", { hmacKeyed: false, status: "ANALYZED" });

      // An asset observed by two distinct sources → corroboration.
      const corrAsset = await seedAsset("HOST", host);
      await seedObs(corrAsset, "subfinder", "host", { status: "DISCOVERED" });
      await seedObs(corrAsset, "assetfinder", "host", { status: "DISCOVERED" });

      const orchestrator = new ScanOrchestrator({ db, runner: emptyRunner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config });
      const summary = await orchestrator.runScan(scanId);
      const stage = summary.stages.find((s) => s.stage === "11-correlation");
      expect(stage?.status).toBe("SUCCEEDED");

      const repo = new Repository(db);
      const obs = await repo.listCorrelationObservations(scanId);
      const fingerprintCorr = obs.filter((o) => (o.data as { relation: string }).relation === "SHARES_SECRET_FINGERPRINT");
      const corroboration = obs.filter((o) => (o.data as { relation: string }).relation === "MULTI_SOURCE_CORROBORATION");
      expect(fingerprintCorr.length).toBe(1);
      expect(corroboration.length).toBeGreaterThanOrEqual(1);

      const edges = await repo.listCorrelationEdges(scanId);
      expect(edges.filter((e) => e.relation === "shares_secret_fingerprint").length).toBe(1);
      const edge = edges.find((e) => e.relation === "shares_secret_fingerprint")!;
      expect(new Set([edge.from_key, edge.to_key])).toEqual(new Set([artifactA, artifactB]));

      // The correlation group is opaque and is not the fingerprint.
      const rec = fingerprintCorr[0]!.data as { correlationGroup: string; sourceRecordIds: string[]; status: string };
      expect(rec.correlationGroup).toMatch(/^[0-9a-f]{16}$/);
      expect(rec.correlationGroup).not.toBe("FP-SHARED");
      expect(rec.sourceRecordIds.length).toBe(2);

      // Security: no raw secret, no fingerprint, and no VALIDATED/CONFIRMED anywhere.
      const all = await db.query<{ n: string }>(
        `SELECT (SELECT count(*) FROM observations WHERE scan_id=$1 AND kind='correlation' AND (data::text LIKE '%FP-SHARED%' OR data::text LIKE $2 OR data::text LIKE '%VALIDATED%' OR data::text LIKE '%CONFIRMED%'))::text AS n`,
        [scanId, `%${RAW_SECRET}%`],
      );
      expect(Number(all.rows[0]!.n)).toBe(0);

      const cov = (await repo.listCoverage(scanId)).find((c) => c.stage === "11-correlation");
      expect(cov?.status).toBe("COLLECTED");
      expect((cov?.details as { secretGroups: number }).secretGroups).toBe(1);
      expect((cov?.details as { edges: number }).edges).toBe(1);

      // Idempotency: rerun → identical counts and edges.
      await new ScanOrchestrator({ db, runner: emptyRunner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config }).runScan(scanId);
      const obs2 = await repo.listCorrelationObservations(scanId);
      const edges2 = await repo.listCorrelationEdges(scanId);
      expect(obs2.length).toBe(obs.length);
      expect(edges2.length).toBe(edges.length);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
