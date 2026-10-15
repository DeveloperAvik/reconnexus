import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { buildReport, createDb, formatReport, renderReportHtml, Repository, ScanService } from "@reconnexus/control-plane";
import { ScopePolicySchema } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";

/**
 * Regression for the "942 API endpoints vs 9 records" report inconsistency. The summary counted
 * every `api-endpoint` observation (across the JS stage and the API-spec stage, with duplicates),
 * while the provider record count was per-provider. The report now counts distinct endpoints by
 * canonical identity and exposes the raw observation count and per-source breakdown alongside it.
 */
const config = loadConfig({ cwd: process.cwd() });
const FROZEN = () => new Date("2026-01-01T00:00:00.000Z");

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

function makePolicy(rootDomain: string): unknown {
  return {
    schemaVersion: 1,
    policyId: randomUUID(),
    projectId: randomUUID(),
    policyVersion: 1,
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "DNS", "ACTIVE_HTTP"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

describe.skipIf(!available)("API endpoint accounting is deduplicated and reconciled", () => {
  it("counts distinct endpoints, not raw observations, and discloses the breakdown", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const workspace = `api${rand}`;
    try {
      const { scanId, projectId } = await new ScanService(db).createScan({
        startUrl: `https://${rootDomain}/`,
        policy: ScopePolicySchema.parse(makePolicy(rootDomain)),
        workspaceName: workspace,
      });
      const origin = `https://${rootDomain}`;
      const mkEndpoint = async (key: string): Promise<string> => {
        const r = await db.query<{ id: string }>("INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'API_ENDPOINT',$2,$2) RETURNING id", [projectId, key]);
        return r.rows[0]!.id;
      };
      const obs = (assetId: string, data: Record<string, unknown>, source: string): Promise<unknown> =>
        db.query(
          `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
           VALUES ($1,$2,$3,$4,'MEDIUM', now(),'api-endpoint',$5::jsonb)`,
          [projectId, scanId, assetId, source, JSON.stringify(data)],
        );

      // Endpoint A observed by BOTH the JS stage and the API-spec stage (2 observations, 1 endpoint).
      const aId = await mkEndpoint(`GET ${origin}/api/v1/users`);
      await obs(aId, { method: "GET", origin, path: "/api/v1/users", discoveredVia: "JS", provider: "builtin-js", documented: false, resolved: true }, "builtin-js");
      await obs(aId, { method: "GET", origin, path: "/api/v1/users", discoveredVia: "SPEC", provider: "builtin-api", documented: true, resolved: true }, "builtin-api");
      // Endpoint B observed once.
      const bId = await mkEndpoint(`POST ${origin}/api/v1/orders`);
      await obs(bId, { method: "POST", origin, path: "/api/v1/orders", discoveredVia: "JS", provider: "builtin-js", documented: false, resolved: true }, "builtin-js");

      await db.query("UPDATE jobs SET status='SUCCEEDED' WHERE scan_id=$1", [scanId]);
      await db.query("UPDATE scan_runs SET status='SUCCEEDED' WHERE id=$1", [scanId]);

      const report = await buildReport(new Repository(db), scanId, { now: FROZEN() });
      expect(report).toBeTruthy();
      // 3 raw observations, 2 distinct endpoints.
      expect(report!.observationCounts.byKind["api-endpoint"]).toBe(3);
      expect(report!.reconciliation.endpointRawObservations).toBe(3);
      expect(report!.reconciliation.endpointDistinct).toBe(2);
      expect(report!.inventory.apis.total).toBe(2);
      expect(report!.inventory.apis.rows.length).toBe(2);
      // The documented observation is the one surfaced for the shared endpoint.
      const shared = report!.inventory.apis.rows.find((r) => r.path === "/api/v1/users");
      expect(shared?.documented).toBe(true);
      // Breakdown by source and provider is present and explains the raw vs distinct gap.
      expect(report!.reconciliation.endpointsBySource.JS).toBe(2);
      expect(report!.reconciliation.endpointsBySource.SPEC).toBe(1);
      expect(report!.reconciliation.endpointsByProvider["builtin-js"]).toBe(2);
      expect(report!.reconciliation.endpointsByProvider["builtin-api"]).toBe(1);
      // The reconciliation is surfaced in the rendered outputs, not only the JSON model.
      expect(formatReport(report!, "human")).toContain("raw=3 distinct=2");
      expect(renderReportHtml(report!)).toContain("Endpoint reconciliation");
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
