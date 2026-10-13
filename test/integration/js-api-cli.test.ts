import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDb, ScanService } from "@reconnexus/control-plane";
import { ScopePolicySchema, ExitCode } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";
import { loadContext } from "../../apps/cli/src/context.js";
import { apisCommand, jsCommand, specsCommand } from "../../apps/cli/src/commands/js.js";
import { paramsCommand } from "../../apps/cli/src/commands/urls.js";
import { makeEnvelope } from "../../apps/cli/src/output.js";

const config = loadConfig({ cwd: process.cwd() });
const ctx = loadContext({});

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

function policy(rootDomain: string): unknown {
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

describe.skipIf(!available)("js/api CLI commands", () => {
  it("lists JS artifacts, endpoints and specs, and aggregates parameters", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const host = `app.${rootDomain}`;
    const workspace = `jscli${rand}`;
    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${host}/`, policy: ScopePolicySchema.parse(policy(rootDomain)), workspaceName: workspace });
      const { scanId, projectId } = created;

      const obs = async (type: string, key: string, value: string, kind: string, data: Record<string, unknown>): Promise<void> => {
        const a = await db.query<{ id: string }>(`INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,$2,$3,$4) RETURNING id`, [projectId, type, key, value]);
        await db.query(
          `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
           VALUES ($1,$2,$3,'builtin-js','MEDIUM', now(),$4,$5::jsonb)`,
          [projectId, scanId, a.rows[0]!.id, kind, JSON.stringify(data)],
        );
      };
      await obs("JS_ARTIFACT", `https://${host}/app.js`, `https://${host}/app.js`, "js-artifact", { contentHash: "c".repeat(64), sizeBytes: 10, status: "RETRIEVED", sourceUrl: `https://${host}/` });
      await obs("API_ENDPOINT", `GET https://${host}/api/users`, `GET /api/users`, "api-endpoint", { method: "GET", origin: `https://${host}`, path: "/api/users", discoveredVia: "JS", documented: false, resolved: true, parameters: [{ name: "page", location: "query", required: false, type: "" }] });
      await obs("URL", `https://${host}/openapi.json`, `https://${host}/openapi.json`, "api-spec", { specVersion: "openapi:3.0.0", parseStatus: "PARSED", pathCount: 1, operationCount: 1, title: "T" });

      const js = await jsCommand(ctx, scanId, {});
      expect(js.exitCode).toBe(ExitCode.SUCCESS);
      expect((js.data as { total: number }).total).toBe(1);

      const apis = await apisCommand(ctx, scanId, {});
      expect((apis.data as { total: number }).total).toBe(1);
      const via = await apisCommand(ctx, scanId, { via: "SPEC" });
      expect((via.data as { total: number }).total).toBe(0);
      const method = await apisCommand(ctx, scanId, { method: "get" });
      expect((method.data as { total: number }).total).toBe(1);

      const specs = await specsCommand(ctx, scanId);
      expect((specs.data as { total: number }).total).toBe(1);

      const params = await paramsCommand(ctx, scanId);
      expect((params.data as { parameters: Array<{ name: string }> }).parameters.some((p) => p.name === "page")).toBe(true);

      const env = JSON.parse(JSON.stringify(makeEnvelope("apis", apis)));
      expect(env.ok).toBe(true);
      expect(env.exitCode).toBe(0);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
