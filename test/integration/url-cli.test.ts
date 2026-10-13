import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDb, ScanService } from "@reconnexus/control-plane";
import { ScopePolicySchema } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";
import { ExitCode } from "@reconnexus/contracts";
import { loadContext } from "../../apps/cli/src/context.js";
import { paramsCommand, urlsListCommand } from "../../apps/cli/src/commands/urls.js";
import { makeEnvelope } from "../../apps/cli/src/output.js";
import { CliError } from "../../apps/cli/src/errors.js";

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
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "DNS", "ACTIVE_HTTP", "CRAWL"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

describe.skipIf(!available)("url CLI commands", () => {
  it("lists and filters URLs, reports parameters, and emits JSON", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const workspace = `urlcli-${rand}`;
    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${rootDomain}/`, policy: ScopePolicySchema.parse(policy(rootDomain)), workspaceName: workspace });
      const { scanId, projectId } = created;
      const seed = async (url: string, data: Record<string, unknown>): Promise<void> => {
        const a = await db.query<{ id: string }>(
          "INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'URL',$2,$2) RETURNING id",
          [projectId, url],
        );
        await db.query(
          `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
           VALUES ($1,$2,$3,'builtin-crawler','MEDIUM', now(),'url',$4::jsonb)`,
          [projectId, scanId, a.rows[0]!.id, JSON.stringify(data)],
        );
      };
      await seed(`https://${rootDomain}/`, { method: "CRAWL", host: rootDomain, statusCode: 200, provider: "builtin-crawler", classifications: [{ category: "HTML_PAGE", confidence: 0.4, evidenceType: "PATH", evidence: "x" }], parameters: [] });
      await seed(`https://${rootDomain}/admin`, { method: "CRAWL", host: rootDomain, statusCode: 200, provider: "builtin-crawler", classifications: [{ category: "ADMIN", confidence: 0.6, evidenceType: "PATH", evidence: "x" }], parameters: [{ name: "page", roles: [{ role: "pagination", confidence: 0.7, evidence: "y" }] }] });

      const all = await urlsListCommand(ctx, scanId, {});
      expect(all.exitCode).toBe(ExitCode.SUCCESS);
      expect((all.data as { total: number }).total).toBe(2);

      const adminOnly = await urlsListCommand(ctx, scanId, { category: "ADMIN" });
      expect((adminOnly.data as { total: number }).total).toBe(1);

      const paramFiltered = await urlsListCommand(ctx, scanId, { param: "page" });
      expect((paramFiltered.data as { total: number }).total).toBe(1);

      const stats = await urlsListCommand(ctx, scanId, { stats: true });
      const s = (stats.data as { stats: { uniqueCanonical: number; rawObservations: number } }).stats;
      expect(s.rawObservations).toBe(2);
      expect(s.uniqueCanonical).toBe(2);

      const params = await paramsCommand(ctx, scanId);
      expect((params.data as { distinct: number }).distinct).toBe(1);

      // JSON envelope contract.
      const env = makeEnvelope("urls", all);
      const round = JSON.parse(JSON.stringify(env));
      expect(round.ok).toBe(true);
      expect(round.exitCode).toBe(0);

      await expect(urlsListCommand(ctx, "00000000-0000-0000-0000-000000000000", {})).rejects.toBeInstanceOf(CliError);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
