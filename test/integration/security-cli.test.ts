import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDb, ScanService } from "@reconnexus/control-plane";
import { ScopePolicySchema, ExitCode } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";
import { loadContext } from "../../apps/cli/src/context.js";
import { securityCommand } from "../../apps/cli/src/commands/security.js";
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
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "ACTIVE_HTTP", "SECURITY_CHECKS"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

describe.skipIf(!available)("security CLI command", () => {
  it("lists and filters security metadata; JSON envelope; missing scan errors", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const origin = `https://${rootDomain}`;
    const workspace = `seccli${rand}`;
    try {
      const created = await new ScanService(db).createScan({ startUrl: `${origin}/`, policy: ScopePolicySchema.parse(policy(rootDomain)), workspaceName: workspace });
      const { scanId, projectId } = created;
      const svc = await db.query<{ id: string }>("INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'SERVICE',$2,$2) RETURNING id", [projectId, origin]);
      const add = (data: Record<string, unknown>): Promise<unknown> =>
        db.query(
          `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
           VALUES ($1,$2,$3,'builtin-security-meta','HIGH', now(),'security-metadata',$4::jsonb)`,
          [projectId, scanId, svc.rows[0]!.id, JSON.stringify(data)],
        );
      await add({ category: "HSTS", name: "strict-transport-security", status: "OBSERVED", observed: true, value: "", detail: { maxAge: 100 } });
      await add({ category: "CORS", name: "cors", status: "INCONSISTENT", observed: true, value: "*", detail: { wildcard: true }, consistent: false });
      await add({ category: "HEADER", name: "x-frame-options", status: "NOT_OBSERVED", observed: false, value: "", detail: {} });

      const all = await securityCommand(ctx, scanId, {});
      expect(all.exitCode).toBe(ExitCode.SUCCESS);
      expect((all.data as { total: number }).total).toBe(3);

      const cors = await securityCommand(ctx, scanId, { category: "cors" });
      expect((cors.data as { total: number }).total).toBe(1);

      const inconsistent = await securityCommand(ctx, scanId, { status: "INCONSISTENT" });
      expect((inconsistent.data as { total: number }).total).toBe(1);

      const byHost = await securityCommand(ctx, scanId, { host: rootDomain });
      expect((byHost.data as { total: number }).total).toBe(3);

      const env = JSON.parse(JSON.stringify(makeEnvelope("security", all)));
      expect(env.ok).toBe(true);
      expect(env.exitCode).toBe(0);

      await expect(securityCommand(ctx, "00000000-0000-0000-0000-000000000000", {})).rejects.toBeInstanceOf(CliError);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
