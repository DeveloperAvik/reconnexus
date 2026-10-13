import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDb, ScanService } from "@reconnexus/control-plane";
import { ScopePolicySchema, ExitCode } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";
import { loadContext } from "../../apps/cli/src/context.js";
import { secretsCommand } from "../../apps/cli/src/commands/secrets.js";
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
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "ACTIVE_HTTP", "SECRET_SCAN"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

describe.skipIf(!available)("secrets CLI command", () => {
  it("lists and filters redacted findings; JSON envelope; missing scan errors", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const artifact = `https://${rootDomain}/app.js`;
    const workspace = `secc${rand}`;
    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${rootDomain}/`, policy: ScopePolicySchema.parse(policy(rootDomain)), workspaceName: workspace });
      const { scanId, projectId } = created;
      const asset = await db.query<{ id: string }>("INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'URL',$2,$2) RETURNING id", [projectId, artifact]);
      const add = (data: Record<string, unknown>): Promise<unknown> =>
        db.query(
          `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
           VALUES ($1,$2,$3,'builtin-secret-scan','MEDIUM', now(),'secret-finding',$4::jsonb)`,
          [projectId, scanId, asset.rows[0]!.id, JSON.stringify(data)],
        );
      await add({ ruleId: "aws-access-key-id", category: "CLOUD_CREDENTIAL", status: "HIGH_CONFIDENCE", confidence: 0.95, artifactUrl: artifact, host: rootDomain, location: "2:5", redactedSnippet: "x='[REDACTED]'", fingerprint: "f1", occurrences: 1 });
      await add({ ruleId: "password-assignment", category: "PASSWORD", status: "SUPPRESSED", confidence: 0.5, artifactUrl: artifact, host: rootDomain, location: "9:1", redactedSnippet: "password='[REDACTED]'", fingerprint: "f2", occurrences: 1, suppressionReason: "placeholder/example value" });

      const all = await secretsCommand(ctx, scanId, {});
      expect(all.exitCode).toBe(ExitCode.SUCCESS);
      expect((all.data as { total: number }).total).toBe(2);

      const high = await secretsCommand(ctx, scanId, { status: "HIGH_CONFIDENCE" });
      expect((high.data as { total: number }).total).toBe(1);

      const byRule = await secretsCommand(ctx, scanId, { rule: "password-assignment" });
      expect((byRule.data as { total: number }).total).toBe(1);

      const byConf = await secretsCommand(ctx, scanId, { confidence: 0.9 });
      expect((byConf.data as { total: number }).total).toBe(1);

      // Rendered output is redacted-only.
      const rendered = all.render ? all.render() : "";
      expect(rendered).toContain("[REDACTED");
      expect(rendered).not.toMatch(/AKIA[0-9A-Z]{16}/);

      const env = JSON.parse(JSON.stringify(makeEnvelope("secrets", all)));
      expect(env.ok).toBe(true);
      expect(env.exitCode).toBe(0);
      expect(JSON.stringify(env)).not.toMatch(/AKIA[0-9A-Z]{16}/);

      await expect(secretsCommand(ctx, "00000000-0000-0000-0000-000000000000", {})).rejects.toBeInstanceOf(CliError);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
