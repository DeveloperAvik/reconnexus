import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDb, ScanService } from "@reconnexus/control-plane";
import { ScopePolicySchema, ExitCode } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";
import { loadContext } from "../../apps/cli/src/context.js";
import { findingsCommand } from "../../apps/cli/src/commands/findings.js";
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
    authorization: {
      reference: "T",
      authorizedBy: "t",
      validFrom: "2020-01-01T00:00:00.000Z",
      validUntil: "2999-01-01T00:00:00.000Z",
      capabilities: ["PASSIVE", "ACTIVE_HTTP", "SECRET_SCAN", "TAKEOVER_CHECK"],
    },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

describe.skipIf(!available)("findings CLI command", () => {
  it("derives findings from secret and takeover candidates; filters; redacted JSON envelope; missing scan errors", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const artifact = `https://${rootDomain}/app.js`;
    const sub = `blog.${rootDomain}`;
    const workspace = `find${rand}`;
    try {
      const created = await new ScanService(db).createScan({ startUrl: `https://${rootDomain}/`, policy: ScopePolicySchema.parse(policy(rootDomain)), workspaceName: workspace });
      const { scanId, projectId } = created;

      const jsAsset = await db.query<{ id: string }>("INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'URL',$2,$2) RETURNING id", [projectId, artifact]);
      await db.query(
        `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
         VALUES ($1,$2,$3,'builtin-secret-scan','MEDIUM', now(),'secret-finding',$4::jsonb)`,
        [
          projectId,
          scanId,
          jsAsset.rows[0]!.id,
          JSON.stringify({ ruleId: "aws-access-key-id", category: "CLOUD_CREDENTIAL", status: "HIGH_CONFIDENCE", confidence: 0.95, host: rootDomain, location: "2:5", redactedSnippet: "x='[REDACTED]'" }),
        ],
      );

      const subAsset = await db.query<{ id: string }>("INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'SUBDOMAIN',$2,$2) RETURNING id", [projectId, sub]);
      await db.query(
        `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
         VALUES ($1,$2,$3,'builtin-takeover','MEDIUM', now(),'takeover-candidate',$4::jsonb)`,
        [projectId, scanId, subAsset.rows[0]!.id, JSON.stringify({ cname: "user.github.io", service: "GitHub Pages", status: "SUSPECTED", confidence: 0.8, httpStatus: 404, evidence: "CNAME -> user.github.io; HTTP 404; unmarked" })],
      );
      // NOT_VULNERABLE takeovers stay inventory, never a finding.
      const subAsset2 = await db.query<{ id: string }>("INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'SUBDOMAIN',$2,$2) RETURNING id", [projectId, `clean.${rootDomain}`]);
      await db.query(
        `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
         VALUES ($1,$2,$3,'builtin-takeover','MEDIUM', now(),'takeover-candidate',$4::jsonb)`,
        [projectId, scanId, subAsset2.rows[0]!.id, JSON.stringify({ cname: "legit.example.com", service: "", status: "NOT_VULNERABLE", confidence: 0.1, httpStatus: 200, evidence: "resolved and serving" })],
      );

      const all = await findingsCommand(ctx, scanId, {});
      expect(all.exitCode).toBe(ExitCode.SUCCESS);
      expect((all.data as { total: number }).total).toBe(2);

      const highSev = await findingsCommand(ctx, scanId, { severity: "HIGH" });
      expect((highSev.data as { total: number }).total).toBe(2); // both the cloud credential and the suspected takeover are HIGH

      const takeoverOnly = await findingsCommand(ctx, scanId, { category: "SUBDOMAIN_TAKEOVER" });
      expect((takeoverOnly.data as { total: number }).total).toBe(1);

      const bySubject = await findingsCommand(ctx, scanId, { subject: sub });
      expect((bySubject.data as { total: number }).total).toBe(1);

      const none = await findingsCommand(ctx, scanId, { category: "DOES_NOT_EXIST" });
      expect((none.data as { total: number }).total).toBe(0);

      // Rendered output never prints a raw secret value; the evidence field in the structured
      // data is the already-redacted snippet carried over from secret-finding, never the raw one.
      const rendered = all.render ? all.render() : "";
      expect(rendered).not.toMatch(/AKIA[0-9A-Z]{16}/);
      expect(rendered).toContain("HIGH");
      const secretFinding = (all.data as { findings: Array<{ category: string; evidence: string }> }).findings.find((f) => f.category === "CLOUD_CREDENTIAL");
      expect(secretFinding?.evidence).toContain("[REDACTED");

      const env = JSON.parse(JSON.stringify(makeEnvelope("findings", all)));
      expect(env.ok).toBe(true);
      expect(env.exitCode).toBe(0);
      expect(JSON.stringify(env)).not.toMatch(/AKIA[0-9A-Z]{16}/);
      // Never a validated finding: ReconNexus performs no exploitation and verifies no credential.
      expect(JSON.stringify(env)).not.toContain('"validation":"VALIDATED"');

      await expect(findingsCommand(ctx, "00000000-0000-0000-0000-000000000000", {})).rejects.toBeInstanceOf(CliError);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
