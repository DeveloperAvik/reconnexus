import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDb, FakeRunner, ScanOrchestrator, ScanService, type DiscoveryRunner } from "@reconnexus/control-plane";
import { LocalArtifactStore } from "@reconnexus/evidence-contracts";
import { ScopePolicySchema, type DiscoveryJob, type DiscoveryResult } from "@reconnexus/contracts";
import { loadConfig } from "@reconnexus/configuration";
import { Logger } from "@reconnexus/logging";

/**
 * Stage 07 selection must include extensionless JavaScript discovered from `<script src>` (marked
 * `scriptRef`), while still excluding non-script assets. This wires the crawler's script-ref output
 * through persistence into the JS analysis stage input.
 */
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

function makePolicy(rootDomain: string): unknown {
  return {
    schemaVersion: 1,
    policyId: randomUUID(),
    projectId: randomUUID(),
    policyVersion: 1,
    authorization: { reference: "T", authorizedBy: "t", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["PASSIVE", "DNS", "ACTIVE_HTTP", "CRAWL", "JS_ANALYSIS"] },
    inScope: { domains: [{ value: rootDomain, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 120, maxArtifactBytes: 1048576 },
  };
}

const empty = (job: DiscoveryJob): DiscoveryResult => ({
  schemaVersion: 1,
  status: "SUCCEEDED",
  provider: job.provider,
  providerVersion: "test",
  execution: { argv: [], exitCode: 0, exitDescription: "", durationMs: 0, stdoutBytes: 0, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" },
  coverage: { attempted: 0, succeeded: 0, failed: 0, skipped: 0, unavailable: 0 },
  records: [],
  diagnostics: [],
});

describe.skipIf(!available)("Stage 07 includes extensionless <script src> references", () => {
  it("feeds scriptRef URLs and script-extension URLs to JS analysis, and excludes static assets", async () => {
    const db = createDb(config.database);
    const rand = Math.random().toString(36).slice(2, 8);
    const rootDomain = `rn-${rand}.example.net`;
    const workspace = `jsref${rand}`;
    const seen: DiscoveryJob[] = [];
    try {
      const { scanId, projectId } = await new ScanService(db).createScan({
        startUrl: `https://${rootDomain}/`,
        policy: ScopePolicySchema.parse(makePolicy(rootDomain)),
        workspaceName: workspace,
      });
      const mkUrl = async (key: string, data: Record<string, unknown>): Promise<void> => {
        const a = await db.query<{ id: string }>("INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'URL',$2,$2) RETURNING id", [projectId, key]);
        await db.query(
          `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data)
           VALUES ($1,$2,$3,'builtin-crawler','MEDIUM', now(),'url',$4::jsonb)`,
          [projectId, scanId, a.rows[0]!.id, JSON.stringify(data)],
        );
      };
      await mkUrl(`https://${rootDomain}/assets/bundle`, { url: `https://${rootDomain}/assets/bundle`, method: "CRAWL", scriptRef: true, parentUrl: `https://${rootDomain}/`, classifications: [{ category: "JAVASCRIPT", confidence: 0.6, evidenceType: "SCRIPT_REF", evidence: "script" }] });
      await mkUrl(`https://${rootDomain}/app.js`, { url: `https://${rootDomain}/app.js`, method: "CRAWL", classifications: [{ category: "JAVASCRIPT", confidence: 0.9, evidenceType: "EXTENSION", evidence: ".js" }] });
      await mkUrl(`https://${rootDomain}/img.png`, { url: `https://${rootDomain}/img.png`, method: "CRAWL", classifications: [{ category: "STATIC_ASSET", confidence: 0.9, evidenceType: "EXTENSION", evidence: ".png" }] });
      await mkUrl(`https://${rootDomain}/page`, { url: `https://${rootDomain}/page`, method: "CRAWL", classifications: [{ category: "HTML_PAGE", confidence: 0.4, evidenceType: "PATH", evidence: "no markers" }] });

      // Mark everything before Stage 07 SUCCEEDED so its dependencies are satisfied.
      await db.query(
        "UPDATE jobs SET status='SUCCEEDED' WHERE scan_id=$1 AND job_key IN ('00-input-authorization','01-target-intelligence','02-subdomain-discovery','03-dns-infra','04-http-probe','05-url-collection','06-url-categorization')",
        [scanId],
      );

      const runner: DiscoveryRunner = new FakeRunner((job) => {
        seen.push(job);
        return empty(job);
      });
      await new ScanOrchestrator({ db, runner, store: new LocalArtifactStore(config.artifacts.root), logger: log, config }).runScan(scanId);

      const jsJob = seen.find((j) => j.kind === "JS_ANALYSIS");
      expect(jsJob).toBeTruthy();
      const jsUrls = jsJob!.inputs.jsUrls ?? [];
      expect(jsUrls).toContain(`https://${rootDomain}/assets/bundle`);
      expect(jsUrls).toContain(`https://${rootDomain}/app.js`);
      expect(jsUrls).not.toContain(`https://${rootDomain}/img.png`);
      expect(jsUrls).not.toContain(`https://${rootDomain}/page`);
    } finally {
      await db.query("DELETE FROM projects WHERE root_domain=$1", [rootDomain]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [workspace]).catch(() => undefined);
      await db.close();
    }
  });
});
