import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDb, ingestDiscoveryResult, insertObservation, migrate, type Db } from "@reconnexus/control-plane";
import { LocalArtifactStore } from "@reconnexus/evidence-contracts";
import { loadConfig } from "@reconnexus/configuration";
import type { DiscoveryRecord, DiscoveryResult } from "@reconnexus/contracts";

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

function result(records: unknown[]): DiscoveryResult {
  return {
    schemaVersion: 1,
    status: "SUCCEEDED",
    provider: "test",
    providerVersion: "test",
    execution: { argv: ["test"], exitCode: 0, exitDescription: "", durationMs: 1, stdoutBytes: 1, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" },
    coverage: { attempted: 1, succeeded: 1, failed: 0, skipped: 0, unavailable: 0 },
    records: records as DiscoveryRecord[],
    diagnostics: [],
  } as DiscoveryResult;
}

interface Fixture { projectId: string; scanId: string; rootDomain: string; policyId: string }

async function makeScan(db: Db, f: { projectId: string; policyId: string; rootDomain: string }): Promise<string> {
  const scan = await db.query<{ id: string }>(
    "INSERT INTO scan_runs (project_id, policy_id, start_url, root_domain) VALUES ($1,$2,$3,$4) RETURNING id",
    [f.projectId, f.policyId, `https://${f.rootDomain}/`, f.rootDomain],
  );
  return scan.rows[0]!.id;
}

async function setup(db: Db): Promise<Fixture & { cleanup: () => Promise<void> }> {
  const name = `idem-${randomUUID().slice(0, 8)}`;
  const rootDomain = `${name}.example.net`;
  const ws = await db.query<{ id: string }>("INSERT INTO workspaces (name) VALUES ($1) RETURNING id", [name]);
  const project = await db.query<{ id: string }>("INSERT INTO projects (workspace_id, name, root_domain) VALUES ($1,$2,$3) RETURNING id", [ws.rows[0]!.id, name, rootDomain]);
  const projectId = project.rows[0]!.id;
  const policy = await db.query<{ id: string }>("INSERT INTO scope_policies (project_id, version, document) VALUES ($1,1,'{}'::jsonb) RETURNING id", [projectId]);
  const policyId = policy.rows[0]!.id;
  const scanId = await makeScan(db, { projectId, policyId, rootDomain });
  return {
    projectId, scanId, rootDomain, policyId,
    cleanup: async () => {
      await db.query("DELETE FROM projects WHERE id=$1", [projectId]).catch(() => undefined);
      await db.query("DELETE FROM workspaces WHERE name=$1", [name]).catch(() => undefined);
    },
  };
}

const count = async (db: Db, scanId: string): Promise<number> =>
  Number((await db.query<{ n: string }>("SELECT count(*) AS n FROM observations WHERE scan_id=$1", [scanId])).rows[0]!.n);
const links = async (db: Db, projectId: string): Promise<number> =>
  Number((await db.query<{ n: string }>("SELECT count(*) AS n FROM evidence_links WHERE project_id=$1", [projectId])).rows[0]!.n);

describe.skipIf(!available)("observation idempotency (unique identity backstop)", () => {
  const store = new LocalArtifactStore(config.artifacts.root);

  it("ingesting the same DiscoveryResult twice, bypassing the orchestrator guard, adds no observations", async () => {
    const db = createDb(config.database);
    await migrate(db, config.migrationsDir);
    const f = await setup(db);
    const r = f.rootDomain;
    const sub = `www.${r}`;
    const records = [
      { type: "HOST_OBSERVATION", host: sub, source: "subfinder", provider: "subfinder", status: "RESOLVED", addresses: ["192.0.2.1"], notes: "" },
      { type: "DNS_RECORD", name: sub, recordType: "A", value: "192.0.2.1", ttl: 60, status: "NOERROR", resolver: "1.1.1.1", error: "" },
      { type: "DNS_RECORD", name: sub, recordType: "A", value: "192.0.2.2", ttl: 60, status: "NOERROR", resolver: "1.1.1.1", error: "" },
      { type: "DNS_RECORD", name: "1.2.0.192.in-addr.arpa", recordType: "PTR", value: sub, ttl: null, status: "NOERROR", resolver: "1.1.1.1", error: "" },
      { type: "IP_METADATA", ip: "192.0.2.1", prefix: "192.0.2.0/24", asn: 64500, asnOrg: "X", networkName: "n", country: "ZZ", source: "rdap", confidence: 0.8, limitations: [] },
      { type: "TECHNOLOGY", url: `https://${sub}/`, host: sub, provider: "fp", technology: { name: "nginx", category: "SERVER", evidenceType: "HEADER", evidence: "server: nginx", confidence: 0.9 } },
      { type: "TAKEOVER_CANDIDATE", host: sub, cname: "x.github.io", service: "GitHub Pages", status: "SUSPECTED", confidence: 0.8, httpStatus: 404, evidence: "e", evidenceType: "T", provider: "tk", source: "takeover" },
      { type: "HTTP_OBSERVATION", url: `https://${sub}/`, host: sub, provider: "http", source: "http", http: { finalUrl: `https://${sub}/`, statusCode: 200, statusText: "OK", contentType: "text/html", title: "t", headers: { server: "nginx" }, redirectChain: [], tls: { sha256: "a".repeat(64) }, probeStatus: "OK", error: "", bodyTruncated: false } },
    ];
    try {
      const res = result(records);
      const first = await ingestDiscoveryResult(db, store, { projectId: f.projectId, scanId: f.scanId, rootDomain: r, provider: "test", result: res, observedAt: new Date("2026-01-01T00:00:00Z") });
      const afterFirst = await count(db, f.scanId);
      const linksFirst = await links(db, f.projectId);
      expect(afterFirst).toBe(first.observations);
      expect(afterFirst).toBeGreaterThanOrEqual(8);

      // Replay with a later timestamp: same facts, so no growth, nothing counted, no duplicate evidence links.
      const second = await ingestDiscoveryResult(db, store, { projectId: f.projectId, scanId: f.scanId, rootDomain: r, provider: "test", result: res, observedAt: new Date("2026-01-02T00:00:00Z") });
      expect(await count(db, f.scanId)).toBe(afterFirst);
      expect(second.observations).toBe(0);
      expect(second.observationIds).toEqual([]);
      expect(await links(db, f.projectId)).toBe(linksFirst);

      // The replay widens last_seen on the surviving rows, and keeps observed_at.
      const row = await db.query<{ observed_at: Date; last_seen: Date }>("SELECT observed_at, last_seen FROM observations WHERE scan_id=$1 AND kind='host'", [f.scanId]);
      expect(row.rows[0]!.observed_at.toISOString()).toBe("2026-01-01T00:00:00.000Z");
      expect(row.rows[0]!.last_seen.toISOString()).toBe("2026-01-02T00:00:00.000Z");
    } finally {
      await f.cleanup();
      await db.close();
    }
  });

  it("keeps distinct kinds, sources, payloads, assets and scans separate", async () => {
    const db = createDb(config.database);
    await migrate(db, config.migrationsDir);
    const f = await setup(db);
    const sub = `a.${f.rootDomain}`;
    const dns = (value: string, ttl: number, status = "NOERROR") => ({ type: "DNS_RECORD", name: sub, recordType: "A", value, ttl, status, resolver: "1.1.1.1", error: "" });
    const host = (source: string, status: string) => ({ type: "HOST_OBSERVATION", host: sub, source, provider: source, status, addresses: [], notes: "" });
    try {
      const ingest = (scanId: string, records: unknown[]) =>
        ingestDiscoveryResult(db, store, { projectId: f.projectId, scanId, rootDomain: f.rootDomain, provider: "test", result: result(records), observedAt: new Date() });

      // different value / ttl / status on the same asset, kind and source => distinct
      await ingest(f.scanId, [dns("192.0.2.1", 60), dns("192.0.2.2", 60), dns("192.0.2.1", 300), dns("192.0.2.1", 60, "TIMEOUT")]);
      expect(await count(db, f.scanId)).toBe(4);

      // same asset, different providers (sources) and status => distinct
      await ingest(f.scanId, [host("subfinder", "RESOLVED"), host("amass", "RESOLVED"), host("subfinder", "UNRESOLVED")]);
      expect(await count(db, f.scanId)).toBe(7);

      // exact repeats inside a single result collapse to one
      await ingest(f.scanId, [dns("198.51.100.9", 1), dns("198.51.100.9", 1)]);
      expect(await count(db, f.scanId)).toBe(8);

      // same facts in a later scan are new history, not merged
      const scan2 = await makeScan(db, f);
      await ingest(scan2, [dns("192.0.2.1", 60)]);
      expect(await count(db, scan2)).toBe(1);
      expect(await count(db, f.scanId)).toBe(8);

      // same data but different kind or source on one asset => distinct; jsonb key order is irrelevant
      const a = (await db.query<{ id: string }>("SELECT id FROM assets WHERE project_id=$1 AND canonical_key=$2", [f.projectId, sub])).rows[0]!.id;
      const base = { projectId: f.projectId, scanId: f.scanId, assetId: a, sourceReliability: "HIGH" as const, observedAt: new Date() };
      const id1 = await insertObservation(db, { ...base, source: "s", kind: "k1", data: { x: 1, y: 2 } });
      const id2 = await insertObservation(db, { ...base, source: "s", kind: "k2", data: { x: 1, y: 2 } });
      const id3 = await insertObservation(db, { ...base, source: "t", kind: "k1", data: { x: 1, y: 2 } });
      const id4 = await insertObservation(db, { ...base, source: "s", kind: "k1", data: { y: 2, x: 1 } });
      expect(new Set([id1, id2, id3]).size).toBe(3);
      expect(id4).toBe(id1);
    } finally {
      await f.cleanup();
      await db.close();
    }
  });

  it("is safe under concurrent ingestion of the same result", async () => {
    const db = createDb(config.database);
    await migrate(db, config.migrationsDir);
    const f = await setup(db);
    const sub = `c.${f.rootDomain}`;
    const records = Array.from({ length: 10 }, (_, i) => ({ type: "DNS_RECORD", name: sub, recordType: "A", value: `192.0.2.${i + 1}`, ttl: 60, status: "NOERROR", resolver: "r", error: "" }));
    try {
      const run = () => ingestDiscoveryResult(db, store, { projectId: f.projectId, scanId: f.scanId, rootDomain: f.rootDomain, provider: "test", result: result(records), observedAt: new Date() });
      const outs = await Promise.all([run(), run(), run(), run(), run()]);
      expect(await count(db, f.scanId)).toBe(10);
      expect(outs.reduce((n, o) => n + o.observations, 0)).toBe(10);
    } finally {
      await f.cleanup();
      await db.close();
    }
  });

  it("enforces uniqueness at the database level for raw inserts", async () => {
    const db = createDb(config.database);
    await migrate(db, config.migrationsDir);
    const f = await setup(db);
    try {
      const a = (await db.query<{ id: string }>("INSERT INTO assets (project_id,type,canonical_key,value) VALUES ($1,'DOMAIN',$2,$2) RETURNING id", [f.projectId, f.rootDomain])).rows[0]!.id;
      const sql = `INSERT INTO observations (project_id,scan_id,asset_id,source,source_reliability,observed_at,kind,data) VALUES ($1,$2,$3,'s','HIGH',now(),'k','{"a":1}'::jsonb)`;
      await db.query(sql, [f.projectId, f.scanId, a]);
      await expect(db.query(sql, [f.projectId, f.scanId, a])).rejects.toThrow(/observations_identity_uidx/);
    } finally {
      await f.cleanup();
      await db.close();
    }
  });
});
