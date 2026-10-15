import { describe, expect, it } from "vitest";
import {
  compareScans,
  ComparisonError,
  type ComparisonSource,
  type ComparisonAssetRow,
  type ComparisonObsRow,
  type ComparisonCoverageRow,
  type ComparisonScanRow,
} from "@reconnexus/control-plane";

/** In-memory ComparisonSource: no database, fully deterministic. */
class FakeSource implements ComparisonSource {
  scans = new Map<string, ComparisonScanRow>();
  assets = new Map<string, ComparisonAssetRow[]>();
  obs = new Map<string, ComparisonObsRow[]>();
  coverage = new Map<string, ComparisonCoverageRow[]>();

  async getScan(id: string): Promise<ComparisonScanRow | null> {
    return this.scans.get(id) ?? null;
  }
  async listScanAssets(id: string, types?: string[]): Promise<ComparisonAssetRow[]> {
    return (this.assets.get(id) ?? []).filter((a) => !types || types.includes(a.type));
  }
  async listScanObservations(id: string, filter: { kinds?: string[]; kindPrefix?: string }): Promise<ComparisonObsRow[]> {
    return (this.obs.get(id) ?? []).filter(
      (o) => (!filter.kinds || filter.kinds.includes(o.kind)) && (!filter.kindPrefix || o.kind.startsWith(filter.kindPrefix)),
    );
  }
  async listCoverage(id: string): Promise<ComparisonCoverageRow[]> {
    return this.coverage.get(id) ?? [];
  }
}

function asset(type: string, value: string, canonical = value): ComparisonAssetRow {
  return { id: canonical, type, canonical_key: canonical, value };
}
function obs(kind: string, assetValue: string, data: Record<string, unknown>, observedAt = "2026-01-01T00:00:00.000Z", assetType = "SERVICE"): ComparisonObsRow {
  return { asset_type: assetType, asset_value: assetValue, canonical_key: assetValue, kind, data, source: "test", observed_at: observedAt };
}
const COLLECTED = (stage: string): ComparisonCoverageRow => ({ stage, status: "COLLECTED" });

function twoScans(project = "p", root = "example.com"): FakeSource {
  const s = new FakeSource();
  s.scans.set("A", { id: "A", project_id: project, root_domain: root });
  s.scans.set("B", { id: "B", project_id: project, root_domain: root });
  return s;
}

describe("comparison engine", () => {
  it("reports baseline-only and current-only assets, and gates removals on coverage", async () => {
    const s = twoScans();
    // Assets category covers several stages; give them all COLLECTED so removals are supported.
    const stages = ["01-target-intelligence", "02-subdomain-discovery", "03-dns-infra", "04-http-probe", "05-url-collection", "07-js-intelligence", "08-api-discovery"];
    s.coverage.set("A", stages.map(COLLECTED));
    s.coverage.set("B", stages.map(COLLECTED));
    s.assets.set("A", [asset("SUBDOMAIN", "keep.example.com"), asset("SUBDOMAIN", "old.example.com")]);
    s.assets.set("B", [asset("SUBDOMAIN", "keep.example.com"), asset("SUBDOMAIN", "new.example.com")]);

    const cmp = await compareScans(s, "A", "B", { categories: ["assets"] });
    const cat = cmp.categories[0]!;
    expect(cat.totals.ADDED).toBe(1);
    expect(cat.totals.REMOVED).toBe(1);
    expect(cat.totals.UNCHANGED).toBe(1);
    // Default output includes every outcome, ordered ADDED → REMOVED → … → UNCHANGED.
    expect(cat.changes.map((c) => `${c.outcome}:${c.assetValue}`)).toEqual([
      "ADDED:new.example.com",
      "REMOVED:old.example.com",
      "UNCHANGED:keep.example.com",
    ]);
  });

  it("does not treat a skipped stage as absence: removal becomes UNKNOWN, addition stays ADDED", async () => {
    const s = twoScans();
    s.coverage.set("A", [COLLECTED("02-subdomain-discovery")]);
    s.coverage.set("B", [{ stage: "02-subdomain-discovery", status: "NOT_ATTEMPTED" }]);
    s.assets.set("A", [asset("SUBDOMAIN", "old.example.com")]);
    s.assets.set("B", [asset("SUBDOMAIN", "new.example.com")]);

    const cmp = await compareScans(s, "A", "B", { categories: ["assets"] });
    const cat = cmp.categories[0]!;
    expect(cat.totals.ADDED).toBe(1);
    expect(cat.totals.REMOVED).toBe(0);
    expect(cat.totals.UNKNOWN).toBe(1);
    const unknown = cat.changes.find((c) => c.outcome === "UNKNOWN")!;
    expect(unknown.reason).toMatch(/not fully collected in the current scan/);
    expect(cmp.limitations.some((l) => l.code === "COVERAGE_GAP")).toBe(true);
  });

  it("distinguishes a DNS record change from a DNS failure", async () => {
    const changed = twoScans();
    changed.coverage.set("A", [COLLECTED("03-dns-infra")]);
    changed.coverage.set("B", [COLLECTED("03-dns-infra")]);
    changed.obs.set("A", [obs("dns:A", "app.example.com", { value: "203.0.113.10", status: "NOERROR" }, "2026-01-01T00:00:00.000Z", "HOST")]);
    changed.obs.set("B", [obs("dns:A", "app.example.com", { value: "203.0.113.99", status: "NOERROR" }, "2026-02-01T00:00:00.000Z", "HOST")]);
    const cmp = await compareScans(changed, "A", "B", { categories: ["dns"] });
    expect(cmp.categories[0]!.totals.CHANGED).toBe(1);
    expect(cmp.categories[0]!.changes[0]!.changedFields).toContain("value");

    const failed = twoScans();
    failed.coverage.set("A", [COLLECTED("03-dns-infra")]);
    failed.coverage.set("B", [{ stage: "03-dns-infra", status: "MISSING" }]);
    failed.obs.set("A", [obs("dns:A", "app.example.com", { value: "203.0.113.10", status: "NOERROR" }, undefined, "HOST")]);
    failed.obs.set("B", [obs("dns:A", "app.example.com", { value: "203.0.113.99", status: "NOERROR" }, undefined, "HOST")]);
    const cmp2 = await compareScans(failed, "A", "B", { categories: ["dns"] });
    expect(cmp2.categories[0]!.totals.CHANGED).toBe(0);
    expect(cmp2.categories[0]!.totals.UNKNOWN).toBe(1);
    expect(cmp2.categories[0]!.changes[0]!.reason).toMatch(/current scan/);
  });

  it("detects HTTP status/title changes and TLS rotation, preserving evidence provenance", async () => {
    const s = twoScans();
    s.coverage.set("A", [COLLECTED("04-http-probe")]);
    s.coverage.set("B", [COLLECTED("04-http-probe")]);
    s.obs.set("A", [
      obs("http", "https://app.example.com", { statusCode: 200, title: "Home", server: "nginx", finalUrl: "https://app.example.com/" }, "2026-01-01T00:00:00.000Z"),
      obs("tls", "certsha-old", { subject: "CN=app.example.com", issuer: "CN=Old CA" }, "2026-01-01T00:00:00.000Z", "CERTIFICATE"),
    ]);
    s.obs.set("B", [
      obs("http", "https://app.example.com", { statusCode: 404, title: "Home", server: "nginx", finalUrl: "https://app.example.com/" }, "2026-02-01T00:00:00.000Z"),
      obs("tls", "certsha-new", { subject: "CN=app.example.com", issuer: "CN=New CA" }, "2026-02-01T00:00:00.000Z", "CERTIFICATE"),
    ]);
    const cmp = await compareScans(s, "A", "B", { categories: ["http", "tls"] });
    const http = cmp.categories.find((c) => c.category === "http")!;
    const tls = cmp.categories.find((c) => c.category === "tls")!;
    expect(http.totals.CHANGED).toBe(1);
    expect(http.changes[0]!.changedFields).toContain("statusCode");
    expect(http.changes[0]!.baseline!.source).toBe("test");
    expect(http.changes[0]!.baseline!.observedAt).toBe("2026-01-01T00:00:00.000Z");
    // Certificate rotation = one removed + one added.
    expect(tls.totals.ADDED).toBe(1);
    expect(tls.totals.REMOVED).toBe(1);
  });

  it("detects JS content-hash and API-route changes", async () => {
    const s = twoScans();
    s.coverage.set("A", [COLLECTED("07-js-intelligence"), COLLECTED("08-api-discovery")]);
    s.coverage.set("B", [COLLECTED("07-js-intelligence"), COLLECTED("08-api-discovery")]);
    s.obs.set("A", [
      obs("js-artifact", "https://app.example.com/main.js", { contentHash: "aaaa", sizeBytes: 100, status: "RETRIEVED" }, "2026-01-01T00:00:00.000Z", "JS_ARTIFACT"),
      obs("api-endpoint", "GET https://app.example.com/api/v1", { method: "GET", origin: "https://app.example.com", path: "/api/v1", documented: true }, "2026-01-01T00:00:00.000Z", "API_ENDPOINT"),
    ]);
    s.obs.set("B", [
      obs("js-artifact", "https://app.example.com/main.js", { contentHash: "bbbb", sizeBytes: 110, status: "RETRIEVED" }, "2026-02-01T00:00:00.000Z", "JS_ARTIFACT"),
      obs("api-endpoint", "GET https://app.example.com/api/v1", { method: "GET", origin: "https://app.example.com", path: "/api/v1", documented: false }, "2026-02-01T00:00:00.000Z", "API_ENDPOINT"),
      obs("api-endpoint", "POST https://app.example.com/api/v1/users", { method: "POST", origin: "https://app.example.com", path: "/api/v1/users", documented: false }, "2026-02-01T00:00:00.000Z", "API_ENDPOINT"),
    ]);
    const cmp = await compareScans(s, "A", "B", { categories: ["js", "api"] });
    const js = cmp.categories.find((c) => c.category === "js")!;
    const api = cmp.categories.find((c) => c.category === "api")!;
    expect(js.totals.CHANGED).toBe(1);
    expect(js.changes[0]!.changedFields).toContain("contentHash");
    expect(api.totals.CHANGED).toBe(1); // documented flag changed
    expect(api.totals.ADDED).toBe(1); // new POST route
  });

  it("tracks finding resolution, regression and status change using stable identities", async () => {
    const s = twoScans();
    s.coverage.set("A", [COLLECTED("09-secret-detection"), COLLECTED("13-subdomain-takeover")]);
    s.coverage.set("B", [COLLECTED("09-secret-detection"), COLLECTED("13-subdomain-takeover")]);
    const secret = (status: string): ComparisonObsRow =>
      obs("secret-finding", "https://app.example.com/main.js", { ruleId: "aws-key", artifactUrl: "https://app.example.com/main.js", location: "12:5", fingerprint: "fp1", status }, "2026-01-01T00:00:00.000Z", "URL");
    s.obs.set("A", [secret("HIGH_CONFIDENCE"), obs("takeover-candidate", "old.example.com", { cname: "x.github.io", status: "SUSPECTED", confidence: 0.8 }, "2026-01-01T00:00:00.000Z", "SUBDOMAIN")]);
    s.obs.set("B", [secret("SUPPRESSED"), obs("takeover-candidate", "brand-new.example.com", { cname: "y.github.io", status: "CANDIDATE", confidence: 0.5 }, "2026-02-01T00:00:00.000Z", "SUBDOMAIN")]);

    const cmp = await compareScans(s, "A", "B", { categories: ["findings"] });
    const cat = cmp.categories[0]!;
    // secret status changed; old takeover removed; new takeover added.
    expect(cat.totals.CHANGED).toBe(1);
    expect(cat.totals.REMOVED).toBe(1);
    expect(cat.totals.ADDED).toBe(1);
    const changed = cat.changes.find((c) => c.outcome === "CHANGED")!;
    expect(changed.changedFields).toContain("status");
  });

  it("deduplicates observations deterministically (latest wins) and orders output stably", async () => {
    const s = twoScans();
    s.coverage.set("A", [COLLECTED("04-http-probe")]);
    s.coverage.set("B", [COLLECTED("04-http-probe")]);
    // Two observations of the same service; the later one must win.
    s.obs.set("A", [
      obs("http", "https://app.example.com", { statusCode: 200 }, "2026-01-01T00:00:00.000Z"),
      obs("http", "https://app.example.com", { statusCode: 301 }, "2026-01-02T00:00:00.000Z"),
    ]);
    s.obs.set("B", [obs("http", "https://app.example.com", { statusCode: 301 }, "2026-02-01T00:00:00.000Z")]);
    const cmp = await compareScans(s, "A", "B", { categories: ["http"] });
    // Same effective value (301) → UNCHANGED, proving the older 200 did not win.
    expect(cmp.categories[0]!.totals.UNCHANGED).toBe(1);
    expect(cmp.categories[0]!.changes[0]!.baseline!.fields.statusCode).toBe(301);
  });

  it("bounds returned rows with --limit while keeping totals exact", async () => {
    const s = twoScans();
    s.coverage.set("A", [COLLECTED("02-subdomain-discovery")]);
    s.coverage.set("B", [COLLECTED("02-subdomain-discovery")]);
    s.assets.set("A", []);
    s.assets.set("B", Array.from({ length: 50 }, (_, i) => asset("SUBDOMAIN", `h${String(i).padStart(3, "0")}.example.com`)));
    const cmp = await compareScans(s, "A", "B", { categories: ["assets"], limit: 10 });
    const cat = cmp.categories[0]!;
    expect(cat.totals.ADDED).toBe(50);
    expect(cat.changes.length).toBe(10);
    expect(cat.truncated).toBe(true);
  });

  it("rejects missing scans and cross-project comparisons", async () => {
    const s = twoScans();
    await expect(compareScans(s, "A", "ZZ", {})).rejects.toBeInstanceOf(ComparisonError);
    const other = new FakeSource();
    other.scans.set("A", { id: "A", project_id: "p1", root_domain: "a.example.com" });
    other.scans.set("B", { id: "B", project_id: "p2", root_domain: "b.example.com" });
    await expect(compareScans(other, "A", "B", {})).rejects.toMatchObject({ code: "CROSS_PROJECT" });
  });

  it("is deterministic: the same inputs produce byte-identical output", async () => {
    const s = twoScans();
    s.coverage.set("A", [COLLECTED("04-http-probe"), COLLECTED("02-subdomain-discovery")]);
    s.coverage.set("B", [COLLECTED("04-http-probe"), COLLECTED("02-subdomain-discovery")]);
    s.assets.set("A", [asset("SUBDOMAIN", "a.example.com"), asset("SUBDOMAIN", "b.example.com")]);
    s.assets.set("B", [asset("SUBDOMAIN", "b.example.com"), asset("SUBDOMAIN", "c.example.com")]);
    s.obs.set("A", [obs("http", "https://a", { statusCode: 200 })]);
    s.obs.set("B", [obs("http", "https://a", { statusCode: 301 })]);
    const fixedNow = () => new Date("2026-03-01T00:00:00.000Z");
    const first = await compareScans(s, "A", "B", { now: fixedNow });
    const second = await compareScans(s, "A", "B", { now: fixedNow });
    expect(JSON.stringify(second)).toBe(JSON.stringify(first));
  });

  it("does not report removals when the current scan failed (coverage FAILED), only UNKNOWN", async () => {
    const s = twoScans();
    // Baseline was collected; the current scan failed everywhere.
    s.coverage.set("A", [COLLECTED("02-subdomain-discovery"), COLLECTED("04-http-probe")]);
    s.coverage.set("B", [
      { stage: "02-subdomain-discovery", status: "FAILED" },
      { stage: "04-http-probe", status: "MISSING" },
    ]);
    s.assets.set("A", [asset("SUBDOMAIN", "was.example.com"), asset("SERVICE", "https://was.example.com")]);
    s.assets.set("B", []);
    const cmp = await compareScans(s, "A", "B", { categories: ["assets"] });
    const cat = cmp.categories[0]!;
    // A failed current scan must never make an asset look removed.
    expect(cat.totals.REMOVED).toBe(0);
    expect(cat.totals.UNKNOWN).toBeGreaterThan(0);
    for (const c of cat.changes) {
      if (c.baseline && !c.current) expect(c.outcome).toBe("UNKNOWN");
      if (c.outcome === "UNKNOWN") expect(c.reason).toBeTruthy();
    }
  });

  it("treats a missing coverage record as NOT_ATTEMPTED (not as absence)", async () => {
    const s = twoScans();
    // Only baseline has a coverage record; the current scan never recorded one.
    s.coverage.set("A", [COLLECTED("03-dns-infra")]);
    s.obs.set("A", [obs("dns:A", "app.example.com", { value: "203.0.113.10", status: "NOERROR" }, undefined, "HOST")]);
    const cmp = await compareScans(s, "A", "B", { categories: ["dns"] });
    const cat = cmp.categories[0]!;
    expect(cat.totals.REMOVED).toBe(0);
    expect(cat.totals.UNKNOWN).toBe(1);
    expect(cat.coverage[0]!.current).toBe("NOT_ATTEMPTED");
    expect(cat.coverage[0]!.comparable).toBe(false);
  });

  it("filters by category and status", async () => {
    const s = twoScans();
    s.coverage.set("A", [COLLECTED("04-http-probe")]);
    s.coverage.set("B", [COLLECTED("04-http-probe")]);
    s.obs.set("A", [obs("http", "https://a", { statusCode: 200 })]);
    s.obs.set("B", [obs("http", "https://a", { statusCode: 200 }), obs("http", "https://b", { statusCode: 200 })]);
    const filtered = await compareScans(s, "A", "B", { categories: ["http", "dns"], statuses: ["ADDED"] });
    // Categories keep their canonical (registry) order, not the order requested.
    expect(filtered.categories.map((c) => c.category)).toEqual(["dns", "http"]);
    const http = filtered.categories.find((c) => c.category === "http")!;
    expect(http.changes.every((c) => c.outcome === "ADDED")).toBe(true);
    // Totals still reflect every outcome.
    expect(http.totals.UNCHANGED).toBe(1);
  });
});
