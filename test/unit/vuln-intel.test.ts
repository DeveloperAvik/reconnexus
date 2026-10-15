import { describe, expect, it } from "vitest";
import {
  ApplicabilityState,
  StaticAdvisorySource,
  VersionCertainty,
  correlateTechnologies,
  fingerprintFromTechnology,
  type AdvisoryRecord,
  type TechnologyFingerprint,
  type VulnerabilitySource,
} from "@reconnexus/control-plane";

function advisory(partial: Partial<AdvisoryRecord> & { cveId: string; productKey: string }): AdvisoryRecord {
  return {
    vendor: "",
    affected: "",
    ranges: [],
    kev: false,
    sourceUrl: `https://nvd.nist.gov/vuln/detail/${partial.cveId}`,
    source: "test",
    ...partial,
  };
}

function fp(name: string, evidence: string, host = "app.example.com", evidenceType = "HEADER"): TechnologyFingerprint {
  return fingerprintFromTechnology({ name, host, category: "WEB_SERVER", evidenceType, evidence, confidence: 0.8 });
}

const NGINX = (o: Partial<AdvisoryRecord> = {}): AdvisoryRecord =>
  advisory({ cveId: "CVE-2021-0001", productKey: "nginx", affected: ">=1.0.0 <1.25.3", ranges: [[{ op: ">=", version: "1.0.0" }, { op: "<", version: "1.25.3" }]], cvss: { version: "3.1", score: 9.8, severity: "CRITICAL", vector: "AV:N" }, ...o });

describe("CVE intelligence engine", () => {
  it("1. flags an exact observed version inside an affected range as MATCH_CANDIDATE (never validated)", async () => {
    const src = new StaticAdvisorySource([NGINX()]);
    const report = await correlateTechnologies("s", [fp("nginx", "server: nginx/1.18.0")], src);
    expect(report.matches).toHaveLength(1);
    const m = report.matches[0]!;
    expect(m.cveId).toBe("CVE-2021-0001");
    expect(m.applicability).toBe(ApplicabilityState.MATCH_CANDIDATE);
    // No state can be VALIDATED automatically.
    expect(report.matches.every((x) => x.applicability !== ApplicabilityState.VALIDATED)).toBe(true);
    expect(m.cvss?.score).toBe(9.8);
  });

  it("2. treats a version outside the affected range as NOT_APPLICABLE and does not list it", async () => {
    const src = new StaticAdvisorySource([NGINX()]);
    const report = await correlateTechnologies("s", [fp("nginx", "server: nginx/1.26.0")], src);
    expect(report.matches).toHaveLength(0);
    expect(report.coverage.notApplicable).toBe(1);
  });

  it("3. refuses to pick a CPE: an ambiguous product needs applicability review", async () => {
    const src = new StaticAdvisorySource([advisory({ cveId: "CVE-2022-0002", productKey: "angular", affected: ">=1.0 <2.0", ranges: [[{ op: ">=", version: "1.0" }, { op: "<", version: "2.0" }]] })]);
    const report = await correlateTechnologies("s", [fp("angular", "x-powered-by: angular/1.8.0")], src);
    expect(report.matches[0]!.applicability).toBe(ApplicabilityState.NEEDS_APPLICABILITY_REVIEW);
  });

  it("3b. an ambiguous product with no advisories is surfaced, not silently dropped (NVD path)", async () => {
    // angular maps to two plausible CPEs, so no CPE is queried. A source that returns nothing (as
    // NVD does for a null CPE) must not make the ambiguity disappear.
    const src = new StaticAdvisorySource([]);
    const report = await correlateTechnologies("s", [fp("angular", "x-powered-by: angular/1.8.0")], src);
    expect(report.coverage.needsReview).toBe(1);
    expect(report.coverage.ambiguousProducts).toContain("angular");
    expect(report.limitations.some((l) => /multiple CPEs/.test(l))).toBe(true);
  });

  it("3c. an unbounded affected range (no version bounds) matches the observed version", async () => {
    const src = new StaticAdvisorySource([advisory({ cveId: "CVE-2023-0009", productKey: "nginx", affected: "all versions", ranges: [[]] })]);
    const report = await correlateTechnologies("s", [fp("nginx", "server: nginx/1.18.0")], src);
    expect(report.matches[0]!.applicability).toBe(ApplicabilityState.MATCH_CANDIDATE);
  });

  it("4. conflicting banners yield a RANGE certainty and a candidate if any version is in range", async () => {
    const src = new StaticAdvisorySource([advisory({ cveId: "CVE-2020-0003", productKey: "nginx", affected: ">=1.16.0 <1.17.0", ranges: [[{ op: ">=", version: "1.16.0" }, { op: "<", version: "1.17.0" }]] })]);
    const report = await correlateTechnologies("s", [fp("nginx", "server: nginx/1.16.0", "a.example.com"), fp("nginx", "server: nginx/1.18.0", "b.example.com")], src);
    const m = report.matches[0]!;
    expect(m.versionCertainty).toBe(VersionCertainty.RANGE);
    expect(m.applicability).toBe(ApplicabilityState.MATCH_CANDIDATE);
    expect(m.rationale).toMatch(/multiple observed versions/);
  });

  it("5. a vendor backport prevents a simplistic vulnerable verdict", async () => {
    const src = new StaticAdvisorySource([NGINX({ backportNote: "vendor backported the fix in 1.18.0-r1" })]);
    const report = await correlateTechnologies("s", [fp("nginx", "server: nginx/1.18.0")], src);
    expect(report.matches[0]!.applicability).toBe(ApplicabilityState.NEEDS_APPLICABILITY_REVIEW);
  });

  it("6. an unreachable intelligence source is SOURCE_UNAVAILABLE, not a clean result", async () => {
    const down: VulnerabilitySource = {
      name: "down",
      lookup: async () => ({ advisories: [], status: "SOURCE_UNAVAILABLE", source: "down", fetchedAt: "2026-01-01T00:00:00.000Z", fromCache: false, stale: false, error: "timeout" }),
    };
    const report = await correlateTechnologies("s", [fp("nginx", "server: nginx/1.18.0")], down);
    expect(report.matches).toHaveLength(0);
    expect(report.coverage.sourceUnavailable).toBe(1);
    expect(report.sources[0]!.status).toBe("SOURCE_UNAVAILABLE");
    expect(report.limitations.some((l) => /unavailable/i.test(l))).toBe(true);
  });

  it("8. records KEV membership distinctly from non-membership", async () => {
    const src = new StaticAdvisorySource([NGINX({ kev: true }), advisory({ cveId: "CVE-2019-0004", productKey: "nginx", affected: "<2.0", ranges: [[{ op: "<", version: "2.0" }]], kev: false })]);
    const report = await correlateTechnologies("s", [fp("nginx", "server: nginx/1.18.0")], src);
    const kev = report.matches.find((m) => m.cveId === "CVE-2021-0001")!;
    const notKev = report.matches.find((m) => m.cveId === "CVE-2019-0004")!;
    expect(kev.kev).toBe(true);
    expect(notKev.kev).toBe(false);
  });

  it("9. deduplicates one CVE observed across multiple assets into a single match", async () => {
    const src = new StaticAdvisorySource([NGINX()]);
    const report = await correlateTechnologies("s", [fp("nginx", "server: nginx/1.18.0", "a.example.com"), fp("nginx", "server: nginx/1.18.0", "b.example.com")], src);
    expect(report.matches).toHaveLength(1);
    expect(report.matches[0]!.hosts.sort()).toEqual(["a.example.com", "b.example.com"]);
  });

  it("10. a missing version yields NEEDS_VERSION_CONFIRMATION rather than a guess", async () => {
    const src = new StaticAdvisorySource([NGINX()]);
    const report = await correlateTechnologies("s", [fp("nginx", "server: nginx")], src);
    expect(report.matches[0]!.applicability).toBe(ApplicabilityState.NEEDS_VERSION_CONFIRMATION);
    expect(report.matches[0]!.observedVersion).toBeNull();
  });

  it("reports products with no CPE mapping instead of guessing", async () => {
    const src = new StaticAdvisorySource([]);
    const report = await correlateTechnologies("s", [fp("Totally Custom Server", "server: totally-custom/3.1")], src);
    expect(report.coverage.unmatchedProducts).toContain("Totally Custom Server");
  });

  it("11. survives JSON persistence/reload without losing applicability state", async () => {
    const src = new StaticAdvisorySource([NGINX()]);
    const report = await correlateTechnologies("s", [fp("nginx", "server: nginx/1.18.0")], src);
    const reloaded = JSON.parse(JSON.stringify(report)) as typeof report;
    expect(reloaded.matches[0]!.applicability).toBe(ApplicabilityState.MATCH_CANDIDATE);
    expect(reloaded.coverage.candidates).toBe(report.coverage.candidates);
  });

  it("orders matches by severity then score, deterministically", async () => {
    const src = new StaticAdvisorySource([
      advisory({ cveId: "CVE-1", productKey: "nginx", affected: "<3", ranges: [[{ op: "<", version: "3" }]], cvss: { version: "3.1", score: 5.0, severity: "MEDIUM", vector: "" } }),
      advisory({ cveId: "CVE-2", productKey: "nginx", affected: "<3", ranges: [[{ op: "<", version: "3" }]], cvss: { version: "3.1", score: 9.9, severity: "CRITICAL", vector: "" } }),
    ]);
    const report = await correlateTechnologies("s", [fp("nginx", "server: nginx/1.0.0")], src);
    expect(report.matches.map((m) => m.cveId)).toEqual(["CVE-2", "CVE-1"]);
  });
});
