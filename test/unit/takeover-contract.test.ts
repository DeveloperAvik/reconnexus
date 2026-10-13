import { describe, expect, it } from "vitest";
import { DiscoveryResultSchema, ReportSchema } from "@reconnexus/contracts";

const result = {
  schemaVersion: 1,
  status: "SUCCEEDED",
  provider: "builtin-takeover",
  providerVersion: "builtin",
  execution: { argv: [], exitCode: null, exitDescription: "", durationMs: 5, stdoutBytes: 0, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" },
  coverage: { attempted: 1, succeeded: 1, failed: 0, skipped: 0, unavailable: 0 },
  records: [
    { type: "TAKEOVER_CANDIDATE", host: "blog.example.com", cname: "user.github.io", service: "GitHub Pages", status: "SUSPECTED", confidence: 0.8, httpStatus: 404, evidence: "CNAME blog.example.com -> user.github.io (GitHub Pages); HTTP 404; unclaimed marker matched", evidenceType: "UNCLAIMED_MARKER", provider: "builtin-takeover", source: "takeover" },
  ],
  diagnostics: [],
};

describe("takeover candidate contract", () => {
  it("accepts a well-formed takeover result", () => {
    const r = DiscoveryResultSchema.safeParse(result);
    expect(r.success, JSON.stringify(r.success ? {} : r.error.flatten())).toBe(true);
  });

  it("rejects an unknown status", () => {
    const bad = structuredClone(result);
    (bad.records[0] as { status: string }).status = "CONFIRMED_TAKEOVER";
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });

  it("rejects a confidence outside [0,1]", () => {
    const bad = structuredClone(result);
    (bad.records[0] as { confidence: number }).confidence = 1.7;
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });

  it("report schema carries takeover candidates and defaults to empty", () => {
    const base = {
      schemaVersion: 1,
      scanId: "11111111-1111-1111-1111-111111111111",
      projectId: "22222222-2222-2222-2222-222222222222",
      rootDomain: "example.com",
      startUrl: "https://example.com/",
      scanStatus: "PARTIAL",
      reportStatus: "PARTIAL",
      generatedAt: "2026-01-01T00:00:00.000Z",
      stages: [],
      coverageGaps: [],
      assetCounts: {},
      observationCounts: { total: 0, byKind: {}, bySource: {} },
      secretFindings: [],
      correlations: [],
      limitations: [],
      summary: "s",
    };
    const parsed = ReportSchema.parse(base);
    expect(parsed.takeoverCandidates).toEqual([]);
  });
});
