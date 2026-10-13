import { describe, expect, it } from "vitest";
import { ReportSchema, ReportStatus } from "@reconnexus/contracts";

const base = {
  schemaVersion: 1,
  scanId: "11111111-1111-1111-1111-111111111111",
  projectId: "22222222-2222-2222-2222-222222222222",
  rootDomain: "example.com",
  startUrl: "https://example.com/",
  scanStatus: "PARTIAL",
  reportStatus: "PARTIAL",
  generatedAt: "2026-01-01T00:00:00.000Z",
  stages: [{ stage: "12-reporting", jobStatus: "SUCCEEDED", attempts: 1, coverageStatus: "COLLECTED", expected: 1, collected: 1, notes: "" }],
  coverageGaps: ["07-js-intelligence:NOT_ATTEMPTED"],
  assetCounts: { URL: 2 },
  observationCounts: { total: 3, byKind: { report: 1 }, bySource: { "stage-12-reporting": 1 } },
  secretFindings: [{ ruleId: "aws-access-key-id", category: "CLOUD_CREDENTIAL", status: "HIGH_CONFIDENCE", confidence: 0.95, artifact: "https://example.com/a.js", host: "example.com", location: "1:3", redactedSnippet: "x='[REDACTED]'" }],
  correlations: [{ relation: "SHARES_SECRET_FINGERPRINT", status: "OBSERVED", subject: "https://example.com/a.js", related: ["https://example.com/b.js"], ruleId: "aws-access-key-id", hmacKeyed: true, correlationGroup: "0123456789abcdef", sourceStage: "11-correlation", evidence: "rule x", confidence: 0.9 }],
  limitations: ["candidate not confirmed"],
  summary: "partial",
};

describe("report contract", () => {
  it("accepts a well-formed report", () => {
    const r = ReportSchema.safeParse(base);
    expect(r.success, JSON.stringify(r.success ? {} : r.error.flatten())).toBe(true);
  });

  it("exposes exactly the six report statuses", () => {
    expect([...ReportStatus.options].sort()).toEqual(["COMPLETE_NO_FINDINGS", "COMPLETE_WITH_FINDINGS", "FAILED", "PARTIAL", "REPORTING_FAILED", "REPORTING_NOT_RUN"]);
  });

  it("rejects an unknown report status", () => {
    expect(ReportSchema.safeParse({ ...base, reportStatus: "PRODUCTION_READY" }).success).toBe(false);
  });

  it("rejects a non-uuid scan id", () => {
    expect(ReportSchema.safeParse({ ...base, scanId: "nope" }).success).toBe(false);
  });

  it("rejects a secret confidence outside [0,1]", () => {
    const bad = structuredClone(base);
    bad.secretFindings[0]!.confidence = 1.9;
    expect(ReportSchema.safeParse(bad).success).toBe(false);
  });
});
