import { describe, expect, it } from "vitest";
import { DiscoveryResultSchema } from "@reconnexus/contracts";

const result = {
  schemaVersion: 1,
  status: "SUCCEEDED",
  provider: "builtin-secret-scan",
  providerVersion: "builtin",
  execution: { argv: [], exitCode: null, exitDescription: "", durationMs: 5, stdoutBytes: 0, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" },
  coverage: { attempted: 1, succeeded: 1, failed: 0, skipped: 0, unavailable: 0 },
  records: [
    {
      type: "SECRET_CANDIDATE",
      ruleId: "aws-access-key-id",
      category: "CLOUD_CREDENTIAL",
      status: "HIGH_CONFIDENCE",
      confidence: 0.95,
      artifactUrl: "https://example.com/app.js",
      host: "example.com",
      location: "3:12",
      redactedSnippet: "const a='[REDACTED]';",
      fingerprint: "deadbeef",
      occurrences: 2,
      rationale: "matched rule aws-access-key-id",
      suppressionReason: "",
      provider: "builtin-secret-scan",
      source: "secret-scan",
    },
    {
      type: "SECRET_SCAN_ARTIFACT",
      artifactUrl: "https://example.com/app.js",
      host: "example.com",
      status: "ANALYZED",
      findingsCount: 1,
      rawBytes: 123,
      hmacKeyed: true,
      error: "",
      provider: "builtin-secret-scan",
      source: "secret-scan",
    },
  ],
  diagnostics: [],
};

describe("secret discovery result contract", () => {
  it("accepts a well-formed secret-scan result", () => {
    const r = DiscoveryResultSchema.safeParse(result);
    expect(r.success, JSON.stringify(r.success ? {} : r.error.flatten())).toBe(true);
  });

  it("rejects an unknown secret category", () => {
    const bad = structuredClone(result);
    (bad.records[0] as { category: string }).category = "SUPER_SECRET_CLASS";
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });

  it("rejects a forbidden VALIDATED status (verification is not permitted)", () => {
    const bad = structuredClone(result);
    (bad.records[0] as { status: string }).status = "VALIDATED";
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });

  it("rejects an out-of-range confidence", () => {
    const bad = structuredClone(result);
    (bad.records[0] as { confidence: number }).confidence = 1.5;
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });

  it("rejects an unknown artifact status", () => {
    const bad = structuredClone(result);
    (bad.records[1] as { status: string }).status = "PROBABLY";
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });
});
