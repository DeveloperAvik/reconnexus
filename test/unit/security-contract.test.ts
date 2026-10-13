import { describe, expect, it } from "vitest";
import { DiscoveryResultSchema } from "@reconnexus/contracts";

const result = {
  schemaVersion: 1,
  status: "SUCCEEDED",
  provider: "builtin-security-meta",
  providerVersion: "builtin",
  execution: { argv: [], exitCode: null, exitDescription: "", durationMs: 5, stdoutBytes: 0, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" },
  coverage: { attempted: 1, succeeded: 1, failed: 0, skipped: 0, unavailable: 0 },
  records: [
    { type: "SECURITY_METADATA", url: "https://example.com/", host: "example.com", category: "HSTS", name: "strict-transport-security", status: "OBSERVED", observed: true, value: "", detail: { maxAge: 31536000, includeSubDomains: true, preload: true }, consistent: null, evidence: "HSTS header", evidenceType: "HEADER", provider: "builtin-security-meta", source: "security-metadata" },
    { type: "SECURITY_METADATA", url: "https://example.com/", host: "example.com", category: "COOKIE", name: "SID", status: "OBSERVED", observed: true, value: "", detail: { secure: true, httpOnly: true, sameSite: "Lax" }, consistent: null, evidence: "cookie attributes", evidenceType: "HEADER", provider: "builtin-security-meta", source: "security-metadata" },
    { type: "SECURITY_METADATA", url: "https://example.com/", host: "example.com", category: "CORS", name: "cors", status: "INCONSISTENT", observed: true, value: "*", detail: { allowOrigin: "*", allowCredentials: true, wildcard: true }, consistent: false, evidence: "CORS headers", evidenceType: "HEADER", provider: "builtin-security-meta", source: "security-metadata" },
    { type: "SECURITY_METADATA", url: "https://example.com/", host: "example.com", category: "TLS", name: "certificate", status: "OBSERVED", observed: true, value: "", detail: { sha256: "a".repeat(64), validNow: true, hostnameMatch: true, daysToExpiry: 90 }, consistent: true, evidence: "TLS peer certificate", evidenceType: "TLS", provider: "builtin-security-meta", source: "security-metadata" },
  ],
  diagnostics: [],
};

describe("security metadata contract", () => {
  it("accepts a well-formed security-metadata result", () => {
    const r = DiscoveryResultSchema.safeParse(result);
    expect(r.success, JSON.stringify(r.success ? {} : r.error.flatten())).toBe(true);
  });

  it("rejects an unknown category", () => {
    const bad = structuredClone(result);
    (bad.records[0] as { category: string }).category = "VIBES";
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });

  it("rejects an unknown status", () => {
    const bad = structuredClone(result);
    (bad.records[0] as { status: string }).status = "PROBABLY_FINE";
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });

  it("rejects a non-primitive detail value (detail must be string|number|boolean|null)", () => {
    const bad = structuredClone(result);
    (bad.records[0] as { detail: Record<string, unknown> }).detail = { nested: { a: 1 } };
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });
});
