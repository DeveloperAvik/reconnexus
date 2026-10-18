import { describe, expect, it } from "vitest";
import { DiscoveryResultSchema, LoginInterfaceRecordSchema } from "@reconnexus/contracts";

const record = {
  type: "LOGIN_INTERFACE" as const,
  url: "https://example.com/admin/login",
  finalUrl: "https://example.com/admin/login",
  host: "example.com",
  kind: "ADMIN" as const,
  status: "DETECTED" as const,
  confidence: 0.85,
  httpStatus: 200,
  title: "Admin Login",
  evidence: "HTTP 200; password form present; title \"Admin Login\"",
  evidenceType: "LOGIN_FORM",
  provider: "builtin-login-finder",
  source: "login-finder",
};

const result = {
  schemaVersion: 1 as const,
  status: "SUCCEEDED" as const,
  provider: "builtin-login-finder",
  providerVersion: "builtin",
  execution: { argv: [], exitCode: null, exitDescription: "", durationMs: 5, stdoutBytes: 0, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" },
  coverage: { attempted: 1, succeeded: 1, failed: 0, skipped: 0, unavailable: 0 },
  records: [record],
  diagnostics: [],
};

describe("login-interface contract", () => {
  it("accepts a well-formed login-interface result", () => {
    const parsed = DiscoveryResultSchema.safeParse(result);
    expect(parsed.success, JSON.stringify(parsed.success ? {} : parsed.error.flatten())).toBe(true);
  });

  it("rejects an unknown interface kind", () => {
    expect(LoginInterfaceRecordSchema.safeParse({ ...record, kind: "SSH" }).success).toBe(false);
  });

  it("rejects an unknown status", () => {
    expect(LoginInterfaceRecordSchema.safeParse({ ...record, status: "CONFIRMED" }).success).toBe(false);
  });

  it("rejects a confidence outside [0,1]", () => {
    expect(LoginInterfaceRecordSchema.safeParse({ ...record, confidence: 1.2 }).success).toBe(false);
  });

  it("accepts a cPanel record", () => {
    expect(LoginInterfaceRecordSchema.safeParse({ ...record, kind: "CPANEL", status: "POSSIBLE", evidenceType: "CPANEL_PORT" }).success).toBe(true);
  });
});
