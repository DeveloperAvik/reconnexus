import { describe, expect, it } from "vitest";
import { DiscoveryResultSchema } from "@reconnexus/contracts";

const httpResult = {
  schemaVersion: 1,
  status: "SUCCEEDED",
  provider: "builtin-http",
  providerVersion: "builtin",
  execution: { argv: [], exitCode: null, exitDescription: "", durationMs: 12, stdoutBytes: 0, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" },
  coverage: { attempted: 1, succeeded: 1, failed: 0, skipped: 0, unavailable: 0 },
  records: [
    {
      type: "HTTP_OBSERVATION",
      url: "https://example.com/",
      host: "example.com",
      provider: "builtin-http",
      source: "http",
      http: {
        finalUrl: "https://example.com/",
        statusCode: 200,
        statusText: "200 OK",
        contentType: "text/html",
        title: "Example",
        headers: { server: "nginx", "content-type": "text/html" },
        redirectChain: [{ from: "http://example.com/", to: "https://example.com/", statusCode: 301 }],
        tls: { subject: "CN=example.com", issuer: "CN=Example CA", notBefore: "2025-01-01T00:00:00Z", notAfter: "2026-01-01T00:00:00Z", sha256: "ab12", protocol: "TLS 1.3", sans: ["example.com"] },
        probeStatus: "OK",
        error: "",
        bodyTruncated: false,
      },
    },
    { type: "TECHNOLOGY", url: "https://example.com/", host: "example.com", provider: "builtin-http", technology: { name: "nginx", category: "WEB_SERVER", evidenceType: "HEADER", evidence: "Server: nginx", confidence: 0.9 } },
  ],
  diagnostics: [],
};

describe("http discovery result contract", () => {
  it("accepts a well-formed HTTP probe + technology result", () => {
    const r = DiscoveryResultSchema.safeParse(httpResult);
    expect(r.success, JSON.stringify(r.success ? {} : r.error.flatten())).toBe(true);
  });

  it("rejects an HTTP observation with an unknown probe status", () => {
    const bad = structuredClone(httpResult);
    (bad.records[0] as { http: { probeStatus: string } }).http.probeStatus = "BANANA";
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });

  it("rejects a technology with an unknown category", () => {
    const bad = structuredClone(httpResult);
    (bad.records[1] as { technology: { category: string } }).technology.category = "NONSENSE";
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });

  it("rejects a technology confidence outside [0,1]", () => {
    const bad = structuredClone(httpResult);
    (bad.records[1] as { technology: { confidence: number } }).technology.confidence = 1.5;
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });
});
