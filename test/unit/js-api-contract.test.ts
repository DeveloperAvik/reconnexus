import { describe, expect, it } from "vitest";
import { DiscoveryResultSchema } from "@reconnexus/contracts";

const result = {
  schemaVersion: 1,
  status: "SUCCEEDED",
  provider: "builtin-js",
  providerVersion: "builtin",
  execution: { argv: [], exitCode: null, exitDescription: "", durationMs: 5, stdoutBytes: 0, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" },
  coverage: { attempted: 1, succeeded: 1, failed: 0, skipped: 0, unavailable: 0 },
  records: [
    {
      type: "JS_ARTIFACT",
      url: "https://example.com/app.js",
      canonicalUrl: "https://example.com/app.js",
      contentHash: "a".repeat(64),
      contentType: "application/javascript",
      sizeBytes: 1234,
      sourceUrl: "https://example.com/",
      discoveryMethod: "stage05",
      status: "RETRIEVED",
      error: "",
      truncated: false,
      provider: "builtin-js",
      source: "js",
    },
    {
      type: "SOURCE_MAP",
      jsUrl: "https://example.com/app.js",
      sourceMapUrl: "https://example.com/app.js.map",
      status: "PARSED",
      sourcesCount: 2,
      sources: ["src/a.ts"],
      sourceRoot: "",
      hasContent: true,
      error: "",
      provider: "builtin-js",
    },
    {
      type: "API_SPEC",
      url: "https://example.com/openapi.json",
      specVersion: "openapi:3.0.0",
      title: "Test",
      format: "JSON",
      servers: ["https://example.com/api"],
      pathCount: 1,
      operationCount: 1,
      securitySchemes: ["bearerAuth"],
      unresolvedRefs: 0,
      parseStatus: "PARSED",
      error: "",
      provider: "builtin-api",
    },
    {
      type: "API_ENDPOINT",
      method: "GET",
      origin: "https://example.com",
      path: "/api/users",
      url: "https://example.com/api/users",
      discoveredVia: "SPEC",
      documented: true,
      resolved: true,
      operationId: "listUsers",
      tags: ["users"],
      parameters: [{ name: "page", location: "query", required: false, type: "integer", evidence: "spec parameter" }],
      contentTypes: ["application/json"],
      authSchemes: ["bearerAuth"],
      sourceUrl: "https://example.com/openapi.json",
      evidence: "declared",
      evidenceType: "OPENAPI",
      provider: "builtin-api",
    },
  ],
  diagnostics: [],
};

describe("js/api discovery result contract", () => {
  it("accepts a well-formed JS + API intelligence result", () => {
    const r = DiscoveryResultSchema.safeParse(result);
    expect(r.success, JSON.stringify(r.success ? {} : r.error.flatten())).toBe(true);
  });

  it("rejects an unknown artifact status", () => {
    const bad = structuredClone(result);
    (bad.records[0] as { status: string }).status = "TOTALLY_FINE";
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });

  it("rejects an unknown endpoint source", () => {
    const bad = structuredClone(result);
    (bad.records[3] as { discoveredVia: string }).discoveredVia = "TELEPATHY";
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });

  it("rejects an unknown parameter location", () => {
    const bad = structuredClone(result);
    (bad.records[3] as { parameters: Array<{ location: string }> }).parameters[0]!.location = "somewhere";
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });

  it("rejects an unknown source-map parse status", () => {
    const bad = structuredClone(result);
    (bad.records[1] as { status: string }).status = "vibes";
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });
});
