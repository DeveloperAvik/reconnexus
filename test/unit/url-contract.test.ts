import { describe, expect, it } from "vitest";
import { DiscoveryJobSchema, DiscoveryResultSchema } from "@reconnexus/contracts";

const urlResult = {
  schemaVersion: 1,
  status: "SUCCEEDED",
  provider: "builtin-crawler",
  providerVersion: "builtin",
  execution: { argv: [], exitCode: null, exitDescription: "", durationMs: 5, stdoutBytes: 0, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" },
  coverage: { attempted: 3, succeeded: 3, failed: 0, skipped: 1, unavailable: 0 },
  records: [
    {
      type: "URL_OBSERVATION",
      url: "http://example.com/api/v1/users?page=2",
      canonicalUrl: "http://example.com/api/v1/users?page=2",
      host: "example.com",
      method: "CRAWL",
      depth: 1,
      statusCode: 200,
      source: "crawl",
      provider: "builtin-crawler",
      classifications: [
        { category: "API_ENDPOINT", confidence: 0.6, evidenceType: "PATH", evidence: "API-like path segment" },
        { category: "PAGINATION", confidence: 0.7, evidenceType: "PARAMETER", evidence: "pagination query parameter" },
      ],
      parameters: [{ name: "page", roles: [{ role: "pagination", confidence: 0.7, evidence: "parameter name 'page'" }] }],
    },
  ],
  diagnostics: [],
};

describe("url observation contract", () => {
  it("accepts a well-formed URL observation", () => {
    const r = DiscoveryResultSchema.safeParse(urlResult);
    expect(r.success, JSON.stringify(r.success ? {} : r.error.flatten())).toBe(true);
  });

  it("rejects an unknown URL category", () => {
    const bad = structuredClone(urlResult);
    (bad.records[0] as { classifications: Array<{ category: string }> }).classifications[0]!.category = "MADE_UP";
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });

  it("rejects an unknown collection method", () => {
    const bad = structuredClone(urlResult);
    (bad.records[0] as { method: string }).method = "TELEPATHY";
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });

  it("rejects a parameter role confidence outside [0,1]", () => {
    const bad = structuredClone(urlResult);
    (bad.records[0] as { parameters: Array<{ roles: Array<{ confidence: number }> }> }).parameters[0]!.roles[0]!.confidence = 2;
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });

  it("accepts a URL_COLLECTION job with seed inputs", () => {
    const job = {
      schemaVersion: 1,
      scanId: "11111111-1111-1111-1111-111111111111",
      projectId: "22222222-2222-2222-2222-222222222222",
      stage: "05-url-collection",
      jobKey: "05-url-collection:builtin-crawler",
      kind: "URL_COLLECTION",
      provider: "builtin-crawler",
      policy: {
        schemaVersion: 1,
        policyId: "33333333-3333-3333-3333-333333333333",
        projectId: "22222222-2222-2222-2222-222222222222",
        policyVersion: 1,
        authorization: { reference: "r", authorizedBy: "a", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["CRAWL"] },
        inScope: { domains: [{ value: "example.com", includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
        exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
        limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 60, maxArtifactBytes: 1048576 },
      },
      inputs: { seedUrls: ["https://example.com/"], domains: ["example.com"], crawlDepth: 2, requestBudget: 100 },
      limits: { maxConcurrency: 4, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 60, maxArtifactBytes: 1048576 },
      allowRestrictedAddresses: false,
    };
    expect(DiscoveryJobSchema.safeParse(job).success).toBe(true);
  });
});
