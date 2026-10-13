import { describe, expect, it } from "vitest";
import { DiscoveryJobSchema, DiscoveryResultSchema } from "@reconnexus/contracts";

// Representative of real Go worker output (builtin-dns).
const dnsResult = {
  schemaVersion: 1,
  status: "SUCCEEDED",
  provider: "builtin-dns",
  providerVersion: "unknown",
  execution: { argv: [], exitCode: 0, exitDescription: "", durationMs: 42, stdoutBytes: 100, stderrBytes: 0, truncated: false, timedOut: false, spawnError: "" },
  coverage: { attempted: 2, succeeded: 2, failed: 0, skipped: 0, unavailable: 0 },
  records: [
    { type: "DNS_RECORD", name: "www.example.com", recordType: "A", value: "104.20.23.154", status: "NOERROR", resolver: "system" },
    { type: "DNS_RECORD", name: "www.example.com", recordType: "CNAME", value: "edge.example.net", ttl: 60, status: "NOERROR", resolver: "system" },
    { type: "HOST_OBSERVATION", host: "www.example.com", source: "dns", provider: "builtin-dns", status: "RESOLVED", addresses: ["104.20.23.154"] },
    { type: "IP_METADATA", ip: "203.0.113.10", prefix: "203.0.113.0/24", asn: 64512, asnOrg: "Example", networkName: "TESTNET", country: "ZZ", source: "rdap", confidence: 0.6, limitations: [] },
  ],
  diagnostics: [],
};

describe("discovery result contract", () => {
  it("accepts real worker-shaped DNS output", () => {
    const r = DiscoveryResultSchema.safeParse(dnsResult);
    expect(r.success, JSON.stringify(r.success ? {} : r.error.flatten())).toBe(true);
  });

  it("rejects a null argv (the worker must emit an array)", () => {
    const bad = structuredClone(dnsResult);
    (bad.execution as { argv: unknown }).argv = null;
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });

  it("rejects a HOST_OBSERVATION without a provider", () => {
    const bad = structuredClone(dnsResult);
    delete (bad.records[2] as { provider?: string }).provider;
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });

  it("rejects an unknown DNS record status", () => {
    const bad = structuredClone(dnsResult);
    (bad.records[0] as { status: string }).status = "MAYBE";
    expect(DiscoveryResultSchema.safeParse(bad).success).toBe(false);
  });

  it("validates a discovery job", () => {
    const job = {
      schemaVersion: 1,
      scanId: "11111111-1111-1111-1111-111111111111",
      projectId: "22222222-2222-2222-2222-222222222222",
      stage: "03-dns-infra",
      jobKey: "03-dns-infra:builtin-dns",
      kind: "DNS",
      provider: "builtin-dns",
      policy: {
        schemaVersion: 1,
        policyId: "33333333-3333-3333-3333-333333333333",
        projectId: "22222222-2222-2222-2222-222222222222",
        policyVersion: 1,
        authorization: { reference: "r", authorizedBy: "a", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2999-01-01T00:00:00.000Z", capabilities: ["DNS"] },
        inScope: { domains: [{ value: "example.com", includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
        exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
        limits: { maxConcurrency: 4, requestsPerSecond: 5, crawlDepth: 1, maxRuntimeSeconds: 60, maxArtifactBytes: 1048576 },
      },
      inputs: { names: ["a.example.com"] },
      limits: { maxConcurrency: 4, requestsPerSecond: 5, crawlDepth: 1, maxRuntimeSeconds: 60, maxArtifactBytes: 1048576 },
      allowRestrictedAddresses: false,
    };
    expect(DiscoveryJobSchema.safeParse(job).success).toBe(true);
  });
});
