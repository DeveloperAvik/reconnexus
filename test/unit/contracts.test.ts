import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  FindingSchema,
  ObservationSchema,
  ProviderDescriptorSchema,
  ScanManifestSchema,
  ScopePolicySchema,
} from "@reconnexus/contracts";

const load = (name: string): unknown =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url)), "utf8"));

describe("scope policy schema", () => {
  it("accepts a valid policy", () => {
    const p = ScopePolicySchema.parse(load("scope-policy.valid.json"));
    expect(p.inScope.domains[0]?.value).toBe("example.com");
    expect(p.limits.maxConcurrency).toBe(8);
  });

  it("rejects an unknown capability", () => {
    const raw = load("scope-policy.valid.json") as Record<string, unknown>;
    (raw.authorization as Record<string, unknown>).capabilities = ["GOD_MODE"];
    expect(ScopePolicySchema.safeParse(raw).success).toBe(false);
  });

  it("defaults limits when omitted", () => {
    const raw = load("scope-policy.valid.json") as Record<string, unknown>;
    delete raw.limits;
    const p = ScopePolicySchema.parse(raw);
    expect(p.limits.maxConcurrency).toBe(8);
  });
});

describe("finding schema", () => {
  it("requires confidence within [0,1] and a valid state", () => {
    const base = {
      projectId: "3f2504e0-4f89-41d3-9a0c-0305e82c3302",
      scanId: "3f2504e0-4f89-41d3-9a0c-0305e82c3303",
      category: "headers",
      title: "Missing CSP",
      severity: "LOW",
      confidence: 0.5,
      validation: "SUSPECTED",
      sourceReliability: "MEDIUM",
      firstSeen: "2026-01-01T00:00:00.000Z",
      lastSeen: "2026-01-01T00:00:00.000Z",
    };
    expect(FindingSchema.safeParse(base).success).toBe(true);
    expect(FindingSchema.safeParse({ ...base, confidence: 1.5 }).success).toBe(false);
    expect(FindingSchema.safeParse({ ...base, validation: "MAYBE" }).success).toBe(false);
  });
});

describe("observation schema", () => {
  it("requires provenance fields", () => {
    expect(
      ObservationSchema.safeParse({
        projectId: "3f2504e0-4f89-41d3-9a0c-0305e82c3302",
        scanId: "3f2504e0-4f89-41d3-9a0c-0305e82c3303",
        assetId: "3f2504e0-4f89-41d3-9a0c-0305e82c3304",
        source: "subfinder",
        sourceReliability: "HIGH",
        observedAt: "2026-01-01T00:00:00.000Z",
        kind: "subdomain",
      }).success,
    ).toBe(true);
  });
});

describe("scan manifest schema", () => {
  it("validates a manifest", () => {
    const manifest = {
      schemaVersion: 1,
      scanId: "3f2504e0-4f89-41d3-9a0c-0305e82c3303",
      projectId: "3f2504e0-4f89-41d3-9a0c-0305e82c3302",
      policyId: "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
      policyVersion: 1,
      startUrl: "https://example.com/",
      rootDomain: "example.com",
      createdAt: "2026-01-01T00:00:00.000Z",
      stages: ["00-input-authorization"],
      requestedCapabilities: ["PASSIVE"],
      enabledProviders: {},
      limits: { maxConcurrency: 8, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 1800, maxArtifactBytes: 8388608 },
    };
    expect(ScanManifestSchema.safeParse(manifest).success).toBe(true);
  });
});

describe("provider descriptor schema", () => {
  it("requires at least one capability and a network behavior", () => {
    const ok = ProviderDescriptorSchema.safeParse({
      name: "example",
      displayName: "Example",
      source: "external_binary",
      capabilities: ["PASSIVE"],
      networkBehavior: "PASSIVE",
    });
    expect(ok.success).toBe(true);
    const bad = ProviderDescriptorSchema.safeParse({ name: "x", displayName: "X", source: "external_binary", capabilities: [], networkBehavior: "PASSIVE" });
    expect(bad.success).toBe(false);
  });
});
