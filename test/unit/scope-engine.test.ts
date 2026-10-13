import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ScopePolicySchema, type ScopePolicy } from "@reconnexus/contracts";
import { ScopeEngine } from "@reconnexus/scope-policy";

const fixture = (name: string): ScopePolicy =>
  ScopePolicySchema.parse(JSON.parse(readFileSync(fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url)), "utf8")));

const validPolicy = fixture("scope-policy.valid.json");
const expiredPolicy = fixture("scope-policy.expired.json");

function engine(policy = validPolicy): ScopeEngine {
  return new ScopeEngine(policy);
}

describe("ScopeEngine authorization", () => {
  it("allows an in-scope subdomain for an authorized capability", () => {
    const d = engine().check({ kind: "HOST", value: "app.example.com", capability: "ACTIVE_HTTP" });
    expect(d.allowed).toBe(true);
    expect(d.code).toBe("ALLOWED");
  });

  it("denies an out-of-scope host", () => {
    const d = engine().check({ kind: "HOST", value: "evil.example.net", capability: "ACTIVE_HTTP" });
    expect(d.allowed).toBe(false);
    expect(d.code).toBe("NOT_IN_SCOPE");
  });

  it("denies when the authorization has expired", () => {
    const d = new ScopeEngine(expiredPolicy).check({ kind: "HOST", value: "example.com", capability: "ACTIVE_HTTP" });
    expect(d.code).toBe("AUTHORIZATION_EXPIRED");
  });

  it("denies an unauthorized capability", () => {
    const d = engine().check({ kind: "HOST", value: "app.example.com", capability: "ACTIVE_TEMPLATE_CHECK" });
    expect(d.code).toBe("CAPABILITY_NOT_PERMITTED");
  });

  it("denies an authorization that is not yet valid", () => {
    const future = { ...validPolicy, authorization: { ...validPolicy.authorization, validFrom: "2998-01-01T00:00:00.000Z" } };
    const d = new ScopeEngine(future).check({ kind: "HOST", value: "app.example.com", capability: "ACTIVE_HTTP" });
    expect(d.code).toBe("AUTHORIZATION_NOT_YET_VALID");
  });

  it("requires a positive scope match, not merely absence of exclusion", () => {
    const empty = { ...validPolicy, inScope: { domains: [], hosts: [], ips: [], cidrs: [] } };
    const d = new ScopeEngine(empty).check({ kind: "HOST", value: "app.example.com", capability: "ACTIVE_HTTP" });
    expect(d.code).toBe("NOT_IN_SCOPE");
  });
});

describe("ScopeEngine exclusions", () => {
  it("excludes an excluded host even if otherwise in scope", () => {
    const d = engine().check({ kind: "HOST", value: "admin.example.com", capability: "ACTIVE_HTTP" });
    expect(d.allowed).toBe(false);
    expect(d.code).toBe("EXCLUDED");
  });

  it("excludes by path prefix", () => {
    const d = engine().check({ kind: "URL", value: "https://app.example.com/logout", capability: "ACTIVE_HTTP" });
    expect(d.code).toBe("EXCLUDED_PATH");
  });

  it("does not exclude a different path", () => {
    const d = engine().check({ kind: "URL", value: "https://app.example.com/dashboard", capability: "ACTIVE_HTTP" });
    expect(d.allowed).toBe(true);
  });
});

describe("ScopeEngine address space", () => {
  it("denies loopback destinations", () => {
    const d = engine().check({ kind: "IP", value: "127.0.0.1", capability: "ACTIVE_HTTP" });
    expect(d.allowed).toBe(false);
    expect(d.code).toBe("RESTRICTED_ADDRESS_SPACE");
  });

  it("denies cloud metadata", () => {
    const d = engine().check({ kind: "IP", value: "169.254.169.254", capability: "ACTIVE_HTTP" });
    expect(d.allowed).toBe(false);
  });

  it("denies IPv4-mapped loopback", () => {
    const d = engine().check({ kind: "IP", value: "::ffff:127.0.0.1", capability: "ACTIVE_HTTP" });
    expect(d.allowed).toBe(false);
  });

  it("denies a public host that resolves to a private address (rebinding)", () => {
    const d = engine().check({
      kind: "HOST",
      value: "app.example.com",
      capability: "ACTIVE_HTTP",
      resolvedAddresses: ["10.0.0.5"],
    });
    expect(d.allowed).toBe(false);
    expect(d.code).toBe("RESTRICTED_ADDRESS_SPACE");
    expect(d.addressDecisions?.[0]?.address).toBe("10.0.0.5");
  });

  it("allows a public host resolving to a public address", () => {
    const d = engine().check({
      kind: "HOST",
      value: "app.example.com",
      capability: "ACTIVE_HTTP",
      resolvedAddresses: ["93.184.216.34"],
    });
    expect(d.allowed).toBe(true);
  });

  it("allows an explicitly authorized in-scope IP", () => {
    const d = engine().check({ kind: "IP", value: "203.0.113.10", capability: "ACTIVE_HTTP" });
    expect(d.allowed).toBe(true);
  });

  it("denies restricted addresses even with INTERNAL_NETWORK unless the override is set", () => {
    const policy = {
      ...validPolicy,
      authorization: { ...validPolicy.authorization, capabilities: [...validPolicy.authorization.capabilities, "INTERNAL_NETWORK" as const] },
    };
    const strict = new ScopeEngine(policy).check({ kind: "HOST", value: "lab.example.com", capability: "ACTIVE_HTTP", resolvedAddresses: ["127.0.0.1"] });
    expect(strict.allowed).toBe(false);
    const relaxed = new ScopeEngine(policy, { allowRestrictedAddresses: true }).check({
      kind: "HOST",
      value: "lab.example.com",
      capability: "ACTIVE_HTTP",
      resolvedAddresses: ["127.0.0.1"],
    });
    expect(relaxed.allowed).toBe(true);
  });
});

describe("ScopeEngine validation", () => {
  it("rejects malformed URLs", () => {
    const d = engine().check({ kind: "URL", value: "not a url", capability: "ACTIVE_HTTP" });
    expect(d.code).toBe("INVALID_TARGET");
  });

  it("emits an audit record for every decision", () => {
    const records: unknown[] = [];
    const e = new ScopeEngine(validPolicy, { auditSink: (r) => records.push(r) });
    e.check({ kind: "HOST", value: "app.example.com", capability: "ACTIVE_HTTP" });
    e.check({ kind: "HOST", value: "evil.example.net", capability: "ACTIVE_HTTP" });
    expect(records).toHaveLength(2);
  });
});
