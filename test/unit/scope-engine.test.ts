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

  it("denies restricted addresses unless listed in scope AND INTERNAL_NETWORK AND the override are all present", () => {
    const withCap = {
      ...validPolicy,
      authorization: { ...validPolicy.authorization, capabilities: [...validPolicy.authorization.capabilities, "INTERNAL_NETWORK" as const] },
    };
    const listed = { ...withCap, inScope: { ...withCap.inScope, ips: [...withCap.inScope.ips, "127.0.0.1"] } };
    const req = { kind: "HOST" as const, value: "lab.example.com", capability: "ACTIVE_HTTP" as const, resolvedAddresses: ["127.0.0.1"] };
    expect(new ScopeEngine(withCap).check(req).allowed).toBe(false); // not listed, no override
    expect(new ScopeEngine(withCap, { allowRestrictedAddresses: true }).check(req).allowed).toBe(false); // override never opens unlisted space
    expect(new ScopeEngine(listed).check(req).allowed).toBe(false); // listed but no override
    expect(new ScopeEngine({ ...listed, authorization: validPolicy.authorization }, { allowRestrictedAddresses: true }).check(req).allowed).toBe(false); // listed + override, no capability
    expect(new ScopeEngine(listed, { allowRestrictedAddresses: true }).check(req).allowed).toBe(true);
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

// P2-1: an explicit in-scope IP/CIDR authorizes only documentation ranges. Every other restricted
// class also needs INTERNAL_NETWORK and allowRestrictedAddresses. Mirrors workers/internal/scope.
describe("ScopeEngine restricted-address policy (P2-1)", () => {
  const listedIps = ["127.0.0.1", "169.254.169.254", "169.254.1.1", "100.64.0.1", "::1", "fd00:ec2::254"];
  const listedCidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fe80::/10", "fd00::/8", "2001:db8::/32"];
  const targets = ["127.0.0.1", "169.254.169.254", "169.254.1.1", "100.64.0.1", "10.20.30.40", "172.16.5.5", "192.168.1.1", "::1", "fd00:ec2::254", "fe80::1", "fd00::1", "::ffff:10.0.0.1"];

  const policyWith = (internal: boolean): ScopePolicy => ({
    ...validPolicy,
    authorization: {
      ...validPolicy.authorization,
      capabilities: [...validPolicy.authorization.capabilities.filter((c) => c !== "INTERNAL_NETWORK"), ...(internal ? (["INTERNAL_NETWORK"] as const) : [])],
    },
    inScope: { ...validPolicy.inScope, ips: [...validPolicy.inScope.ips, ...listedIps], cidrs: [...validPolicy.inScope.cidrs, ...listedCidrs] },
  });
  const literal = (ip: string): string => (ip.includes(":") ? `[${ip}]` : ip);

  it("denies explicitly listed restricted addresses without capability and flag (IP, URL, DNS answer)", () => {
    for (const [internal, flag] of [[false, false], [true, false], [false, true]] as const) {
      const e = new ScopeEngine(policyWith(internal), { allowRestrictedAddresses: flag });
      for (const ip of targets) {
        const reqs = [
          { kind: "IP" as const, value: ip },
          { kind: "URL" as const, value: `http://${literal(ip)}/` },
          { kind: "HOST" as const, value: "app.example.com", resolvedAddresses: [ip] },
        ];
        for (const r of reqs) {
          const d = e.check({ ...r, capability: "ACTIVE_HTTP" });
          expect(d.allowed, `${r.kind} ${ip} internal=${internal} flag=${flag}`).toBe(false);
          expect(d.code).toBe("RESTRICTED_ADDRESS_SPACE");
        }
      }
    }
  });

  it("allows explicitly listed restricted addresses only with capability and flag", () => {
    const e = new ScopeEngine(policyWith(true), { allowRestrictedAddresses: true });
    for (const ip of targets) {
      expect(e.check({ kind: "IP", value: ip, capability: "ACTIVE_HTTP" }).allowed, ip).toBe(true);
      expect(e.check({ kind: "HOST", value: "app.example.com", capability: "ACTIVE_HTTP", resolvedAddresses: [ip] }).allowed, ip).toBe(true);
    }
    // The override never grants scope: unlisted addresses are still not in scope.
    expect(e.check({ kind: "IP", value: "172.32.0.1", capability: "ACTIVE_HTTP" }).code).toBe("NOT_IN_SCOPE");
    // Unlisted restricted space stays denied even with capability+flag, for literals and DNS answers
    // alike (keeps DNS rebinding to an unlisted internal address blocked).
    for (const ip of ["127.0.0.2", "169.254.169.253", "100.100.100.100", "fc00::1"]) {
      expect(e.check({ kind: "IP", value: ip, capability: "ACTIVE_HTTP" }).code, ip).toBe("RESTRICTED_ADDRESS_SPACE");
      expect(e.check({ kind: "HOST", value: "app.example.com", capability: "ACTIVE_HTTP", resolvedAddresses: [ip] }).code, ip).toBe("RESTRICTED_ADDRESS_SPACE");
    }
  });

  it("keeps the documented exception: explicit documentation-range entries need no override", () => {
    const e = new ScopeEngine(policyWith(false));
    for (const ip of ["203.0.113.10", "198.51.100.77", "2001:db8::5"]) {
      expect(e.check({ kind: "IP", value: ip, capability: "ACTIVE_HTTP" }).allowed, ip).toBe(true);
    }
    expect(e.check({ kind: "HOST", value: "app.example.com", capability: "ACTIVE_HTTP", resolvedAddresses: ["198.51.100.9"] }).allowed).toBe(true);
    // Not listed => not exempt.
    expect(e.check({ kind: "IP", value: "192.0.2.1", capability: "ACTIVE_HTTP" }).allowed).toBe(false);
  });

  it("does not exempt non-documentation reserved ranges even when listed", () => {
    const p = policyWith(false);
    const e = new ScopeEngine({ ...p, inScope: { ...p.inScope, cidrs: [...p.inScope.cidrs, "240.0.0.0/4", "198.18.0.0/15", "0.0.0.0/8"] } });
    for (const ip of ["240.0.0.1", "198.18.0.1", "0.0.0.1"]) {
      expect(e.check({ kind: "IP", value: ip, capability: "ACTIVE_HTTP" }).code, ip).toBe("RESTRICTED_ADDRESS_SPACE");
    }
  });

  it("exclusions still beat explicit restricted entries", () => {
    const p = policyWith(true);
    const e = new ScopeEngine({ ...p, exclusions: { ...p.exclusions, ips: ["10.0.0.99"] } }, { allowRestrictedAddresses: true });
    expect(e.check({ kind: "IP", value: "10.0.0.99", capability: "ACTIVE_HTTP" }).code).toBe("EXCLUDED");
  });
});
