import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ScopePolicySchema } from "@reconnexus/contracts";
import { ScopeEngine, resolveAndCheck } from "@reconnexus/scope-policy";
import { tryParseUrl } from "@reconnexus/normalization";

const policy = ScopePolicySchema.parse(
  JSON.parse(readFileSync(fileURLToPath(new URL("../fixtures/scope-policy.valid.json", import.meta.url)), "utf8")),
);
const engine = new ScopeEngine(policy);

const urlCorpus = readFileSync(fileURLToPath(new URL("../fixtures/urls.known.txt", import.meta.url)), "utf8")
  .split("\n")
  .map((l) => l.trim())
  .filter((l) => l.length > 0 && !l.startsWith("#"));

/**
 * RELEASE GATE: no target outside scope may ever be allowed. This test fails the build if
 * scope enforcement lets anything through.
 */
describe("scope enforcement release gate", () => {
  it("never allows a URL whose host is outside the authorized domains", () => {
    const violations: string[] = [];
    for (const raw of urlCorpus) {
      const parsed = tryParseUrl(raw, { allowedSchemes: ["http", "https"] });
      if (!parsed) continue; // malformed/unsupported: rejected before scope
      const d = engine.check({ kind: "URL", value: raw, capability: "ACTIVE_HTTP" });
      const hostOk = parsed.host === "example.com" || parsed.host.endsWith(".example.com");
      if (d.allowed && !hostOk) violations.push(`${raw} -> ${d.code}`);
    }
    expect(violations).toEqual([]);
  });

  it("rejects non-http(s) and malformed targets", () => {
    for (const raw of ["ftp://example.com/x", "javascript:alert(1)", "not-a-url"]) {
      const parsed = tryParseUrl(raw, { allowedSchemes: ["http", "https"] });
      expect(parsed, raw).toBeNull();
    }
  });

  it("denies every restricted address class", () => {
    const restricted = [
      "127.0.0.1",
      "127.1.2.3",
      "10.0.0.1",
      "172.16.0.1",
      "192.168.1.1",
      "169.254.1.1",
      "169.254.169.254",
      "100.64.0.1",
      "0.0.0.0",
      "::1",
      "fe80::1",
      "fc00::1",
      "fd00:ec2::254",
      "::ffff:127.0.0.1",
      "::ffff:169.254.169.254",
      "::ffff:10.0.0.1",
    ];
    const allowed: string[] = [];
    for (const ip of restricted) {
      const d = engine.check({ kind: "IP", value: ip, capability: "ACTIVE_HTTP" });
      if (d.allowed) allowed.push(ip);
    }
    expect(allowed).toEqual([]);
  });

  it("re-authorizes a redirect destination and blocks it when out of scope", () => {
    const d = engine.check({
      kind: "URL",
      value: "https://evil.example.net/steal",
      capability: "ACTIVE_HTTP",
      isRedirect: true,
    });
    expect(d.allowed).toBe(false);
  });

  it("network-disabled by default: no DNS is performed", async () => {
    // resolveAndCheck with resolve=false must not hit the network and must return the literal decision.
    const d = await resolveAndCheck(engine, { kind: "HOST", value: "app.example.com", capability: "ACTIVE_HTTP" }, { resolve: false });
    expect(d.allowed).toBe(true);
  });

  it("treats DNS failure as a denial, never an allow", async () => {
    const failing = (): Promise<string[]> => Promise.reject(new Error("ENOTFOUND"));
    const d = await resolveAndCheck(
      new ScopeEngine(policy),
      { kind: "HOST", value: "app.example.com", capability: "ACTIVE_HTTP" },
      { resolve: true, resolver: failing },
    );
    expect(d.allowed).toBe(false);
    expect(d.code).toBe("DNS_RESOLUTION_FAILED");
  });

  it("blocklists a rebinding answer injected by a resolver", async () => {
    const rebind = (): Promise<string[]> => Promise.resolve(["169.254.169.254"]);
    const d = await resolveAndCheck(
      new ScopeEngine(policy),
      { kind: "HOST", value: "app.example.com", capability: "ACTIVE_HTTP" },
      { resolve: true, resolver: rebind },
    );
    expect(d.allowed).toBe(false);
    expect(d.code).toBe("RESTRICTED_ADDRESS_SPACE");
  });
});
