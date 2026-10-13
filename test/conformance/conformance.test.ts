import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ScopePolicySchema, type ScopePolicy } from "@reconnexus/contracts";
import { ScopeEngine } from "@reconnexus/scope-policy";
import {
  classifyIp,
  hostMatchesDomain,
  parseIp,
  publicSuffix,
  registrableDomain,
  tryParseUrl,
} from "@reconnexus/normalization";

const fixturesDir = fileURLToPath(new URL("../fixtures/conformance", import.meta.url));
const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const workersDir = fileURLToPath(new URL("../../workers", import.meta.url));

const readJson = (name: string): unknown => JSON.parse(readFileSync(`${fixturesDir}/${name}`, "utf8"));

interface DomainCase {
  host: string;
  expected: string | null;
}
interface MatchCase {
  host: string;
  value: string;
  includeSubdomains: boolean;
  expected: boolean;
}
interface IpCase {
  input: string;
  canonical: string | null;
  version: number | null;
  categories: string[];
}
interface ScopeCase {
  name: string;
  kind: string;
  value: string;
  capability: string;
  resolvedAddresses?: string[];
  isRedirect?: boolean;
  authorizationOverride?: { validFrom: string; validUntil: string };
  expected: { allowed: boolean; code: string };
}

function tsCategories(input: string): string[] {
  const ip = parseIp(input);
  if (!ip) return [];
  const c = classifyIp(ip);
  const pairs: Array<[boolean, string]> = [
    [c.isPrivate, "private"],
    [c.isLoopback, "loopback"],
    [c.isLinkLocal, "link-local"],
    [c.isUniqueLocal, "unique-local"],
    [c.isCGNAT, "cgnat"],
    [c.isMulticast, "multicast"],
    [c.isUnspecified, "unspecified"],
    [c.isBroadcast, "broadcast"],
    [c.isReserved, "reserved"],
    [c.isMetadata, "metadata"],
  ];
  return pairs.filter(([on]) => on).map(([, n]) => n).sort();
}

function computeTs(): unknown {
  const domains = readJson("domains.json") as {
    registrable: DomainCase[];
    suffix: DomainCase[];
    matching: MatchCase[];
  };
  const ips = readJson("ips.json") as IpCase[];
  const scope = readJson("scope.json") as {
    policy: ScopePolicy;
    now: string;
    cases: ScopeCase[];
  };

  const registrable = domains.registrable.map((c) => ({ host: c.host, result: registrableDomain(c.host) }));
  const suffix = domains.suffix.map((c) => ({ host: c.host, result: publicSuffix(c.host) }));
  const matching = domains.matching.map((c) => ({
    host: c.host,
    value: c.value,
    includeSubdomains: c.includeSubdomains,
    result: hostMatchesDomain(c.host, c.value, c.includeSubdomains),
  }));
  const ipResults = ips.map((c) => {
    const ip = parseIp(c.input);
    return {
      input: c.input,
      canonical: ip ? ip.canonical : null,
      version: ip ? ip.version : null,
      categories: tsCategories(c.input),
    };
  });
  const urls = readJson("urls.json") as Array<{ input: string; expected: string | null }>;
  const urlResults = urls.map((c) => {
    const parsed = tryParseUrl(c.input);
    return { input: c.input, result: parsed ? parsed.canonical : null };
  });

  const scopeResults = scope.cases.map((c) => {
    const policy = structuredClone(scope.policy);
    if (c.authorizationOverride) {
      policy.authorization.validFrom = c.authorizationOverride.validFrom;
      policy.authorization.validUntil = c.authorizationOverride.validUntil;
    }
    const engine = new ScopeEngine(policy);
    const decision = engine.check({
      kind: c.kind as never,
      value: c.value,
      capability: c.capability as never,
      now: new Date(scope.now),
      ...(c.resolvedAddresses ? { resolvedAddresses: c.resolvedAddresses } : {}),
      ...(c.isRedirect ? { isRedirect: c.isRedirect } : {}),
    });
    return { name: c.name, allowed: decision.allowed, code: decision.code };
  });

  return { registrable, suffix, matching, ips: ipResults, scope: scopeResults, urls: urlResults };
}

function goAvailable(): boolean {
  try {
    execFileSync("go", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

describe("scope conformance fixtures (TypeScript)", () => {
  it("computes results matching the fixtures' expected values", () => {
    const domains = readJson("domains.json") as { registrable: DomainCase[]; suffix: DomainCase[]; matching: MatchCase[] };
    const ips = readJson("ips.json") as IpCase[];
    const out = computeTs() as {
      registrable: { result: string | null }[];
      suffix: { result: string | null }[];
      matching: { result: boolean }[];
      ips: { canonical: string | null; version: number | null; categories: string[] }[];
      scope: { name: string; allowed: boolean; code: string }[];
      urls: { result: string | null }[];
    };
    domains.registrable.forEach((c, i) => expect(out.registrable[i]!.result, `registrable ${c.host}`).toBe(c.expected));
    domains.suffix.forEach((c, i) => expect(out.suffix[i]!.result, `suffix ${c.host}`).toBe(c.expected));
    domains.matching.forEach((c, i) => expect(out.matching[i]!.result, `match ${c.host}`).toBe(c.expected));
    ips.forEach((c, i) => {
      expect(out.ips[i]!.canonical, `canonical ${c.input}`).toBe(c.canonical);
      expect(out.ips[i]!.version, `version ${c.input}`).toBe(c.version);
      expect(out.ips[i]!.categories, `categories ${c.input}`).toEqual(c.categories);
    });
    const urls = readJson("urls.json") as Array<{ input: string; expected: string | null }>;
    urls.forEach((c, i) => {
      expect(out.urls[i]!.result, `canonical url ${c.input}`).toBe(c.expected);
    });
  });

  const run = goAvailable() ? it : it.skip;
  run("agrees with the Go engine on every fixture", () => {
    const ts = computeTs();
    const goOut = execFileSync("go", ["run", "./cmd/conformance", fixturesDir], {
      cwd: workersDir,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
    const go = JSON.parse(goOut);
    expect(go).toEqual(ts);
  });
});

// Keep ScopePolicySchema referenced so fixture drift is caught by the contract schema.
describe("conformance policy schema", () => {
  it("parses the fixture policy", () => {
    const scope = readJson("scope.json") as { policy: unknown };
    expect(ScopePolicySchema.safeParse(scope.policy).success).toBe(true);
    void repoRoot;
  });
});
