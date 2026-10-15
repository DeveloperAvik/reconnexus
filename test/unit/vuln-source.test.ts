import { describe, expect, it } from "vitest";
import {
  CachingVulnerabilitySource,
  NvdVulnerabilitySource,
  StaticAdvisorySource,
  kevCveSet,
  type AdvisoryRecord,
  type VulnerabilitySource,
} from "@reconnexus/control-plane";

function res(status: number, body: unknown): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as unknown as Response;
}

const NVD_PAYLOAD = {
  vulnerabilities: [
    {
      cve: {
        id: "CVE-2021-44228",
        sourceIdentifier: "apache",
        published: "2021-12-10T00:00:00.000",
        lastModified: "2021-12-11T00:00:00.000",
        metrics: { cvssMetricV31: [{ cvssData: { baseScore: 10.0, baseSeverity: "CRITICAL", vectorString: "CVSS:3.1/AV:N" } }] },
        configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:apache:log4j:*:*", versionStartIncluding: "2.0", versionEndExcluding: "2.15.0" }] }] }],
      },
    },
  ],
};

describe("NVD source", () => {
  it("parses affected ranges, CVSS and KEV membership from a CPE query", async () => {
    let calledUrl = "";
    const fetchMock = (async (url: string) => {
      calledUrl = String(url);
      return res(200, NVD_PAYLOAD);
    }) as unknown as typeof fetch;
    const src = new NvdVulnerabilitySource({ fetch: fetchMock, kev: new Set(["CVE-2021-44228"]), retries: 0 });
    const r = await src.lookup({ productKey: "log4j", cpe: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", version: "2.14.1" });
    expect(calledUrl).toContain("cpeName=cpe%3A2.3%3Aa%3Aapache%3Alog4j");
    expect(r.status).toBe("OK");
    const a = r.advisories[0]!;
    expect(a.cveId).toBe("CVE-2021-44228");
    expect(a.cvss?.score).toBe(10);
    expect(a.kev).toBe(true);
    expect(a.affected).toBe(">= 2.0 < 2.15.0");
    expect(a.ranges[0]).toEqual([{ op: ">=", version: "2.0" }, { op: "<", version: "2.15.0" }]);
  });

  it("does not call the network when there is no CPE to query", async () => {
    let called = false;
    const fetchMock = (async () => {
      called = true;
      return res(200, {});
    }) as unknown as typeof fetch;
    const src = new NvdVulnerabilitySource({ fetch: fetchMock });
    const r = await src.lookup({ productKey: "x", cpe: null, version: null });
    expect(called).toBe(false);
    expect(r.status).toBe("OK");
    expect(r.advisories).toEqual([]);
  });

  it("retries on rate limiting (429) and then succeeds", async () => {
    let n = 0;
    const fetchMock = (async () => {
      n++;
      return n === 1 ? res(429, {}) : res(200, NVD_PAYLOAD);
    }) as unknown as typeof fetch;
    const src = new NvdVulnerabilitySource({ fetch: fetchMock, retries: 2 });
    const r = await src.lookup({ productKey: "log4j", cpe: "cpe:2.3:a:apache:log4j:*:*", version: "2.14.1" });
    expect(n).toBe(2);
    expect(r.status).toBe("OK");
    expect(r.advisories).toHaveLength(1);
  });

  it("returns SOURCE_UNAVAILABLE (not an empty OK) after repeated timeouts", async () => {
    const fetchMock = (async () => {
      const e = new Error("aborted");
      e.name = "AbortError";
      throw e;
    }) as unknown as typeof fetch;
    const src = new NvdVulnerabilitySource({ fetch: fetchMock, retries: 1, timeoutMs: 5 });
    const r = await src.lookup({ productKey: "log4j", cpe: "cpe:2.3:a:apache:log4j:*:*", version: "2.14.1" });
    expect(r.status).toBe("SOURCE_UNAVAILABLE");
    expect(r.error).toMatch(/timeout/);
  });

  it("extracts KEV ids from a catalog document", () => {
    const set = kevCveSet({ vulnerabilities: [{ cveID: "CVE-1" }, { cveID: "CVE-2" }, { not: "an id" }] });
    expect(set.has("CVE-1")).toBe(true);
    expect(set.has("CVE-2")).toBe(true);
    expect(kevCveSet(null).size).toBe(0);
  });
});

describe("caching source", () => {
  const adv: AdvisoryRecord = { cveId: "CVE-X", productKey: "nginx", vendor: "", affected: "<2", ranges: [[{ op: "<", version: "2" }]], kev: false, sourceUrl: "u", source: "inner" };

  it("serves a fresh entry from cache and refetches after the TTL", async () => {
    let calls = 0;
    const inner: VulnerabilitySource = { name: "inner", lookup: async (q) => ({ advisories: [adv], status: "OK", source: "inner", fetchedAt: "t", fromCache: false, stale: false, ...(q.productKey ? {} : {}) }) };
    const counting: VulnerabilitySource = { name: "inner", lookup: (q) => { calls++; return inner.lookup(q); } };
    let clock = 0;
    const cache = new CachingVulnerabilitySource(counting, { ttlMs: 1000, now: () => new Date(clock) });
    const q = { productKey: "nginx", cpe: "cpe:2.3:a:nginx:nginx:*:*", version: "1.0" };
    const first = await cache.lookup(q);
    expect(first.fromCache).toBe(false);
    clock = 500;
    const second = await cache.lookup(q);
    expect(second.fromCache).toBe(true);
    expect(calls).toBe(1);
    clock = 2000; // past TTL
    await cache.lookup(q);
    expect(calls).toBe(2);
  });

  it("degrades to a stale entry (flagged) when the source fails, never a false negative", async () => {
    const good = new StaticAdvisorySource([adv], "inner");
    let healthy = true;
    const flaky: VulnerabilitySource = {
      name: "inner",
      lookup: async (q) => (healthy ? good.lookup(q) : { advisories: [], status: "SOURCE_UNAVAILABLE", source: "inner", fetchedAt: "t", fromCache: false, stale: false, error: "down" }),
    };
    let clock = 0;
    const cache = new CachingVulnerabilitySource(flaky, { ttlMs: 100, staleIfErrorMs: 10_000, now: () => new Date(clock) });
    const q = { productKey: "nginx", cpe: "cpe:2.3:a:nginx:nginx:*:*", version: "1.0" };
    await cache.lookup(q);
    healthy = false;
    clock = 5000; // past TTL, within stale window
    const stale = await cache.lookup(q);
    expect(stale.status).toBe("OK");
    expect(stale.stale).toBe(true);
    expect(stale.advisories).toHaveLength(1);
  });
});
