import type { AdvisoryRecord, CvssScore } from "./types.js";

/**
 * Vulnerability-intelligence sources.
 *
 * A source is a small, injectable adapter so the engine never talks to the network directly and
 * tests never require a real service. `StaticAdvisorySource` serves a local database or fixtures;
 * `NvdVulnerabilitySource` talks to the NVD 2.0 API with timeouts, bounded retries and KEV merging;
 * `CachingVulnerabilitySource` wraps any source with a TTL cache and **graceful degradation** — a
 * failing source with a stale cache still yields data, clearly flagged stale, rather than a false
 * negative.
 */

export interface AdvisoryQuery {
  productKey: string;
  cpe: string | null;
  version: string | null;
}

export interface SourceResult {
  advisories: AdvisoryRecord[];
  status: "OK" | "SOURCE_UNAVAILABLE";
  source: string;
  fetchedAt: string;
  fromCache: boolean;
  stale: boolean;
  error?: string;
}

export interface VulnerabilitySource {
  readonly name: string;
  lookup(query: AdvisoryQuery): Promise<SourceResult>;
}

function nowIso(now: () => Date): string {
  return now().toISOString();
}

/** A source backed by an in-memory list of advisories (a local DB, a fixture, or a loaded file). */
export class StaticAdvisorySource implements VulnerabilitySource {
  readonly name: string;
  constructor(
    private readonly advisories: AdvisoryRecord[],
    name = "static",
    private readonly now: () => Date = () => new Date(),
  ) {
    this.name = name;
  }

  async lookup(query: AdvisoryQuery): Promise<SourceResult> {
    const advisories = this.advisories.filter((a) => a.productKey === query.productKey);
    return { advisories, status: "OK", source: this.name, fetchedAt: nowIso(this.now), fromCache: false, stale: false };
  }
}

interface CacheEntry {
  result: SourceResult;
  storedAt: number;
}

export interface CacheOptions {
  ttlMs: number;
  now?: () => Date;
  store?: Map<string, CacheEntry>;
  /** When the inner source fails, serve a stale entry up to this age. 0 disables stale fallback. */
  staleIfErrorMs?: number;
}

/** Wrap a source with a TTL cache. On inner failure, a stale (but present) entry is served and
 * flagged `stale`, so an intelligence outage degrades to "possibly out of date", never to "clean". */
export class CachingVulnerabilitySource implements VulnerabilitySource {
  readonly name: string;
  private readonly store: Map<string, CacheEntry>;
  private readonly now: () => Date;
  constructor(
    private readonly inner: VulnerabilitySource,
    private readonly opts: CacheOptions,
  ) {
    this.name = `cache(${inner.name})`;
    this.store = opts.store ?? new Map();
    this.now = opts.now ?? (() => new Date());
  }

  private key(q: AdvisoryQuery): string {
    return `${this.inner.name}\u0000${q.productKey}\u0000${q.cpe ?? ""}\u0000${q.version ?? ""}`;
  }

  async lookup(query: AdvisoryQuery): Promise<SourceResult> {
    const key = this.key(query);
    const nowMs = this.now().getTime();
    const cached = this.store.get(key);
    if (cached && nowMs - cached.storedAt < this.opts.ttlMs) {
      return { ...cached.result, fromCache: true, stale: false };
    }
    try {
      const fresh = await this.inner.lookup(query);
      if (fresh.status === "SOURCE_UNAVAILABLE") {
        return this.degrade(cached, nowMs, fresh);
      }
      this.store.set(key, { result: fresh, storedAt: nowMs });
      return fresh;
    } catch (err) {
      return this.degrade(cached, nowMs, {
        advisories: [],
        status: "SOURCE_UNAVAILABLE",
        source: this.inner.name,
        fetchedAt: nowIso(this.now),
        fromCache: false,
        stale: false,
        error: (err as Error).message,
      });
    }
  }

  private degrade(cached: CacheEntry | undefined, nowMs: number, failure: SourceResult): SourceResult {
    const maxStale = this.opts.staleIfErrorMs ?? 0;
    if (cached && maxStale > 0 && nowMs - cached.storedAt <= maxStale) {
      return { ...cached.result, fromCache: true, stale: true, ...(failure.error ? { error: failure.error } : {}) };
    }
    return failure;
  }
}

// ---------------------------------------------------------------------------- NVD / KEV

export interface NvdOptions {
  fetch: typeof fetch;
  /** NVD API key, sent as `apiKey` when present (raises the rate limit). */
  apiKey?: string;
  baseUrl?: string;
  timeoutMs?: number;
  retries?: number;
  /** CVE ids known to be exploited in the wild (CISA KEV). */
  kev?: Set<string>;
  now?: () => Date;
}

function cvssFrom(metrics: unknown): CvssScore | undefined {
  const m = metrics as Record<string, unknown> | undefined;
  if (!m) return undefined;
  for (const key of ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const arr = m[key];
    if (Array.isArray(arr) && arr.length > 0) {
      const first = arr[0] as Record<string, unknown>;
      const data = (first.cvssData ?? {}) as Record<string, unknown>;
      const version = key === "cvssMetricV2" ? "2.0" : key === "cvssMetricV30" ? "3.0" : "3.1";
      const score = typeof data.baseScore === "number" ? data.baseScore : Number(data.baseScore);
      if (Number.isFinite(score)) {
        return { version, score, severity: String(data.baseSeverity ?? ""), vector: String(data.vectorString ?? "") };
      }
    }
  }
  return undefined;
}

/**
 * The `vendor:product` identity of a CPE string, or "" when it cannot be determined. Handles the
 * CPE 2.3 formatted-string binding (`cpe:2.3:part:vendor:product:…`) and the older URI binding
 * (`cpe:/part:vendor:product:…`).
 */
export function cpeProductKey(cpe: string): string {
  const parts = (cpe ?? "").split(":");
  if (parts[0] !== "cpe") return "";
  if (parts[1] === "2.3") return `${(parts[3] ?? "").toLowerCase()}:${(parts[4] ?? "").toLowerCase()}`;
  if ((parts[1] ?? "").startsWith("/")) return `${(parts[2] ?? "").toLowerCase()}:${(parts[3] ?? "").toLowerCase()}`;
  return "";
}

/**
 * Extract machine-evaluable affected ranges from an NVD `configurations` array.
 *
 * A single CVE can list `cpeMatch` entries for several products (and for `AND`-nodes). Only the
 * ranges whose CPE belongs to the queried `vendor:product` are kept, so a multi-product CVE cannot
 * produce a candidate for an unrelated component. When either identity cannot be parsed the entry is
 * kept (to avoid silently dropping a range).
 */
function rangesFromConfigurations(configurations: unknown, queryCpe: string | null): { ranges: AdvisoryRecord["ranges"]; affected: string } {
  const out: AdvisoryRecord["ranges"] = [];
  const human: string[] = [];
  const want = cpeProductKey(queryCpe ?? "");
  if (!Array.isArray(configurations)) return { ranges: out, affected: "" };
  for (const cfg of configurations as Array<Record<string, unknown>>) {
    const nodes = cfg.nodes;
    if (!Array.isArray(nodes)) continue;
    for (const node of nodes as Array<Record<string, unknown>>) {
      const matches = node.cpeMatch;
      if (!Array.isArray(matches)) continue;
      for (const match of matches as Array<Record<string, unknown>>) {
        if (match.vulnerable === false) continue;
        const criteria = typeof match.criteria === "string" ? match.criteria : "";
        const got = cpeProductKey(criteria);
        if (want && got && got !== want) continue; // a different product's range
        const group: Array<{ op: ">=" | "<=" | ">" | "<" | "="; version: string }> = [];
        const si = match.versionStartIncluding;
        const se = match.versionStartExcluding;
        const ei = match.versionEndIncluding;
        const ee = match.versionEndExcluding;
        if (typeof si === "string") group.push({ op: ">=", version: si });
        if (typeof se === "string") group.push({ op: ">", version: se });
        if (typeof ei === "string") group.push({ op: "<=", version: ei });
        if (typeof ee === "string") group.push({ op: "<", version: ee });
        out.push(group);
        human.push(
          [
            typeof si === "string" ? `>= ${si}` : "",
            typeof se === "string" ? `> ${se}` : "",
            typeof ee === "string" ? `< ${ee}` : "",
            typeof ei === "string" ? `<= ${ei}` : "",
          ]
            .filter(Boolean)
            .join(" ") || "all versions",
        );
      }
    }
  }
  return { ranges: out, affected: human.join("; ") };
}

export class NvdVulnerabilitySource implements VulnerabilitySource {
  readonly name = "nvd";
  private readonly fetch: typeof fetch;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly kev: Set<string>;
  private readonly now: () => Date;

  constructor(opts: NvdOptions) {
    this.fetch = opts.fetch;
    this.baseUrl = (opts.baseUrl ?? "https://services.nvd.nist.gov/rest/json/cves/2.0").replace(/\/$/, "");
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.retries = Math.max(0, opts.retries ?? 2);
    this.kev = opts.kev ?? new Set();
    this.now = opts.now ?? (() => new Date());
    if (opts.apiKey) this.apiKey = opts.apiKey;
  }
  private apiKey?: string;

  async lookup(query: AdvisoryQuery): Promise<SourceResult> {
    const fetchedAt = nowIso(this.now);
    if (!query.cpe) {
      // No CPE to query; the engine reports the mapping problem itself.
      return { advisories: [], status: "OK", source: this.name, fetchedAt, fromCache: false, stale: false };
    }
    const url = `${this.baseUrl}?cpeName=${encodeURIComponent(query.cpe)}&isVulnerable`;
    const headers: Record<string, string> = { accept: "application/json" };
    if (this.apiKey) headers.apiKey = this.apiKey;

    let lastError = "";
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const res = await this.fetch(url, { headers, signal: controller.signal });
        if (res.status === 429 || res.status === 503) {
          lastError = `rate limited (HTTP ${res.status})`;
          await delay(250 * 2 ** attempt);
          continue;
        }
        if (!res.ok) {
          lastError = `HTTP ${res.status}`;
          continue;
        }
        const json = (await res.json()) as { vulnerabilities?: unknown };
        return {
          advisories: this.parse(json, query),
          status: "OK",
          source: this.name,
          fetchedAt: nowIso(this.now),
          fromCache: false,
          stale: false,
        };
      } catch (err) {
        lastError = (err as Error).name === "AbortError" ? `timeout after ${this.timeoutMs}ms` : (err as Error).message;
      } finally {
        clearTimeout(timer);
      }
    }
    return { advisories: [], status: "SOURCE_UNAVAILABLE", source: this.name, fetchedAt: nowIso(this.now), fromCache: false, stale: false, error: lastError || "unknown error" };
  }

  private parse(json: { vulnerabilities?: unknown }, query: AdvisoryQuery): AdvisoryRecord[] {
    const out: AdvisoryRecord[] = [];
    if (!Array.isArray(json.vulnerabilities)) return out;
    for (const item of json.vulnerabilities as Array<Record<string, unknown>>) {
      const cve = item.cve as Record<string, unknown> | undefined;
      if (!cve || typeof cve.id !== "string") continue;
      const { ranges, affected } = rangesFromConfigurations(cve.configurations, query.cpe);
      const cvss = cvssFrom(cve.metrics);
      out.push({
        cveId: cve.id,
        productKey: query.productKey,
        vendor: "",
        ...(typeof cve.sourceIdentifier === "string" ? { title: cve.sourceIdentifier } : {}),
        affected: affected || "all versions",
        ranges,
        ...(cvss ? { cvss } : {}),
        ...(typeof cve.published === "string" ? { published: cve.published } : {}),
        ...(typeof cve.lastModified === "string" ? { modified: cve.lastModified } : {}),
        kev: this.kev.has(cve.id),
        sourceUrl: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
        source: this.name,
      });
    }
    return out;
  }
}

/** Parse a CISA KEV catalog document into a set of exploited CVE ids. */
export function kevCveSet(json: unknown): Set<string> {
  const set = new Set<string>();
  const vulns = (json as { vulnerabilities?: unknown } | undefined)?.vulnerabilities;
  if (!Array.isArray(vulns)) return set;
  for (const v of vulns as Array<Record<string, unknown>>) {
    if (typeof v.cveID === "string") set.add(v.cveID);
  }
  return set;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
