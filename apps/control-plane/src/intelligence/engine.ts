import { mapProductToCpe } from "./products.js";
import type { VulnerabilitySource } from "./source.js";
import { compareVersions, versionInRange } from "./version.js";
import {
  ApplicabilityState,
  CpeMapping,
  VersionCertainty,
  type AdvisoryRecord,
  type CveLookupCoverage,
  type TechnologyFingerprint,
  type VersionCertaintyValue,
  type VulnerabilityMatch,
  type VulnerabilityReport,
} from "./types.js";

/**
 * Correlate technology fingerprints with published advisories.
 *
 * The engine is deliberately conservative: a version inside a published affected range yields a
 * `MATCH_CANDIDATE` (never `VALIDATED`); an unknown version yields `NEEDS_VERSION_CONFIRMATION`
 * rather than a guess; an ambiguous product mapping or a vendor backport yields
 * `NEEDS_APPLICABILITY_REVIEW`; and an intelligence outage yields `SOURCE_UNAVAILABLE` instead of a
 * silent pass. Nothing here can set `VALIDATED`.
 */

export interface CorrelateOptions {
  now?: () => Date;
  /** Cap on distinct products looked up (bounds external calls). */
  maxProducts?: number;
}

interface ProductGroup {
  key: string;
  product: string;
  vendor: string;
  cpe: string | null;
  mapping: (typeof CpeMapping)[keyof typeof CpeMapping];
  fingerprints: TechnologyFingerprint[];
  versions: string[];
  certainty: VersionCertaintyValue;
  conflict: boolean;
}

function groupProducts(fingerprints: TechnologyFingerprint[]): ProductGroup[] {
  const groups = new Map<string, ProductGroup>();
  for (const fp of fingerprints) {
    let g = groups.get(fp.productKey);
    if (!g) {
      const lookup = mapProductToCpe(fp.product);
      g = { key: fp.productKey, product: fp.product, vendor: fp.vendor, cpe: lookup.cpe, mapping: lookup.mapping, fingerprints: [], versions: [], certainty: VersionCertainty.UNKNOWN, conflict: false };
      groups.set(fp.productKey, g);
    }
    g.fingerprints.push(fp);
    if (fp.observedVersion) g.versions.push(fp.observedVersion);
  }
  for (const g of groups.values()) {
    const distinct = Array.from(new Set(g.versions)).sort(compareVersions);
    if (distinct.length === 0) {
      g.certainty = VersionCertainty.UNKNOWN;
    } else if (distinct.length === 1) {
      const source = g.fingerprints.find((f) => f.observedVersion === distinct[0]);
      g.certainty = source?.versionCertainty ?? VersionCertainty.INFERRED;
    } else {
      // Different versions of the same product on different hosts (or a changed banner): a bounded
      // range, not a single truth. Matching evaluates every observed version.
      g.certainty = VersionCertainty.RANGE;
      g.conflict = true;
    }
    g.versions = distinct;
  }
  return Array.from(groups.values()).sort((a, b) => a.key.localeCompare(b.key));
}

interface RangeEval {
  result: boolean | null;
  /** The specific observed versions that fall inside the affected range (for version-accurate evidence). */
  matchedVersions: Set<string>;
  /** True when a range group had no version bound, so every observed version is affected. */
  unbounded: boolean;
}

function satisfiesVersion(v: string, op: ">=" | "<=" | ">" | "<" | "=", bound: string): boolean | null {
  if (versionInRange(v, `${op}${bound}`) === null) return null;
  const cmp = compareVersions(v, bound);
  switch (op) {
    case ">=":
      return cmp >= 0;
    case "<=":
      return cmp <= 0;
    case ">":
      return cmp > 0;
    case "<":
      return cmp < 0;
    case "=":
      return cmp === 0;
  }
}

function evaluateRanges(versions: string[], ranges: AdvisoryRecord["ranges"]): RangeEval {
  const matched = new Set<string>();
  if (versions.length === 0 || ranges.length === 0) return { result: null, matchedVersions: matched, unbounded: false };
  let sawNull = false;
  let unbounded = false;
  for (const group of ranges) {
    if (group.length === 0) {
      unbounded = true;
      for (const v of versions) matched.add(v);
      continue;
    }
    for (const v of versions) {
      let ok = true;
      let unknown = false;
      for (const c of group) {
        const r = satisfiesVersion(v, c.op, c.version);
        if (r === false) {
          ok = false;
          break;
        }
        if (r === null) unknown = true;
      }
      if (ok && !unknown) matched.add(v);
      else if (ok && unknown) sawNull = true;
      // `ok === false` means a constraint definitively excluded this version: not inconclusive.
    }
  }
  if (matched.size > 0) return { result: true, matchedVersions: matched, unbounded };
  return { result: sawNull ? null : false, matchedVersions: matched, unbounded };
}

function severityRank(m: VulnerabilityMatch): number {
  const sev = (m.cvss?.severity ?? "").toUpperCase();
  const order: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, NONE: 1 };
  if (sev in order) return order[sev]!;
  if (m.cvss) return 1.5;
  return 0;
}

export async function correlateTechnologies(
  scanId: string,
  fingerprints: TechnologyFingerprint[],
  source: VulnerabilitySource,
  opts: CorrelateOptions = {},
): Promise<VulnerabilityReport> {
  const now = opts.now ?? (() => new Date());
  const products = groupProducts(fingerprints).slice(0, opts.maxProducts ?? 500);

  const coverage: CveLookupCoverage = {
    products: products.length,
    matched: 0,
    candidates: 0,
    needsVersion: 0,
    needsReview: 0,
    notApplicable: 0,
    inconclusive: 0,
    sourceUnavailable: 0,
    unmatchedProducts: [],
    ambiguousProducts: [],
    staleSources: 0,
  };
  const matches = new Map<string, VulnerabilityMatch>();
  const sources = new Map<string, { source: string; status: string; fetchedAt: string | null; stale: boolean; detail?: string }>();
  const limitations: string[] = [
    "A CVE candidate is an inference from an observed product/version, not a confirmed vulnerability; ReconNexus never validates exploitation.",
    "Only versions visible in persisted technology evidence are evaluated; an absent or masked version yields NEEDS_VERSION_CONFIRMATION, not a match.",
    "A vendor backport or mitigation can make an in-range version unaffected; such matches require human applicability review.",
  ];

  for (const g of products) {
    if (g.mapping === CpeMapping.UNMATCHED) {
      coverage.unmatchedProducts.push(g.product);
      continue;
    }
    const versionForLookup = g.versions.length === 1 ? g.versions[0]! : null;
    const lookup = await source.lookup({ productKey: g.key, cpe: g.cpe, version: versionForLookup });
    const prev = sources.get(lookup.source);
    const entry = { source: lookup.source, status: lookup.status, fetchedAt: lookup.fetchedAt, stale: lookup.stale, ...(lookup.error ? { detail: lookup.error } : {}) };
    // Keep the least-healthy status seen for this source.
    if (!prev || (prev.status === "OK" && lookup.status !== "OK") || (lookup.stale && !prev.stale)) sources.set(lookup.source, entry);
    if (lookup.stale) coverage.staleSources++;

    if (lookup.status === "SOURCE_UNAVAILABLE") {
      coverage.sourceUnavailable++;
      continue;
    }

    let produced = false;
    for (const advisory of lookup.advisories) {
      const { state, rationale, rangeEval } = applicability(g, advisory);
      if (state === ApplicabilityState.NOT_APPLICABLE) {
        coverage.notApplicable++;
        continue;
      }
      produced = true;
      if (state === ApplicabilityState.INCONCLUSIVE) coverage.inconclusive++;
      if (state === ApplicabilityState.NEEDS_VERSION_CONFIRMATION) coverage.needsVersion++;
      if (state === ApplicabilityState.NEEDS_APPLICABILITY_REVIEW) coverage.needsReview++;
      if (state === ApplicabilityState.MATCH_CANDIDATE) coverage.candidates++;

      const key = `${advisory.cveId}\u0000${g.key}`;
      const existing = matches.get(key);
      // Cite only the fingerprints that actually carried the matched version (or all, if the
      // advisory had no version bound), so a host with a generic banner is never implied vulnerable.
      const contributing = rangeEval.unbounded
        ? g.fingerprints
        : g.fingerprints.filter((f) => f.observedVersion !== null && rangeEval.matchedVersions.has(f.observedVersion));
      const evidenceSet = contributing.length > 0 ? contributing : g.fingerprints;
      const hosts = Array.from(new Set(evidenceSet.map((f) => f.host).filter(Boolean))).sort();
      const refs = Array.from(new Set(evidenceSet.map((f) => f.evidenceRef))).sort();
      const match: VulnerabilityMatch = {
        cveId: advisory.cveId,
        product: g.product,
        productKey: g.key,
        vendor: g.vendor,
        observedVersion: g.versions.join(", ") || null,
        versionCertainty: g.certainty,
        applicability: state,
        rationale,
        affected: advisory.affected,
        ...(advisory.fixedIn ? { fixedIn: advisory.fixedIn } : {}),
        ...(advisory.backportNote ? { backportNote: advisory.backportNote } : {}),
        ...(advisory.cvss ? { cvss: advisory.cvss } : {}),
        kev: advisory.kev,
        sourceUrl: advisory.sourceUrl,
        source: advisory.source,
        ...(advisory.published ? { published: advisory.published } : {}),
        ...(advisory.modified ? { modified: advisory.modified } : {}),
        lookupAt: lookup.fetchedAt,
        stale: lookup.stale,
        evidenceRefs: refs,
        hosts,
      };
      if (existing) {
        existing.hosts = Array.from(new Set([...existing.hosts, ...hosts])).sort();
        existing.evidenceRefs = Array.from(new Set([...existing.evidenceRefs, ...refs]));
      } else {
        matches.set(key, match);
      }
    }
    // An ambiguous product that yielded no advisory outcome (e.g. the NVD path, where an ambiguous
    // mapping has no CPE to query) must still be surfaced: silently dropping it would hide the
    // ambiguity and imply the product was clean.
    if (g.mapping === CpeMapping.AMBIGUOUS && !produced) {
      coverage.needsReview++;
      coverage.ambiguousProducts.push(g.product);
    }
  }

  const ordered = Array.from(matches.values()).sort(
    (a, b) => severityRank(b) - severityRank(a) || (b.cvss?.score ?? 0) - (a.cvss?.score ?? 0) || a.cveId.localeCompare(b.cveId),
  );
  coverage.matched = new Set(ordered.map((m) => m.productKey)).size;

  if (coverage.unmatchedProducts.length) {
    limitations.push(`${coverage.unmatchedProducts.length} product(s) had no CPE mapping and were not looked up: ${coverage.unmatchedProducts.slice(0, 10).join(", ")}`);
  }
  if (coverage.ambiguousProducts.length) {
    limitations.push(`${coverage.ambiguousProducts.length} product(s) mapped to multiple CPEs and require applicability review: ${coverage.ambiguousProducts.slice(0, 10).join(", ")}`);
  }
  if (coverage.sourceUnavailable > 0) {
    limitations.push("One or more intelligence sources were unavailable for some products; those CVEs are unknown, not absent.");
  }

  return {
    scanId,
    generatedAt: now().toISOString(),
    matches: ordered,
    coverage,
    sources: Array.from(sources.values()),
    limitations,
  };
}

type ApplicabilityValue = (typeof ApplicabilityState)[keyof typeof ApplicabilityState];
const EMPTY_EVAL: RangeEval = { result: null, matchedVersions: new Set(), unbounded: false };

/** Decide the applicability state for one product group against one advisory. */
export function applicability(g: ProductGroup, advisory: AdvisoryRecord): { state: ApplicabilityValue; rationale: string; rangeEval: RangeEval } {
  if (g.mapping === CpeMapping.AMBIGUOUS) {
    return { state: ApplicabilityState.NEEDS_APPLICABILITY_REVIEW, rationale: "product maps to multiple CPEs; the CVE's product identity must be confirmed by a human", rangeEval: EMPTY_EVAL };
  }
  if (g.versions.length === 0 || g.certainty === VersionCertainty.UNKNOWN) {
    return { state: ApplicabilityState.NEEDS_VERSION_CONFIRMATION, rationale: "a CVE exists for this product but no usable version was observed", rangeEval: EMPTY_EVAL };
  }
  if (advisory.ranges.length === 0) {
    return { state: ApplicabilityState.INCONCLUSIVE, rationale: "the advisory has no machine-evaluable version range", rangeEval: EMPTY_EVAL };
  }
  const ev = evaluateRanges(g.versions, advisory.ranges);
  if (ev.result === null) {
    return { state: ApplicabilityState.INCONCLUSIVE, rationale: "observed version could not be compared to the affected range", rangeEval: ev };
  }
  if (!ev.result) {
    return { state: ApplicabilityState.NOT_APPLICABLE, rationale: "observed version is outside every published affected range", rangeEval: ev };
  }
  if (advisory.backportNote) {
    return { state: ApplicabilityState.NEEDS_APPLICABILITY_REVIEW, rationale: `in range, but a vendor backport/mitigation may apply: ${advisory.backportNote}`, rangeEval: ev };
  }
  const conflict = g.conflict ? " (multiple observed versions; at least one is in range)" : "";
  return { state: ApplicabilityState.MATCH_CANDIDATE, rationale: `observed version is inside the affected range${conflict}; not yet validated`, rangeEval: ev };
}
