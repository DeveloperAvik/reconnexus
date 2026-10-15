/**
 * Vulnerability-intelligence vocabulary. These are deliberately distinct from the scan statuses:
 * a CVE *candidate* is an inference from an observed product/version, never a confirmed
 * vulnerability, and the applicability state records exactly how far the evidence goes.
 */

/** How precisely a version was observed for a product. */
export const VersionCertainty = {
  /** A concrete version was read from a banner/header/body (e.g. `nginx/1.25.3`). */
  EXACT: "EXACT",
  /** A version was derived indirectly (a range, a family, or a build hint). */
  INFERRED: "INFERRED",
  /** Only a bounded range is known (e.g. conflicting banners give min..max). */
  RANGE: "RANGE",
  /** No usable version evidence. */
  UNKNOWN: "UNKNOWN",
} as const;
export type VersionCertaintyValue = (typeof VersionCertainty)[keyof typeof VersionCertainty];

/** How confidently a product name was mapped to a CPE 2.3 identifier. */
export const CpeMapping = {
  EXACT: "EXACT",
  PROBABLE: "PROBABLE",
  AMBIGUOUS: "AMBIGUOUS",
  UNMATCHED: "UNMATCHED",
} as const;
export type CpeMappingValue = (typeof CpeMapping)[keyof typeof CpeMapping];

/**
 * Applicability of one CVE to one observed product/version. Each state has one meaning and is never
 * silently converted into another:
 *  - MATCH_CANDIDATE:            the observed version falls in a published affected range; unvalidated.
 *  - NEEDS_VERSION_CONFIRMATION: a CVE may apply but the product's version is unknown/uncertain.
 *  - NEEDS_APPLICABILITY_REVIEW: the product mapped ambiguously, or a backport/mitigation exists.
 *  - VALIDATED:                  a human confirmed applicability (never set automatically).
 *  - NOT_APPLICABLE:             the observed version is outside every published affected range.
 *  - INCONCLUSIVE:               the range or version could not be evaluated.
 *  - SOURCE_UNAVAILABLE:         the intelligence source could not be consulted.
 */
export const ApplicabilityState = {
  MATCH_CANDIDATE: "MATCH_CANDIDATE",
  NEEDS_VERSION_CONFIRMATION: "NEEDS_VERSION_CONFIRMATION",
  NEEDS_APPLICABILITY_REVIEW: "NEEDS_APPLICABILITY_REVIEW",
  VALIDATED: "VALIDATED",
  NOT_APPLICABLE: "NOT_APPLICABLE",
  INCONCLUSIVE: "INCONCLUSIVE",
  SOURCE_UNAVAILABLE: "SOURCE_UNAVAILABLE",
} as const;
export type ApplicabilityStateValue = (typeof ApplicabilityState)[keyof typeof ApplicabilityState];

/** A technology observation normalised into product/version evidence, with provenance. */
export interface TechnologyFingerprint {
  product: string;
  /** Best-effort vendor from the product dictionary; empty when unknown. */
  vendor: string;
  /** Normalised (lowercased) product key. */
  productKey: string;
  observedVersion: string | null;
  versionCertainty: VersionCertaintyValue;
  /** The asset the fingerprint was observed on. */
  host: string;
  category: string;
  /** Where the evidence came from: header, body, banner, script, protocol… */
  evidenceSource: string;
  evidence: string;
  confidence: number;
  /** Stable back-reference to the observation that produced this fingerprint. */
  evidenceRef: string;
}

export interface CvssScore {
  version: string;
  score: number;
  severity: string;
  vector: string;
}

/** One CVE as published by a source, with the affected criteria needed to evaluate a version. */
export interface AdvisoryRecord {
  cveId: string;
  /** Product key this advisory is filed under (matches `TechnologyFingerprint.productKey`). */
  productKey: string;
  vendor: string;
  title?: string;
  /** Human-readable affected criteria, kept verbatim for the report. */
  affected: string;
  /** Machine-evaluable ranges (OR-of-AND). Empty means "unknown range". */
  ranges: Array<Array<{ op: ">=" | "<=" | ">" | "<" | "="; version: string }>>;
  fixedIn?: string;
  /** A vendor backport or mitigation that may defeat a naive range comparison. */
  backportNote?: string;
  cvss?: CvssScore;
  published?: string;
  modified?: string;
  /** CISA KEV membership. */
  kev: boolean;
  sourceUrl: string;
  source: string;
}

export interface SourceLookup {
  productKey: string;
  cpe: string | null;
  cpeMapping: CpeMappingValue;
  advisories: AdvisoryRecord[];
  status: "OK" | "SOURCE_UNAVAILABLE";
  source: string;
  fetchedAt: string;
  fromCache: boolean;
  stale: boolean;
  /** Populated when status is SOURCE_UNAVAILABLE. */
  error?: string;
}

export interface VulnerabilityMatch {
  cveId: string;
  product: string;
  productKey: string;
  vendor: string;
  observedVersion: string | null;
  versionCertainty: VersionCertaintyValue;
  applicability: ApplicabilityStateValue;
  /** Why the state was chosen, in plain language. */
  rationale: string;
  affected: string;
  fixedIn?: string;
  backportNote?: string;
  cvss?: CvssScore;
  kev: boolean;
  sourceUrl: string;
  source: string;
  published?: string;
  modified?: string;
  lookupAt: string;
  stale: boolean;
  /** Evidence that supports this match (observation back-references). */
  evidenceRefs: string[];
  hosts: string[];
}

export interface CveLookupCoverage {
  products: number;
  matched: number;
  candidates: number;
  needsVersion: number;
  needsReview: number;
  notApplicable: number;
  inconclusive: number;
  sourceUnavailable: number;
  unmatchedProducts: string[];
  /** Products whose name mapped to multiple plausible CPEs; a human must disambiguate. */
  ambiguousProducts: string[];
  staleSources: number;
}

export interface VulnerabilityReport {
  scanId: string;
  generatedAt: string;
  matches: VulnerabilityMatch[];
  coverage: CveLookupCoverage;
  /** Data-source freshness and failures, surfaced rather than hidden. */
  sources: Array<{ source: string; status: string; fetchedAt: string | null; stale: boolean; detail?: string }>;
  limitations: string[];
}
