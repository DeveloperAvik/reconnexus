import { StageId, type StageIdValue } from "@reconnexus/contracts";

/**
 * Read-only scan-to-scan change intelligence.
 *
 * The engine compares the observations two scans actually recorded. It never issues a network
 * request and never invents a change. A change is only reported as ADDED/REMOVED/CHANGED when the
 * stage that produces that category was fully `COLLECTED` in the relevant scan; otherwise the item
 * is reported `UNKNOWN` with the reason, because a skipped/failed/partial stage is a coverage gap,
 * not evidence of absence.
 */

export const ChangeOutcome = {
  ADDED: "ADDED",
  REMOVED: "REMOVED",
  CHANGED: "CHANGED",
  UNCHANGED: "UNCHANGED",
  UNKNOWN: "UNKNOWN",
} as const;
export type ChangeOutcomeValue = (typeof ChangeOutcome)[keyof typeof ChangeOutcome];

/** Outcome display order for deterministic output. */
export const OUTCOME_ORDER: ChangeOutcomeValue[] = [
  ChangeOutcome.ADDED,
  ChangeOutcome.REMOVED,
  ChangeOutcome.CHANGED,
  ChangeOutcome.UNKNOWN,
  ChangeOutcome.UNCHANGED,
];

export interface ComparisonAssetRow {
  id: string;
  type: string;
  canonical_key: string;
  value: string;
}

export interface ComparisonObsRow {
  asset_type: string;
  asset_value: string;
  canonical_key: string;
  kind: string;
  data: Record<string, unknown>;
  source: string;
  observed_at: Date | string;
}

export interface ComparisonCoverageRow {
  stage: string;
  status: string;
}

export interface ComparisonScanRow {
  id: string;
  project_id: string;
  root_domain: string;
}

/**
 * The read-only subset of `Repository` the engine needs. `Repository` satisfies it structurally;
 * tests can supply an in-memory source.
 */
export interface ComparisonSource {
  getScan(scanId: string): Promise<ComparisonScanRow | null>;
  listScanAssets(scanId: string, types?: string[]): Promise<ComparisonAssetRow[]>;
  listScanObservations(scanId: string, filter: { kinds?: string[]; kindPrefix?: string }): Promise<ComparisonObsRow[]>;
  listCoverage(scanId: string): Promise<ComparisonCoverageRow[]>;
}

export class ComparisonError extends Error {
  constructor(
    message: string,
    readonly code: "NOT_FOUND" | "CROSS_PROJECT",
  ) {
    super(message);
    this.name = "ComparisonError";
  }
}

/** Normalized observation used by every category comparator. */
export interface ComparisonObs {
  assetType: string;
  assetValue: string;
  canonicalKey: string;
  kind: string;
  data: Record<string, unknown>;
  source: string;
  observedAt: string;
}

export interface ChangeItem {
  category: string;
  outcome: ChangeOutcomeValue;
  key: string;
  assetType: string;
  assetValue: string;
  stage: StageIdValue;
  baseline: { source: string; observedAt: string; fields: Record<string, unknown> } | null;
  current: { source: string; observedAt: string; fields: Record<string, unknown> } | null;
  /** For CHANGED: the projection fields whose values differ. */
  changedFields?: string[];
  /** For UNKNOWN: why the change could not be established. */
  reason?: string;
}

export interface CategoryStageCoverage {
  stage: string;
  baseline: string;
  current: string;
  /** True when both scans fully collected this stage, so a REMOVED/CHANGED verdict is supported. */
  comparable: boolean;
}

export interface CategoryComparison {
  category: string;
  description: string;
  coverage: CategoryStageCoverage[];
  totals: Record<ChangeOutcomeValue, number>;
  total: number;
  changes: ChangeItem[];
  truncated: boolean;
}

export interface ComparisonLimitation {
  code: string;
  detail: string;
}

export interface ScanComparison {
  baselineScanId: string;
  currentScanId: string;
  projectId: string;
  rootDomain: string;
  generatedAt: string;
  categories: CategoryComparison[];
  limitations: ComparisonLimitation[];
}

export interface CompareOptions {
  categories?: string[];
  statuses?: ChangeOutcomeValue[];
  /** Max change rows returned per category (totals stay exact). */
  limit?: number;
  now?: () => Date;
}

// ---------------------------------------------------------------------------- helpers

/** Stable JSON for structural equality and hashing: object keys sorted at every depth. */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
}

function toIso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : String(value);
}

/** Top-level projection keys whose stable values differ, in sorted order. */
function changedFields(a: Record<string, unknown>, b: Record<string, unknown>): string[] {
  const keys = Array.from(new Set([...Object.keys(a), ...Object.keys(b)])).sort();
  return keys.filter((k) => stableStringify(a[k]) !== stableStringify(b[k]));
}

function countOf(value: unknown): number {
  return Array.isArray(value) ? value.length : 0;
}

// ---------------------------------------------------------------------------- category specs

interface CategorySpec {
  name: string;
  description: string;
  load: { kinds?: string[]; kindPrefix?: string } | { assets: true };
  /** Stages that would produce this category, for coverage reporting. */
  stages: StageIdValue[];
  /** The stage that produces a given item, used for the coverage-gap decision. */
  stageFor(obs: ComparisonObs): StageIdValue;
  identity(obs: ComparisonObs): string;
  /** Comparable projection; only stable, meaningful fields (never timestamps or evidence blobs). */
  project(obs: ComparisonObs): Record<string, unknown>;
}

/** Asset type → the stage that discovers it (used to gate "removed" verdicts). */
const ASSET_STAGE: Record<string, StageIdValue> = {
  DOMAIN: StageId.TARGET_INTELLIGENCE,
  SUBDOMAIN: StageId.SUBDOMAIN_DISCOVERY,
  HOST: StageId.SUBDOMAIN_DISCOVERY,
  IP: StageId.DNS_INFRA,
  CIDR: StageId.DNS_INFRA,
  ASN: StageId.DNS_INFRA,
  SERVICE: StageId.HTTP_PROBE,
  CERTIFICATE: StageId.HTTP_PROBE,
  TECHNOLOGY: StageId.HTTP_PROBE,
  URL: StageId.URL_COLLECTION,
  JS_ARTIFACT: StageId.JS_INTELLIGENCE,
  API_ENDPOINT: StageId.API_DISCOVERY,
};

function str(v: unknown): string {
  return typeof v === "string" ? v : v === null || v === undefined ? "" : String(v);
}

export const CATEGORY_SPECS: CategorySpec[] = [
  {
    name: "assets",
    description: "observed assets by type (subdomains, hosts, IPs, services, URLs, endpoints, JS, certificates)",
    load: { assets: true },
    stages: Array.from(new Set(Object.values(ASSET_STAGE))),
    stageFor: (o) => ASSET_STAGE[o.assetType] ?? StageId.SUBDOMAIN_DISCOVERY,
    identity: (o) => `${o.assetType}\u0000${o.canonicalKey}`,
    project: () => ({}),
  },
  {
    name: "dns",
    description: "DNS records (A/AAAA/CNAME/MX/NS/TXT/PTR) and their targets",
    load: { kindPrefix: "dns:" },
    stages: [StageId.DNS_INFRA],
    stageFor: () => StageId.DNS_INFRA,
    identity: (o) => `${o.assetType}|${o.assetValue}|${o.kind.slice(4).toUpperCase()}`,
    project: (o) => ({ value: str(o.data.value), status: str(o.data.status) }),
  },
  {
    name: "http",
    description: "HTTP services: status, title, server, content type, final URL, redirects",
    load: { kinds: ["http"] },
    stages: [StageId.HTTP_PROBE],
    stageFor: () => StageId.HTTP_PROBE,
    identity: (o) => `${o.assetType}|${o.assetValue}`,
    project: (o) => ({
      statusCode: o.data.statusCode ?? null,
      statusText: str(o.data.statusText),
      contentType: str(o.data.contentType),
      title: str(o.data.title),
      server: str(o.data.server),
      finalUrl: str(o.data.finalUrl),
      probeStatus: str(o.data.probeStatus),
    }),
  },
  {
    name: "tls",
    description: "TLS certificates presented by services (rotation/addition/removal)",
    load: { kinds: ["tls"] },
    stages: [StageId.HTTP_PROBE],
    stageFor: () => StageId.HTTP_PROBE,
    identity: (o) => `${o.assetType}|${o.canonicalKey}`,
    project: (o) => ({
      subject: str(o.data.subject),
      issuer: str(o.data.issuer),
      protocol: str(o.data.protocol),
      notBefore: str(o.data.notBefore),
      notAfter: str(o.data.notAfter),
      sanCount: countOf(o.data.sans),
    }),
  },
  {
    name: "technology",
    description: "detected technologies per host",
    load: { kinds: ["technology"] },
    stages: [StageId.HTTP_PROBE],
    stageFor: () => StageId.HTTP_PROBE,
    identity: (o) => `${str(o.data.host)}|${o.assetValue}`,
    project: (o) => ({ category: str(o.data.category) }),
  },
  {
    name: "api",
    description: "API endpoints and specification changes",
    load: { kinds: ["api-endpoint", "api-spec"] },
    stages: [StageId.API_DISCOVERY],
    stageFor: () => StageId.API_DISCOVERY,
    identity: (o) =>
      o.kind === "api-spec"
        ? `spec|${o.assetValue}`
        : `endpoint|${str(o.data.method)}|${str(o.data.origin)}${str(o.data.path)}`,
    project: (o) =>
      o.kind === "api-spec"
        ? { specVersion: str(o.data.specVersion), pathCount: o.data.pathCount ?? null, operationCount: o.data.operationCount ?? null, parseStatus: str(o.data.parseStatus) }
        : { documented: o.data.documented ?? null, resolved: o.data.resolved ?? null, params: countOf(o.data.parameters), contentTypes: o.data.contentTypes ?? [] },
  },
  {
    name: "js",
    description: "JavaScript artifacts (content hash/size) and source maps",
    load: { kinds: ["js-artifact", "source-map"] },
    stages: [StageId.JS_INTELLIGENCE],
    stageFor: () => StageId.JS_INTELLIGENCE,
    identity: (o) => `${o.kind}|${o.canonicalKey}`,
    project: (o) =>
      o.kind === "js-artifact"
        ? { contentHash: str(o.data.contentHash), sizeBytes: o.data.sizeBytes ?? null, status: str(o.data.status) }
        : { status: str(o.data.status), sourcesCount: o.data.sourcesCount ?? null, hasContent: o.data.hasContent ?? null },
  },
  {
    name: "findings",
    description: "secret findings and subdomain-takeover candidates, including resolution/regression",
    load: { kinds: ["secret-finding", "takeover-candidate"] },
    stages: [StageId.SECRET_DETECTION, StageId.TAKEOVER],
    stageFor: (o) => (o.kind === "takeover-candidate" ? StageId.TAKEOVER : StageId.SECRET_DETECTION),
    identity: (o) =>
      o.kind === "takeover-candidate"
        ? `takeover|${o.assetValue}|${str(o.data.cname)}`
        : `secret|${str(o.data.ruleId)}|${str(o.data.artifactUrl)}|${str(o.data.location)}|${str(o.data.fingerprint)}`,
    project: (o) =>
      o.kind === "takeover-candidate"
        ? { status: str(o.data.status), confidence: o.data.confidence ?? null, httpStatus: o.data.httpStatus ?? null, service: str(o.data.service) }
        : { status: str(o.data.status), confidence: o.data.confidence ?? null, category: str(o.data.category) },
  },
];

export function categoryNames(): string[] {
  return CATEGORY_SPECS.map((s) => s.name);
}

// ---------------------------------------------------------------------------- engine

async function loadCategory(source: ComparisonSource, scanId: string, spec: CategorySpec): Promise<ComparisonObs[]> {
  if ("assets" in spec.load) {
    const rows = await source.listScanAssets(scanId);
    return rows.map((a) => ({ assetType: a.type, assetValue: a.value, canonicalKey: a.canonical_key, kind: "asset", data: {}, source: "inventory", observedAt: "" }));
  }
  const rows = await source.listScanObservations(scanId, {
    ...(spec.load.kinds ? { kinds: spec.load.kinds } : {}),
    ...(spec.load.kindPrefix ? { kindPrefix: spec.load.kindPrefix } : {}),
  });
  return rows.map((o) => ({
    assetType: o.asset_type,
    assetValue: o.asset_value,
    canonicalKey: o.canonical_key,
    kind: o.kind,
    data: o.data ?? {},
    source: o.source,
    observedAt: toIso(o.observed_at),
  }));
}

/** Deduplicate by identity, keeping the observation with the latest `observedAt` (then a stable
 * tie-break) so duplicate observations compare deterministically. */
function indexByIdentity(spec: CategorySpec, obs: ComparisonObs[]): Map<string, ComparisonObs> {
  const map = new Map<string, ComparisonObs>();
  for (const o of obs) {
    const key = spec.identity(o);
    const prev = map.get(key);
    if (!prev) {
      map.set(key, o);
      continue;
    }
    const cmp = prev.observedAt.localeCompare(o.observedAt);
    if (cmp < 0 || (cmp === 0 && stableStringify(prev.data) <= stableStringify(o.data))) map.set(key, o);
  }
  return map;
}

export async function compareScans(
  source: ComparisonSource,
  baselineScanId: string,
  currentScanId: string,
  opts: CompareOptions = {},
): Promise<ScanComparison> {
  const [baseline, current] = await Promise.all([source.getScan(baselineScanId), source.getScan(currentScanId)]);
  if (!baseline) throw new ComparisonError(`baseline scan not found: ${baselineScanId}`, "NOT_FOUND");
  if (!current) throw new ComparisonError(`current scan not found: ${currentScanId}`, "NOT_FOUND");
  if (baseline.project_id !== current.project_id) {
    throw new ComparisonError("scans belong to different projects; a comparison would be meaningless", "CROSS_PROJECT");
  }

  const [baseCoverage, currCoverage] = await Promise.all([source.listCoverage(baselineScanId), source.listCoverage(currentScanId)]);
  const baseCov = new Map(baseCoverage.map((c) => [c.stage, c.status]));
  const currCov = new Map(currCoverage.map((c) => [c.stage, c.status]));
  const covered = (m: Map<string, string>, stage: string): boolean => m.get(stage) === "COLLECTED";

  const selected = opts.categories && opts.categories.length > 0 ? new Set(opts.categories) : null;
  const specs = CATEGORY_SPECS.filter((s) => !selected || selected.has(s.name));
  const statusFilter = opts.statuses && opts.statuses.length > 0 ? new Set(opts.statuses) : null;

  const categories: CategoryComparison[] = [];
  const limitations: ComparisonLimitation[] = [];

  for (const spec of specs) {
    const [baseObs, currObs] = await Promise.all([loadCategory(source, baselineScanId, spec), loadCategory(source, currentScanId, spec)]);
    const baseMap = indexByIdentity(spec, baseObs);
    const currMap = indexByIdentity(spec, currObs);

    const totals: Record<ChangeOutcomeValue, number> = { ADDED: 0, REMOVED: 0, CHANGED: 0, UNCHANGED: 0, UNKNOWN: 0 };
    const changes: ChangeItem[] = [];

    const keys = Array.from(new Set([...baseMap.keys(), ...currMap.keys()])).sort();
    for (const key of keys) {
      const b = baseMap.get(key);
      const c = currMap.get(key);
      const stage = spec.stageFor((c ?? b)!);
      const baseOk = covered(baseCov, stage);
      const currOk = covered(currCov, stage);
      const bothCovered = baseOk && currOk;

      let outcome: ChangeOutcomeValue;
      let reason: string | undefined;
      let diff: string[] | undefined;

      if (b && !c) {
        if (bothCovered) outcome = ChangeOutcome.REMOVED;
        else {
          outcome = ChangeOutcome.UNKNOWN;
          reason = !currOk ? `${stage} not fully collected in the current scan` : `${stage} not fully collected in the baseline scan`;
        }
      } else if (!b && c) {
        outcome = ChangeOutcome.ADDED;
      } else {
        const bf = spec.project(b!);
        const cf = spec.project(c!);
        const fields = changedFields(bf, cf);
        if (fields.length === 0) {
          outcome = ChangeOutcome.UNCHANGED;
        } else if (bothCovered) {
          outcome = ChangeOutcome.CHANGED;
          diff = fields;
        } else {
          outcome = ChangeOutcome.UNKNOWN;
          reason = !currOk ? `difference seen, but ${stage} was not fully collected in the current scan` : `difference seen, but ${stage} was not fully collected in the baseline scan`;
          diff = fields;
        }
      }

      totals[outcome]++;
      const item: ChangeItem = {
        category: spec.name,
        outcome,
        key,
        assetType: (c ?? b)!.assetType,
        assetValue: (c ?? b)!.assetValue,
        stage,
        baseline: b ? { source: b.source, observedAt: b.observedAt, fields: spec.project(b) } : null,
        current: c ? { source: c.source, observedAt: c.observedAt, fields: spec.project(c) } : null,
        ...(diff ? { changedFields: diff } : {}),
        ...(reason ? { reason } : {}),
      };
      if (!statusFilter || statusFilter.has(outcome)) changes.push(item);
    }

    // Deterministic ordering: outcome group, then key.
    changes.sort((a, z) => OUTCOME_ORDER.indexOf(a.outcome) - OUTCOME_ORDER.indexOf(z.outcome) || a.key.localeCompare(z.key));
    const limited = opts.limit && opts.limit > 0 ? changes.slice(0, opts.limit) : changes;

    const coverage: CategoryStageCoverage[] = spec.stages.map((stage) => ({
      stage,
      baseline: baseCov.get(stage) ?? "NOT_ATTEMPTED",
      current: currCov.get(stage) ?? "NOT_ATTEMPTED",
      comparable: covered(baseCov, stage) && covered(currCov, stage),
    }));
    for (const cov of coverage) {
      if (!cov.comparable) {
        limitations.push({
          code: "COVERAGE_GAP",
          detail: `${spec.name}: ${cov.stage} is baseline=${cov.baseline} current=${cov.current}; removals/changes in this category are reported UNKNOWN, not as absence`,
        });
      }
    }

    categories.push({ category: spec.name, description: spec.description, coverage, totals, total: keys.length, changes: limited, truncated: limited.length < changes.length });
  }

  return {
    baselineScanId,
    currentScanId,
    projectId: current.project_id,
    rootDomain: current.root_domain,
    generatedAt: (opts.now ?? (() => new Date()))().toISOString(),
    categories,
    limitations: dedupeLimitations(limitations),
  };
}

function dedupeLimitations(items: ComparisonLimitation[]): ComparisonLimitation[] {
  const seen = new Set<string>();
  const out: ComparisonLimitation[] = [];
  for (const i of items) {
    const k = `${i.code}\u0000${i.detail}`;
    if (!seen.has(k)) {
      seen.add(k);
      out.push(i);
    }
  }
  return out;
}

export const COMPARISON_LIMITATIONS: string[] = [
  "A comparison is an observation-set diff between two scans, not a claim that an asset appeared or disappeared on the target.",
  "A stage that was skipped, failed, partial, blocked or not attempted establishes no absence; affected removals/changes are reported UNKNOWN.",
  "Only observations persisted by each scan are compared; a category with no persisted evidence compares as empty, which is disclosed per stage coverage.",
  "Findings are candidates unless already validated by their own stage; a transition to absent means 'not observed this scan', not 'resolved on the target'.",
];
