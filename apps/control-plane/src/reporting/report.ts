import {
  OrderedStages,
  RECONNEXUS_VERSION,
  REPORT_SCHEMA_VERSION,
  ReportSchema,
  type Report,
  type ReportAssessment,
  type ReportEvidenceRef,
  type ReportFinding,
  type ReportIncompleteStage,
  type ReportInventory,
  type ReportProvider,
  type ReportProviderError,
  type ReportStatusValue,
  type ScopePolicy,
  type StageReport,
} from "@reconnexus/contracts";
import { redactString } from "@reconnexus/logging";
import type { Repository, ScanRow } from "../repository.js";
import { buildFindings, findingTotals } from "./findings.js";

export class ReportRedactionError extends Error {
  constructor(message: string, readonly reason?: unknown) {
    super(`report redaction failed closed: ${message}`);
    this.name = "ReportRedactionError";
  }
}

export const REPORT_LIMITATIONS: string[] = [
  "Secret findings are candidates: a pattern match does not prove a credential is valid, active, or exploitable.",
  "No finding is VALIDATED by a scan: ReconNexus performs no exploitation and verifies no credential, so validation requires manual confirmation.",
  "Severity describes the impact if a candidate is real; it is independent of confidence and of validation state.",
  "Correlations are evidence joins (e.g. shared keyed fingerprints, multi-source corroboration); they are not proof of exploitability or causation.",
  "Multi-source corroboration means multiple sources reported the same asset; it is not proof of causation.",
  "NOT_OBSERVED metadata reflects a single response at a point in time; it is not proof that a control is absent.",
  "A SKIPPED stage was not run (usually no eligible inputs) — it did not 'find nothing'.",
  "Inventory sections may be capped; a capped section is marked truncated and its total is reported separately from the rows shown.",
  "Asset counts are project-level, because canonical asset identity is per project.",
  "Fingerprints produced with different HMAC keys are not comparable; correlation assumes a stable key.",
  "Subdomain-takeover entries are CANDIDATES: a CNAME to a takeover-prone service with an unclaimed response is not proof the subdomain is takeoverable, and no takeover was attempted.",
];

/** Default cap on rows per inventory section, so a large scan cannot produce an unbounded report. */
export const REPORT_DEFAULT_MAX_ROWS = 200;
/** Default cap on evidence-appendix entries. */
export const REPORT_DEFAULT_MAX_EVIDENCE = 200;

function sortedRecord(rec: Record<string, number>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const k of Object.keys(rec).sort()) out[k] = rec[k]!;
  return out;
}

/**
 * Reconcile the analysis status from the non-reporting stages, mirroring the orchestrator's
 * reconciliation. The reporting job itself is excluded so the report can be derived while Stage 12
 * is still running (and before the scan status is reconciled).
 */
export function deriveAnalysisStatus(statuses: string[]): string {
  if (statuses.length === 0) return "PARTIAL";
  if (statuses.some((s) => s === "RUNNING" || s === "QUEUED")) return "PARTIAL";
  const anySuccess = statuses.some((s) => s === "SUCCEEDED" || s === "PARTIAL");
  const anyFail = statuses.some((s) => ["FAILED", "SOURCE_UNAVAILABLE", "BLOCKED"].includes(s));
  const anySkipped = statuses.some((s) => s === "SKIPPED");
  const allSucceeded = statuses.every((s) => s === "SUCCEEDED");
  if (allSucceeded) return "SUCCEEDED";
  if (anySuccess && (anyFail || anySkipped)) return "PARTIAL";
  if (anyFail && !anySuccess) return "FAILED";
  return "PARTIAL";
}

export function deriveReportStatus(
  analysisStatus: string,
  jobs: Array<{ jobKey: string; status: string }>,
  findingsCount: number,
): ReportStatusValue {
  const job12 = jobs.find((j) => j.jobKey === "12-reporting");
  if (job12 && ["FAILED", "SOURCE_UNAVAILABLE", "BLOCKED"].includes(job12.status)) return "REPORTING_FAILED";
  // REPORTING_NOT_RUN only when the reporting stage has never started.
  if (!job12 || job12.status === "QUEUED") return "REPORTING_NOT_RUN";
  if (analysisStatus === "FAILED") return "FAILED";
  if (analysisStatus === "PARTIAL" || analysisStatus === "CANCELLED") return "PARTIAL";
  if (analysisStatus === "SUCCEEDED") return findingsCount > 0 ? "COMPLETE_WITH_FINDINGS" : "COMPLETE_NO_FINDINGS";
  return "PARTIAL";
}

function buildSummary(scan: ScanRow, reportStatus: ReportStatusValue, stages: StageReport[], secrets: number, correlations: number, gaps: string[]): string {
  const parts: string[] = [];
  switch (reportStatus) {
    case "COMPLETE_WITH_FINDINGS":
      parts.push(`Analysis complete for ${scan.root_domain} with ${secrets} redacted secret candidate(s) and ${correlations} correlation(s).`);
      break;
    case "COMPLETE_NO_FINDINGS":
      parts.push(`Analysis complete for ${scan.root_domain} with no reportable findings.`);
      break;
    case "PARTIAL":
      parts.push(`Analysis PARTIAL for ${scan.root_domain}: some stages were skipped or failed, so absence of findings is not established.`);
      break;
    case "FAILED":
      parts.push(`Analysis FAILED for ${scan.root_domain}: results are incomplete and must not be read as "nothing found".`);
      break;
    case "REPORTING_NOT_RUN":
      parts.push(`Reporting has not been run for ${scan.root_domain}; the snapshot below reflects current persisted state.`);
      break;
    case "REPORTING_FAILED":
      parts.push(`Report generation FAILED for ${scan.root_domain}; no report was produced.`);
      break;
  }
  const skipped = stages.filter((s) => s.jobStatus === "SKIPPED").map((s) => s.stage);
  if (skipped.length) parts.push(`${skipped.length} stage(s) skipped: ${skipped.join(", ")}.`);
  if (gaps.length) parts.push(`Coverage gaps: ${gaps.join(", ")}.`);
  return parts.join(" ");
}

export interface BuildReportOptions {
  now: Date;
  /** Cap on rows per inventory section (totals remain exact). */
  maxRows?: number;
  /** Cap on evidence-appendix entries. */
  maxEvidence?: number;
}

function iso(value: Date | string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/** A bounded inventory section: exact `total`, capped `rows`, explicit `truncated`. */
function sectionOf<R>(total: number, rows: R[]): { total: number; shown: number; truncated: boolean; rows: R[] } {
  return { total, shown: rows.length, truncated: total > rows.length, rows };
}

interface CoverageDetails {
  providers?: unknown;
  durationMs?: unknown;
  startedAt?: unknown;
  finishedAt?: unknown;
}

/** Provider rows persisted in `coverage_records.details.providers` by the orchestrator. */
function providersFromDetails(details: unknown): ReportProvider[] {
  const raw = (details as CoverageDetails | null | undefined)?.providers;
  if (!Array.isArray(raw)) return [];
  const out: ReportProvider[] = [];
  for (const p of raw) {
    if (typeof p !== "object" || p === null) continue;
    const o = p as Record<string, unknown>;
    const provider = asString(o.provider);
    if (!provider) continue;
    out.push({
      provider,
      providerVersion: asString(o.providerVersion),
      outcome: asString(o.outcome) || "UNKNOWN",
      records: asNumber(o.records) ?? 0,
      reason: asString(o.reason),
      durationMs: asNumber(o.durationMs),
      attempts: asNumber(o.attempts) ?? 0,
      timedOut: o.timedOut === true,
      truncated: o.truncated === true,
    });
  }
  return out;
}

async function buildAssessment(repo: Repository, scan: ScanRow, policy: ScopePolicy | null): Promise<ReportAssessment> {
  const snapshot = (typeof scan.config_snapshot === "object" && scan.config_snapshot !== null ? scan.config_snapshot : {}) as Record<string, unknown>;
  const startedAt = iso(scan.started_at);
  const finishedAt = iso(scan.finished_at);
  const durationMs =
    startedAt !== null && finishedAt !== null ? Math.max(0, new Date(finishedAt).getTime() - new Date(startedAt).getTime()) : null;
  return {
    workspace: await repo.getWorkspaceName(scan.project_id),
    profile: asString(snapshot.profile) || "default",
    createdAt: iso(scan.created_at),
    startedAt,
    finishedAt,
    durationMs,
    policyVersion: policy?.policyVersion ?? 0,
    authorization: {
      reference: policy?.authorization.reference ?? "",
      authorizedBy: policy?.authorization.authorizedBy ?? "",
      validFrom: policy?.authorization.validFrom ?? "",
      validUntil: policy?.authorization.validUntil ?? "",
      capabilities: policy ? [...policy.authorization.capabilities] : [],
    },
    scope: {
      domains: policy ? policy.inScope.domains.map((d) => (d.includeSubdomains ? `${d.value} (+subdomains)` : d.value)) : [],
      hosts: policy ? [...policy.inScope.hosts] : [],
      ips: policy ? [...policy.inScope.ips] : [],
      cidrs: policy ? [...policy.inScope.cidrs] : [],
      excludedDomains: policy ? policy.exclusions.domains.map((d) => d.value) : [],
      excludedHosts: policy ? [...policy.exclusions.hosts] : [],
      excludedIps: policy ? [...policy.exclusions.ips] : [],
      excludedCidrs: policy ? [...policy.exclusions.cidrs] : [],
      excludedPaths: policy ? [...policy.exclusions.paths] : [],
      limits: {
        maxConcurrency: policy?.limits.maxConcurrency ?? 0,
        requestsPerSecond: policy?.limits.requestsPerSecond ?? 0,
        crawlDepth: policy?.limits.crawlDepth ?? 0,
        maxRuntimeSeconds: policy?.limits.maxRuntimeSeconds ?? 0,
        maxArtifactBytes: policy?.limits.maxArtifactBytes ?? 0,
      },
    },
  };
}

/**
 * Asset, service and intelligence inventory. Totals come from the authoritative observation
 * counts; rows are capped at `maxRows` so a large scan cannot produce an unbounded report. A
 * section whose rows were capped is marked `truncated`.
 */
async function buildInventory(repo: Repository, scanId: string, byKind: Record<string, number>, maxRows: number): Promise<ReportInventory> {
  const dnsSampleLimit = Math.max(maxRows, Math.min(maxRows * 8, 20000));

  const [dns, http, tech, urls, apis, specs, js, sourceMaps, security] = await Promise.all([
    repo.listDnsObservations(scanId, dnsSampleLimit),
    repo.listHttpObservations(scanId, maxRows),
    repo.listTechnologyObservations(scanId, maxRows),
    repo.listUrlObservations(scanId, maxRows),
    repo.listApiEndpoints(scanId, maxRows),
    repo.listApiSpecs(scanId, maxRows),
    repo.listJsArtifacts(scanId, maxRows),
    repo.listSourceMaps(scanId, maxRows),
    repo.listSecurityMetadata(scanId, maxRows),
  ]);

  // Hosts are grouped from the DNS sample; the sample is explicitly capped, so the host section
  // reports how many names it covers rather than implying full DNS coverage.
  const hostMap = new Map<string, { addresses: Set<string>; recordTypes: Set<string>; resolved: boolean }>();
  for (const r of dns) {
    const entry = hostMap.get(r.name) ?? { addresses: new Set<string>(), recordTypes: new Set<string>(), resolved: false };
    entry.recordTypes.add(r.record_type);
    if ((r.record_type === "A" || r.record_type === "AAAA") && r.value) {
      entry.addresses.add(r.value);
      if (r.status === "NOERROR") entry.resolved = true;
    }
    hostMap.set(r.name, entry);
  }
  const hostRows = Array.from(hostMap.entries())
    .slice(0, maxRows)
    .map(([host, e]) => ({
      host,
      addresses: Array.from(e.addresses).sort(),
      recordTypes: Array.from(e.recordTypes).sort(),
      resolved: e.resolved,
    }));
  const hostsTruncated = dns.length >= dnsSampleLimit || hostMap.size > hostRows.length;

  const serviceRows = http.map((h) => {
    const data = (h.data ?? {}) as { tls?: { subject?: string; issuer?: string; notAfter?: string } };
    const tls = data.tls ? [data.tls.issuer ?? "", data.tls.notAfter ?? ""].filter(Boolean).join(" · ") : "";
    return {
      url: h.url,
      finalUrl: h.final_url,
      host: h.host ?? "",
      statusCode: h.status_code,
      title: h.title,
      server: h.server,
      probeStatus: h.probe_status,
      tls,
    };
  });

  interface UrlData {
    host?: string;
    method?: string;
    statusCode?: number | null;
    provider?: string;
    classifications?: Array<{ category?: string }>;
    parameters?: Array<{ name?: string; roles?: Array<{ role?: string }> }>;
  }
  const urlRows = urls.map((u) => {
    const d = (u.data ?? {}) as UrlData;
    return {
      url: u.url,
      host: d.host ?? "",
      method: d.method ?? "",
      statusCode: typeof d.statusCode === "number" ? d.statusCode : null,
      categories: (d.classifications ?? []).map((c) => c.category ?? "").filter(Boolean),
      parameters: (d.parameters ?? []).map((p) => p.name ?? "").filter(Boolean),
      provider: d.provider ?? "",
    };
  });

  interface EndpointData {
    method?: string;
    origin?: string;
    path?: string;
    discoveredVia?: string;
    documented?: boolean;
    resolved?: boolean;
    parameters?: Array<{ name?: string; location?: string }>;
    authSchemes?: string[];
  }
  const apiRows = apis.map((e) => {
    const d = (e.data ?? {}) as EndpointData;
    return {
      method: d.method ?? "",
      origin: d.origin ?? "",
      path: d.path ?? "",
      discoveredVia: d.discoveredVia ?? "",
      documented: d.documented === true,
      resolved: d.resolved !== false,
      parameters: (d.parameters ?? []).map((p) => p.name ?? "").filter(Boolean),
      authSchemes: asStringArray(d.authSchemes),
    };
  });

  const specRows = specs.map((s) => {
    const d = (s.data ?? {}) as { specVersion?: string; parseStatus?: string; title?: string; pathCount?: number; operationCount?: number };
    return {
      url: s.url,
      specVersion: d.specVersion ?? "",
      parseStatus: d.parseStatus ?? "",
      title: d.title ?? "",
      pathCount: d.pathCount ?? 0,
      operationCount: d.operationCount ?? 0,
    };
  });

  const mapByJsUrl = new Map(sourceMaps.map((m) => [m.url, (m.data ?? {}) as { status?: string; sourcesCount?: number }]));
  const jsRows = js.map((a) => {
    const d = (a.data ?? {}) as { status?: string; sizeBytes?: number; contentHash?: string };
    const sm = mapByJsUrl.get(a.url);
    return {
      url: a.url,
      status: d.status ?? "",
      sizeBytes: asNumber(d.sizeBytes),
      contentHash: (d.contentHash ?? "").slice(0, 16),
      sourceMapStatus: sm?.status ?? "",
      sourcesCount: asNumber(sm?.sourcesCount),
    };
  });

  const securityRows = security.map((m) => {
    const d = (m.data ?? {}) as { category?: string; name?: string; status?: string; evidence?: string; value?: string };
    return {
      service: m.service,
      category: d.category ?? "",
      name: d.name ?? "",
      status: d.status ?? "",
      detail: d.evidence ?? d.value ?? "",
    };
  });

  // Parameter inventory is derived from the URL and endpoint samples above, so it describes the
  // sample rather than claiming complete parameter coverage.
  const params = new Map<string, { count: number; roles: Set<string> }>();
  const bumpParam = (name: string, role: string): void => {
    const e = params.get(name) ?? { count: 0, roles: new Set<string>() };
    e.count++;
    if (role) e.roles.add(role);
    params.set(name, e);
  };
  for (const u of urls) {
    const d = (u.data ?? {}) as UrlData;
    for (const p of d.parameters ?? []) for (const r of p.roles ?? []) bumpParam(p.name ?? "", r.role ?? "");
  }
  for (const e of apis) {
    const d = (e.data ?? {}) as EndpointData;
    for (const p of d.parameters ?? []) bumpParam(p.name ?? "", p.location ?? "unknown");
  }
  params.delete("");
  const paramRows = Array.from(params.entries())
    .map(([name, e]) => ({ name, count: e.count, roles: Array.from(e.roles).sort() }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
    .slice(0, maxRows);

  return {
    hosts: { total: hostMap.size, shown: hostRows.length, truncated: hostsTruncated, rows: hostRows },
    services: sectionOf(byKind.http ?? serviceRows.length, serviceRows),
    technologies: sectionOf(byKind.technology ?? tech.length, tech.map((t) => ({
      name: t.name,
      host: t.host,
      category: t.category,
      evidenceType: t.evidence_type,
      evidence: t.evidence,
      confidence: Math.min(1, Math.max(0, Number(t.confidence) || 0)),
    }))),
    urls: sectionOf(byKind.url ?? urlRows.length, urlRows),
    apis: sectionOf(byKind["api-endpoint"] ?? apiRows.length, apiRows),
    specs: sectionOf(byKind["api-spec"] ?? specRows.length, specRows),
    parameters: {
      total: params.size,
      shown: paramRows.length,
      truncated: params.size > paramRows.length || (byKind.url ?? 0) > urls.length,
      rows: paramRows,
    },
    javascript: sectionOf(byKind["js-artifact"] ?? jsRows.length, jsRows),
    security: sectionOf(byKind["security-metadata"] ?? securityRows.length, securityRows),
  };
}

/** Why an incomplete stage matters, in a sentence a reader can act on. */
function impactOf(stage: string, jobStatus: string): string {
  switch (jobStatus) {
    case "SKIPPED":
      return `${stage} was not run (no eligible inputs or not authorized), so its dimension is unmeasured — absence of results is not evidence of absence.`;
    case "BLOCKED":
      return `${stage} was blocked because a prerequisite stage did not succeed, so everything downstream of it is unmeasured.`;
    case "FAILED":
      return `${stage} failed; any results it would have produced are missing from this report.`;
    case "SOURCE_UNAVAILABLE":
      return `${stage} could not reach its source, so its coverage is incomplete for reasons outside the target.`;
    case "CANCELLED":
      return `${stage} was cancelled before completing; its coverage is partial by construction.`;
    case "PARTIAL":
      return `${stage} completed partially: some providers or inputs did not produce results.`;
    case "QUEUED":
    case "RUNNING":
      return `${stage} has not finished, so this report is a snapshot of an in-flight scan.`;
    default:
      return `${stage} did not reach SUCCEEDED, so its coverage is not established.`;
  }
}

/** Build a deterministic, redacted report from persisted state. Returns null if the scan is absent. */
export async function buildReport(repo: Repository, scanId: string, opts: BuildReportOptions): Promise<Report | null> {
  const scan = await repo.getScan(scanId);
  if (!scan) return null;
  const maxRows = Math.max(1, opts.maxRows ?? REPORT_DEFAULT_MAX_ROWS);
  const maxEvidence = Math.max(0, opts.maxEvidence ?? REPORT_DEFAULT_MAX_EVIDENCE);

  const [jobs, coverage, assetCounts, obs, secretRows, corrRows, takeoverRows, outcomes, executions, policyRow, evidenceRows, evidenceTotal] =
    await Promise.all([
      repo.listJobs(scanId),
      repo.listCoverage(scanId),
      repo.countAssetsByType(scan.project_id),
      repo.countObservations(scanId),
      repo.listSecretFindings(scanId),
      repo.listCorrelationObservations(scanId),
      repo.listTakeoverCandidates(scanId),
      repo.listProviderOutcomes(scanId),
      repo.listProviderExecutions(scanId),
      repo.getPolicyById(scan.policy_id),
      repo.listEvidenceArtifacts(scanId, maxEvidence),
      repo.countEvidenceArtifacts(scanId),
    ]);
  const covByStage = new Map(coverage.map((c) => [c.stage, c]));
  const inventory = await buildInventory(repo, scanId, obs.byKind, maxRows);

  // Execution metrics, keyed by stage+provider. Several executions can exist for one provider
  // (retries); attempts is their count and the metrics come from the most recent one.
  const execByKey = new Map<string, { attempts: number; durationMs: number | null; timedOut: boolean; truncated: boolean; version: string }>();
  for (const e of executions) {
    const key = `${e.stage}\u0000${e.provider}`;
    const prev = execByKey.get(key);
    execByKey.set(key, {
      attempts: (prev?.attempts ?? 0) + 1,
      durationMs: asNumber(e.duration_ms),
      timedOut: e.timed_out === true || prev?.timedOut === true,
      truncated: e.truncated === true || prev?.truncated === true,
      version: e.provider_version ?? prev?.version ?? "",
    });
  }

  const outcomesByStage = new Map<string, typeof outcomes>();
  for (const o of outcomes) {
    const list = outcomesByStage.get(o.stage) ?? [];
    list.push(o);
    outcomesByStage.set(o.stage, list);
  }

  const providersForStage = (stage: string, details: unknown): ReportProvider[] => {
    const fromDetails = providersFromDetails(details);
    const base: ReportProvider[] =
      fromDetails.length > 0
        ? fromDetails
        : (outcomesByStage.get(stage) ?? []).map((o) => ({
            provider: o.provider,
            providerVersion: o.provider_version ?? "",
            outcome: o.outcome,
            records: o.records_count,
            reason: o.reason,
            durationMs: null,
            attempts: 0,
            timedOut: false,
            truncated: false,
          }));
    return base
      .map((p) => {
        const exec = execByKey.get(`${stage}\u0000${p.provider}`);
        return {
          ...p,
          providerVersion: p.providerVersion || exec?.version || "",
          durationMs: p.durationMs ?? exec?.durationMs ?? null,
          attempts: p.attempts || exec?.attempts || 0,
          timedOut: p.timedOut || exec?.timedOut === true,
          truncated: p.truncated || exec?.truncated === true,
        };
      })
      .sort((a, b) => (a.provider < b.provider ? -1 : a.provider > b.provider ? 1 : 0));
  };

  const stageOrder = new Map<string, number>(OrderedStages.map((s, i) => [s as string, i]));
  const stages: StageReport[] = jobs
    .map((j) => {
      const c = covByStage.get(j.job_key);
      const details = (c?.details ?? null) as CoverageDetails | null;
      const providers = providersForStage(j.stage, details);
      return {
        stage: j.stage,
        jobStatus: j.status,
        attempts: j.attempts,
        coverageStatus: c?.status ?? null,
        expected: c?.expected ?? 0,
        collected: c?.collected ?? 0,
        notes: c?.notes ?? "",
        durationMs: asNumber(details?.durationMs),
        startedAt: typeof details?.startedAt === "string" ? details.startedAt : null,
        finishedAt: typeof details?.finishedAt === "string" ? details.finishedAt : null,
        records: providers.reduce((n, p) => n + p.records, 0),
        retries: Math.max(0, j.attempts - 1),
        lastError: j.last_error ?? "",
        providers,
      };
    })
    .sort((a, b) => (stageOrder.get(a.stage) ?? 999) - (stageOrder.get(b.stage) ?? 999));

  const coverageGaps = coverage
    .filter((c) => c.status !== "COLLECTED" && c.stage !== "12-reporting")
    .map((c) => `${c.stage}:${c.status}`)
    .sort();

  const incompleteStages: ReportIncompleteStage[] = stages
    .filter((s) => s.jobStatus !== "SUCCEEDED")
    .map((s) => ({
      stage: s.stage,
      jobStatus: s.jobStatus,
      coverageStatus: s.coverageStatus,
      reason: s.lastError || s.notes || "",
      impact: impactOf(s.stage, s.jobStatus),
    }));

  const providerErrors: ReportProviderError[] = outcomes
    .filter((o) => o.outcome !== "SUCCEEDED")
    .map((o) => ({
      stage: o.stage,
      provider: o.provider,
      outcome: o.outcome,
      reason: o.reason,
      records: o.records_count,
      timedOut: execByKey.get(`${o.stage}\u0000${o.provider}`)?.timedOut === true,
    }))
    .sort((a, b) => (a.stage + a.provider < b.stage + b.provider ? -1 : 1));

  const secretFindings = secretRows
    .map((r) => {
      const d = r.data as { ruleId?: string; category?: string; status?: string; confidence?: number; host?: string; location?: string; redactedSnippet?: string };
      return {
        ruleId: d.ruleId ?? "unknown",
        category: d.category ?? "OTHER",
        status: d.status ?? "CANDIDATE",
        confidence: typeof d.confidence === "number" ? d.confidence : 0,
        artifact: r.artifact,
        host: d.host ?? "",
        location: d.location ?? "",
        redactedSnippet: d.redactedSnippet ?? "",
      };
    })
    .sort((a, b) => (a.ruleId + a.artifact + a.location < b.ruleId + b.artifact + b.location ? -1 : 1));

  const correlations = corrRows
    .map((r) => {
      const d = r.data as { relation?: string; status?: string; related?: string[]; ruleId?: string; hmacKeyed?: boolean; correlationGroup?: string; sourceStage?: string; evidence?: string; confidence?: number };
      return {
        relation: d.relation ?? "UNKNOWN",
        status: d.status ?? "OBSERVED",
        subject: r.subject,
        related: d.related ?? [],
        ruleId: d.ruleId ?? "",
        hmacKeyed: d.hmacKeyed ?? false,
        correlationGroup: d.correlationGroup ?? "",
        sourceStage: d.sourceStage ?? "",
        evidence: d.evidence ?? "",
        confidence: typeof d.confidence === "number" ? d.confidence : 0,
      };
    })
    .sort((a, b) => (a.relation + a.subject < b.relation + b.subject ? -1 : 1));

  const takeoverCandidates = takeoverRows
    .map((r) => {
      const d = r.data as { cname?: string; service?: string; status?: string; confidence?: number; httpStatus?: number | null; evidence?: string };
      return {
        host: r.host,
        cname: d.cname ?? "",
        service: d.service ?? "",
        status: d.status ?? "CANDIDATE",
        confidence: typeof d.confidence === "number" ? d.confidence : 0,
        httpStatus: typeof d.httpStatus === "number" ? d.httpStatus : null,
        evidence: d.evidence ?? "",
      };
    })
    .sort((a, b) => (a.host < b.host ? -1 : 1));

  const findings: ReportFinding[] = buildFindings(secretFindings, takeoverCandidates);

  const actionableTakeovers = takeoverCandidates.filter((t) => t.status === "SUSPECTED" || t.status === "CANDIDATE").length;
  const findingsCount = secretFindings.length + correlations.length + actionableTakeovers;
  const analysisStatus = deriveAnalysisStatus(jobs.filter((j) => j.job_key !== "12-reporting").map((j) => j.status));
  const reportStatus = deriveReportStatus(
    analysisStatus,
    jobs.map((j) => ({ jobKey: j.job_key, status: j.status })),
    findingsCount,
  );

  const policy = policyRow?.document ?? null;
  const snapshot = (typeof scan.config_snapshot === "object" && scan.config_snapshot !== null ? scan.config_snapshot : {}) as Record<string, unknown>;
  const providerVersions: Record<string, string> = {};
  for (const o of outcomes) {
    const v = o.provider_version ?? execByKey.get(`${o.stage}\u0000${o.provider}`)?.version ?? "";
    if (v) providerVersions[o.provider] = v;
  }

  const evidenceAppendix: ReportEvidenceRef[] = evidenceRows.map((e) => ({
    sha256: e.sha256,
    storageUri: e.storage_uri,
    contentType: e.content_type,
    sizeBytes: Number(e.size_bytes) || 0,
    redacted: e.redacted === true,
    createdAt: iso(e.created_at) ?? "",
  }));

  const limitations = [...REPORT_LIMITATIONS];
  if (evidenceTotal > evidenceAppendix.length) {
    limitations.push(`Evidence appendix lists ${evidenceAppendix.length} of ${evidenceTotal} stored artifacts (capped for report size).`);
  }

  const report: Report = {
    schemaVersion: REPORT_SCHEMA_VERSION,
    scanId,
    projectId: scan.project_id,
    rootDomain: scan.root_domain,
    startUrl: scan.start_url,
    scanStatus: analysisStatus,
    reportStatus,
    generatedAt: opts.now.toISOString(),
    assessment: await buildAssessment(repo, scan, policy),
    stages,
    coverageGaps,
    incompleteStages,
    providerErrors,
    assetCounts: sortedRecord(assetCounts),
    observationCounts: { total: obs.total, byKind: sortedRecord(obs.byKind), bySource: sortedRecord(obs.bySource) },
    inventory,
    findings,
    findingTotals: findingTotals(findings),
    secretFindings,
    correlations,
    takeoverCandidates,
    evidenceAppendix,
    reproducibility: {
      toolVersion: RECONNEXUS_VERSION,
      reportSchemaVersion: REPORT_SCHEMA_VERSION,
      configSchemaVersion: asNumber(snapshot.configSchemaVersion) ?? 0,
      policyVersion: policy?.policyVersion ?? 0,
      scopePolicyId: policy?.policyId ?? "",
      commands: [`reconnexus report ${scanId} --format json`, `reconnexus coverage ${scanId}`, `reconnexus scan status ${scanId}`],
      providerVersions: Object.fromEntries(Object.entries(providerVersions).sort(([a], [b]) => (a < b ? -1 : 1))),
      derivedFromPersistedStateOnly: true,
    },
    limitations,
    summary: buildSummary(scan, reportStatus, stages, secretFindings.length, correlations.length, coverageGaps),
  };
  return ReportSchema.parse(report);
}

/**
 * Accept any report document — a freshly built v2 model, or a v1 report persisted by an earlier
 * build — and return it with v2 sections filled from their defaults. Formatters call this so one
 * code path renders every schema version, and a malformed document is rejected rather than
 * rendered partially.
 */
export function normalizeReport(report: unknown): Report {
  return ReportSchema.parse(report);
}

export type Redactor = (value: unknown) => unknown;

/**
 * Structure-preserving boundary redactor: applies the centralized string redactor to every string
 * *value* while leaving object keys and numeric/boolean structure intact (so count maps such as
 * `byKind: {"secret-finding": 3}` are not corrupted). Fails closed on any error.
 */
export function redactStringsOnly(value: unknown, depth = 0): unknown {
  if (depth > 32) throw new ReportRedactionError("redaction depth exceeded");
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return redactString(value);
  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") return value;
  if (Array.isArray(value)) return value.map((v) => redactStringsOnly(v, depth + 1));
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = redactStringsOnly(v, depth + 1);
    return out;
  }
  throw new ReportRedactionError(`unsupported value type ${typeof value}`);
}

/**
 * Re-apply redaction at the report boundary (defence in depth) and re-validate. Fails closed: on
 * any error it throws and never returns the unredacted report.
 */
export function redactReport(report: Report, redactor: Redactor = redactStringsOnly): Report {
  let redacted: unknown;
  try {
    redacted = redactor(report);
  } catch (err) {
    throw new ReportRedactionError("redactor threw", err);
  }
  const parsed = ReportSchema.safeParse(redacted);
  if (!parsed.success) {
    throw new ReportRedactionError("redacted report failed schema validation");
  }
  return parsed.data;
}
