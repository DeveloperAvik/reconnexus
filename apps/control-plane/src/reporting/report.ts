import { OrderedStages, ReportSchema, type Report, type ReportStatusValue, type StageReport } from "@reconnexus/contracts";
import { redactString } from "@reconnexus/logging";
import type { Repository, ScanRow } from "../repository.js";

export class ReportRedactionError extends Error {
  constructor(message: string, readonly reason?: unknown) {
    super(`report redaction failed closed: ${message}`);
    this.name = "ReportRedactionError";
  }
}

export const REPORT_LIMITATIONS: string[] = [
  "Secret findings are candidates: a pattern match does not prove a credential is valid, active, or exploitable.",
  "Correlations are evidence joins (e.g. shared keyed fingerprints, multi-source corroboration); they are not proof of exploitability or causation.",
  "Multi-source corroboration means multiple sources reported the same asset; it is not proof of causation.",
  "NOT_OBSERVED metadata reflects a single response at a point in time; it is not proof that a control is absent.",
  "A SKIPPED stage was not run (usually no eligible inputs) — it did not 'find nothing'.",
  "Asset counts are project-level, because canonical asset identity is per project.",
  "Fingerprints produced with different HMAC keys are not comparable; correlation assumes a stable key.",
  "Subdomain-takeover entries are CANDIDATES: a CNAME to a takeover-prone service with an unclaimed response is not proof the subdomain is takeoverable, and no takeover was attempted.",
];

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
}

/** Build a deterministic, redacted report from persisted state. Returns null if the scan is absent. */
export async function buildReport(repo: Repository, scanId: string, opts: BuildReportOptions): Promise<Report | null> {
  const scan = await repo.getScan(scanId);
  if (!scan) return null;
  const [jobs, coverage, assetCounts, obs, secretRows, corrRows, takeoverRows] = await Promise.all([
    repo.listJobs(scanId),
    repo.listCoverage(scanId),
    repo.countAssetsByType(scan.project_id),
    repo.countObservations(scanId),
    repo.listSecretFindings(scanId),
    repo.listCorrelationObservations(scanId),
    repo.listTakeoverCandidates(scanId),
  ]);
  const covByStage = new Map(coverage.map((c) => [c.stage, c]));

  const stageOrder = new Map<string, number>(OrderedStages.map((s, i) => [s as string, i]));
  const stages: StageReport[] = jobs
    .map((j) => {
      const c = covByStage.get(j.job_key);
      return {
        stage: j.stage,
        jobStatus: j.status,
        attempts: j.attempts,
        coverageStatus: c?.status ?? null,
        expected: c?.expected ?? 0,
        collected: c?.collected ?? 0,
        notes: c?.notes ?? "",
      };
    })
    .sort((a, b) => (stageOrder.get(a.stage) ?? 999) - (stageOrder.get(b.stage) ?? 999));

  const coverageGaps = coverage
    .filter((c) => c.status !== "COLLECTED" && c.stage !== "12-reporting")
    .map((c) => `${c.stage}:${c.status}`)
    .sort();

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

  const actionableTakeovers = takeoverCandidates.filter((t) => t.status === "SUSPECTED" || t.status === "CANDIDATE").length;
  const findingsCount = secretFindings.length + correlations.length + actionableTakeovers;
  const analysisStatus = deriveAnalysisStatus(jobs.filter((j) => j.job_key !== "12-reporting").map((j) => j.status));
  const reportStatus = deriveReportStatus(
    analysisStatus,
    jobs.map((j) => ({ jobKey: j.job_key, status: j.status })),
    findingsCount,
  );

  const report: Report = {
    schemaVersion: 1,
    scanId,
    projectId: scan.project_id,
    rootDomain: scan.root_domain,
    startUrl: scan.start_url,
    scanStatus: analysisStatus,
    reportStatus,
    generatedAt: opts.now.toISOString(),
    stages,
    coverageGaps,
    assetCounts: sortedRecord(assetCounts),
    observationCounts: { total: obs.total, byKind: sortedRecord(obs.byKind), bySource: sortedRecord(obs.bySource) },
    secretFindings,
    correlations,
    takeoverCandidates,
    limitations: [...REPORT_LIMITATIONS],
    summary: buildSummary(scan, reportStatus, stages, secretFindings.length, correlations.length, coverageGaps),
  };
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
