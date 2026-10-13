import { z } from "zod";

/**
 * Overall interpretation of a scan, derived deterministically from authoritative scan/job/coverage
 * records. `COMPLETE_*` requires the scan to be reconciled `SUCCEEDED`; a scan with skipped or
 * failed stages is never reported as complete. `REPORTING_*` states describe Stage 12 itself.
 */
export const ReportStatus = z.enum([
  "COMPLETE_WITH_FINDINGS",
  "COMPLETE_NO_FINDINGS",
  "PARTIAL",
  "FAILED",
  "REPORTING_NOT_RUN",
  "REPORTING_FAILED",
]);
export type ReportStatusValue = z.infer<typeof ReportStatus>;

export const ReportFormat = z.enum(["human", "json", "jsonl", "csv"]);
export type ReportFormatValue = z.infer<typeof ReportFormat>;

export const StageReportSchema = z.object({
  stage: z.string().min(1),
  jobStatus: z.string().min(1),
  attempts: z.number().int().nonnegative(),
  coverageStatus: z.string().nullable().default(null),
  expected: z.number().int().nonnegative().default(0),
  collected: z.number().int().nonnegative().default(0),
  notes: z.string().default(""),
});
export type StageReport = z.infer<typeof StageReportSchema>;

/** A redacted secret candidate. It is NEVER a confirmed/validated credential. */
export const ReportSecretFindingSchema = z.object({
  ruleId: z.string().min(1),
  category: z.string().min(1),
  status: z.string().min(1),
  confidence: z.number().min(0).max(1),
  artifact: z.string().default(""),
  host: z.string().default(""),
  location: z.string().default(""),
  redactedSnippet: z.string().default(""),
});
export type ReportSecretFinding = z.infer<typeof ReportSecretFindingSchema>;

/** An evidence correlation. It is NEVER proof of exploitability or causation. */
export const ReportCorrelationSchema = z.object({
  relation: z.string().min(1),
  status: z.string().min(1),
  subject: z.string().min(1),
  related: z.array(z.string()).default([]),
  ruleId: z.string().default(""),
  hmacKeyed: z.boolean().default(false),
  /** Opaque group id; never the fingerprint itself. */
  correlationGroup: z.string().default(""),
  sourceStage: z.string().default(""),
  evidence: z.string().default(""),
  confidence: z.number().min(0).max(1),
});
export type ReportCorrelation = z.infer<typeof ReportCorrelationSchema>;

/** A potential subdomain-takeover candidate (never a confirmed takeover). */
export const ReportTakeoverSchema = z.object({
  host: z.string().min(1),
  cname: z.string().default(""),
  service: z.string().default(""),
  status: z.string().min(1),
  confidence: z.number().min(0).max(1),
  httpStatus: z.number().int().nullable().default(null),
  evidence: z.string().default(""),
});
export type ReportTakeover = z.infer<typeof ReportTakeoverSchema>;

export const ReportSchema = z.object({
  schemaVersion: z.literal(1),
  scanId: z.string().uuid(),
  projectId: z.string().uuid(),
  rootDomain: z.string().min(1),
  startUrl: z.string().min(1),
  scanStatus: z.string().min(1),
  reportStatus: ReportStatus,
  generatedAt: z.string().datetime({ offset: true }),
  stages: z.array(StageReportSchema),
  coverageGaps: z.array(z.string()),
  assetCounts: z.record(z.string(), z.number().int().nonnegative()),
  observationCounts: z.object({
    total: z.number().int().nonnegative(),
    byKind: z.record(z.string(), z.number().int().nonnegative()),
    bySource: z.record(z.string(), z.number().int().nonnegative()),
  }),
  secretFindings: z.array(ReportSecretFindingSchema),
  correlations: z.array(ReportCorrelationSchema),
  takeoverCandidates: z.array(ReportTakeoverSchema).default([]),
  limitations: z.array(z.string()),
  summary: z.string(),
});
export type Report = z.infer<typeof ReportSchema>;
