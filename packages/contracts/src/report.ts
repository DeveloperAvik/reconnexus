import { z } from "zod";
import { Severity, ValidationState } from "./status.js";

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

export const ReportFormat = z.enum(["human", "json", "jsonl", "csv", "html", "sarif"]);
export type ReportFormatValue = z.infer<typeof ReportFormat>;

/**
 * Version of the canonical report model. v2 adds assessment metadata, stage execution metrics,
 * inventory sections, derived findings, provider errors, reproducibility and an evidence appendix.
 * Every v2 section carries a default, so a persisted v1 document still parses unchanged.
 */
export const REPORT_SCHEMA_VERSION = 2 as const;

/** A per-provider execution record as persisted by the orchestrator (never re-derived live). */
export const ReportProviderSchema = z.object({
  provider: z.string().min(1),
  providerVersion: z.string().default(""),
  outcome: z.string().min(1),
  records: z.number().int().nonnegative().default(0),
  reason: z.string().default(""),
  /** `null` when no duration was persisted — distinct from a genuine zero. */
  durationMs: z.number().int().nonnegative().nullable().default(null),
  attempts: z.number().int().nonnegative().default(0),
  timedOut: z.boolean().default(false),
  truncated: z.boolean().default(false),
});
export type ReportProvider = z.infer<typeof ReportProviderSchema>;

export const StageReportSchema = z.object({
  stage: z.string().min(1),
  jobStatus: z.string().min(1),
  attempts: z.number().int().nonnegative(),
  coverageStatus: z.string().nullable().default(null),
  expected: z.number().int().nonnegative().default(0),
  collected: z.number().int().nonnegative().default(0),
  notes: z.string().default(""),
  // v2 execution metrics. `null` means "not persisted", never "zero".
  durationMs: z.number().int().nonnegative().nullable().default(null),
  startedAt: z.string().nullable().default(null),
  finishedAt: z.string().nullable().default(null),
  records: z.number().int().nonnegative().default(0),
  retries: z.number().int().nonnegative().default(0),
  lastError: z.string().default(""),
  providers: z.array(ReportProviderSchema).default([]),
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

/**
 * A finding interpreted from persisted candidate records. `severity`, `confidence` and
 * `validation` are independent dimensions: this platform performs no exploitation, so nothing is
 * ever reported as `VALIDATED` from a scan alone.
 */
export const ReportFindingSchema = z.object({
  /** Deterministic id derived from the finding's identity (stable across runs of one scan). */
  id: z.string().min(1),
  title: z.string().min(1),
  category: z.string().default(""),
  severity: z.enum(Object.values(Severity) as [string, ...string[]]),
  confidence: z.number().min(0).max(1),
  validation: z.enum(Object.values(ValidationState) as [string, ...string[]]),
  subject: z.string().default(""),
  sourceStage: z.string().default(""),
  sourceKind: z.string().default(""),
  /** Redacted, human-readable evidence. Never a raw credential or artifact body. */
  evidence: z.string().default(""),
  /** Pointers an analyst can follow: artifact URLs, hosts, CLI commands. Not raw evidence. */
  evidenceRefs: z.array(z.string()).default([]),
  remediation: z.string().default(""),
  references: z.array(z.string()).default([]),
});
export type ReportFinding = z.infer<typeof ReportFindingSchema>;

/** Counts by severity / validation state, always present so zero is distinguishable from absent. */
export const ReportFindingTotalsSchema = z.object({
  total: z.number().int().nonnegative().default(0),
  bySeverity: z.record(z.string(), z.number().int().nonnegative()).default({}),
  byValidation: z.record(z.string(), z.number().int().nonnegative()).default({}),
  validated: z.number().int().nonnegative().default(0),
});
export type ReportFindingTotals = z.infer<typeof ReportFindingTotalsSchema>;

/**
 * A bounded inventory section. `total` is the number of persisted records; `rows` may be capped,
 * in which case `truncated` is true and `shown` < `total`. An empty section with `total: 0` means
 * "nothing was recorded", which is not the same as a stage that never ran — read the stage table.
 */
function section<T extends z.ZodTypeAny>(row: T) {
  return z
    .object({
      total: z.number().int().nonnegative().default(0),
      shown: z.number().int().nonnegative().default(0),
      truncated: z.boolean().default(false),
      rows: z.array(row).default([]),
    })
    .default({});
}

export const ReportHostRowSchema = z.object({
  host: z.string().default(""),
  addresses: z.array(z.string()).default([]),
  recordTypes: z.array(z.string()).default([]),
  resolved: z.boolean().default(false),
});

export const ReportServiceRowSchema = z.object({
  url: z.string().default(""),
  finalUrl: z.string().default(""),
  host: z.string().default(""),
  statusCode: z.number().int().nullable().default(null),
  title: z.string().default(""),
  server: z.string().default(""),
  probeStatus: z.string().default(""),
  tls: z.string().default(""),
});

export const ReportTechnologyRowSchema = z.object({
  name: z.string().default(""),
  host: z.string().default(""),
  category: z.string().default(""),
  evidenceType: z.string().default(""),
  evidence: z.string().default(""),
  confidence: z.number().min(0).max(1).default(0),
});

export const ReportUrlRowSchema = z.object({
  url: z.string().default(""),
  host: z.string().default(""),
  method: z.string().default(""),
  statusCode: z.number().int().nullable().default(null),
  categories: z.array(z.string()).default([]),
  parameters: z.array(z.string()).default([]),
  provider: z.string().default(""),
});

export const ReportApiRowSchema = z.object({
  method: z.string().default(""),
  origin: z.string().default(""),
  path: z.string().default(""),
  discoveredVia: z.string().default(""),
  documented: z.boolean().default(false),
  resolved: z.boolean().default(true),
  parameters: z.array(z.string()).default([]),
  authSchemes: z.array(z.string()).default([]),
});

export const ReportSpecRowSchema = z.object({
  url: z.string().default(""),
  specVersion: z.string().default(""),
  parseStatus: z.string().default(""),
  title: z.string().default(""),
  pathCount: z.number().int().nonnegative().default(0),
  operationCount: z.number().int().nonnegative().default(0),
});

export const ReportParamRowSchema = z.object({
  name: z.string().default(""),
  count: z.number().int().nonnegative().default(0),
  roles: z.array(z.string()).default([]),
});

export const ReportJsRowSchema = z.object({
  url: z.string().default(""),
  status: z.string().default(""),
  sizeBytes: z.number().int().nonnegative().nullable().default(null),
  contentHash: z.string().default(""),
  sourceMapStatus: z.string().default(""),
  sourcesCount: z.number().int().nonnegative().nullable().default(null),
});

export const ReportSecurityRowSchema = z.object({
  service: z.string().default(""),
  category: z.string().default(""),
  name: z.string().default(""),
  status: z.string().default(""),
  detail: z.string().default(""),
});

export const ReportInventorySchema = z
  .object({
    hosts: section(ReportHostRowSchema),
    services: section(ReportServiceRowSchema),
    technologies: section(ReportTechnologyRowSchema),
    urls: section(ReportUrlRowSchema),
    apis: section(ReportApiRowSchema),
    specs: section(ReportSpecRowSchema),
    parameters: section(ReportParamRowSchema),
    javascript: section(ReportJsRowSchema),
    security: section(ReportSecurityRowSchema),
  })
  .default({});
export type ReportInventory = z.infer<typeof ReportInventorySchema>;

/** Scope as authorized, so a reader can tell what was in and out of bounds. */
export const ReportScopeSchema = z
  .object({
    domains: z.array(z.string()).default([]),
    hosts: z.array(z.string()).default([]),
    ips: z.array(z.string()).default([]),
    cidrs: z.array(z.string()).default([]),
    excludedDomains: z.array(z.string()).default([]),
    excludedHosts: z.array(z.string()).default([]),
    excludedIps: z.array(z.string()).default([]),
    excludedCidrs: z.array(z.string()).default([]),
    excludedPaths: z.array(z.string()).default([]),
    limits: z
      .object({
        maxConcurrency: z.number().int().nonnegative().default(0),
        requestsPerSecond: z.number().nonnegative().default(0),
        crawlDepth: z.number().int().nonnegative().default(0),
        maxRuntimeSeconds: z.number().int().nonnegative().default(0),
        maxArtifactBytes: z.number().int().nonnegative().default(0),
      })
      .default({}),
  })
  .default({});
export type ReportScope = z.infer<typeof ReportScopeSchema>;

export const ReportAssessmentSchema = z
  .object({
    workspace: z.string().default(""),
    /** Provider-selection profile actually used for the run, as persisted at run start. */
    profile: z.string().default("default"),
    createdAt: z.string().nullable().default(null),
    startedAt: z.string().nullable().default(null),
    finishedAt: z.string().nullable().default(null),
    durationMs: z.number().int().nonnegative().nullable().default(null),
    policyVersion: z.number().int().nonnegative().default(0),
    authorization: z
      .object({
        reference: z.string().default(""),
        authorizedBy: z.string().default(""),
        validFrom: z.string().default(""),
        validUntil: z.string().default(""),
        capabilities: z.array(z.string()).default([]),
      })
      .default({}),
    scope: ReportScopeSchema,
  })
  .default({});
export type ReportAssessment = z.infer<typeof ReportAssessmentSchema>;

/** A tool/provider error worth surfacing: what failed, where, and what it means for coverage. */
export const ReportProviderErrorSchema = z.object({
  stage: z.string().min(1),
  provider: z.string().default(""),
  outcome: z.string().min(1),
  reason: z.string().default(""),
  records: z.number().int().nonnegative().default(0),
  timedOut: z.boolean().default(false),
});
export type ReportProviderError = z.infer<typeof ReportProviderErrorSchema>;

export const ReportIncompleteStageSchema = z.object({
  stage: z.string().min(1),
  jobStatus: z.string().min(1),
  coverageStatus: z.string().nullable().default(null),
  reason: z.string().default(""),
  impact: z.string().default(""),
});
export type ReportIncompleteStage = z.infer<typeof ReportIncompleteStageSchema>;

export const ReportReproducibilitySchema = z
  .object({
    toolVersion: z.string().default(""),
    reportSchemaVersion: z.number().int().positive().default(1),
    configSchemaVersion: z.number().int().nonnegative().default(0),
    policyVersion: z.number().int().nonnegative().default(0),
    scopePolicyId: z.string().default(""),
    /** Commands that regenerate this report from the same persisted state. */
    commands: z.array(z.string()).default([]),
    providerVersions: z.record(z.string(), z.string()).default({}),
    /** True when the model is derived solely from persisted state with no network access. */
    derivedFromPersistedStateOnly: z.boolean().default(true),
  })
  .default({});
export type ReportReproducibility = z.infer<typeof ReportReproducibilitySchema>;

/** A content-addressed evidence artifact. The appendix lists references, never contents. */
/**
 * Coverage reconciliation: every headline aggregate is paired with the raw count it was derived
 * from, so `raw observations → distinct/normalized records → rows shown` is auditable. Endpoint
 * source counts are per discovery source (JS, SPEC, HTTP); an endpoint found by more than one
 * source is counted in each, so they may sum to more than the distinct total.
 */
export const ReportReconciliationSchema = z
  .object({
    endpointRawObservations: z.number().int().nonnegative().default(0),
    endpointDistinct: z.number().int().nonnegative().default(0),
    endpointShown: z.number().int().nonnegative().default(0),
    endpointsBySource: z.record(z.string(), z.number().int().nonnegative()).default({}),
    endpointsByProvider: z.record(z.string(), z.number().int().nonnegative()).default({}),
  })
  .default({});
export type ReportReconciliation = z.infer<typeof ReportReconciliationSchema>;

export const ReportEvidenceRefSchema = z.object({
  sha256: z.string().default(""),
  storageUri: z.string().default(""),
  contentType: z.string().default(""),
  sizeBytes: z.number().int().nonnegative().default(0),
  redacted: z.boolean().default(false),
  createdAt: z.string().default(""),
});
export type ReportEvidenceRef = z.infer<typeof ReportEvidenceRefSchema>;

export const ReportSchema = z.object({
  /** 1 = pre-v2 persisted reports; 2 = current model. */
  schemaVersion: z.union([z.literal(1), z.literal(2)]).default(REPORT_SCHEMA_VERSION),
  scanId: z.string().uuid(),
  projectId: z.string().uuid(),
  rootDomain: z.string().min(1),
  startUrl: z.string().min(1),
  scanStatus: z.string().min(1),
  reportStatus: ReportStatus,
  generatedAt: z.string().datetime({ offset: true }),
  assessment: ReportAssessmentSchema,
  stages: z.array(StageReportSchema),
  coverageGaps: z.array(z.string()),
  incompleteStages: z.array(ReportIncompleteStageSchema).default([]),
  providerErrors: z.array(ReportProviderErrorSchema).default([]),
  assetCounts: z.record(z.string(), z.number().int().nonnegative()),
  observationCounts: z.object({
    total: z.number().int().nonnegative(),
    byKind: z.record(z.string(), z.number().int().nonnegative()),
    bySource: z.record(z.string(), z.number().int().nonnegative()),
  }),
  reconciliation: ReportReconciliationSchema,
  inventory: ReportInventorySchema,
  findings: z.array(ReportFindingSchema).default([]),
  findingTotals: ReportFindingTotalsSchema.default({}),
  secretFindings: z.array(ReportSecretFindingSchema),
  correlations: z.array(ReportCorrelationSchema),
  takeoverCandidates: z.array(ReportTakeoverSchema).default([]),
  evidenceAppendix: z.array(ReportEvidenceRefSchema).default([]),
  reproducibility: ReportReproducibilitySchema,
  limitations: z.array(z.string()),
  summary: z.string(),
});
export type Report = z.infer<typeof ReportSchema>;
