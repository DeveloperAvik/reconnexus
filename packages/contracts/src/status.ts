/** Job and scan-run lifecycle states. Zero exit code alone never implies SUCCEEDED. */
export const JobStatus = {
  QUEUED: "QUEUED",
  RUNNING: "RUNNING",
  SUCCEEDED: "SUCCEEDED",
  PARTIAL: "PARTIAL",
  FAILED: "FAILED",
  SKIPPED: "SKIPPED",
  BLOCKED: "BLOCKED",
  CANCELLED: "CANCELLED",
  SOURCE_UNAVAILABLE: "SOURCE_UNAVAILABLE",
} as const;
export type JobStatusValue = (typeof JobStatus)[keyof typeof JobStatus];

export const TerminalJobStatuses: ReadonlySet<JobStatusValue> = new Set([
  JobStatus.SUCCEEDED,
  JobStatus.PARTIAL,
  JobStatus.FAILED,
  JobStatus.SKIPPED,
  JobStatus.BLOCKED,
  JobStatus.CANCELLED,
  JobStatus.SOURCE_UNAVAILABLE,
]);

/** Interpreted finding lifecycle. `severity`, `confidence` and `validation` are independent dimensions. */
export const ValidationState = {
  OBSERVED: "OBSERVED",
  SUSPECTED: "SUSPECTED",
  VALIDATED: "VALIDATED",
  REJECTED: "REJECTED",
  INDETERMINATE: "INDETERMINATE",
} as const;
export type ValidationStateValue = (typeof ValidationState)[keyof typeof ValidationState];

export const Severity = {
  INFO: "INFO",
  LOW: "LOW",
  MEDIUM: "MEDIUM",
  HIGH: "HIGH",
  CRITICAL: "CRITICAL",
} as const;
export type SeverityValue = (typeof Severity)[keyof typeof Severity];

/** Provenance/quality rating of a data source, kept separate from severity and confidence. */
export const SourceReliability = {
  AUTHORITATIVE: "AUTHORITATIVE",
  HIGH: "HIGH",
  MEDIUM: "MEDIUM",
  LOW: "LOW",
  UNKNOWN: "UNKNOWN",
} as const;
export type SourceReliabilityValue = (typeof SourceReliability)[keyof typeof SourceReliability];

export const CoverageStatus = {
  COLLECTED: "COLLECTED",
  MISSING: "MISSING",
  PARTIAL: "PARTIAL",
  NOT_ATTEMPTED: "NOT_ATTEMPTED",
  BLOCKED: "BLOCKED",
} as const;
export type CoverageStatusValue = (typeof CoverageStatus)[keyof typeof CoverageStatus];
