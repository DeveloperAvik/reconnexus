import { JobStatus } from "@reconnexus/contracts";

/** Record counts by discovery record type, taken verbatim from a provider result. */
export function countRecordsByType(records: ReadonlyArray<{ type: string }>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const r of records) out[r.type] = (out[r.type] ?? 0) + 1;
  const sorted: Record<string, number> = {};
  for (const k of Object.keys(out).sort()) sorted[k] = out[k]!;
  return sorted;
}

/**
 * Retry semantics per provider outcome:
 *  - FAILED: transient/unknown execution failure -> retryable.
 *  - SUCCEEDED / PARTIAL: work was done (PARTIAL means truncated/timed-out coverage, which a rerun
 *    with the same limits would not improve) -> never retried; the persisted result is reused.
 *  - SOURCE_UNAVAILABLE: the tool/source is missing or down, a permanent condition for this run
 *    -> not retried (an explicit resume re-evaluates it).
 *  - SKIPPED / BLOCKED: a deliberate decision (nothing to do, scope or prerequisite) -> not retried.
 *  - CANCELLED: the operator stopped the scan -> never retried.
 */
export function isRetryableProviderOutcome(outcome: string): boolean {
  return outcome === JobStatus.FAILED;
}

/** A stage is retried only when at least one of its providers ended in a retryable outcome. */
export function shouldRetryStage(providers: ReadonlyArray<{ outcome: string }>): boolean {
  return providers.some((p) => isRetryableProviderOutcome(p.outcome));
}

export const NON_RETRYABLE_SETTLED: ReadonlySet<string> = new Set([JobStatus.SOURCE_UNAVAILABLE, JobStatus.SKIPPED, JobStatus.BLOCKED]);

export type FingerprintCorrelationState = "NO_SECRET_FINDINGS" | "ENABLED" | "PARTIAL_UNKEYED" | "DISABLED_NO_HMAC_KEY";

/**
 * Whether secret-fingerprint correlation could run for a scan's findings. A finding correlates only
 * with a non-empty fingerprint produced under a configured HMAC key. Detection itself is unaffected:
 * the note says correlation is disabled, never that detection failed. Contains no key material.
 */
export function fingerprintCorrelationStatus(
  findings: ReadonlyArray<{ artifact: string; fingerprint: string }>,
  keyedByArtifact: ReadonlyMap<string, boolean>,
): { state: FingerprintCorrelationState; note: string } {
  if (findings.length === 0) return { state: "NO_SECRET_FINDINGS", note: "" };
  const usable = findings.filter((f) => f.fingerprint !== "" && keyedByArtifact.get(f.artifact) === true).length;
  if (usable === findings.length) return { state: "ENABLED", note: "" };
  if (usable === 0) {
    return {
      state: "DISABLED_NO_HMAC_KEY",
      note: "secretFingerprintCorrelation=DISABLED (RECONNEXUS_HMAC_KEY was not set when secrets were scanned; secret detection is unaffected, findings are not correlated)",
    };
  }
  return {
    state: "PARTIAL_UNKEYED",
    note: `secretFingerprintCorrelation=PARTIAL (${findings.length - usable} of ${findings.length} findings have no keyed fingerprint and were not correlated; RECONNEXUS_HMAC_KEY was missing for some artifacts, e.g. set partway through or absent from some workers)`,
  };
}

export function aggregate(outcomes: string[]): string {
  if (outcomes.length === 0) return JobStatus.SKIPPED;
  const count = (s: string): number => outcomes.filter((o) => o === s).length;
  const ok = count(JobStatus.SUCCEEDED);
  const partial = count(JobStatus.PARTIAL);
  const failed = count(JobStatus.FAILED);
  const unavailable = count(JobStatus.SOURCE_UNAVAILABLE);
  const skipped = count(JobStatus.SKIPPED);
  const blocked = count(JobStatus.BLOCKED);
  const cancelled = count(JobStatus.CANCELLED);
  if (cancelled === outcomes.length) return JobStatus.CANCELLED;
  if (blocked === outcomes.length) return JobStatus.BLOCKED;
  if (skipped === outcomes.length) return JobStatus.SKIPPED;
  if (unavailable === outcomes.length) return JobStatus.SOURCE_UNAVAILABLE;
  if (failed === outcomes.length) return JobStatus.FAILED;
  if (ok === outcomes.length) return JobStatus.SUCCEEDED;
  // Any provider that returned PARTIAL, or any mix that is not all-success, means this stage's
  // coverage is incomplete. Reporting it SUCCEEDED would let one provider's partial result be
  // masked by its siblings (or by itself, for a single-provider stage).
  if (ok + partial > 0) return JobStatus.PARTIAL;
  return JobStatus.FAILED;
}

export function coverageStatusFor(stageStatus: string): string {
  switch (stageStatus) {
    case JobStatus.SUCCEEDED:
      return "COLLECTED";
    case JobStatus.PARTIAL:
      return "PARTIAL";
    case JobStatus.SKIPPED:
      return "NOT_ATTEMPTED";
    case JobStatus.BLOCKED:
      return "BLOCKED";
    default:
      return "MISSING";
  }
}
