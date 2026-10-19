import { JobStatus } from "@reconnexus/contracts";
import type { JobRow } from "../repository.js";

export function dependenciesSatisfied(job: JobRow, all: JobRow[], completed: Set<string>): boolean {
  if (job.depends_on.length === 0) return true;
  return job.depends_on.every((dep) => {
    const depJob = all.find((j) => j.job_key === dep);
    if (!depJob) return true;
    return [JobStatus.SUCCEEDED, JobStatus.PARTIAL, JobStatus.SKIPPED].includes(depJob.status as never) || completed.has(dep);
  });
}

export function deriveScanStatus(statuses: string[]): string {
  if (statuses.some((s) => s === JobStatus.RUNNING || s === JobStatus.QUEUED)) {
    // Something was left incomplete by an unexpected stop.
    return JobStatus.PARTIAL;
  }
  const anySuccess = statuses.some((s) => s === JobStatus.SUCCEEDED || s === JobStatus.PARTIAL);
  const anyFail = statuses.some((s) => s === JobStatus.FAILED || s === JobStatus.SOURCE_UNAVAILABLE || s === JobStatus.BLOCKED);
  const anySkipped = statuses.some((s) => s === JobStatus.SKIPPED);
  const allSucceeded = statuses.every((s) => s === JobStatus.SUCCEEDED);
  if (allSucceeded) return JobStatus.SUCCEEDED;
  if (anySuccess && (anyFail || anySkipped)) return JobStatus.PARTIAL;
  if (anyFail && !anySuccess) return JobStatus.FAILED;
  if (anySkipped) return JobStatus.PARTIAL;
  return JobStatus.PARTIAL;
}
