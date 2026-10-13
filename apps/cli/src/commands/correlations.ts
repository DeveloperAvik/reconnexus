import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

const STAGE = "11-correlation";

interface CorrelationData {
  relation?: string;
  status?: string;
  subject?: string;
  related?: string[];
  ruleId?: string;
  hmacKeyed?: boolean;
  correlationGroup?: string;
  sourceStage?: string;
  evidence?: string;
  confidence?: number;
}

export interface CorrelationsOptions {
  relation?: string;
  subject?: string;
  limit?: number;
}

/**
 * Reports Stage 11 correlation results. Output is redacted (opaque correlation groups only — never
 * fingerprints or secret values). The command distinguishes: stage not run, failed, partial, and a
 * successful run with no correlations.
 */
export async function correlationsCommand(ctx: Context, scanId: string, opts: CorrelationsOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);

    const coverage = (await repo.listCoverage(scanId)).find((c) => c.stage === STAGE);
    const job = (await repo.listJobs(scanId)).find((j) => j.job_key === STAGE);
    const observations = (await repo.listCorrelationObservations(scanId)).map((r) => ({ subject: r.subject, ...(r.data as CorrelationData) }));
    const edges = await repo.listCorrelationEdges(scanId);

    const filtered = observations.filter((o) => {
      if (opts.relation && o.relation !== opts.relation) return false;
      if (opts.subject && !(o.subject ?? "").includes(opts.subject) && !(o.related ?? []).some((r) => r.includes(opts.subject!))) return false;
      return true;
    });
    const limited = opts.limit ? filtered.slice(0, opts.limit) : filtered;

    const stageState =
      coverage === undefined
        ? "NOT_RUN"
        : coverage.status === "COLLECTED"
          ? "COMPLETE"
          : coverage.status === "PARTIAL"
            ? "PARTIAL"
            : job?.status === "FAILED" || job?.status === "SOURCE_UNAVAILABLE"
              ? "FAILED"
              : coverage.status;

    const gaps = (coverage?.details as { coverageGaps?: string[] } | undefined)?.coverageGaps ?? [];
    const data = { scanId, stageState, stageJobStatus: job?.status ?? null, coverage: coverage?.status ?? null, correlationObservations: filtered.length, edges: edges.length, coverageGaps: gaps, correlations: limited };

    const headline: Record<string, string> = {
      NOT_RUN: `Stage 11 correlation has NOT been run for scan ${scanId}.`,
      FAILED: `Stage 11 correlation FAILED for scan ${scanId}.`,
      PARTIAL: `Stage 11 correlation completed PARTIALLY for scan ${scanId}.`,
      COMPLETE: filtered.length === 0 ? `Stage 11 correlation COMPLETE for scan ${scanId}: no correlations found.` : `Stage 11 correlation COMPLETE for scan ${scanId}: ${filtered.length} correlations.`,
    };

    return result({
      exitCode: ExitCode.SUCCESS,
      data,
      render: () =>
        [
          headline[stageState] ?? `Stage 11 correlation state: ${stageState}`,
          `  job: ${job?.status ?? "(none)"}  coverage: ${coverage?.status ?? "(none)"}`,
          `  edges: ${edges.length} (source stage-11-correlation)`,
          gaps.length ? `  coverage gaps: ${gaps.join(", ")}` : "",
          "",
          ...limited.map((o) => `  ${(o.relation ?? "").padEnd(28)} ${(o.status ?? "").padEnd(9)} ${o.subject ?? ""}  -> ${(o.related ?? []).join(", ")}${o.correlationGroup ? `  [group ${o.correlationGroup}]` : ""}`),
        ].filter((l) => l !== "").join("\n"),
    });
  } finally {
    await db.close();
  }
}
