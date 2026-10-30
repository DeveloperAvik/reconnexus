import { writeFileSync } from "node:fs";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { ExitCode, type Report } from "@reconnexus/contracts";
import {
  buildReport,
  createDb,
  csvField,
  formatReport,
  redactReport,
  REPORT_DEFAULT_MAX_ROWS,
  Repository,
} from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { color, result, type CommandResult } from "../output.js";

/**
 * Report formatting lives in the control plane so that every format is rendered from the one
 * canonical model. These re-exports keep the historical CLI import path working.
 */
export { csvField, formatReport };

export interface ReportOptions {
  format?: string;
  /** Write the rendered report to this path instead of stdout. */
  out?: string;
  /** Cap on rows per inventory section (totals stay exact). */
  maxRows?: number;
}

const FORMATS = new Set(["human", "json", "jsonl", "csv", "html", "sarif"]);

/** Warnings that keep a successfully generated report from reading as a successful assessment. */
function statusWarnings(report: Report): string[] {
  switch (report.reportStatus) {
    case "PARTIAL":
      return ["assessment is PARTIAL: stages were skipped or failed, so absence of findings is not established"];
    case "FAILED":
      return ["assessment FAILED: the report describes an incomplete scan"];
    case "REPORTING_FAILED":
      return ["the reporting stage failed for this scan; this report was generated on demand from persisted state"];
    case "REPORTING_NOT_RUN":
      return ["the reporting stage has not run; this report is a snapshot of current persisted state"];
    default:
      return [];
  }
}

export async function reportCommand(ctx: Context, scanId: string, opts: ReportOptions): Promise<CommandResult<unknown>> {
  const format = opts.format ?? "human";
  if (!FORMATS.has(format)) {
    throw new CliError(`unsupported report format: ${format} (expected human, json, jsonl, csv, html or sarif)`, ExitCode.USAGE_ERROR);
  }
  if (opts.maxRows !== undefined && (!Number.isFinite(opts.maxRows) || opts.maxRows < 1)) {
    throw new CliError("--max-rows must be a positive integer", ExitCode.USAGE_ERROR);
  }

  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    // Reporting is read-only with respect to scan execution: it builds from persisted state and
    // performs no network request and no write.
    const built = await buildReport(repo, scanId, { now: new Date(), maxRows: opts.maxRows ?? REPORT_DEFAULT_MAX_ROWS });
    if (!built) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);
    let report: Report;
    try {
      report = redactReport(built);
    } catch {
      // Fail closed: never emit an unredacted report.
      throw new CliError("report generation failed closed (redaction error); nothing was emitted", ExitCode.GENERAL_ERROR);
    }

    const rendered = formatReport(report, format);
    let writtenTo: string | undefined;
    if (opts.out) {
      writtenTo = resolve(opts.out);
      try {
        mkdirSync(dirname(writtenTo), { recursive: true });
        writeFileSync(writtenTo, rendered.endsWith("\n") ? rendered : `${rendered}\n`, { encoding: "utf8", mode: 0o600 });
      } catch (err) {
        throw new CliError(`could not write report to ${writtenTo}: ${(err as Error).message}`, ExitCode.GENERAL_ERROR);
      }
    }

    return result({
      exitCode: ExitCode.SUCCESS,
      data: writtenTo ? { ...report, outputPath: writtenTo } : report,
      warnings: statusWarnings(report),
      render: () =>
        writtenTo
          ? [
              `${color.green("✓")} ${format} report written`,
              `  ${color.dim("path")}    ${writtenTo}`,
              `  ${color.dim("status")}  ${report.reportStatus}  ${color.dim(`(analysis ${report.scanStatus})`)}`,
            ].join("\n")
          : rendered,
    });
  } finally {
    await db.close();
  }
}
