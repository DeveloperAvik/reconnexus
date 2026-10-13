import { ExitCode, type Report } from "@reconnexus/contracts";
import { buildReport, createDb, redactReport, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

export interface ReportOptions {
  format?: string;
}

/** Escape a CSV field and neutralise spreadsheet formula injection (=, +, -, @, tab, CR). */
export function csvField(v: string): string {
  let out = v;
  if (/^[=+\-@\t\r]/.test(out)) out = `'${out}`;
  return /[",\n]/.test(out) ? `"${out.replace(/"/g, '""')}"` : out;
}

export function formatReport(report: Report, format: string): string {
  if (format === "json") return JSON.stringify(report, null, 2);
  const takeovers = report.takeoverCandidates ?? [];
  if (format === "jsonl") {
    const lines: string[] = [];
    lines.push(JSON.stringify({ kind: "summary", scanId: report.scanId, rootDomain: report.rootDomain, scanStatus: report.scanStatus, reportStatus: report.reportStatus, generatedAt: report.generatedAt }));
    for (const s of report.stages) lines.push(JSON.stringify({ kind: "stage", ...s }));
    for (const f of report.secretFindings) lines.push(JSON.stringify({ kind: "secret", ...f }));
    for (const c of report.correlations) lines.push(JSON.stringify({ kind: "correlation", ...c }));
    for (const t of takeovers) lines.push(JSON.stringify({ kind: "takeover", ...t }));
    return lines.join("\n");
  }
  if (format === "csv") {
    const rows: string[] = ["section,type,key,status,detail"];
    for (const s of report.stages) rows.push(["stage", s.jobStatus, s.stage, s.coverageStatus ?? "", s.notes].map((x) => csvField(String(x))).join(","));
    for (const f of report.secretFindings) rows.push(["secret", f.category, f.ruleId, f.status, `${f.artifact} ${f.location} ${f.redactedSnippet}`].map((x) => csvField(String(x))).join(","));
    for (const c of report.correlations) rows.push(["correlation", c.relation, c.subject, c.status, c.related.join(" ")].map((x) => csvField(String(x))).join(","));
    for (const t of takeovers) rows.push(["takeover", t.service, t.host, t.status, `${t.cname} ${t.httpStatus ?? ""} ${t.evidence}`].map((x) => csvField(String(x))).join(","));
    return rows.join("\n");
  }
  // human
  const lines: string[] = [];
  lines.push(`ReconNexus report — ${report.rootDomain}  (scan ${report.scanId})`);
  lines.push(`Status: ${report.reportStatus}   scan: ${report.scanStatus}   generated: ${report.generatedAt}`);
  lines.push(`Summary: ${report.summary}`);
  lines.push("");
  lines.push("Stages:");
  for (const s of report.stages) {
    lines.push(`  ${s.stage.padEnd(26)} ${s.jobStatus.padEnd(18)} coverage=${(s.coverageStatus ?? "-").padEnd(14)} ${s.collected}/${s.expected}${s.notes ? "  " + s.notes : ""}`);
  }
  if (report.coverageGaps.length) lines.push(`Coverage gaps: ${report.coverageGaps.join(", ")}`);
  lines.push(`Observations: ${report.observationCounts.total}  byKind=${JSON.stringify(report.observationCounts.byKind)}`);
  lines.push(`Assets: ${JSON.stringify(report.assetCounts)}`);
  lines.push("");
  lines.push(`Secret findings (redacted candidates): ${report.secretFindings.length}`);
  for (const f of report.secretFindings) {
    lines.push(`  ${f.status.padEnd(16)} ${f.ruleId.padEnd(28)} ${f.artifact} ${f.location}  ${f.redactedSnippet}`);
  }
  lines.push("");
  lines.push(`Correlations: ${report.correlations.length}`);
  for (const c of report.correlations) {
    lines.push(`  ${c.relation.padEnd(28)} ${c.status.padEnd(9)} ${c.subject} -> ${c.related.join(", ")}${c.correlationGroup ? `  [group ${c.correlationGroup}]` : ""}`);
  }
  lines.push("");
  lines.push(`Subdomain-takeover candidates: ${report.takeoverCandidates.length}`);
  for (const t of takeovers) {
    lines.push(`  ${t.status.padEnd(16)} ${t.host.padEnd(34)} ${String(t.httpStatus ?? "-").padEnd(4)} ${t.service}  cname=${t.cname}`);
  }
  lines.push("");
  lines.push("Limitations:");
  for (const l of report.limitations) lines.push(`  - ${l}`);
  return lines.join("\n");
}

export async function reportCommand(ctx: Context, scanId: string, opts: ReportOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const built = await buildReport(repo, scanId, { now: new Date() });
    if (!built) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);
    let report: Report;
    try {
      report = redactReport(built);
    } catch {
      // Fail closed: never emit an unredacted report.
      throw new CliError("report generation failed closed (redaction error); nothing was emitted", ExitCode.GENERAL_ERROR);
    }
    const format = opts.format ?? "human";
    return result({
      exitCode: ExitCode.SUCCESS,
      data: report,
      render: () => formatReport(report, format),
    });
  } finally {
    await db.close();
  }
}
