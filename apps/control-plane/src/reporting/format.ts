import type { Report, ReportFormatValue } from "@reconnexus/contracts";
import { renderReportHtml } from "./html.js";
import { normalizeReport } from "./report.js";

/**
 * Every output format is rendered from the one canonical report model; no format re-queries the
 * database or re-derives a status. A format may show less than the model holds, never more.
 */

/** Escape a CSV field and neutralise spreadsheet formula injection (=, +, -, @, tab, CR). */
export function csvField(v: string): string {
  let out = v;
  if (/^[=+\-@\t\r]/.test(out)) out = `'${out}`;
  return /[",\n]/.test(out) ? `"${out.replace(/"/g, '""')}"` : out;
}

function csvRow(cells: unknown[]): string {
  return cells.map((x) => csvField(String(x ?? ""))).join(",");
}

function dash(v: number | null): string {
  return v === null ? "-" : String(v);
}

/** `1.2s` / `94s` / `3m 14s`, or `-` when nothing was measured (never a fabricated zero). */
function duration(ms: number | null): string {
  if (ms === null) return "-";
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 10) return `${s.toFixed(1)}s`;
  if (s < 60) return `${Math.round(s)}s`;
  return `${Math.floor(s / 60)}m ${String(Math.round(s % 60)).padStart(2, "0")}s`;
}

function pct(n: number): string {
  return `${Math.round(n * 100)}%`;
}

/**
 * JSON Lines: one object per line, each tagged with `kind`. The original kinds (`summary`,
 * `stage`, `secret`, `correlation`, `takeover`) keep their shape; later kinds are appended, so a
 * consumer that filters on `kind` is unaffected.
 */
export function formatJsonl(input: Report): string {
  const report = normalizeReport(input);
  const lines: string[] = [];
  lines.push(
    JSON.stringify({
      kind: "summary",
      scanId: report.scanId,
      rootDomain: report.rootDomain,
      scanStatus: report.scanStatus,
      reportStatus: report.reportStatus,
      generatedAt: report.generatedAt,
    }),
  );
  for (const s of report.stages) lines.push(JSON.stringify({ kind: "stage", ...s }));
  for (const f of report.secretFindings) lines.push(JSON.stringify({ kind: "secret", ...f }));
  for (const c of report.correlations) lines.push(JSON.stringify({ kind: "correlation", ...c }));
  for (const t of report.takeoverCandidates) lines.push(JSON.stringify({ kind: "takeover", ...t }));
  for (const f of report.findings) lines.push(JSON.stringify({ kind: "finding", ...f }));
  for (const e of report.providerErrors) lines.push(JSON.stringify({ kind: "provider-error", ...e }));
  for (const i of report.incompleteStages) lines.push(JSON.stringify({ kind: "incomplete-stage", ...i }));
  for (const e of report.evidenceAppendix) lines.push(JSON.stringify({ kind: "evidence", ...e }));
  lines.push(JSON.stringify({ kind: "assessment", ...report.assessment }));
  lines.push(JSON.stringify({ kind: "reproducibility", ...report.reproducibility }));
  return lines.join("\n");
}

/**
 * CSV: a flat `section,type,key,status,detail` sheet. The header and the original section rows are
 * unchanged; `finding`, `provider-error` and `incomplete-stage` rows are appended after them.
 */
export function formatCsv(input: Report): string {
  const report = normalizeReport(input);
  const rows: string[] = ["section,type,key,status,detail"];
  for (const s of report.stages) rows.push(csvRow(["stage", s.jobStatus, s.stage, s.coverageStatus ?? "", s.notes]));
  for (const f of report.secretFindings) rows.push(csvRow(["secret", f.category, f.ruleId, f.status, `${f.artifact} ${f.location} ${f.redactedSnippet}`]));
  for (const c of report.correlations) rows.push(csvRow(["correlation", c.relation, c.subject, c.status, c.related.join(" ")]));
  for (const t of report.takeoverCandidates) rows.push(csvRow(["takeover", t.service, t.host, t.status, `${t.cname} ${t.httpStatus ?? ""} ${t.evidence}`]));
  for (const f of report.findings) rows.push(csvRow(["finding", f.severity, f.subject || f.title, f.validation, `${f.category} confidence=${f.confidence} ${f.evidence}`]));
  for (const e of report.providerErrors) rows.push(csvRow(["provider-error", e.provider, e.stage, e.outcome, e.reason]));
  for (const i of report.incompleteStages) rows.push(csvRow(["incomplete-stage", i.jobStatus, i.stage, i.coverageStatus ?? "", i.impact]));
  return rows.join("\n");
}

/** The terminal report: dense, aligned, and explicit about what was and was not established. */
export function formatHuman(input: Report): string {
  const report = normalizeReport(input);
  const a = report.assessment;
  const lines: string[] = [];
  const pad = (s: string, n: number): string => (s.length >= n ? s : s + " ".repeat(n - s.length));

  lines.push(`ReconNexus report — ${report.rootDomain}  (scan ${report.scanId})`);
  lines.push(`Status: ${report.reportStatus}   scan: ${report.scanStatus}   generated: ${report.generatedAt}`);
  lines.push(`Summary: ${report.summary}`);
  lines.push("");
  lines.push("Assessment:");
  lines.push(`  target:        ${report.rootDomain}  (start ${report.startUrl})`);
  lines.push(`  assessment:    ${report.scanId}`);
  lines.push(`  workspace:     ${a.workspace || "-"}   profile: ${a.profile}`);
  lines.push(`  started:       ${a.startedAt ?? "-"}   finished: ${a.finishedAt ?? "-"}   elapsed: ${duration(a.durationMs)}`);
  lines.push(`  authorization: ${a.authorization.reference || "-"} by ${a.authorization.authorizedBy || "-"} (valid until ${a.authorization.validUntil || "-"})`);
  lines.push(`  capabilities:  ${a.authorization.capabilities.join(", ") || "-"}`);
  lines.push(`  scope:         ${a.scope.domains.join(", ") || "-"}`);
  if (a.scope.excludedDomains.length || a.scope.excludedPaths.length) {
    lines.push(`  exclusions:    ${[...a.scope.excludedDomains, ...a.scope.excludedPaths].join(", ")}`);
  }
  lines.push("");
  lines.push("Stages:");
  for (const s of report.stages) {
    const providers = s.providers.length ? s.providers.map((p) => `${p.provider}:${p.outcome}(${p.records})`).join(" ") : "";
    // The orchestrator writes `provider:outcome` pairs into coverage notes; printing them again
    // after the provider column would say the same thing twice.
    const providerNotes = s.providers.map((p) => `${p.provider}:${p.outcome}`).sort().join(" ");
    const notes = s.notes.split(/\s+/).filter(Boolean).sort().join(" ") === providerNotes ? "" : s.notes;
    lines.push(
      `  ${pad(s.stage, 26)} ${pad(s.jobStatus, 18)} ${pad(`coverage=${s.coverageStatus ?? "-"}`, 23)} ${pad(`${s.collected}/${s.expected}`, 11)}` +
        ` ${pad(duration(s.durationMs), 8)} ${pad(`records=${s.records}`, 14)}${s.retries > 0 ? pad(` retries=${s.retries}`, 12) : pad("", 12)}` +
        `${providers ? " " + providers : ""}${notes ? "  " + notes : ""}`,
    );
  }
  if (report.coverageGaps.length) lines.push(`Coverage gaps: ${report.coverageGaps.join(", ")}`);
  lines.push(`Observations: ${report.observationCounts.total}  byKind=${JSON.stringify(report.observationCounts.byKind)}`);
  lines.push(`Assets: ${JSON.stringify(report.assetCounts)}`);
  lines.push("");
  lines.push("Inventory (recorded / shown in this report):");
  for (const [name, sec] of Object.entries(report.inventory)) {
    const note = !sec.truncated ? "" : sec.shown < sec.total ? "(truncated)" : "(derived from a capped sample)";
    lines.push(`  ${pad(name, 14)} ${pad(String(sec.total), 8)} ${pad(String(sec.shown), 8)} ${note}`.trimEnd());
  }
  const recon = report.reconciliation ?? {};
  const bySource = Object.entries(recon.endpointsBySource ?? {}).map(([k, v]) => `${k || "unknown"}=${v}`).join(" ") || "-";
  const byProvider = Object.entries(recon.endpointsByProvider ?? {}).map(([k, v]) => `${k || "unknown"}=${v}`).join(" ") || "-";
  lines.push(
    `  endpoints:     raw=${recon.endpointRawObservations ?? 0} distinct=${recon.endpointDistinct ?? 0} shown=${recon.endpointShown ?? 0}  bySource=[${bySource}] byProvider=[${byProvider}]`,
  );
  lines.push("");
  const t = report.findingTotals;
  lines.push(`Findings: ${t.total}  (critical=${t.bySeverity.CRITICAL ?? 0} high=${t.bySeverity.HIGH ?? 0} medium=${t.bySeverity.MEDIUM ?? 0} low=${t.bySeverity.LOW ?? 0} info=${t.bySeverity.INFO ?? 0}; validated=${t.validated})`);
  for (const f of report.findings) {
    lines.push(`  ${pad(f.severity, 9)} ${pad(f.validation, 14)} ${pad(pct(f.confidence), 5)} ${f.title}`);
    if (f.evidence) lines.push(`            evidence: ${f.evidence}`);
    if (f.remediation) lines.push(`            remediation: ${f.remediation}`);
  }
  lines.push("");
  lines.push(`Secret findings (redacted candidates): ${report.secretFindings.length}`);
  for (const f of report.secretFindings) {
    lines.push(`  ${pad(f.status, 16)} ${pad(f.ruleId, 28)} ${f.artifact} ${f.location}  ${f.redactedSnippet}`);
  }
  lines.push("");
  lines.push(`Correlations: ${report.correlations.length}`);
  for (const c of report.correlations) {
    lines.push(`  ${pad(c.relation, 28)} ${pad(c.status, 9)} ${c.subject} -> ${c.related.join(", ")}${c.correlationGroup ? `  [group ${c.correlationGroup}]` : ""}`);
  }
  lines.push("");
  lines.push(`Subdomain-takeover candidates: ${report.takeoverCandidates.length}`);
  for (const t2 of report.takeoverCandidates) {
    lines.push(`  ${pad(t2.status, 16)} ${pad(t2.host, 34)} ${pad(String(t2.httpStatus ?? "-"), 4)} ${t2.service}  cname=${t2.cname}`);
  }
  if (report.providerErrors.length) {
    lines.push("");
    lines.push(`Tool/provider errors: ${report.providerErrors.length}`);
    for (const e of report.providerErrors) {
      lines.push(`  ${pad(e.stage, 26)} ${pad(e.provider, 22)} ${pad(e.outcome, 18)} records=${dash(e.records)}${e.timedOut ? " timed-out" : ""}  ${e.reason}`);
    }
  }
  if (report.incompleteStages.length) {
    lines.push("");
    lines.push(`Incomplete stages: ${report.incompleteStages.length}`);
    for (const i of report.incompleteStages) lines.push(`  ${pad(i.stage, 26)} ${pad(i.jobStatus, 18)} ${i.impact}`);
  }
  lines.push("");
  lines.push("Reproducibility:");
  lines.push(`  tool ${report.reproducibility.toolVersion}  report-schema v${report.reproducibility.reportSchemaVersion}  policy v${report.reproducibility.policyVersion}`);
  if (Object.keys(report.reproducibility.providerVersions).length) {
    lines.push(`  providers: ${Object.entries(report.reproducibility.providerVersions).map(([k, v]) => `${k}=${v}`).join(" ")}`);
  }
  lines.push(`  derived from persisted state only: ${report.reproducibility.derivedFromPersistedStateOnly ? "yes" : "no"}`);
  if (report.evidenceAppendix.length) {
    lines.push(`  evidence artifacts: ${report.evidenceAppendix.length}`);
  }
  lines.push("");
  lines.push("Limitations:");
  for (const l of report.limitations) lines.push(`  - ${l}`);
  return lines.join("\n");
}

/** Render the canonical model in one of the supported formats. */
export function formatReport(report: Report, format: string): string {
  switch (format as ReportFormatValue) {
    case "json":
      return JSON.stringify(normalizeReport(report), null, 2);
    case "jsonl":
      return formatJsonl(report);
    case "csv":
      return formatCsv(report);
    case "html":
      return renderReportHtml(report);
    case "human":
    default:
      return formatHuman(report);
  }
}
