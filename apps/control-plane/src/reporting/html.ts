import type { Report, ReportFinding, ReportProvider, StageReport } from "@reconnexus/contracts";
import { normalizeReport } from "./report.js";

/**
 * Self-contained HTML exporter for the canonical report model.
 *
 * Safety rules, enforced by construction rather than by review:
 *   - Every value from the model goes through `esc()`. Nothing is interpolated raw.
 *   - The document contains no `<script>`, no inline event handlers and no external references
 *     (no remote CSS, fonts, images or links), so untrusted strings cannot become executable and
 *     opening the file cannot phone home. Interactivity is CSS-only (`<details>`).
 *   - URLs from the model are rendered as text, never as `href`, so a `javascript:` or `data:`
 *     URL discovered during a scan can never become a clickable link.
 *   - CSS class names come from fixed whitelists keyed by status, never from model strings.
 *   - The model handed in is already redacted; this renderer adds no new data sources.
 */

/** Defensive display cap per table, independent of the model's own row caps. */
const MAX_TABLE_ROWS = 500;

export function esc(value: unknown): string {
  const s = typeof value === "string" ? value : value === null || value === undefined ? "" : String(value);
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Fixed severity classes. An unknown severity renders neutral rather than inventing a level. */
function severityClass(severity: string): string {
  switch (severity) {
    case "CRITICAL":
      return "sev-critical";
    case "HIGH":
      return "sev-high";
    case "MEDIUM":
      return "sev-medium";
    case "LOW":
      return "sev-low";
    case "INFO":
      return "sev-info";
    default:
      return "sev-unknown";
  }
}

function statusClass(status: string): string {
  switch (status) {
    case "SUCCEEDED":
    case "COLLECTED":
    case "COMPLETE_WITH_FINDINGS":
    case "COMPLETE_NO_FINDINGS":
    case "OK":
    case "RETRIEVED":
    case "PARSED":
    case "ANALYZED":
    case "OBSERVED":
      return "st-ok";
    case "PARTIAL":
    case "RUNNING":
    case "OVERSIZED":
    case "INCONSISTENT":
    case "REDIRECT_DENIED":
    case "INFERRED":
    case "SUSPECTED":
      return "st-partial";
    case "SKIPPED":
    case "NOT_ATTEMPTED":
    case "QUEUED":
    case "REPORTING_NOT_RUN":
    case "NOT_OBSERVED":
    case "NOT_FOUND":
    case "DISABLED":
    case "SUPPRESSED":
    case "REJECTED":
    case "INDETERMINATE":
    case "UNKNOWN":
      return "st-idle";
    case "FAILED":
    case "SOURCE_UNAVAILABLE":
    case "BLOCKED":
    case "MISSING":
    case "REPORTING_FAILED":
    case "ERROR":
    case "MALFORMED":
    case "ANALYSIS_FAILED":
    case "MISMATCHED_MIME":
      return "st-fail";
    case "CANCELLED":
      return "st-cancel";
    default:
      return "st-unknown";
  }
}

function badge(text: string, cls: string): string {
  return `<span class="badge ${cls}">${esc(text)}</span>`;
}

/** Colour modifier for the headline verdict panel, keyed to the overall report status. */
function verdictModifier(reportStatus: string): string {
  switch (reportStatus) {
    case "COMPLETE_NO_FINDINGS":
      return "verdict-clean";
    case "COMPLETE_WITH_FINDINGS":
      return "verdict-findings";
    case "PARTIAL":
    case "REPORTING_NOT_RUN":
      return "verdict-warn";
    case "FAILED":
    case "REPORTING_FAILED":
      return "verdict-bad";
    default:
      return "verdict-idle";
  }
}

/** A plain-language sentence an operator can act on without reading the whole report. */
function verdictHeadline(reportStatus: string, findings: number): string {
  switch (reportStatus) {
    case "COMPLETE_NO_FINDINGS":
      return "Assessment complete — no candidate findings";
    case "COMPLETE_WITH_FINDINGS":
      return `Assessment complete — ${findings} candidate finding${findings === 1 ? "" : "s"} to review`;
    case "PARTIAL":
      return "Assessment partial — results are incomplete";
    case "FAILED":
      return "Assessment failed — this is not a clean result";
    case "REPORTING_NOT_RUN":
      return "Reporting has not run — a snapshot of current state";
    case "REPORTING_FAILED":
      return "Report generation failed";
    default:
      return "Assessment status";
  }
}

/** True only when every stage completed, so a lack of findings can be stated confidently. */
function isComplete(reportStatus: string): boolean {
  return reportStatus === "COMPLETE_WITH_FINDINGS" || reportStatus === "COMPLETE_NO_FINDINGS";
}

/** `-` whenever a value was not measured, so a missing metric never reads as zero. */
function num(value: number | null | undefined): string {
  return value === null || value === undefined ? "<span class=\"na\" title=\"not recorded\">—</span>" : esc(value.toLocaleString("en-US"));
}

function duration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "<span class=\"na\" title=\"not recorded\">—</span>";
  if (ms < 1000) return `${esc(ms)}ms`;
  const s = ms / 1000;
  if (s < 10) return `${esc(s.toFixed(1))}s`;
  if (s < 60) return `${esc(Math.round(s))}s`;
  return `${esc(Math.floor(s / 60))}m ${esc(String(Math.round(s % 60)).padStart(2, "0"))}s`;
}

function confidence(c: number): string {
  const p = Math.round(Math.min(1, Math.max(0, c)) * 100);
  return `<span class="conf" role="img" aria-label="confidence ${esc(p)} percent"><span class="conf-bar" style="width:${esc(p)}%"></span></span><span class="conf-n">${esc(p)}%</span>`;
}

function timestamp(value: string | null): string {
  return value === null || value === "" ? "<span class=\"na\">—</span>" : `<time>${esc(value)}</time>`;
}

function list(values: readonly string[]): string {
  if (values.length === 0) return "<span class=\"na\">—</span>";
  return values.map((v) => `<code>${esc(v)}</code>`).join(" ");
}

interface Column<R> {
  head: string;
  cell: (row: R) => string;
  numeric?: boolean;
  /** Identifier-like columns that must keep their value on one line (stage ids, hashes, hosts). */
  nowrap?: boolean;
}

/** A table, or an explicit "nothing recorded" note — never an empty element with no explanation. */
function tableOf<R>(caption: string, cols: Array<Column<R>>, rows: readonly R[], emptyNote: string): string {
  if (rows.length === 0) return `<p class="empty">${esc(emptyNote)}</p>`;
  const shown = rows.slice(0, MAX_TABLE_ROWS);
  const cls = (c: Column<R>): string => {
    const names = [c.numeric ? "n" : "", c.nowrap ? "nw" : ""].filter(Boolean).join(" ");
    return names ? ` class="${names}"` : "";
  };
  const head = cols.map((c) => `<th scope="col"${cls(c)}>${esc(c.head)}</th>`).join("");
  const body = shown.map((r) => `<tr>${cols.map((c) => `<td${cls(c)}>${c.cell(r)}</td>`).join("")}</tr>`).join("");
  const note = rows.length > shown.length ? `<p class="note">Showing ${esc(shown.length)} of ${esc(rows.length)} rows in this table.</p>` : "";
  return `<div class="scroll"><table><caption>${esc(caption)}</caption><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>${note}`;
}

function sectionMeta(sec: { total: number; shown: number; truncated: boolean }): string {
  const t = sec.truncated
    ? `<span class="trunc">truncated — showing ${esc(sec.shown)} of ${esc(sec.total)}</span>`
    : `<span class="full">${esc(sec.total)} recorded</span>`;
  return `<p class="secmeta">${t}</p>`;
}

function kv(label: string, value: string): string {
  return `<div class="kv"><dt>${esc(label)}</dt><dd>${value}</dd></div>`;
}

function providerCell(providers: readonly ReportProvider[]): string {
  if (providers.length === 0) return "<span class=\"na\">—</span>";
  return providers
    .map(
      (p) =>
        `<span class="prov">${esc(p.provider)}${p.providerVersion && p.providerVersion !== "unknown" ? `<span class="pv"> ${esc(p.providerVersion)}</span>` : ""} ${badge(
          p.outcome,
          statusClass(p.outcome),
        )} <span class="pr">${esc(p.records.toLocaleString("en-US"))} rec</span>${p.durationMs === null ? "" : ` <span class="pd">${duration(p.durationMs)}</span>`}${
          p.timedOut ? ' <span class="pw">timed out</span>' : ""
        }${p.truncated ? ' <span class="pw">truncated</span>' : ""}</span>`,
    )
    .join("");
}

function stageRows(stages: readonly StageReport[]): string {
  return tableOf<StageReport>(
    "Stage execution and coverage",
    [
      { head: "Stage", cell: (s) => `<code>${esc(s.stage)}</code>`, nowrap: true },
      { head: "Job", cell: (s) => badge(s.jobStatus, statusClass(s.jobStatus)) },
      { head: "Coverage", cell: (s) => (s.coverageStatus === null ? "<span class=\"na\">—</span>" : badge(s.coverageStatus, statusClass(s.coverageStatus))) },
      { head: "Collected / expected", cell: (s) => `${esc(s.collected)} / ${esc(s.expected)}`, numeric: true },
      { head: "Records", cell: (s) => num(s.records), numeric: true },
      { head: "Duration", cell: (s) => duration(s.durationMs), numeric: true },
      { head: "Attempts", cell: (s) => `${esc(s.attempts)}${s.retries > 0 ? ` <span class="pw">(${esc(s.retries)} retr${s.retries === 1 ? "y" : "ies"})</span>` : ""}`, numeric: true },
      { head: "Providers", cell: (s) => providerCell(s.providers), nowrap: true },
      { head: "Notes", cell: (s) => (s.lastError ? `<span class="err">${esc(s.lastError)}</span> ${esc(s.notes)}` : esc(s.notes)) },
    ],
    stages,
    "No stages are recorded for this scan.",
  );
}

function findingCard(f: ReportFinding): string {
  return [
    `<article class="finding ${severityClass(f.severity)}" aria-labelledby="f-${esc(f.id)}">`,
    `<h3 id="f-${esc(f.id)}">${badge(f.severity, severityClass(f.severity))} ${esc(f.title)}</h3>`,
    `<dl class="finding-meta">`,
    kv("Validation", badge(f.validation, f.validation === "VALIDATED" ? "st-ok" : statusClass(f.validation))),
    kv("Confidence", confidence(f.confidence)),
    kv("Category", `<code>${esc(f.category)}</code>`),
    kv("Subject", `<code>${esc(f.subject)}</code>`),
    kv("Source", `<code>${esc(f.sourceStage)}</code> / <code>${esc(f.sourceKind)}</code>`),
    kv("Finding id", `<code>${esc(f.id)}</code>`),
    `</dl>`,
    f.evidence ? `<p class="evidence"><strong>Evidence (redacted):</strong> <code>${esc(f.evidence)}</code></p>` : "",
    f.evidenceRefs.length ? `<p class="refs"><strong>Evidence references:</strong> ${list(f.evidenceRefs)}</p>` : "",
    f.remediation ? `<p class="remediation"><strong>Remediation:</strong> ${esc(f.remediation)}</p>` : "",
    f.references.length ? `<p class="refs"><strong>References:</strong> ${list(f.references)}</p>` : "",
    `</article>`,
  ].join("");
}

const STYLES = `
:root{--bg:#fff;--fg:#14171a;--muted:#5b6670;--line:#e2e6ea;--card:#f7f9fa;--ok:#1b7f4b;--partial:#9a6200;--fail:#b3261e;--idle:#5b6670;--cancel:#7a4f9a;--accent:#1f4f82;--warnbg:#fff6e5}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.skip{position:absolute;left:-9999px}
.skip:focus{left:8px;top:8px;background:var(--bg);padding:8px;border:2px solid var(--accent);z-index:10}
.wrap{max-width:1180px;margin:0 auto;padding:24px 20px 64px}
header.top{border-bottom:3px solid var(--accent);padding-bottom:16px;margin-bottom:24px}
header.top h1{font-size:1.6rem;margin:0 0 4px}
header.top .sub{color:var(--muted);font-size:.95rem}
h2{font-size:1.2rem;margin:36px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:1rem;margin:18px 0 8px}
p{margin:8px 0}
a{color:var(--accent);text-decoration:none;border-bottom:1px solid transparent}
a:hover,a:focus{border-bottom-color:currentColor}
nav p{display:flex;flex-wrap:wrap;gap:4px 10px}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.86em;overflow-wrap:anywhere;background:var(--card);padding:1px 4px;border-radius:3px}
.verdict{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--accent);border-radius:6px;padding:14px 16px}
.verdict .big{font-size:1.05rem;font-weight:600}
.verdict-head{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.verdict-badge{font-size:.78rem}
.verdict-text{font-size:1.02rem;margin:10px 0 6px}
.verdict-sub{color:var(--muted);font-size:.85rem;margin:0}
.verdict-clean{border-left-color:var(--ok)}
.verdict-findings{border-left-color:var(--accent)}
.verdict-warn{border-left-color:var(--partial)}
.verdict-bad{border-left-color:var(--fail)}
.verdict-idle{border-left-color:var(--idle)}
.banner{border-radius:6px;padding:12px 14px;margin:14px 0;font-size:.94rem;border:1px solid var(--line)}
.banner-warn{background:var(--warnbg);border-left:5px solid var(--partial)}
.brand{font-size:.78rem;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);font-weight:700}
.brand .ver{font-weight:500;letter-spacing:.06em}
.legal{font-size:.82rem}
nav.toc{border:1px solid var(--line);border-radius:8px;background:var(--card);padding:6px 16px;margin:0 0 24px}
nav.toc ol{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:2px 24px}
nav.toc li{margin:4px 0}
nav.toc a{display:flex;justify-content:space-between;gap:12px;padding:4px 2px;border-bottom:1px solid transparent}
nav.toc a:hover{border-bottom-color:currentColor}
.tcount{color:var(--muted);font-size:.82em;font-variant-numeric:tabular-nums}
main{counter-reset:section}
main>section{counter-increment:section;scroll-margin-top:16px}
main>section>h2::before{content:counter(section) ". ";color:var(--muted);font-weight:600}
.legend{display:flex;flex-wrap:wrap;gap:8px 18px;align-items:center;margin:10px 0}
.legend .lab{color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;margin-right:2px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px}
.card .n{font-size:1.5rem;font-weight:650;line-height:1.2}
.card .l{color:var(--muted);font-size:.8rem;text-transform:uppercase;letter-spacing:.04em}
dl.meta,dl.finding-meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:8px 20px;margin:12px 0}
.kv dt{color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.04em}
.kv dd{margin:2px 0 0}
.scroll{overflow-x:auto;margin:10px 0}
table{min-width:100%;border-collapse:collapse;font-size:.9rem}
td.nw,th.nw{white-space:nowrap}
td.nw code{overflow-wrap:normal}
td:not(.nw):not(.n){min-width:180px}
caption{text-align:left;color:var(--muted);font-size:.8rem;padding-bottom:6px}
th,td{border-bottom:1px solid var(--line);padding:7px 10px;text-align:left;vertical-align:top}
th{background:var(--card);font-size:.78rem;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);position:sticky;top:0}
td.n,th.n{text-align:right;white-space:nowrap}
tbody tr:hover{background:var(--card)}
.badge{display:inline-block;font-size:.72rem;font-weight:650;letter-spacing:.03em;padding:2px 7px;border-radius:10px;border:1px solid currentColor;white-space:nowrap}
.st-ok{color:var(--ok)}.st-partial{color:var(--partial)}.st-fail{color:var(--fail)}.st-idle{color:var(--idle)}.st-cancel{color:var(--cancel)}.st-unknown{color:var(--muted)}
.sev-critical{color:#7d1a13}.sev-high{color:var(--fail)}.sev-medium{color:var(--partial)}.sev-low{color:var(--accent)}.sev-info{color:var(--idle)}.sev-unknown{color:var(--muted)}
.na{color:var(--muted)}
.empty{color:var(--muted);background:var(--card);border:1px dashed var(--line);border-radius:6px;padding:10px 12px}
.note,.secmeta{color:var(--muted);font-size:.82rem}
.trunc{color:var(--partial);font-weight:600}
.prov{display:inline-block;margin:0 10px 2px 0;white-space:nowrap}
.pv,.pr,.pd{color:var(--muted);font-size:.8em}
.pw{color:var(--partial);font-size:.8em}
.err{color:var(--fail)}
.conf{display:inline-block;width:70px;height:7px;background:var(--line);border-radius:4px;overflow:hidden;vertical-align:middle}
.conf-bar{display:block;height:100%;background:var(--accent)}
.conf-n{color:var(--muted);font-size:.8em;margin-left:6px}
.finding{border:1px solid var(--line);border-left:5px solid currentColor;border-radius:6px;padding:12px 16px;margin:14px 0;background:var(--bg)}
.finding h3{margin-top:0;color:var(--fg)}
.finding p{color:var(--fg);font-size:.92rem}
.evidence code{white-space:pre-wrap}
details{border:1px solid var(--line);border-radius:6px;padding:8px 12px;margin:10px 0;background:var(--card)}
summary{cursor:pointer;font-weight:600}
footer{margin-top:40px;padding-top:14px;border-top:1px solid var(--line);color:var(--muted);font-size:.82rem}
ul.lim{padding-left:20px}ul.lim li{margin:4px 0;font-size:.9rem}
@media (max-width:640px){.wrap{padding:16px 12px 48px}table{font-size:.82rem}th{position:static}}
@media print{
 @page{margin:14mm}
 body{font-size:11pt}
 .wrap{max-width:none;padding:0}
 .scroll{overflow:visible}
 td:not(.nw):not(.n){min-width:0}
 details{break-inside:avoid}details>summary{display:none}details[open],details{border:0;background:transparent;padding:0}
 details>*{display:block!important}
 table{width:100%}
 th{position:static}
 .finding,tr,.card{break-inside:avoid}
 .skip,.verdict{border-color:#999}
 a[href]:after{content:""}
}
@media (prefers-color-scheme:dark){
 :root{--bg:#15181b;--fg:#e9edf1;--muted:#9aa5ae;--line:#2b3238;--card:#1d2226;--ok:#56c288;--partial:#e0a33c;--fail:#ef6b60;--idle:#9aa5ae;--cancel:#b58ad6;--accent:#6ea8e0;--warnbg:#33290f}
 .sev-critical{color:#ff8a7e}
}
`;

/** Render the canonical report model as one self-contained, printable HTML document. */
export function renderReportHtml(input: Report): string {
  const report = normalizeReport(input);
  const a = report.assessment;
  const inv = report.inventory;
  const recon = report.reconciliation;
  const t = report.findingTotals;
  const complete = isComplete(report.reportStatus);
  const title = `ReconNexus assessment report — ${report.rootDomain}`;

  const execSummary = [
    `<section id="summary" aria-labelledby="h-summary">`,
    `<h2 id="h-summary">Executive summary</h2>`,
    `<div class="verdict ${verdictModifier(report.reportStatus)}">`,
    `<div class="verdict-head">`,
    `<span class="badge ${statusClass(report.reportStatus)} verdict-badge">${esc(report.reportStatus)}</span>`,
    `<span class="big">${esc(verdictHeadline(report.reportStatus, t.total))}</span>`,
    `</div>`,
    `<p class="verdict-text">${esc(report.summary)}</p>`,
    `<p class="verdict-sub">analysis ${badge(report.scanStatus, statusClass(report.scanStatus))} · ${esc(report.stages.length)} stages · generated ${esc(report.generatedAt)}</p>`,
    `</div>`,
    complete
      ? ""
      : `<div class="banner banner-warn" role="note"><strong>Coverage warning.</strong> This assessment did not complete every stage (` +
        `analysis <code>${esc(report.scanStatus)}</code>). The absence of a result is not evidence of absence — treat untested ` +
        `dimensions as <em>unknown</em>, not clean.</div>`,
    `<div class="cards">`,
    `<div class="card"><div class="n">${esc(t.total)}</div><div class="l">Findings (candidates)</div></div>`,
    `<div class="card"><div class="n">${esc((t.bySeverity.CRITICAL ?? 0) + (t.bySeverity.HIGH ?? 0))}</div><div class="l">High or critical</div></div>`,
    `<div class="card"><div class="n">${esc(t.validated)}</div><div class="l">Validated</div></div>`,
    `<div class="card"><div class="n">${esc(inv.hosts.total)}</div><div class="l">Hosts seen in DNS</div></div>`,
    `<div class="card"><div class="n">${esc(inv.services.total)}</div><div class="l">HTTP services</div></div>`,
    `<div class="card"><div class="n">${esc(inv.urls.total)}</div><div class="l">URLs</div></div>`,
    `<div class="card"><div class="n">${esc(inv.apis.total)}</div><div class="l">API endpoints</div></div>`,
    `<div class="card"><div class="n">${esc(report.observationCounts.total)}</div><div class="l">Observations</div></div>`,
    `</div>`,
    `<p class="note">Counts below are discovered assets and observations, not vulnerabilities. A finding is a
      <em>candidate</em> interpreted from evidence: ReconNexus performs no exploitation and verifies no credential, so
      <strong>${esc(t.validated)}</strong> finding${t.validated === 1 ? " is" : "s are"} validated. ${
        complete ? "Every stage of this assessment succeeded." : "See the coverage warning above."
      }</p>`,
    `</section>`,
  ].join("");

  const assessmentSection = [
    `<section id="assessment" aria-labelledby="h-assessment">`,
    `<h2 id="h-assessment">Scope &amp; methodology</h2>`,
    `<p class="note">What was authorized, what limits applied, and when the assessment ran. Only in-scope targets were ever contacted.</p>`,
    `<dl class="meta">`,
    kv("Target", `<code>${esc(report.rootDomain)}</code>`),
    kv("Start URL", `<code>${esc(report.startUrl)}</code>`),
    kv("Assessment id", `<code>${esc(report.scanId)}</code>`),
    kv("Project id", `<code>${esc(report.projectId)}</code>`),
    kv("Workspace", esc(a.workspace || "—")),
    kv("Provider profile", `<code>${esc(a.profile)}</code>`),
    kv("Created", timestamp(a.createdAt)),
    kv("Started", timestamp(a.startedAt)),
    kv("Finished", timestamp(a.finishedAt)),
    kv("Elapsed", duration(a.durationMs)),
    kv("Report generated", timestamp(report.generatedAt)),
    kv("Authorization reference", esc(a.authorization.reference || "—")),
    kv("Authorized by", esc(a.authorization.authorizedBy || "—")),
    kv("Authorization window", `${timestamp(a.authorization.validFrom || null)} → ${timestamp(a.authorization.validUntil || null)}`),
    kv("Policy version", esc(a.policyVersion)),
    kv("Capabilities", list(a.authorization.capabilities)),
    `</dl>`,
    `<h3>Scope</h3>`,
    `<dl class="meta">`,
    kv("In-scope domains", list(a.scope.domains)),
    kv("In-scope hosts", list(a.scope.hosts)),
    kv("In-scope IPs", list(a.scope.ips)),
    kv("In-scope CIDRs", list(a.scope.cidrs)),
    kv("Excluded domains", list(a.scope.excludedDomains)),
    kv("Excluded hosts", list(a.scope.excludedHosts)),
    kv("Excluded paths", list(a.scope.excludedPaths)),
    kv(
      "Limits",
      `concurrency ${esc(a.scope.limits.maxConcurrency)} · ${esc(a.scope.limits.requestsPerSecond)} req/s · crawl depth ${esc(
        a.scope.limits.crawlDepth,
      )} · runtime ${esc(a.scope.limits.maxRuntimeSeconds)}s · artifact ${esc(a.scope.limits.maxArtifactBytes)} bytes`,
    ),
    `</dl>`,
    `</section>`,
  ].join("");

  const stagesSection = [
    `<section id="stages" aria-labelledby="h-stages">`,
    `<h2 id="h-stages">Stage execution and coverage</h2>`,
    stageRows(report.stages),
    report.coverageGaps.length
      ? `<p><strong>Coverage gaps:</strong> ${list(report.coverageGaps)}</p>`
      : `<p class="note">No coverage gaps recorded: every stage with a coverage record reported COLLECTED.</p>`,
    `</section>`,
  ].join("");

  const invSection = [
    `<section id="inventory" aria-labelledby="h-inventory">`,
    `<h2 id="h-inventory">Asset and service inventory</h2>`,
    `<h3>Hosts (from DNS observations)</h3>`,
    sectionMeta(inv.hosts),
    tableOf(
      "Hosts and resolved addresses",
      [
        { head: "Host", cell: (r: typeof inv.hosts.rows[number]) => `<code>${esc(r.host)}</code>`, nowrap: true },
        { head: "Addresses", cell: (r: typeof inv.hosts.rows[number]) => list(r.addresses) },
        { head: "Record types", cell: (r: typeof inv.hosts.rows[number]) => list(r.recordTypes) },
        { head: "Resolved", cell: (r: typeof inv.hosts.rows[number]) => (r.resolved ? badge("YES", "st-ok") : badge("NO", "st-idle")) },
      ],
      inv.hosts.rows,
      "No DNS observations were recorded for this scan.",
    ),
    `<h3>HTTP services</h3>`,
    sectionMeta(inv.services),
    tableOf(
      "HTTP services observed",
      [
        { head: "URL", cell: (r: typeof inv.services.rows[number]) => `<code>${esc(r.url)}</code>` },
        { head: "Status", cell: (r: typeof inv.services.rows[number]) => num(r.statusCode), numeric: true },
        { head: "Probe", cell: (r: typeof inv.services.rows[number]) => badge(r.probeStatus || "UNKNOWN", statusClass(r.probeStatus)) },
        { head: "Title", cell: (r: typeof inv.services.rows[number]) => esc(r.title) },
        { head: "Server", cell: (r: typeof inv.services.rows[number]) => esc(r.server) },
        { head: "Final URL", cell: (r: typeof inv.services.rows[number]) => `<code>${esc(r.finalUrl)}</code>` },
        { head: "TLS", cell: (r: typeof inv.services.rows[number]) => esc(r.tls) },
      ],
      inv.services.rows,
      "No HTTP service was observed. Check the stage table: the probe stage may not have run.",
    ),
    `<h3>Technologies</h3>`,
    sectionMeta(inv.technologies),
    tableOf(
      "Technology observations with supporting evidence",
      [
        { head: "Technology", cell: (r: typeof inv.technologies.rows[number]) => esc(r.name) },
        { head: "Host", cell: (r: typeof inv.technologies.rows[number]) => `<code>${esc(r.host)}</code>` },
        { head: "Category", cell: (r: typeof inv.technologies.rows[number]) => esc(r.category) },
        { head: "Confidence", cell: (r: typeof inv.technologies.rows[number]) => confidence(r.confidence), numeric: true },
        { head: "Evidence", cell: (r: typeof inv.technologies.rows[number]) => `${esc(r.evidenceType)} <code>${esc(r.evidence)}</code>` },
      ],
      inv.technologies.rows,
      "No technology fingerprints were recorded.",
    ),
    `<h3>Security metadata</h3>`,
    sectionMeta(inv.security),
    `<p class="note">A NOT_OBSERVED control reflects one response at a point in time; it is not proof the control is absent.</p>`,
    tableOf(
      "Security-metadata observations",
      [
        { head: "Service", cell: (r: typeof inv.security.rows[number]) => `<code>${esc(r.service)}</code>` },
        { head: "Category", cell: (r: typeof inv.security.rows[number]) => esc(r.category) },
        { head: "Name", cell: (r: typeof inv.security.rows[number]) => esc(r.name) },
        { head: "Status", cell: (r: typeof inv.security.rows[number]) => badge(r.status || "UNKNOWN", statusClass(r.status)) },
        { head: "Detail", cell: (r: typeof inv.security.rows[number]) => `<code>${esc(r.detail)}</code>` },
      ],
      inv.security.rows,
      "No security metadata was collected.",
    ),
    `</section>`,
  ].join("");

  const intelSection = [
    `<section id="intelligence" aria-labelledby="h-intel">`,
    `<h2 id="h-intel">URL, API, parameter and JavaScript intelligence</h2>`,
    `<details open><summary>URLs (${esc(inv.urls.total)})</summary>`,
    sectionMeta(inv.urls),
    tableOf(
      "Collected URLs",
      [
        { head: "URL", cell: (r: typeof inv.urls.rows[number]) => `<code>${esc(r.url)}</code>` },
        { head: "Status", cell: (r: typeof inv.urls.rows[number]) => num(r.statusCode), numeric: true },
        { head: "Method", cell: (r: typeof inv.urls.rows[number]) => esc(r.method) },
        { head: "Categories", cell: (r: typeof inv.urls.rows[number]) => list(r.categories) },
        { head: "Parameters", cell: (r: typeof inv.urls.rows[number]) => list(r.parameters) },
        { head: "Provider", cell: (r: typeof inv.urls.rows[number]) => esc(r.provider) },
      ],
      inv.urls.rows,
      "No URLs were collected.",
    ),
    `</details>`,
    `<details open><summary>API endpoints (${esc(inv.apis.total)})</summary>`,
    sectionMeta(inv.apis),
    tableOf(
      "API endpoints",
      [
        { head: "Method", cell: (r: typeof inv.apis.rows[number]) => esc(r.method), nowrap: true },
        { head: "Origin", cell: (r: typeof inv.apis.rows[number]) => `<code>${esc(r.origin)}</code>` },
        { head: "Path", cell: (r: typeof inv.apis.rows[number]) => `<code>${esc(r.path)}</code>` },
        { head: "Source", cell: (r: typeof inv.apis.rows[number]) => esc(r.discoveredVia) },
        { head: "Documented", cell: (r: typeof inv.apis.rows[number]) => (r.documented ? badge("SPEC", "st-ok") : badge("OBSERVED", "st-idle")) },
        { head: "Resolved", cell: (r: typeof inv.apis.rows[number]) => (r.resolved ? badge("YES", "st-ok") : badge("DYNAMIC", "st-partial")) },
        { head: "Parameters", cell: (r: typeof inv.apis.rows[number]) => list(r.parameters) },
        { head: "Auth", cell: (r: typeof inv.apis.rows[number]) => list(r.authSchemes) },
      ],
      inv.apis.rows,
      "No API endpoints were discovered.",
    ),
    `</details>`,
    `<details><summary>Endpoint reconciliation</summary>`,
    `<p class="note">Raw observations → distinct endpoints → rows shown. Per-source counts overlap (an endpoint found by two sources appears in both), so they may sum to more than the distinct total.</p>`,
    `<dl class="meta">`,
    kv("Raw endpoint observations", esc(recon.endpointRawObservations ?? 0)),
    kv("Distinct endpoints", esc(recon.endpointDistinct ?? 0)),
    kv("Rows shown", esc(recon.endpointShown ?? 0)),
    kv("By discovery source", list(Object.entries(recon.endpointsBySource ?? {}).map(([k, v]) => `${k || "unknown"}=${v}`))),
    kv("By provider", list(Object.entries(recon.endpointsByProvider ?? {}).map(([k, v]) => `${k || "unknown"}=${v}`))),
    `</dl>`,
    `</details>`,
    `<details open><summary>API specifications (${esc(inv.specs.total)})</summary>`,
    sectionMeta(inv.specs),
    tableOf(
      "API specifications and parse outcomes",
      [
        { head: "URL", cell: (r: typeof inv.specs.rows[number]) => `<code>${esc(r.url)}</code>` },
        { head: "Version", cell: (r: typeof inv.specs.rows[number]) => esc(r.specVersion) },
        { head: "Parse", cell: (r: typeof inv.specs.rows[number]) => badge(r.parseStatus || "UNKNOWN", statusClass(r.parseStatus)) },
        { head: "Title", cell: (r: typeof inv.specs.rows[number]) => esc(r.title) },
        { head: "Paths", cell: (r: typeof inv.specs.rows[number]) => num(r.pathCount), numeric: true },
        { head: "Operations", cell: (r: typeof inv.specs.rows[number]) => num(r.operationCount), numeric: true },
      ],
      inv.specs.rows,
      "No API specification was found or parsed.",
    ),
    `</details>`,
    `<details open><summary>Parameters (${esc(inv.parameters.total)} distinct)</summary>`,
    sectionMeta(inv.parameters),
    inv.parameters.truncated
      ? `<p class="note">Derived from the URL and endpoint rows above, which were capped — treat this inventory as a sample, not complete parameter coverage.</p>`
      : "",
    tableOf(
      "Parameter inventory",
      [
        { head: "Parameter", cell: (r: typeof inv.parameters.rows[number]) => `<code>${esc(r.name)}</code>`, nowrap: true },
        { head: "Occurrences", cell: (r: typeof inv.parameters.rows[number]) => num(r.count), numeric: true },
        { head: "Roles / locations", cell: (r: typeof inv.parameters.rows[number]) => list(r.roles) },
      ],
      inv.parameters.rows,
      "No parameters were observed.",
    ),
    `</details>`,
    `<details open><summary>JavaScript artifacts (${esc(inv.javascript.total)})</summary>`,
    sectionMeta(inv.javascript),
    tableOf(
      "JavaScript artifacts and source maps",
      [
        { head: "URL", cell: (r: typeof inv.javascript.rows[number]) => `<code>${esc(r.url)}</code>` },
        { head: "Status", cell: (r: typeof inv.javascript.rows[number]) => badge(r.status || "UNKNOWN", statusClass(r.status)) },
        { head: "Size", cell: (r: typeof inv.javascript.rows[number]) => num(r.sizeBytes), numeric: true },
        { head: "Content hash", cell: (r: typeof inv.javascript.rows[number]) => `<code>${esc(r.contentHash)}</code>` },
        { head: "Source map", cell: (r: typeof inv.javascript.rows[number]) => (r.sourceMapStatus ? badge(r.sourceMapStatus, statusClass(r.sourceMapStatus)) : "<span class=\"na\">—</span>") },
        { head: "Sources", cell: (r: typeof inv.javascript.rows[number]) => num(r.sourcesCount), numeric: true },
      ],
      inv.javascript.rows,
      "No JavaScript artifacts were retrieved.",
    ),
    `</details>`,
    `</section>`,
  ].join("");

  const findingsSection = [
    `<section id="findings" aria-labelledby="h-findings">`,
    `<h2 id="h-findings">Findings</h2>`,
    `<div class="cards">`,
    ...(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const).map(
      (sev) => `<div class="card"><div class="n ${severityClass(sev)}">${esc(t.bySeverity[sev] ?? 0)}</div><div class="l">${esc(sev.toLowerCase())}</div></div>`,
    ),
    `</div>`,
    `<p class="note">Severity is the impact <em>if</em> the candidate is real; confidence is the detector's confidence;
      validation states how far the evidence goes. The three are independent — a high-severity, high-confidence candidate
      is still unvalidated until a person confirms it.</p>`,
    report.findings.length === 0
      ? `<p class="empty">No findings were derived. ${
          report.reportStatus === "COMPLETE_NO_FINDINGS"
            ? "Every stage succeeded, so this is a clean result for the dimensions this build measures."
            : "This assessment is incomplete, so this is not evidence that none exist."
        }</p>`
      : report.findings.slice(0, MAX_TABLE_ROWS).map(findingCard).join(""),
    report.findings.length > MAX_TABLE_ROWS
      ? `<p class="note">Showing ${esc(MAX_TABLE_ROWS)} of ${esc(report.findings.length)} findings; use the JSON format for the complete set.</p>`
      : "",
    `<h3>Correlations (${esc(report.correlations.length)})</h3>`,
    tableOf(
      "Evidence correlations",
      [
        { head: "Relation", cell: (c: typeof report.correlations[number]) => esc(c.relation) },
        { head: "Status", cell: (c: typeof report.correlations[number]) => badge(c.status, statusClass(c.status)) },
        { head: "Subject", cell: (c: typeof report.correlations[number]) => `<code>${esc(c.subject)}</code>` },
        { head: "Related", cell: (c: typeof report.correlations[number]) => list(c.related) },
        { head: "Keyed", cell: (c: typeof report.correlations[number]) => (c.hmacKeyed ? badge("HMAC", "st-ok") : badge("NO", "st-idle")) },
        { head: "Group", cell: (c: typeof report.correlations[number]) => `<code>${esc(c.correlationGroup)}</code>` },
        { head: "Confidence", cell: (c: typeof report.correlations[number]) => confidence(c.confidence), numeric: true },
      ],
      report.correlations,
      "No correlations were recorded.",
    ),
    `</section>`,
  ].join("");

  const problemsSection = [
    `<section id="problems" aria-labelledby="h-problems">`,
    `<h2 id="h-problems">Tool errors and incomplete stages</h2>`,
    `<h3>Provider errors (${esc(report.providerErrors.length)})</h3>`,
    tableOf(
      "Providers that did not succeed",
      [
        { head: "Stage", cell: (e: typeof report.providerErrors[number]) => `<code>${esc(e.stage)}</code>`, nowrap: true },
        { head: "Provider", cell: (e: typeof report.providerErrors[number]) => esc(e.provider) },
        { head: "Outcome", cell: (e: typeof report.providerErrors[number]) => badge(e.outcome, statusClass(e.outcome)) },
        { head: "Records", cell: (e: typeof report.providerErrors[number]) => num(e.records), numeric: true },
        { head: "Timed out", cell: (e: typeof report.providerErrors[number]) => (e.timedOut ? badge("YES", "st-fail") : badge("NO", "st-idle")) },
        { head: "Reason", cell: (e: typeof report.providerErrors[number]) => esc(e.reason) },
      ],
      report.providerErrors,
      "Every provider that ran reported SUCCEEDED.",
    ),
    `<h3>Incomplete stages (${esc(report.incompleteStages.length)})</h3>`,
    tableOf(
      "Stages that did not reach SUCCEEDED, and what that means",
      [
        { head: "Stage", cell: (i: typeof report.incompleteStages[number]) => `<code>${esc(i.stage)}</code>`, nowrap: true },
        { head: "Job", cell: (i: typeof report.incompleteStages[number]) => badge(i.jobStatus, statusClass(i.jobStatus)) },
        { head: "Coverage", cell: (i: typeof report.incompleteStages[number]) => (i.coverageStatus === null ? "<span class=\"na\">—</span>" : badge(i.coverageStatus, statusClass(i.coverageStatus))) },
        { head: "Reason", cell: (i: typeof report.incompleteStages[number]) => esc(i.reason) },
        { head: "Impact on this report", cell: (i: typeof report.incompleteStages[number]) => esc(i.impact) },
      ],
      report.incompleteStages,
      "Every stage reached SUCCEEDED.",
    ),
    `</section>`,
  ].join("");

  const repro = report.reproducibility;
  const reproSection = [
    `<section id="reproducibility" aria-labelledby="h-repro">`,
    `<h2 id="h-repro">Reproducibility and evidence appendix</h2>`,
    `<dl class="meta">`,
    kv("Tool version", `<code>${esc(repro.toolVersion)}</code>`),
    kv("Report schema", `v${esc(repro.reportSchemaVersion)}`),
    kv("Config schema", `v${esc(repro.configSchemaVersion)}`),
    kv("Scope policy", `<code>${esc(repro.scopePolicyId)}</code> v${esc(repro.policyVersion)}`),
    kv("Derived from persisted state only", repro.derivedFromPersistedStateOnly ? badge("YES", "st-ok") : badge("NO", "st-fail")),
    kv("Generated at", timestamp(report.generatedAt)),
    `</dl>`,
    `<h3>Provider versions</h3>`,
    Object.keys(repro.providerVersions).length === 0
      ? `<p class="empty">No provider version was recorded.</p>`
      : `<p>${Object.entries(repro.providerVersions)
          .map(([k, v]) => `<code>${esc(k)}=${esc(v)}</code>`)
          .join(" ")}</p>`,
    `<h3>Regenerate</h3>`,
    `<p>${repro.commands.map((c) => `<code>${esc(c)}</code>`).join("<br>")}</p>`,
    `<h3>Evidence appendix (${esc(report.evidenceAppendix.length)})</h3>`,
    `<p class="note">Content-addressed references only. Artifact bodies are never embedded in a report.</p>`,
    tableOf(
      "Stored evidence artifacts",
      [
        { head: "SHA-256", cell: (e: typeof report.evidenceAppendix[number]) => `<code>${esc(e.sha256)}</code>`, nowrap: true },
        { head: "Storage URI", cell: (e: typeof report.evidenceAppendix[number]) => `<code>${esc(e.storageUri)}</code>` },
        { head: "Type", cell: (e: typeof report.evidenceAppendix[number]) => esc(e.contentType) },
        { head: "Size", cell: (e: typeof report.evidenceAppendix[number]) => num(e.sizeBytes), numeric: true },
        { head: "Redacted", cell: (e: typeof report.evidenceAppendix[number]) => (e.redacted ? badge("YES", "st-ok") : badge("NO", "st-idle")) },
        { head: "Created", cell: (e: typeof report.evidenceAppendix[number]) => timestamp(e.createdAt || null) },
      ],
      report.evidenceAppendix,
      "No evidence artifacts were stored for this scan.",
    ),
    `<h3>Counts</h3>`,
    tableOf(
      "Observations by kind",
      [
        { head: "Kind", cell: (r: [string, number]) => `<code>${esc(r[0])}</code>`, nowrap: true },
        { head: "Count", cell: (r: [string, number]) => num(r[1]), numeric: true },
      ],
      Object.entries(report.observationCounts.byKind),
      "No observations were recorded.",
    ),
    tableOf(
      "Project assets by type",
      [
        { head: "Type", cell: (r: [string, number]) => `<code>${esc(r[0])}</code>`, nowrap: true },
        { head: "Count", cell: (r: [string, number]) => num(r[1]), numeric: true },
      ],
      Object.entries(report.assetCounts),
      "No assets were recorded.",
    ),
    `</section>`,
  ].join("");

  const limitationsSection = [
    `<section id="limitations" aria-labelledby="h-lim">`,
    `<h2 id="h-lim">How to read this report</h2>`,
    `<div class="legend"><span class="lab">Outcome</span>${badge("SUCCEEDED", "st-ok")}${badge("PARTIAL", "st-partial")}${badge("FAILED", "st-fail")}${badge("SKIPPED", "st-idle")}${badge("CANCELLED", "st-cancel")}</div>`,
    `<div class="legend"><span class="lab">Severity</span>${badge("CRITICAL", "sev-critical")}${badge("HIGH", "sev-high")}${badge("MEDIUM", "sev-medium")}${badge("LOW", "sev-low")}${badge("INFO", "sev-info")}</div>`,
    `<p class="note">Severity is impact <em>if</em> the candidate is real; confidence is detector confidence; validation is how far the evidence goes. They are independent.</p>`,
    `<ul class="lim">${report.limitations.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>`,
    `</section>`,
  ].join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="referrer" content="no-referrer">
<meta name="generator" content="ReconNexus ${esc(repro.toolVersion)}">
<title>${esc(title)}</title>
<style>${STYLES}</style>
</head>
<body>
<a class="skip" href="#summary">Skip to the executive summary</a>
<div class="wrap">
<header class="top">
<div class="brand">ReconNexus <span class="ver">· assessment report</span></div>
<h1>${esc(report.rootDomain)}</h1>
<p class="sub">assessment <code>${esc(report.scanId)}</code> &nbsp; ${badge(report.reportStatus, statusClass(report.reportStatus))} ${badge(report.scanStatus, statusClass(report.scanStatus))} &nbsp; generated ${esc(report.generatedAt)}</p>
<p class="sub legal">Authorized assessment artifact. Handle according to the authorization under which it was produced; it may describe sensitive attack surface.</p>
</header>
<nav class="toc" aria-label="Report contents">
<ol>
<li><a href="#summary">Executive summary</a></li>
<li><a href="#assessment">Scope &amp; methodology</a></li>
<li><a href="#stages">Stage execution &amp; coverage</a></li>
<li><a href="#inventory">Asset &amp; service inventory</a></li>
<li><a href="#intelligence">URL / API / JS intelligence</a></li>
<li><a href="#findings">Findings <span class="tcount">${esc(t.total)}</span></a></li>
<li><a href="#problems">Errors &amp; incomplete stages <span class="tcount">${esc(report.providerErrors.length + report.incompleteStages.length)}</span></a></li>
<li><a href="#reproducibility">Reproducibility &amp; evidence</a></li>
<li><a href="#limitations">How to read this report</a></li>
</ol>
</nav>
<main>
${execSummary}
${assessmentSection}
${stagesSection}
${invSection}
${intelSection}
${findingsSection}
${problemsSection}
${reproSection}
${limitationsSection}
</main>
<footer>
<p>ReconNexus ${esc(repro.toolVersion)} · report schema v${esc(repro.reportSchemaVersion)} · ${esc(report.reportStatus)} / analysis ${esc(report.scanStatus)}</p>
<p>Generated from persisted assessment state. No network request was made while producing this report.</p>
</footer>
</div>
</body>
</html>
`;
}
