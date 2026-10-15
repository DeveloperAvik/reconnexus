import { ExitCode } from "@reconnexus/contracts";
import {
  categoryNames,
  compareScans,
  ComparisonError,
  esc,
  type ChangeItem,
  type ScanComparison,
} from "@reconnexus/control-plane";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { color, result, type CommandResult } from "../output.js";

export interface ChangesOptions {
  category?: string;
  status?: string;
  limit?: number;
  format?: string;
}

const OUTCOMES = ["ADDED", "REMOVED", "CHANGED", "UNCHANGED", "UNKNOWN"] as const;
type Outcome = (typeof OUTCOMES)[number];

const OUTCOME_MARK: Record<Outcome, string> = {
  ADDED: color.green("+"),
  REMOVED: color.red("-"),
  CHANGED: color.yellow("~"),
  UNCHANGED: color.dim("="),
  UNKNOWN: color.dim("?"),
};

function oneLine(item: ChangeItem): string {
  const where = `${item.assetType} ${item.assetValue}`;
  if (item.outcome === "CHANGED" && item.changedFields && item.baseline && item.current) {
    const diffs = item.changedFields.map((f) => `${f} ${JSON.stringify(item.baseline!.fields[f])}→${JSON.stringify(item.current!.fields[f])}`).join(", ");
    return `${where}  ${diffs}`;
  }
  if (item.outcome === "UNKNOWN") return `${where}  ${color.dim(item.reason ?? "")}`;
  if (item.outcome === "REMOVED" && item.baseline) return `${where}  ${color.dim(`(${item.stage})`)}`;
  if (item.outcome === "ADDED" && item.current) return `${where}  ${color.dim(`(${item.stage})`)}`;
  return where;
}

export function renderChangesHuman(cmp: ScanComparison): string {
  const lines: string[] = [];
  lines.push(`Change intelligence — ${cmp.rootDomain}  (baseline ${color.dim(cmp.baselineScanId)} → current ${color.dim(cmp.currentScanId)})`);
  lines.push("");
  for (const cat of cmp.categories) {
    const t = cat.totals;
    lines.push(
      `  ${cat.category.padEnd(12)} ${color.green(`+${t.ADDED}`)} ${color.red(`-${t.REMOVED}`)} ${color.yellow(`~${t.CHANGED}`)} ${color.dim(`?${t.UNKNOWN}`)} ${color.dim(`=${t.UNCHANGED}`)}${
        cat.truncated ? color.dim(` (showing ${cat.changes.length} of ${cat.total})`) : ""
      }`,
    );
    for (const item of cat.changes) {
      if (item.outcome === "UNCHANGED") continue;
      lines.push(`    ${OUTCOME_MARK[item.outcome as Outcome]} ${oneLine(item)}`);
    }
  }
  lines.push("");
  lines.push(color.dim("  observation-set comparison; a skipped/failed/partial stage is a coverage gap, not absence"));
  if (cmp.limitations.length) {
    lines.push("  limitations:");
    for (const l of cmp.limitations) lines.push(color.dim(`    - ${l.detail}`));
  }
  return lines.join("\n");
}

export function renderChangesHtml(cmp: ScanComparison): string {
  const rows: string[] = [];
  for (const cat of cmp.categories) {
    const t = cat.totals;
    rows.push(`<h2 id="cat-${esc(cat.category)}">${esc(cat.category)}</h2>`);
    rows.push(`<p class="counts">+${esc(t.ADDED)} · −${esc(t.REMOVED)} · ~${esc(t.CHANGED)} · ?${esc(t.UNKNOWN)} · =${esc(t.UNCHANGED)} <span class="desc">${esc(cat.description)}</span></p>`);
    rows.push("<table><thead><tr><th>Change</th><th>Asset</th><th>Stage</th><th>Detail</th></tr></thead><tbody>");
    for (const item of cat.changes) {
      const detail = item.outcome === "CHANGED" && item.changedFields ? item.changedFields.join(", ") : (item.reason ?? "");
      rows.push(`<tr><td class="o">${esc(item.outcome)}</td><td>${esc(item.assetType)} ${esc(item.assetValue)}</td><td>${esc(item.stage)}</td><td>${esc(detail)}</td></tr>`);
    }
    rows.push("</tbody></table>");
  }
  const lim = cmp.limitations.map((l) => `<li>${esc(l.detail)}</li>`).join("");
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ReconNexus change report — ${esc(cmp.rootDomain)}</title>
<style>
:root{color-scheme:light dark}body{font:15px/1.5 system-ui,sans-serif;margin:0 auto;max-width:60rem;padding:2rem}
h1{font-size:1.5rem}h2{font-size:1.1rem;margin-top:2rem;border-bottom:1px solid #8884;padding-bottom:.25rem}
.counts{font-variant-numeric:tabular-nums}.desc,.o{color:#777}
table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{text-align:left;padding:.3rem .5rem;border-bottom:1px solid #8882;vertical-align:top}
li{color:#555}
</style></head><body>
<h1>ReconNexus change report — ${esc(cmp.rootDomain)}</h1>
<p class="desc">baseline ${esc(cmp.baselineScanId)} → current ${esc(cmp.currentScanId)} · generated ${esc(cmp.generatedAt)}</p>
${rows.join("\n")}
<h2>Limitations</h2><ul>${lim}</ul>
</body></html>`;
}

export async function changesCommand(
  ctx: Context,
  baselineScanId: string,
  currentScanId: string,
  opts: ChangesOptions,
): Promise<CommandResult<unknown>> {
  const format = opts.format ?? "human";
  if (!["human", "json", "html"].includes(format)) {
    throw new CliError(`unsupported format: ${format} (expected human, json or html)`, ExitCode.USAGE_ERROR);
  }
  const known = categoryNames();
  const categories = opts.category ? opts.category.split(",").map((c) => c.trim()).filter(Boolean) : undefined;
  if (categories) {
    const bad = categories.filter((c) => !known.includes(c));
    if (bad.length) throw new CliError(`unknown comparison category: ${bad.join(", ")} (expected ${known.join(", ")})`, ExitCode.USAGE_ERROR);
  }
  const statuses = opts.status ? opts.status.split(",").map((s) => s.trim().toUpperCase()) : undefined;
  if (statuses) {
    const bad = statuses.filter((s) => !(OUTCOMES as readonly string[]).includes(s));
    if (bad.length) throw new CliError(`unknown comparison status: ${bad.join(", ")} (expected ${OUTCOMES.join(", ")})`, ExitCode.USAGE_ERROR);
  }
  if (opts.limit !== undefined && (!Number.isFinite(opts.limit) || opts.limit < 1)) {
    throw new CliError("--limit must be a positive integer", ExitCode.USAGE_ERROR);
  }

  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    let cmp: ScanComparison;
    try {
      cmp = await compareScans(repo, baselineScanId, currentScanId, {
        ...(categories ? { categories } : {}),
        ...(statuses ? { statuses: statuses as Outcome[] } : {}),
        ...(opts.limit ? { limit: opts.limit } : {}),
      });
    } catch (err) {
      if (err instanceof ComparisonError) throw new CliError(err.message, ExitCode.USAGE_ERROR);
      throw err;
    }

    const rendered = format === "json" ? JSON.stringify(cmp, null, 2) : format === "html" ? renderChangesHtml(cmp) : renderChangesHuman(cmp);
    return result({
      exitCode: ExitCode.SUCCESS,
      data: cmp,
      warnings: cmp.limitations.some((l) => l.code === "COVERAGE_GAP") ? ["some stages were not fully collected; affected changes are reported UNKNOWN"] : [],
      render: () => rendered,
    });
  } finally {
    await db.close();
  }
}

