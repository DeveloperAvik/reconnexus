import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { color, result, statusColor, type CommandResult } from "../output.js";

interface TakeoverData {
  host?: string;
  cname?: string;
  service?: string;
  status?: string;
  confidence?: number;
  httpStatus?: number | null;
  evidence?: string;
  evidenceType?: string;
}

export interface TakeoverOptions {
  status?: string;
  service?: string;
  host?: string;
  limit?: number;
}

/**
 * Lists subdomain-takeover candidates for a scan. Candidates only — a CNAME to a takeover-prone
 * service with an unclaimed response is NOT proof the subdomain is takeoverable.
 */
export async function takeoverCommand(ctx: Context, scanId: string, opts: TakeoverOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);
    const all = (await repo.listTakeoverCandidates(scanId)).map((r) => ({ host: r.host, ...(r.data as TakeoverData) }));
    const filtered = all.filter((t) => {
      if (opts.status && (t.status ?? "").toUpperCase() !== opts.status.toUpperCase()) return false;
      if (opts.service && !(t.service ?? "").toLowerCase().includes(opts.service.toLowerCase())) return false;
      if (opts.host && !(t.host ?? "").includes(opts.host)) return false;
      return true;
    });
    const limited = opts.limit ? filtered.slice(0, opts.limit) : filtered;
    const byStatus: Record<string, number> = {};
    for (const t of filtered) byStatus[t.status ?? "?"] = (byStatus[t.status ?? "?"] ?? 0) + 1;
    const actionable = filtered.filter((t) => t.status === "SUSPECTED" || t.status === "CANDIDATE").length;
    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, total: filtered.length, actionable, byStatus, candidates: limited },
      render: () =>
        [
          `Subdomain-takeover candidates for scan ${scanId}: ${filtered.length} (${actionable} actionable)`,
          `  by status: ${JSON.stringify(byStatus)}`,
          "",
          ...limited.map((t) => {
            const http = t.httpStatus === null || t.httpStatus === undefined ? "-" : String(t.httpStatus);
            return `  ${statusColor(t.status ?? "").padEnd(20)} ${(t.host ?? "").padEnd(34)} ${http.padEnd(4)} ${t.service ?? ""}  cname=${t.cname ?? ""}`;
          }),
          "",
          color.dim("Candidates are not confirmed takeovers; no claim/registration was attempted."),
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
