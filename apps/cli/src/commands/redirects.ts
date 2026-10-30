import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

interface RedirectData {
  host?: string;
  testedUrl?: string;
  parameter?: string;
  status?: string;
  confidence?: number;
  httpStatus?: number | null;
  location?: string;
  evidence?: string;
}

export interface RedirectsOptions {
  host?: string;
  status?: string;
  limit?: number;
}

/** Lists open-redirect probes found by the cors-redirect stage. */
export async function redirectsCommand(ctx: Context, scanId: string, opts: RedirectsOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);

    const filtered = (await repo.listOpenRedirectFindings(scanId))
      .map((r) => ({ url: r.url, ...(r.data as RedirectData) }))
      .filter((r) => {
        if (opts.host && !(r.host ?? "").includes(opts.host)) return false;
        if (opts.status && (r.status ?? "").toLowerCase() !== opts.status.toLowerCase()) return false;
        return true;
      });
    const limited = opts.limit ? filtered.slice(0, opts.limit) : filtered;
    const byStatus: Record<string, number> = {};
    for (const r of filtered) byStatus[r.status ?? "?"] = (byStatus[r.status ?? "?"] ?? 0) + 1;

    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, total: filtered.length, byStatus, items: limited },
      render: () =>
        [
          `Open-redirect probes for scan ${scanId}: ${filtered.length} candidate(s) checked`,
          ...(filtered.length > 0 ? [`  by status: ${JSON.stringify(byStatus)}`] : []),
          "",
          ...limited.map((r) => `  ${(r.status ?? "").padEnd(14)} param=${(r.parameter ?? "").padEnd(16)} HTTP ${r.httpStatus}  ${r.url}\n    ${r.evidence ?? ""}`),
          "",
          "CONFIRMED means the response redirected to the externally-controlled value the probe injected",
          "into that parameter. NOT_VULNERABLE probes are omitted from findings but still counted here as",
          "coverage.",
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
