import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

interface CorsData {
  host?: string;
  status?: string;
  confidence?: number;
  allowOrigin?: string;
  allowCredentials?: boolean;
  testedOrigin?: string;
  httpStatus?: number | null;
  evidence?: string;
}

export interface CorsOptions {
  host?: string;
  status?: string;
  limit?: number;
}

/** Lists CORS reflection probes found by the cors-redirect stage. */
export async function corsCommand(ctx: Context, scanId: string, opts: CorsOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);

    const filtered = (await repo.listCorsFindings(scanId))
      .map((r) => ({ url: r.url, ...(r.data as CorsData) }))
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
          `CORS probes for scan ${scanId}: ${filtered.length} origin(s) checked`,
          ...(filtered.length > 0 ? [`  by status: ${JSON.stringify(byStatus)}`] : []),
          "",
          ...limited.map(
            (r) => `  ${(r.status ?? "").padEnd(42)} HTTP ${r.httpStatus}  credentials=${r.allowCredentials ?? false}  ${r.url}\n    ${r.evidence ?? ""}`,
          ),
          "",
          "A REFLECTS_* status means the probe sent an arbitrary Origin and the response echoed it back.",
          "_WITH_CREDENTIALS means Access-Control-Allow-Credentials: true was also present, letting any",
          "origin read authenticated responses. NOT_VULNERABLE probes are omitted from findings but",
          "still counted here as coverage.",
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
