import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

interface ContentData {
  host?: string;
  path?: string;
  category?: string;
  status?: string;
  severity?: string;
  confidence?: number;
  httpStatus?: number;
  contentLength?: number;
  evidence?: string;
}

export interface ContentOptions {
  host?: string;
  category?: string;
  status?: string;
  limit?: number;
}

/** Lists paths found by the content-discovery stage (exposed files, backups, debug endpoints, listings). */
export async function contentCommand(ctx: Context, scanId: string, opts: ContentOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);

    const filtered = (await repo.listContentDiscoveries(scanId))
      .map((r) => ({ url: r.url, ...(r.data as ContentData) }))
      .filter((r) => {
        if (opts.host && !(r.host ?? "").includes(opts.host)) return false;
        if (opts.category && (r.category ?? "").toLowerCase() !== opts.category.toLowerCase()) return false;
        if (opts.status && (r.status ?? "").toLowerCase() !== opts.status.toLowerCase()) return false;
        return true;
      });
    const limited = opts.limit ? filtered.slice(0, opts.limit) : filtered;
    const byCategory: Record<string, number> = {};
    for (const r of filtered) byCategory[r.category ?? "?"] = (byCategory[r.category ?? "?"] ?? 0) + 1;

    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, total: filtered.length, byCategory, items: limited },
      render: () =>
        [
          `Content discovery for scan ${scanId}: ${filtered.length} path(s)`,
          ...(filtered.length > 0 ? [`  by category: ${JSON.stringify(byCategory)}`] : []),
          "",
          ...limited.map((r) => `  ${(r.status ?? "").padEnd(10)} ${(r.severity ?? "").padEnd(7)} ${(r.category ?? "").padEnd(18)} HTTP ${r.httpStatus}  ${r.url}\n             ${r.evidence ?? ""}`),
          "",
          "CONFIRMED means a content marker was present; POSSIBLE means the path only answered differently from a missing path. Response bodies are not stored. The path list is short and fixed: no hit is not proof of absence.",
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
