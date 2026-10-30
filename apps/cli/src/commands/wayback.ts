import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

interface WaybackDiffData {
  host?: string;
  firstSeen?: string;
  lastStatus?: number;
  mimeType?: string;
  confidence?: number;
  evidence?: string;
}

export interface WaybackDiffOptions {
  host?: string;
  limit?: number;
}

/** Lists archived-but-unobserved paths found by the wayback-diff stage. */
export async function waybackCommand(ctx: Context, scanId: string, opts: WaybackDiffOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);

    const filtered = (await repo.listWaybackDiffFindings(scanId))
      .map((r) => ({ url: r.url, ...(r.data as WaybackDiffData) }))
      .filter((r) => !opts.host || (r.host ?? "").includes(opts.host));
    const limited = opts.limit ? filtered.slice(0, opts.limit) : filtered;

    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, total: filtered.length, items: limited },
      render: () =>
        [
          `Wayback-archived, unobserved paths for scan ${scanId}: ${filtered.length} found`,
          "",
          ...limited.map((r) => `  first seen ${r.firstSeen}  ${r.mimeType}  ${r.url}\n    ${r.evidence ?? ""}`),
          "",
          "This is never a live check: none of these paths were requested again here, only",
          "compared against what this scan already crawled. Confirm manually whether they are",
          "still reachable before treating any of them as current.",
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
