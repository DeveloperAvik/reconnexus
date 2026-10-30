import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

interface ParamDiscoveryData {
  host?: string;
  parameter?: string;
  confidence?: number;
  httpStatus?: number | null;
  baselineStatus?: number | null;
  baselineLength?: number;
  testLength?: number;
  evidence?: string;
  evidenceType?: string;
}

export interface ParamDiscoveryOptions {
  host?: string;
  parameter?: string;
  limit?: number;
}

/** Lists undocumented parameters found by the parameter-discovery stage. */
export async function paramsDiscoveredCommand(ctx: Context, scanId: string, opts: ParamDiscoveryOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);

    const filtered = (await repo.listParamDiscoveryFindings(scanId))
      .map((r) => ({ url: r.url, ...(r.data as ParamDiscoveryData) }))
      .filter((r) => {
        if (opts.host && !(r.host ?? "").includes(opts.host)) return false;
        if (opts.parameter && (r.parameter ?? "").toLowerCase() !== opts.parameter.toLowerCase()) return false;
        return true;
      });
    const limited = opts.limit ? filtered.slice(0, opts.limit) : filtered;

    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, total: filtered.length, items: limited },
      render: () =>
        [
          `Discovered parameters for scan ${scanId}: ${filtered.length} found`,
          "",
          ...limited.map((r) => `  ${(r.parameter ?? "").padEnd(16)} ${(r.evidenceType ?? "").padEnd(18)} HTTP ${r.httpStatus}  ${r.url}\n    ${r.evidence ?? ""}`),
          "",
          "Every row here is already a positive discovery (a parameter whose presence changed the",
          "response); a wordlist entry that showed no difference is never recorded, the same as a",
          "closed port is not recorded by the port scanner.",
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
