import { ExitCode } from "@reconnexus/contracts";
import { createDb, loadScanRisk, RISK_LEVELS, Repository, type HostRisk } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

export interface RiskOptions {
  top?: number;
  minScore?: number;
  level?: string;
  /** Show the contributing factors for each host. */
  explain?: boolean;
}

/** Ranks the hosts of a scan by how much attention they deserve, with the reasons for each score. */
export async function riskCommand(ctx: Context, scanId: string, opts: RiskOptions): Promise<CommandResult<unknown>> {
  if (opts.level && !(RISK_LEVELS as readonly string[]).includes(opts.level.toUpperCase())) {
    throw new CliError(`unknown level '${opts.level}' (expected one of: ${RISK_LEVELS.join(", ")})`, ExitCode.USAGE_ERROR);
  }
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);

    const all = await loadScanRisk(repo, scanId);
    const filtered = all.filter((h) => (opts.minScore === undefined || h.score >= opts.minScore) && (!opts.level || h.level === opts.level.toUpperCase()));
    const shown = opts.top ? filtered.slice(0, opts.top) : filtered;
    const byLevel: Record<string, number> = {};
    for (const h of filtered) byLevel[h.level] = (byLevel[h.level] ?? 0) + 1;

    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, total: filtered.length, byLevel, hosts: shown },
      render: () =>
        [
          `Risk ranking for scan ${scanId}: ${filtered.length} host(s)`,
          ...(filtered.length > 0 ? [`  by level: ${JSON.stringify(byLevel)}`] : []),
          "",
          ...shown.flatMap((h: HostRisk) => [
            `  ${h.score.toFixed(1).padStart(5)}  ${h.level.padEnd(8)} ${h.host}  (${h.findingCount} finding(s), ${h.openPorts.length} open port(s))`,
            ...(opts.explain ? h.factors.map((f) => `           +${f.points.toFixed(1).padStart(4)}  ${f.label}`) : []),
          ]),
          "",
          "A prioritization aid built from candidates and observations; nothing is exploited or validated. Use --explain to see the factors.",
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
