import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

interface MetaData {
  category?: string;
  name?: string;
  status?: string;
  observed?: boolean;
  value?: string;
  detail?: Record<string, unknown>;
  consistent?: boolean | null;
  evidence?: string;
  evidenceType?: string;
  host?: string;
  provider?: string;
}

export interface SecurityOptions {
  category?: string;
  status?: string;
  host?: string;
  limit?: number;
}

export async function securityCommand(ctx: Context, scanId: string, opts: SecurityOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);
    const all = (await repo.listSecurityMetadata(scanId)).map((r) => ({ service: r.service, ...(r.data as MetaData) }));
    const filtered = all.filter((m) => {
      if (opts.category && (m.category ?? "").toUpperCase() !== opts.category.toUpperCase()) return false;
      if (opts.status && (m.status ?? "").toUpperCase() !== opts.status.toUpperCase()) return false;
      if (opts.host && !(m.service ?? "").includes(opts.host)) return false;
      return true;
    });
    const limited = opts.limit ? filtered.slice(0, opts.limit) : filtered;
    const byStatus: Record<string, number> = {};
    for (const m of filtered) byStatus[m.status ?? "?"] = (byStatus[m.status ?? "?"] ?? 0) + 1;
    const byCategory: Record<string, number> = {};
    for (const m of filtered) byCategory[m.category ?? "?"] = (byCategory[m.category ?? "?"] ?? 0) + 1;
    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, total: filtered.length, byStatus, byCategory, metadata: limited },
      render: () =>
        [
          `Security metadata for scan ${scanId}: ${filtered.length}`,
          `  by status:   ${JSON.stringify(byStatus)}`,
          `  by category: ${JSON.stringify(byCategory)}`,
          "",
          ...limited.map((m) => {
            const val = m.value ? ` = ${m.value}` : "";
            const flag = m.consistent === false ? " [INCONSISTENT]" : "";
            return `  ${(m.category ?? "").padEnd(12)} ${(m.status ?? "").padEnd(16)} ${m.service ?? ""}  ${m.name ?? ""}${val}${flag}`;
          }),
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
