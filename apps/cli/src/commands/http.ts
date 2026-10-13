import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

export async function httpCommand(ctx: Context, scanId: string): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);
    const probes = await repo.listHttpObservations(scanId);
    const ok = probes.filter((p) => p.probe_status === "OK").length;
    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, total: probes.length, ok, probes },
      render: () =>
        [
          `HTTP probes for scan ${scanId}: ${probes.length} (${ok} OK)`,
          "",
          ...probes.map((p) => {
            const code = p.status_code === null ? "-" : String(p.status_code);
            const title = p.title ? `  "${p.title}"` : "";
            const server = p.server ? ` [${p.server}]` : "";
            return `  ${code.padEnd(4)} ${p.probe_status.padEnd(16)} ${p.final_url || p.url}${server}${title}`;
          }),
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}

export async function technologiesCommand(ctx: Context, scanId: string): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);
    const techs = await repo.listTechnologyObservations(scanId);
    const byName = new Map<string, number>();
    for (const t of techs) byName.set(t.name, (byName.get(t.name) ?? 0) + 1);
    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, total: techs.length, distinct: byName.size, technologies: techs },
      render: () =>
        [
          `Technology observations for scan ${scanId}: ${techs.length} across ${byName.size} technologies`,
          "",
          ...techs.map((t) => `  ${t.name.padEnd(24)} ${t.category.padEnd(18)} conf=${Number(t.confidence).toFixed(2)} ${t.host}  (${t.evidence_type}: ${t.evidence})`),
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
