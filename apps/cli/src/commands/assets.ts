import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

export interface AssetsListOptions {
  type?: string;
  limit?: number;
}

const ALL_TYPES = ["DOMAIN", "SUBDOMAIN", "HOST", "IP", "CIDR", "ASN", "URL", "SERVICE", "JS_ARTIFACT", "API_ENDPOINT", "CERTIFICATE", "TECHNOLOGY"];

export async function assetsListCommand(ctx: Context, scanId: string, opts: AssetsListOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);
    const types = opts.type ? opts.type.split(",").map((t) => t.trim().toUpperCase()) : ALL_TYPES;
    const assets = await repo.listAssets(scan.project_id, types);
    const limited = opts.limit ? assets.slice(0, opts.limit) : assets;
    const byType = limited.reduce<Record<string, number>>((acc, a) => {
      acc[a.type] = (acc[a.type] ?? 0) + 1;
      return acc;
    }, {});
    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, projectId: scan.project_id, total: assets.length, counts: byType, assets: limited },
      render: () =>
        [
          `Assets for project ${scan.project_id} (scan ${scanId})`,
          `  total: ${assets.length}`,
          ...Object.entries(byType).map(([t, n]) => `    ${t.padEnd(14)} ${n}`),
          "",
          ...limited.map((a) => `  ${a.type.padEnd(14)} ${a.value}`),
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
