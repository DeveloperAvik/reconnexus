import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { color, result, type CommandResult } from "../output.js";

export interface AssetsListOptions {
  type?: string;
  limit?: number;
}

export interface AssetsDiffOptions {
  type?: string;
  limit?: number;
}

type AssetRow = { id: string; type: string; canonical_key: string; value: string };

/** Identity of an asset for comparison: its type plus its canonical key (not the display value). */
function assetKey(a: AssetRow): string {
  return `${a.type}\u0000${a.canonical_key}`;
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

/**
 * Read-only comparison of the assets observed in two scans of the same project. An asset is
 * "added" when the current scan observed it and the baseline did not, and "removed" the reverse.
 * This is an observation-set comparison, not a claim that an asset appeared or disappeared on the
 * target: a stage that was skipped in one scan is not evidence of absence (the report says so too).
 */
export async function assetsDiffCommand(
  ctx: Context,
  baselineId: string,
  currentId: string,
  opts: AssetsDiffOptions,
): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const [baseline, current] = await Promise.all([repo.getScan(baselineId), repo.getScan(currentId)]);
    if (!baseline) throw new CliError(`baseline scan not found: ${baselineId}`, ExitCode.USAGE_ERROR);
    if (!current) throw new CliError(`current scan not found: ${currentId}`, ExitCode.USAGE_ERROR);
    if (baseline.project_id !== current.project_id) {
      throw new CliError("scans belong to different projects; a comparison would be meaningless", ExitCode.USAGE_ERROR);
    }
    const types = opts.type ? opts.type.split(",").map((t) => t.trim().toUpperCase()) : ALL_TYPES;
    const [baseAssets, currAssets] = await Promise.all([
      repo.listScanAssets(baselineId, types),
      repo.listScanAssets(currentId, types),
    ]);

    const baseKeys = new Set(baseAssets.map(assetKey));
    const currKeys = new Set(currAssets.map(assetKey));
    const added = currAssets.filter((a) => !baseKeys.has(assetKey(a)));
    const removed = baseAssets.filter((a) => !currKeys.has(assetKey(a)));
    const unchanged = currAssets.filter((a) => baseKeys.has(assetKey(a)));

    const limit = opts.limit;
    const shownAdded = limit ? added.slice(0, limit) : added;
    const shownRemoved = limit ? removed.slice(0, limit) : removed;
    const truncNote = limit && (added.length > shownAdded.length || removed.length > shownRemoved.length) ? ` (showing up to ${limit} per side)` : "";

    return result({
      exitCode: ExitCode.SUCCESS,
      data: {
        baselineScanId: baselineId,
        currentScanId: currentId,
        projectId: current.project_id,
        types,
        counts: { added: added.length, removed: removed.length, unchanged: unchanged.length },
        added: shownAdded,
        removed: shownRemoved,
      },
      render: () =>
        [
          `Asset changes: ${color.dim(baselineId)} -> ${color.dim(currentId)}  (${current.root_domain})`,
          `  types: ${types.join(", ")}`,
          `  ${color.green("+")} added ${added.length}   ${color.red("-")} removed ${removed.length}   unchanged ${unchanged.length}${color.dim(truncNote)}`,
          "",
          ...shownAdded.map((a) => `  ${color.green("+")} ${a.type.padEnd(14)} ${a.value}`),
          ...shownRemoved.map((a) => `  ${color.red("-")} ${a.type.padEnd(14)} ${a.value}`),
          "",
          color.dim("  observation-set comparison; a skipped stage in either scan is not evidence of absence"),
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
