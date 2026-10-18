import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

interface LoginInterfaceData {
  kind?: string;
  status?: string;
  confidence?: number;
  httpStatus?: number | null;
  finalUrl?: string;
  title?: string;
  evidence?: string;
  evidenceType?: string;
  host?: string;
}

export interface FinderOptions {
  status?: string;
  host?: string;
  confidence?: number;
  limit?: number;
}

const LABELS: Record<"ADMIN" | "CPANEL", { title: string; noun: string }> = {
  ADMIN: { title: "Admin login interfaces", noun: "admin login" },
  CPANEL: { title: "cPanel/WHM/webmail interfaces", noun: "control-panel" },
};

async function finderCommand(
  ctx: Context,
  scanId: string,
  kind: "ADMIN" | "CPANEL",
  opts: FinderOptions,
): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);

    const all = (await repo.listLoginInterfaces(scanId))
      .map((r) => ({ url: r.url, ...(r.data as LoginInterfaceData) }))
      .filter((r) => (r.kind ?? "").toUpperCase() === kind);
    const filtered = all.filter((r) => {
      if (opts.status && (r.status ?? "").toUpperCase() !== opts.status.toUpperCase()) return false;
      if (opts.host && !(r.host ?? "").includes(opts.host)) return false;
      if (opts.confidence !== undefined && (r.confidence ?? 0) < opts.confidence) return false;
      return true;
    });
    const limited = opts.limit ? filtered.slice(0, opts.limit) : filtered;
    const detected = filtered.filter((r) => r.status === "DETECTED").length;
    const byStatus: Record<string, number> = {};
    for (const r of filtered) byStatus[r.status ?? "?"] = (byStatus[r.status ?? "?"] ?? 0) + 1;
    const label = LABELS[kind];

    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, kind, total: filtered.length, detected, byStatus, interfaces: limited },
      render: () =>
        [
          `${label.title} for scan ${scanId}: ${filtered.length} (${detected} detected)`,
          ...(filtered.length > 0 ? [`  by status: ${JSON.stringify(byStatus)}`] : []),
          "",
          ...limited.map((r) => {
            const http = r.httpStatus === null || r.httpStatus === undefined ? "-" : String(r.httpStatus);
            const title = r.title ? `  "${r.title}"` : "";
            return `  ${(r.status ?? "").padEnd(9)} conf=${(r.confidence ?? 0).toFixed(2)} ${http.padEnd(4)} ${r.url}${title}  ${r.evidence ?? ""}`;
          }),
          "",
          `Only unauthenticated GET requests were made; no ${label.noun} credentials were submitted.`,
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}

/** Lists administrative login interfaces discovered by the login-finder stage. */
export async function adminCommand(ctx: Context, scanId: string, opts: FinderOptions): Promise<CommandResult<unknown>> {
  return finderCommand(ctx, scanId, "ADMIN", opts);
}

/** Lists cPanel/WHM/webmail interfaces discovered by the login-finder stage. */
export async function cpanelCommand(ctx: Context, scanId: string, opts: FinderOptions): Promise<CommandResult<unknown>> {
  return finderCommand(ctx, scanId, "CPANEL", opts);
}
