import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

interface PortData {
  host?: string;
  ip?: string;
  port?: number;
  protocol?: string;
  state?: string;
  service?: string;
  product?: string;
  version?: string;
  extraInfo?: string;
  tls?: boolean;
  confidence?: number;
}

export interface PortsOptions {
  host?: string;
  port?: number;
  service?: string;
  limit?: number;
}

/** Lists open TCP ports and identified services found by the port-scan stage. */
export async function portsCommand(ctx: Context, scanId: string, opts: PortsOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);

    const filtered = (await repo.listPortObservations(scanId))
      .map((r) => r.data as PortData)
      .filter((r) => {
        if (opts.host && !(r.host ?? "").includes(opts.host)) return false;
        if (opts.port !== undefined && r.port !== opts.port) return false;
        if (opts.service && !(r.service ?? "").toLowerCase().includes(opts.service.toLowerCase())) return false;
        return true;
      });
    const limited = opts.limit ? filtered.slice(0, opts.limit) : filtered;
    const byService: Record<string, number> = {};
    for (const r of filtered) byService[r.service || "unidentified"] = (byService[r.service || "unidentified"] ?? 0) + 1;
    const addresses = new Set(filtered.map((r) => r.ip)).size;

    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, total: filtered.length, addresses, byService, ports: limited },
      render: () =>
        [
          `Open ports for scan ${scanId}: ${filtered.length} across ${addresses} address(es)`,
          ...(filtered.length > 0 ? [`  by service: ${JSON.stringify(byService)}`] : []),
          "",
          ...limited.map((r) => {
            const detail = [r.product, r.version, r.extraInfo].filter(Boolean).join(" ");
            const svc = `${r.service || "?"}${r.tls ? "/tls" : ""}`;
            return `  ${String(r.ip ?? "").padEnd(40)} ${`${r.port}/${r.protocol}`.padEnd(10)} ${(r.state ?? "").padEnd(13)} ${svc.padEnd(12)} ${detail}  (${r.host})`;
          }),
          "",
          "Product/version are service-detection claims, not verified. Closed and unscanned ports are not recorded.",
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
