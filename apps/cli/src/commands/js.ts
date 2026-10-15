import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

interface JsData {
  contentHash?: string;
  contentType?: string;
  sizeBytes?: number;
  status?: string;
  sourceUrl?: string;
  provider?: string;
}

interface SmData {
  sourceMapUrl?: string;
  status?: string;
  sourcesCount?: number;
}

interface EndpointData {
  method?: string;
  origin?: string;
  path?: string;
  url?: string;
  discoveredVia?: string;
  documented?: boolean;
  resolved?: boolean;
  operationId?: string;
  tags?: string[];
  parameters?: Array<{ name: string; location: string }>;
  authSchemes?: string[];
}

export async function jsCommand(ctx: Context, scanId: string, opts: { status?: string; limit?: number }): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);
    const artifacts = (await repo.listJsArtifacts(scanId)).map((r) => ({ url: r.url, ...(r.data as JsData) }));
    const sourceMaps = (await repo.listSourceMaps(scanId)).map((r) => ({ jsUrl: r.url, ...(r.data as SmData) }));
    const filtered = opts.status ? artifacts.filter((a) => a.status === opts.status) : artifacts;
    const limited = opts.limit ? filtered.slice(0, opts.limit) : filtered;
    const parsedMaps = sourceMaps.filter((s) => s.status === "PARSED").length;
    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, total: filtered.length, artifacts: limited, sourceMaps },
      render: () =>
        [
          `JavaScript artifacts for scan ${scanId}: ${filtered.length} (source maps parsed: ${parsedMaps}/${sourceMaps.length})`,
          "",
          ...limited.map((a) => {
            const hash = (a.contentHash ?? "").slice(0, 12);
            const size = a.sizeBytes ?? 0;
            return `  ${(a.status ?? "").padEnd(16)} ${String(size).padStart(8)}B  ${hash}  ${a.url}`;
          }),
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}

export interface ApisListOptions {
  host?: string;
  method?: string;
  via?: string;
  documented?: boolean;
  unresolved?: boolean;
  limit?: number;
}

export async function apisCommand(ctx: Context, scanId: string, opts: ApisListOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);
    const endpoints = (await repo.listApiEndpoints(scanId)).map((r) => ({ key: r.key, ...(r.data as EndpointData) }));
    const filtered = endpoints.filter((e) => {
      if (opts.host && !(e.origin ?? "").includes(opts.host)) return false;
      if (opts.method && (e.method ?? "").toUpperCase() !== opts.method.toUpperCase()) return false;
      if (opts.via && e.discoveredVia !== opts.via.toUpperCase()) return false;
      if (opts.documented === true && !e.documented) return false;
      if (opts.unresolved === true && e.resolved !== false) return false;
      return true;
    });
    const limited = opts.limit ? filtered.slice(0, opts.limit) : filtered;
    const byVia: Record<string, number> = {};
    for (const e of filtered) byVia[e.discoveredVia ?? "?"] = (byVia[e.discoveredVia ?? "?"] ?? 0) + 1;
    // Distinct endpoints are the headline; the raw observation count explains a higher report card
    // number (the same endpoint found by several sources is one endpoint but several observations).
    const rawObservations = await repo.countApiEndpointObservations(scanId);
    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, total: filtered.length, rawObservations, byVia, endpoints: limited },
      render: () =>
        [
          `API endpoints for scan ${scanId}: ${filtered.length} distinct (from ${rawObservations} observation(s))  (by source: ${JSON.stringify(byVia)})`,
          "",
          ...limited.map((e) => {
            const doc = e.documented ? "doc" : e.resolved === false ? "dyn" : "obs";
            const params = (e.parameters ?? []).map((p) => p.name).join(",");
            return `  ${(e.method ?? "").padEnd(8)} ${doc.padEnd(4)} ${e.origin ?? ""}${e.path ?? ""}${params ? "  {" + params + "}" : ""}`;
          }),
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}

export async function specsCommand(ctx: Context, scanId: string): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);
    const specs = await repo.listApiSpecs(scanId);
    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, total: specs.length, specs },
      render: () =>
        [
          `API specifications for scan ${scanId}: ${specs.length}`,
          "",
          ...specs.map((s) => {
            const d = s.data as { specVersion?: string; parseStatus?: string; title?: string; pathCount?: number; operationCount?: number };
            return `  ${(d.parseStatus ?? "").padEnd(10)} ${(d.specVersion ?? "").padEnd(14)} paths=${d.pathCount ?? 0} ops=${d.operationCount ?? 0}  ${s.url}  ${d.title ?? ""}`;
          }),
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
