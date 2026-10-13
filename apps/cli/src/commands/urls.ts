import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

interface UrlData {
  originalUrl?: string;
  method?: string;
  depth?: number;
  statusCode?: number | null;
  classifications?: Array<{ category: string; confidence: number; evidenceType: string; evidence: string }>;
  parameters?: Array<{ name: string; roles: Array<{ role: string; confidence: number; evidence: string }> }>;
  provider?: string;
  host?: string;
}

export interface UrlsListOptions {
  host?: string;
  provider?: string;
  category?: string;
  param?: string;
  method?: string;
  status?: string;
  limit?: number;
  stats?: boolean;
}

export async function urlsListCommand(ctx: Context, scanId: string, opts: UrlsListOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);
    const rows = await repo.listUrlObservations(scanId);
    const outcomes = await repo.listProviderOutcomes(scanId);

    const items = rows.map((r) => ({ url: r.url, ...(r.data as UrlData) }));

    const filtered = items.filter((it) => {
      if (opts.host && !(it.host ?? "").includes(opts.host)) return false;
      if (opts.provider && it.provider !== opts.provider) return false;
      if (opts.method && it.method !== opts.method) return false;
      if (opts.status) {
        const want = Number(opts.status);
        if (it.statusCode !== want) return false;
      }
      if (opts.category && !(it.classifications ?? []).some((c) => c.category === opts.category)) return false;
      if (opts.param && !(it.parameters ?? []).some((p) => p.name === opts.param)) return false;
      return true;
    });
    const limited = opts.limit ? filtered.slice(0, opts.limit) : filtered;

    if (opts.stats) {
      const skippedByProviders = await repo.sumProviderSkipped(scanId);
      const stats = computeStats(items, outcomes, skippedByProviders);
      return result({
        exitCode: ExitCode.SUCCESS,
        data: { scanId, stats },
        render: () =>
          [
            `URL collection statistics for scan ${scanId}`,
            `  providers:      ${stats.providers.map((p) => `${p.provider}=${p.records}(${p.outcome})`).join(", ") || "(none)"}`,
            `  raw observations: ${stats.rawObservations}`,
            `  unique canonical URLs: ${stats.uniqueCanonical}`,
            `  duplicate rate: ${(stats.duplicateRate * 100).toFixed(1)}%`,
            `  skipped by providers (out-of-scope/malformed candidates): ${stats.skippedByProviders}`,
            `  by method: ${JSON.stringify(stats.byMethod)}`,
            `  by host: ${JSON.stringify(stats.byHost)}`,
            `  classification distribution: ${JSON.stringify(stats.classifications)}`,
            `  parameter inventory: ${JSON.stringify(stats.parameters)}`,
          ].join("\n"),
      });
    }

    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, total: filtered.length, urls: limited },
      render: () =>
        [
          `URLs for scan ${scanId}: ${filtered.length}${opts.limit && filtered.length > limited.length ? ` (showing ${limited.length})` : ""}`,
          "",
          ...limited.map((it) => {
            const code = it.statusCode === null || it.statusCode === undefined ? "-" : String(it.statusCode);
            const cats = (it.classifications ?? []).map((c) => c.category).join(",");
            return `  ${code.padEnd(4)} ${(it.method ?? "").padEnd(8)} ${it.url}  [${cats}]`;
          }),
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}

export async function paramsCommand(ctx: Context, scanId: string): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);
    const rows = await repo.listUrlObservations(scanId);
    const inventory = new Map<string, { count: number; roles: Map<string, number> }>();
    const bump = (name: string, role: string): void => {
      const entry = inventory.get(name) ?? { count: 0, roles: new Map<string, number>() };
      entry.count++;
      entry.roles.set(role, (entry.roles.get(role) ?? 0) + 1);
      inventory.set(name, entry);
    };
    for (const r of rows) {
      const data = r.data as UrlData;
      for (const p of data.parameters ?? []) for (const role of p.roles) bump(p.name, role.role);
    }
    // Include parameters declared/extracted on API endpoints.
    for (const e of await repo.listApiEndpoints(scanId)) {
      const data = e.data as { parameters?: Array<{ name: string; location: string; required?: boolean }> };
      for (const p of data.parameters ?? []) bump(p.name, p.location || "unknown");
    }
    const params = Array.from(inventory.entries())
      .map(([name, e]) => ({ name, count: e.count, roles: Array.from(e.roles.entries()).map(([role, n]) => ({ role, count: n })) }))
      .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));

    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, distinct: params.length, parameters: params },
      render: () =>
        [
          `Parameter inventory for scan ${scanId}: ${params.length} distinct`,
          "",
          ...params.map((p) => `  ${p.name.padEnd(20)} count=${String(p.count).padEnd(5)} roles=${p.roles.map((r) => `${r.role}:${r.count}`).join(",")}`),
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}

interface OutcomeRow {
  provider: string;
  outcome: string;
  records_count: number;
}

function computeStats(
  items: Array<{ url: string; host?: string; method?: string; classifications?: Array<{ category: string }>; parameters?: Array<{ name: string; roles: Array<{ role: string }> }> }>,
  outcomes: OutcomeRow[],
  skippedByProviders: number,
) {
  const byMethod: Record<string, number> = {};
  const byHost: Record<string, number> = {};
  const classifications: Record<string, number> = {};
  const parameters: Record<string, number> = {};
  const providers = outcomes
    .filter((o) => o.records_count > 0 || ["builtin-crawler", "builtin-static", "gau", "waybackurls", "katana", "mock-url"].includes(o.provider))
    .map((o) => ({ provider: o.provider, outcome: o.outcome, records: o.records_count }));
  for (const it of items) {
    byMethod[it.method ?? "?"] = (byMethod[it.method ?? "?"] ?? 0) + 1;
    byHost[it.host ?? "?"] = (byHost[it.host ?? "?"] ?? 0) + 1;
    for (const c of it.classifications ?? []) classifications[c.category] = (classifications[c.category] ?? 0) + 1;
    for (const p of it.parameters ?? []) for (const r of p.roles) parameters[r.role] = (parameters[r.role] ?? 0) + 1;
  }
  const rawObservations = items.length;
  const uniqueCanonical = new Set(items.map((i) => i.url)).size;
  return {
    providers,
    rawObservations,
    uniqueCanonical,
    duplicateRate: rawObservations === 0 ? 0 : 1 - uniqueCanonical / rawObservations,
    skippedByProviders,
    byMethod,
    byHost,
    classifications,
    parameters,
  };
}
