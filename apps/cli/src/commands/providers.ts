import { ExitCode, type ProviderHealthReport } from "@reconnexus/contracts";
import { checkProvider, getCatalogEntry, PROVIDER_CATALOG } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

export async function providersListCommand(ctx: Context): Promise<CommandResult<unknown>> {
  const reports: ProviderHealthReport[] = [];
  for (const entry of PROVIDER_CATALOG) {
    reports.push(await checkProvider(entry, ctx.config.providers[entry.name]?.binaryPath));
  }
  return result({
    exitCode: ExitCode.SUCCESS,
    data: { providers: reports },
    render: () => {
      const lines = ["Provider                 Status           Version    Path"];
      for (const r of reports) {
        lines.push(
          `${r.name.padEnd(24)} ${r.status.padEnd(16)} ${(r.version ?? "-").padEnd(10)} ${r.path ?? r.message}`,
        );
      }
      return lines.join("\n");
    },
  });
}

/** Machine-readable provider compatibility matrix (capabilities, network behaviour, limits). */
export function providersMatrixCommand(ctx: Context): CommandResult<unknown> {
  const matrix = PROVIDER_CATALOG.map((p) => ({
    name: p.name,
    displayName: p.displayName,
    source: p.source,
    binary: p.binaryName,
    capabilities: p.capabilities,
    networkBehavior: p.networkBehavior,
    requiresCredentials: p.requiresCredentials,
    requiredCredentials: p.requiredCredentials,
    timeoutMs: p.timeoutMs,
    retryable: p.retryable,
    supportsCancellation: p.supportsCancellation,
    maxOutputBytes: p.maxOutputBytes,
    hasHealthCheck: Boolean(p.healthCheck),
  }));
  return result({
    exitCode: ExitCode.SUCCESS,
    data: { providers: matrix },
    render: () => JSON.stringify(matrix, null, 2),
  });
}

export async function providersCheckCommand(ctx: Context, name: string): Promise<CommandResult<unknown>> {
  const entry = getCatalogEntry(name);
  if (!entry) {
    throw new CliError(`unknown provider '${name}'. Known: ${PROVIDER_CATALOG.map((p) => p.name).join(", ")}`, ExitCode.USAGE_ERROR);
  }
  const report = await checkProvider(entry, ctx.config.providers[name]?.binaryPath);
  const exitCode = report.status === "OK" ? ExitCode.SUCCESS : ExitCode.DEPENDENCY_MISSING;
  return result({
    exitCode,
    data: report,
    render: () =>
      [
        `${report.name}: ${report.status}`,
        `  version: ${report.version ?? "unknown"}`,
        `  path: ${report.path ?? "(none)"}`,
        `  message: ${report.message}`,
        `  capabilities: ${entry.capabilities.join(", ")}`,
        `  networkBehavior: ${entry.networkBehavior}`,
      ].join("\n"),
  });
}
