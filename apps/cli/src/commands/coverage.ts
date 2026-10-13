import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

export async function coverageCommand(ctx: Context, scanId: string): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);
    const coverage = await repo.listCoverage(scanId);
    const providers = await repo.listProviderOutcomes(scanId);

    const counts = providers.reduce<Record<string, number>>((acc, p) => {
      acc[p.outcome] = (acc[p.outcome] ?? 0) + 1;
      return acc;
    }, {});

    const payload = { scanId, scanStatus: scan.status, coverage, providers, providerOutcomeCounts: counts };
    return result({
      exitCode: ExitCode.SUCCESS,
      data: payload,
      render: () =>
        [
          `Coverage for scan ${scanId} (${scan.status})`,
          "",
          "Stage coverage:",
          ...coverage.map((c) => `  ${c.stage.padEnd(28)} ${c.status.padEnd(14)} collected=${c.collected} expected=${c.expected} ${c.notes}`),
          "",
          `Providers attempted: ${providers.length}`,
          `  succeeded=${counts.SUCCEEDED ?? 0} partial=${counts.PARTIAL ?? 0} failed=${counts.FAILED ?? 0} unavailable=${counts.SOURCE_UNAVAILABLE ?? 0} skipped=${counts.SKIPPED ?? 0} blocked=${counts.BLOCKED ?? 0}`,
          "",
          "Provider detail:",
          ...providers.map((p) => `  ${p.stage.padEnd(24)} ${p.provider.padEnd(14)} ${p.outcome.padEnd(18)} records=${p.records_count} v=${p.provider_version ?? "?"} ${p.reason}`),
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
