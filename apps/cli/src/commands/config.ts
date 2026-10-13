import { ExitCode } from "@reconnexus/contracts";
import type { ReconNexusConfig } from "@reconnexus/configuration";
import { createDb, migrate, migrationStatus } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { result, type CommandResult } from "../output.js";

function redactConfig(config: ReconNexusConfig): ReconNexusConfig {
  const redacted = structuredClone(config);
  try {
    const u = new URL(redacted.database.url);
    if (u.password) u.password = "***";
    redacted.database.url = u.toString();
  } catch {
    /* leave as-is */
  }
  return redacted;
}

export function configShowCommand(ctx: Context): CommandResult<unknown> {
  const redacted = redactConfig(ctx.config);
  return result({
    exitCode: ExitCode.SUCCESS,
    data: redacted,
    render: () => JSON.stringify(redacted, null, 2),
  });
}

export function configValidateCommand(ctx: Context): CommandResult<unknown> {
  return result({
    exitCode: ExitCode.SUCCESS,
    data: { valid: true, config: redactConfig(ctx.config) },
    render: () => `configuration OK\n  database: ${redactConfig(ctx.config).database.url}\n  artifacts: ${ctx.config.artifacts.root}\n  migrations: ${ctx.config.migrationsDir}`,
  });
}

export interface MigrateOptions {
  status?: boolean;
}

export async function configMigrateCommand(ctx: Context, opts: MigrateOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    if (opts.status) {
      const rows = await migrationStatus(db, ctx.config.migrationsDir);
      const pending = rows.filter((r) => !r.applied).length;
      return result({
        exitCode: ExitCode.SUCCESS,
        data: { migrations: rows, pending },
        render: () => {
          const lines = ["Migration status", ""];
          for (const r of rows) lines.push(`  ${r.applied ? "applied" : "pending"}  ${r.version}_${r.name}`);
          lines.push("", `${pending} pending`);
          return lines.join("\n");
        },
      });
    }
    const res = await migrate(db, ctx.config.migrationsDir);
    return result({
      exitCode: ExitCode.SUCCESS,
      data: res,
      render: () =>
        [`applied: ${res.applied.length ? res.applied.join(", ") : "(none)"}`, `skipped: ${res.skipped.length ? res.skipped.join(", ") : "(none)"}`].join("\n"),
    });
  } finally {
    await db.close();
  }
}
