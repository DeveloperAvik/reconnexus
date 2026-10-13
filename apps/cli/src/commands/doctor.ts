import { accessSync, constants, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ExitCode } from "@reconnexus/contracts";
import {
  checkAllProviders,
  checkDatabase,
  checkRedis,
  checkTool,
} from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { result, type CommandResult } from "../output.js";

interface DoctorReport {
  runtime: unknown[];
  dependencies: unknown[];
  providers: unknown[];
  paths: unknown;
  ok: boolean;
}

export async function doctorCommand(ctx: Context): Promise<CommandResult<DoctorReport>> {
  const { config, logger } = ctx;
  logger.debug("running dependency diagnostics");

  const runtime = [
    { name: "node", ok: true, version: process.version, message: process.execPath },
    await checkTool("go", ["version"]),
  ];

  const [postgres, redis] = await Promise.all([checkDatabase(config), checkRedis(config)]);

  const providers = await checkAllProviders(config);

  const paths = {
    artifactsRoot: config.artifacts.root,
    migrationsDir: config.migrationsDir,
    artifactsWritable: checkWritable(config.artifacts.root),
  };

  const criticalOk =
    postgres.ok &&
    runtime.every((r) => (r as { ok: boolean }).ok) &&
    (paths.artifactsWritable as boolean);
  const providersOk = providers.some((p) => p.status === "OK");

  const report: DoctorReport = {
    runtime,
    dependencies: [postgres, redis],
    providers,
    paths,
    ok: criticalOk,
  };

  const exitCode = criticalOk && providersOk ? ExitCode.SUCCESS : ExitCode.DEPENDENCY_MISSING;

  return result({
    exitCode,
    data: report,
    warnings: providersOk ? [] : ["no external providers are healthy; recon stages that require them cannot run"],
    render: () => {
      const lines: string[] = ["ReconNexus doctor", ""];
      lines.push("Runtime");
      for (const r of runtime) {
        const ok = (r as { ok: boolean }).ok;
        lines.push(`  ${ok ? "OK  " : "FAIL"} ${(r as { name: string }).name} ${(r as { version?: string }).version ?? ""} — ${(r as { message: string }).message}`);
      }
      lines.push("", "Dependencies");
      for (const d of [postgres, redis]) {
        lines.push(`  ${d.ok ? "OK  " : "FAIL"} ${d.name}${d.version ? ` ${d.version}` : ""} — ${d.message}`);
      }
      lines.push("", "Paths");
      lines.push(`  artifacts root: ${paths.artifactsRoot} (writable: ${paths.artifactsWritable})`);
      lines.push(`  migrations dir: ${paths.migrationsDir}`);
      lines.push("", "Providers");
      for (const p of providers) {
        lines.push(`  ${p.status === "OK" ? "OK  " : p.status === "MISSING" ? "MISS" : "FAIL"} ${p.name}${p.version ? ` ${p.version}` : ""} — ${p.message}`);
      }
      lines.push("", exitCode === ExitCode.SUCCESS ? "doctor: healthy" : "doctor: problems detected");
      return lines.join("\n");
    },
  });
}

function checkWritable(dir: string): boolean {
  try {
    mkdirSync(dir, { recursive: true });
    accessSync(dir, constants.W_OK);
    const probe = join(dir, `.write-probe-${process.pid}`);
    writeFileSync(probe, "ok");
    rmSync(probe, { force: true });
    return true;
  } catch {
    return false;
  }
}
