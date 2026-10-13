import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

interface FindingData {
  ruleId?: string;
  category?: string;
  status?: string;
  confidence?: number;
  artifactUrl?: string;
  host?: string;
  location?: string;
  redactedSnippet?: string;
  fingerprint?: string;
  occurrences?: number;
  suppressionReason?: string;
}

export interface SecretsOptions {
  rule?: string;
  category?: string;
  status?: string;
  confidence?: number;
  artifact?: string;
  host?: string;
  limit?: number;
}

/**
 * Lists secret-detection findings. Output is redacted-only: the snippet shown is the value-redacted
 * context produced by the worker. There is deliberately no flag to reveal raw values.
 */
export async function secretsCommand(ctx: Context, scanId: string, opts: SecretsOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);
    const all = (await repo.listSecretFindings(scanId)).map((r) => ({ artifact: r.artifact, ...(r.data as FindingData) }));
    const filtered = all.filter((f) => {
      if (opts.rule && f.ruleId !== opts.rule) return false;
      if (opts.category && (f.category ?? "").toUpperCase() !== opts.category.toUpperCase()) return false;
      if (opts.status && (f.status ?? "").toUpperCase() !== opts.status.toUpperCase()) return false;
      if (opts.confidence !== undefined && (f.confidence ?? 0) < opts.confidence) return false;
      if (opts.artifact && !(f.artifactUrl ?? "").includes(opts.artifact)) return false;
      if (opts.host && !(f.host ?? "").includes(opts.host)) return false;
      return true;
    });
    const limited = opts.limit ? filtered.slice(0, opts.limit) : filtered;
    const artifacts = await repo.listSecretScanArtifacts(scanId);
    const byRule: Record<string, number> = {};
    const byStatus: Record<string, number> = {};
    const byCategory: Record<string, number> = {};
    for (const f of filtered) {
      byRule[f.ruleId ?? "?"] = (byRule[f.ruleId ?? "?"] ?? 0) + 1;
      byStatus[f.status ?? "?"] = (byStatus[f.status ?? "?"] ?? 0) + 1;
      byCategory[f.category ?? "?"] = (byCategory[f.category ?? "?"] ?? 0) + 1;
    }
    const artStatus: Record<string, number> = {};
    for (const a of artifacts) {
      const s = (a.data as { status?: string }).status ?? "?";
      artStatus[s] = (artStatus[s] ?? 0) + 1;
    }
    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, total: filtered.length, byRule, byStatus, byCategory, artifacts: { total: artifacts.length, byStatus: artStatus }, findings: limited },
      render: () =>
        [
          `Secret findings for scan ${scanId}: ${filtered.length} (redacted)`,
          `  by rule:     ${JSON.stringify(byRule)}`,
          `  by status:   ${JSON.stringify(byStatus)}`,
          `  by category: ${JSON.stringify(byCategory)}`,
          `  artifacts:   ${artifacts.length} ${JSON.stringify(artStatus)}`,
          "",
          ...limited.map((f) => `  ${(f.status ?? "").padEnd(16)} ${(f.ruleId ?? "").padEnd(26)} conf=${(f.confidence ?? 0).toFixed(2)} ${f.artifact ?? ""} ${f.location ?? ""}  ${f.redactedSnippet ?? ""}`),
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
