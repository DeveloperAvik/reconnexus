import { ExitCode } from "@reconnexus/contracts";
import { createDb, loadScanFindings, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { color, result, statusColor, type CommandResult } from "../output.js";

export interface FindingsOptions {
  category?: string;
  severity?: string;
  validation?: string;
  subject?: string;
  limit?: number;
}

/**
 * Lists the scan's redacted, evidence-backed findings (the same list `report` embeds), derived
 * from secret, takeover and security-metadata candidates. Severity, confidence and validation stay
 * separate columns: a HIGH-severity row is an impact estimate *if* the candidate is real, not a
 * claim that it is. Nothing here is ever `VALIDATED` — ReconNexus performs no exploitation and
 * verifies no credential.
 */
export async function findingsCommand(ctx: Context, scanId: string, opts: FindingsOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);

    const all = await loadScanFindings(repo, scanId);
    const filtered = all.filter((f) => {
      if (opts.category && f.category.toUpperCase() !== opts.category.toUpperCase()) return false;
      if (opts.severity && f.severity.toUpperCase() !== opts.severity.toUpperCase()) return false;
      if (opts.validation && f.validation.toUpperCase() !== opts.validation.toUpperCase()) return false;
      if (opts.subject && !f.subject.toLowerCase().includes(opts.subject.toLowerCase())) return false;
      return true;
    });
    const limited = opts.limit ? filtered.slice(0, opts.limit) : filtered;

    const bySeverity: Record<string, number> = {};
    const byValidation: Record<string, number> = {};
    const byCategory: Record<string, number> = {};
    for (const f of filtered) {
      bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
      byValidation[f.validation] = (byValidation[f.validation] ?? 0) + 1;
      byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
    }

    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, total: filtered.length, bySeverity, byValidation, byCategory, findings: limited },
      render: () =>
        [
          `Findings for scan ${scanId}: ${filtered.length}`,
          `  by severity:   ${JSON.stringify(bySeverity)}`,
          `  by validation: ${JSON.stringify(byValidation)}`,
          `  by category:   ${JSON.stringify(byCategory)}`,
          "",
          ...limited.map(
            (f) =>
              `  ${statusColor(f.severity).padEnd(10)} ${f.validation.padEnd(14)} conf=${f.confidence.toFixed(2)} ${f.category.padEnd(22)} ${f.subject}  ${f.title}`,
          ),
          "",
          color.dim("Candidates and inferences only; nothing here is a confirmed/validated vulnerability."),
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
