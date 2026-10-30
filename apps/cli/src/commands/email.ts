import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

interface EmailSecurityData {
  category?: string;
  status?: string;
  confidence?: number;
  value?: string;
  evidence?: string;
}

export interface EmailOptions {
  category?: string;
  status?: string;
}

/** Lists SPF/DMARC/DKIM observations found by the email-security stage. */
export async function emailCommand(ctx: Context, scanId: string, opts: EmailOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);

    const filtered = (await repo.listEmailSecurityFindings(scanId))
      .map((r) => ({ host: r.host, ...(r.data as EmailSecurityData) }))
      .filter((r) => {
        if (opts.category && (r.category ?? "").toLowerCase() !== opts.category.toLowerCase()) return false;
        if (opts.status && (r.status ?? "").toLowerCase() !== opts.status.toLowerCase()) return false;
        return true;
      });

    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, total: filtered.length, items: filtered },
      render: () =>
        [
          `Email security posture for scan ${scanId}: ${filtered.length} observation(s)`,
          "",
          ...filtered.map((r) => `  ${(r.category ?? "").padEnd(6)} ${(r.status ?? "").padEnd(14)} ${r.host}\n    ${r.evidence ?? ""}`),
          "",
          "DKIM's NOT_DETECTED is never proof DKIM is absent: it only means none of a fixed list of",
          "common selectors resolved. SPF/DMARC ABSENT, WEAK and MISCONFIGURED are real findings;",
          "STRONG and DETECTED are good posture, not an issue.",
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
