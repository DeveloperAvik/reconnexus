import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

interface GithubMatchData {
  host?: string;
  query?: string;
  repository?: string;
  path?: string;
  sha?: string;
  score?: number;
  evidence?: string;
}

export interface GithubLeaksOptions {
  repository?: string;
  limit?: number;
}

/** Lists public GitHub code matches found by the github-leaks stage. */
export async function githubCommand(ctx: Context, scanId: string, opts: GithubLeaksOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);

    const filtered = (await repo.listGithubLeakFindings(scanId))
      .map((r) => ({ url: r.url, ...(r.data as GithubMatchData) }))
      .filter((r) => !opts.repository || (r.repository ?? "").toLowerCase().includes(opts.repository.toLowerCase()));
    const limited = opts.limit ? filtered.slice(0, opts.limit) : filtered;

    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, total: filtered.length, items: limited },
      render: () =>
        [
          `GitHub code matches for scan ${scanId}: ${filtered.length} found`,
          "",
          ...limited.map((r) => `  ${(r.repository ?? "").padEnd(40)} ${r.path}\n    ${r.evidence ?? ""}\n    ${r.url}`),
          "",
          "A mention of the domain in public code is not itself a vulnerability; confirm manually.",
          "A fragment that also matched a secret-detection rule produces its own entry in `secrets`.",
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
