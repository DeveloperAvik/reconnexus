import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

interface GraphQLData {
  host?: string;
  status?: string;
  confidence?: number;
  httpStatus?: number | null;
  queryType?: string;
  mutationType?: string;
  typeCount?: number;
  queryFieldCount?: number;
  mutationFieldCount?: number;
  evidence?: string;
}

export interface GraphQLOptions {
  host?: string;
  status?: string;
  limit?: number;
}

/** Lists GraphQL introspection probes found by the graphql-intelligence stage. */
export async function graphqlCommand(ctx: Context, scanId: string, opts: GraphQLOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);

    const filtered = (await repo.listGraphQLFindings(scanId))
      .map((r) => ({ url: r.url, ...(r.data as GraphQLData) }))
      .filter((r) => {
        if (opts.host && !(r.host ?? "").includes(opts.host)) return false;
        if (opts.status && (r.status ?? "").toLowerCase() !== opts.status.toLowerCase()) return false;
        return true;
      });
    const limited = opts.limit ? filtered.slice(0, opts.limit) : filtered;
    const byStatus: Record<string, number> = {};
    for (const r of filtered) byStatus[r.status ?? "?"] = (byStatus[r.status ?? "?"] ?? 0) + 1;

    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, total: filtered.length, byStatus, items: limited },
      render: () =>
        [
          `GraphQL probes for scan ${scanId}: ${filtered.length} candidate(s) checked`,
          ...(filtered.length > 0 ? [`  by status: ${JSON.stringify(byStatus)}`] : []),
          "",
          ...limited.map(
            (r) =>
              `  ${(r.status ?? "").padEnd(22)} HTTP ${r.httpStatus}  types=${r.typeCount ?? 0}  query=${r.queryFieldCount ?? 0} mutation=${r.mutationFieldCount ?? 0}  ${r.url}\n    ${r.evidence ?? ""}`,
          ),
          "",
          "INTROSPECTION_ENABLED means the introspection query returned a non-null __schema object,",
          "disclosing root type names and field counts. NOT_GRAPHQL probes are omitted from findings",
          "but still counted here as coverage.",
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
