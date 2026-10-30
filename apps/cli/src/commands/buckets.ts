import { ExitCode } from "@reconnexus/contracts";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { result, type CommandResult } from "../output.js";

interface BucketData {
  host?: string;
  cloudProvider?: string;
  bucket?: string;
  status?: string;
  confidence?: number;
  httpStatus?: number | null;
  objectCount?: number;
  evidence?: string;
}

export interface BucketsOptions {
  host?: string;
  status?: string;
  limit?: number;
}

/** Lists cloud storage buckets found by the cloud-storage stage (CNAME-fronted S3/GCS buckets). */
export async function bucketsCommand(ctx: Context, scanId: string, opts: BucketsOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);

    const filtered = (await repo.listCloudStorageFindings(scanId))
      .map((r) => ({ url: r.url, ...(r.data as BucketData) }))
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
          `Cloud storage for scan ${scanId}: ${filtered.length} CNAME-fronted bucket(s) checked`,
          ...(filtered.length > 0 ? [`  by status: ${JSON.stringify(byStatus)}`] : []),
          "",
          ...limited.map(
            (r) =>
              `  ${(r.status ?? "").padEnd(13)} ${(r.cloudProvider ?? "").padEnd(4)} ${String(r.bucket ?? "").padEnd(30)} HTTP ${r.httpStatus}${r.objectCount ? ` (${r.objectCount} objects)` : ""}  via ${r.host}\n               ${r.evidence ?? ""}`,
          ),
          "",
          "LISTABLE means the response carried an actual object listing. The request always went to the",
          "in-scope host's own CNAME, never to the bucket's cloud-provider hostname directly.",
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}
