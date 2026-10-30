import { JobStatus } from "@reconnexus/contracts";
import type { Db } from "../db/pool.js";
import type { JobRow, Repository, ScanRow } from "../repository.js";
import { insertObservation, upsertAsset, upsertCoverageInternal } from "./ingest.js";
import type { ProviderOutcomeSummary } from "./types.js";

/** Result of running one stage, as consumed by the retry loop. */
export type StageRunResult = { status: string; providers: ProviderOutcomeSummary[]; reason?: string };

/**
 * The narrow slice of orchestrator state that provider-less ("derived") stages need. The
 * orchestrator owns the mutable state; `totals` is the orchestrator's own counter object (mutated
 * in place) and `stageTiming` reads its live stage clock.
 */
export interface DerivedStageContext {
  db: Db;
  repo: Repository;
  now: () => Date;
  stageTiming: (stage: string) => { startedAt?: string; finishedAt?: string; durationMs?: number };
  totals: { assetsCreated: number; observations: number; relationships: number };
}

/**
 * Stage 06 — URL categorization. Classification is computed during URL collection (stage 05);
 * this stage materializes the categorization dimension as coverage and confirms every discovered
 * URL carries at least one classification. It performs no network requests.
 */
export async function runUrlCategorization(ctx: DerivedStageContext, scan: ScanRow, job: JobRow): Promise<StageRunResult> {
  const rows = await ctx.repo.listUrlObservations(scan.id);
  const total = rows.length;
  let classified = 0;
  const byCategory: Record<string, number> = {};
  for (const r of rows) {
    const cats = (r.data as { classifications?: Array<{ category: string }> }).classifications ?? [];
    if (cats.length > 0) classified++;
    for (const c of cats) byCategory[c.category] = (byCategory[c.category] ?? 0) + 1;
  }
  const status = total === 0 ? JobStatus.SKIPPED : classified === total ? JobStatus.SUCCEEDED : JobStatus.PARTIAL;
  const cov = total === 0 ? "NOT_ATTEMPTED" : classified === total ? "COLLECTED" : "PARTIAL";
  await ctx.db.withTransaction((c) =>
    upsertCoverageInternal(c, {
      scanId: scan.id,
      projectId: scan.project_id,
      stage: job.stage,
      status: cov,
      expected: total,
      collected: classified,
      notes: total === 0 ? "no URLs to categorize" : `${classified}/${total} URLs classified`,
      details: { byCategory, ...ctx.stageTiming(job.stage) },
    }),
  );
  return { status, providers: [] };
}

export async function runTargetIntelligence(ctx: DerivedStageContext, scan: ScanRow, job: JobRow): Promise<StageRunResult> {
  const now = ctx.now();
  await ctx.db.withTransaction(async (client) => {
    const a = await upsertAsset(client, { projectId: scan.project_id, type: "DOMAIN", canonicalKey: scan.root_domain, value: scan.root_domain, seenAt: now });
    if (a.inserted) ctx.totals.assetsCreated++;
    await insertObservation(client, { projectId: scan.project_id, scanId: scan.id, assetId: a.id, source: "control-plane", sourceReliability: "AUTHORITATIVE", observedAt: now, kind: "target", data: { startUrl: scan.start_url, rootDomain: scan.root_domain } });
    ctx.totals.observations++;
    await upsertCoverageInternal(client, { scanId: scan.id, projectId: scan.project_id, stage: job.stage, status: "COLLECTED", expected: 1, collected: 1, notes: "root target recorded", details: ctx.stageTiming(job.stage) });
  });
  return { status: JobStatus.SUCCEEDED, providers: [] };
}
