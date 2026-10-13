import { ExitCode } from "@reconnexus/contracts";
import { LocalArtifactStore } from "@reconnexus/evidence-contracts";
import {
  createDb,
  GoWorkerRunner,
  InvalidTargetError,
  Repository,
  resolveWorkerCommand,
  ScanOrchestrator,
  ScanService,
  ScopeDeniedError,
  type CreateScanResult,
  type DiscoveryRunner,
  type OrchestratorEvent,
  type ScanRunSummary,
} from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import {
  color,
  formatCount,
  formatDuration,
  heading,
  padVisible,
  result,
  statusLabel,
  statusSymbol,
  table,
  formatDecision,
  type CommandResult,
} from "../output.js";
import { resolvePolicy } from "../policy.js";

export interface ScanStartOptions {
  policy?: string;
  workspace?: string;
  allowRestricted?: boolean;
  run?: boolean;
}

async function createScan(ctx: Context, startUrl: string, opts: ScanStartOptions): Promise<CreateScanResult> {
  const { policy } = resolvePolicy(opts.policy, ctx.config.defaultPolicyFile);
  const db = createDb(ctx.config.database);
  try {
    const service = new ScanService(db);
    return await service.createScan({
      startUrl,
      policy,
      ...(opts.workspace ? { workspaceName: opts.workspace } : {}),
      allowRestrictedAddresses: opts.allowRestricted ?? ctx.config.network.allowRestrictedAddresses,
      configSnapshot: { configSchemaVersion: ctx.config.schemaVersion },
    });
  } finally {
    await db.close();
  }
}

export async function scanStartCommand(ctx: Context, startUrl: string, opts: ScanStartOptions): Promise<CommandResult<unknown>> {
  let created: CreateScanResult;
  try {
    created = await createScan(ctx, startUrl, opts);
  } catch (err) {
    if (err instanceof ScopeDeniedError) {
      return result({
        exitCode: ExitCode.SCOPE_DENIED,
        decision: err.decision,
        warnings: ["start URL rejected before any network execution"],
        render: () => `Scope denied:\n${formatDecision(err.decision)}`,
      });
    }
    if (err instanceof InvalidTargetError) {
      throw new CliError(err.message, ExitCode.USAGE_ERROR, { url: err.url });
    }
    throw err;
  }

  if (opts.run) {
    const runResult = await runOrResume(ctx, created.scanId, {});
    return runResult;
  }

  return result({
    exitCode: ExitCode.SUCCESS,
    data: created,
    render: () =>
      [
        `${statusSymbol("SUCCEEDED")} scan authorized ${color.dim("· stage 00 complete, nothing executed yet")}`,
        "",
        ...table(
          [
            [color.dim("scan"), color.bold(created.scanId)],
            [color.dim("target"), created.manifest.rootDomain],
            [color.dim("start url"), created.manifest.startUrl],
          ],
          ["left", "left"],
        ).map((l) => `  ${l}`),
        "",
        color.dim("  run:     ") + `reconnexus scan run ${created.scanId}`,
        color.dim("  report:  ") + `reconnexus report ${created.scanId}`,
      ].join("\n"),
  });
}

export interface ScanRunOptions {
  providers?: string;
  dnsProviders?: string;
  ipProviders?: string;
  httpProviders?: string;
  urlProviders?: string;
  jsProviders?: string;
  apiProviders?: string;
  securityProviders?: string;
  secretProviders?: string;
  maxAttempts?: number;
}

function buildOrchestrator(
  ctx: Context,
  db: ReturnType<typeof createDb>,
  opts: ScanRunOptions,
  signal?: AbortSignal,
  progress?: ProgressRenderer,
): ScanOrchestrator {
  // While progress is rendered, the per-provider info lines would repeat it less legibly, and a
  // log line written straight to stderr would land on top of the line being drawn. Warnings and
  // errors still reach the log, through the renderer; `--log-level debug` keeps everything.
  const logger = progress
    ? ctx.logger.derive({ sink: progress.logSink, ...(ctx.logger.currentLevel === "info" ? { level: "warn" as const } : {}) })
    : ctx.logger;
  const onEvent = progress?.onEvent;
  const cmd = resolveWorkerCommand(ctx.config.worker, process.cwd());
  const runner: DiscoveryRunner = new GoWorkerRunner(cmd);
  const store = new LocalArtifactStore(ctx.config.artifacts.root);
  const overrides: Record<string, string[]> = {};
  if (opts.providers) overrides.SUBDOMAINS = splitList(opts.providers);
  if (opts.dnsProviders) overrides.DNS = splitList(opts.dnsProviders);
  if (opts.ipProviders) overrides.IP_METADATA = splitList(opts.ipProviders);
  if (opts.httpProviders) overrides.HTTP_PROBE = splitList(opts.httpProviders);
  if (opts.urlProviders) overrides.URL_COLLECTION = splitList(opts.urlProviders);
  if (opts.jsProviders) overrides.JS_ANALYSIS = splitList(opts.jsProviders);
  if (opts.apiProviders) overrides.API_SPEC = splitList(opts.apiProviders);
  if (opts.securityProviders) overrides.SECURITY_META = splitList(opts.securityProviders);
  if (opts.secretProviders) overrides.SECRET_SCAN = splitList(opts.secretProviders);
  return new ScanOrchestrator({
    db,
    runner,
    store,
    logger,
    config: ctx.config,
    ...(Object.keys(overrides).length ? { providerOverrides: overrides as never } : {}),
    ...(opts.maxAttempts ? { maxAttempts: opts.maxAttempts } : {}),
    ...(signal ? { signal } : {}),
    ...(onEvent ? { onEvent } : {}),
  });
}

function splitList(s: string): string[] {
  return s.split(",").map((x) => x.trim()).filter(Boolean);
}

/** Stage ids are `NN-some-name`; split them so the number and the name can be columns. */
function stageParts(stage: string): { index: string; name: string } {
  const m = /^(\d+)-(.*)$/.exec(stage);
  if (!m) return { index: "  ", name: stage };
  return { index: m[1]!, name: m[2]!.replace(/-/g, " ") };
}

const STAGE_NAME_WIDTH = 22;

interface ProgressRenderer {
  onEvent: (e: OrchestratorEvent) => void;
  /** Log sink that clears any line being drawn first, so the two never interleave. */
  logSink: (line: string) => void;
}

/**
 * Renders live progress to stderr in human mode. One line per stage as it finishes, with the
 * providers that ran and what each returned; on a terminal the stage currently running is shown
 * on a transient line that the result then overwrites. Returns nothing in `--json` mode or when
 * the log level says the operator wants quiet.
 */
function progressPrinter(ctx: Context): ProgressRenderer | undefined {
  if (ctx.json || ctx.config.logging.level === "error") return undefined;
  const tty = process.stderr.isTTY === true;
  const write = (s: string): void => void process.stderr.write(s);
  const clearLine = (): void => {
    if (tty) write("\r\u001b[2K");
  };
  const providers = new Map<string, string[]>();

  const onEvent = (e: OrchestratorEvent): void => {
    switch (e.type) {
      case "scan-start": {
        write(`\n${color.bold("ReconNexus")} ${color.dim("·")} ${color.bold(e.rootDomain)} ${color.dim("·")} ${color.dim(e.scanId)}\n`);
        write(`${color.dim(`${e.stages} stages`)}\n\n`);
        return;
      }
      case "stage-start": {
        const { index, name } = stageParts(e.stage);
        providers.delete(e.stage);
        if (tty) write(`  ${color.cyan("•")} ${color.dim(index)} ${name}${color.dim(" …")}`);
        return;
      }
      case "provider-end": {
        const list = providers.get(e.stage) ?? [];
        const count = e.status === "SKIPPED" || e.status === "BLOCKED" ? "" : ` ${color.dim(formatCount(e.records))}`;
        const mark = e.status === "SUCCEEDED" ? "" : ` ${color.dim(`(${e.status.toLowerCase()})`)}`;
        list.push(`${e.provider}${count}${mark}`);
        providers.set(e.stage, list);
        if (tty) {
          const { index, name } = stageParts(e.stage);
          clearLine();
          write(`  ${color.cyan("•")} ${color.dim(index)} ${name}${color.dim(" … " + e.provider)}`);
        }
        return;
      }
      case "stage-end": {
        clearLine();
        const { index, name } = stageParts(e.stage);
        const cells = [
          `  ${statusSymbol(e.status)}`,
          color.dim(index),
          padVisible(name, STAGE_NAME_WIDTH),
          padVisible(e.durationMs > 0 ? color.dim(formatDuration(e.durationMs)) : "", 8, "right"),
        ];
        const detail = providers.get(e.stage);
        if (detail?.length) cells.push(color.dim("·") + " " + detail.join(color.dim(" · ")));
        else if (e.reason) cells.push(color.dim("· " + e.reason));
        write(`${cells.join(" ")}\n`);
        return;
      }
      case "scan-end": {
        // The verdict belongs to the summary on stdout; keep the live stream free of duplicates.
        write("\n");
        return;
      }
    }
  };

  return {
    onEvent,
    logSink: (line) => {
      clearLine();
      write(`  ${line}\n`);
    },
  };
}

/**
 * The final block on stdout: the verdict, what was persisted, anything that did not fully
 * succeed, and the next command. The per-stage detail lives in the progress stream, so it is
 * repeated here only when progress was not rendered.
 */
function renderRunSummary(summary: ScanRunSummary, showedProgress: boolean): string {
  const lines: string[] = [];
  const incomplete = summary.stages.filter((s) => s.status !== "SUCCEEDED");

  lines.push(`${statusSymbol(summary.status)} scan ${statusLabel(summary.status)}  ${color.dim(summary.scanId)}`);
  lines.push("");
  lines.push(
    ...table(
      [
        [color.dim("new assets"), formatCount(summary.assetsCreated)],
        [color.dim("observations"), formatCount(summary.observations)],
        [color.dim("relationships"), formatCount(summary.relationships)],
      ],
      ["left", "right"],
    ).map((l) => `  ${l}`),
  );

  if (!showedProgress) {
    lines.push("", heading("stages"));
    lines.push(
      ...table(
        summary.stages.map((s) => {
          const { index, name } = stageParts(s.stage);
          const detail = s.providers.length
            ? s.providers.map((p) => `${p.provider} ${color.dim(formatCount(p.records))}${p.outcome === "SUCCEEDED" ? "" : color.dim(` (${p.outcome.toLowerCase()})`)}`).join(color.dim(" · "))
            : color.dim(s.reason ?? "");
          return [`  ${statusSymbol(s.status)}`, color.dim(index), name, detail];
        }),
      ),
    );
  }

  if (incomplete.length > 0) {
    lines.push("", heading(`${incomplete.length} of ${summary.stages.length} stages did not fully succeed`));
    lines.push(
      ...table(
        incomplete.map((s) => {
          const { index, name } = stageParts(s.stage);
          const degraded = s.providers.filter((p) => p.outcome !== "SUCCEEDED");
          const why =
            degraded.length > 0
              ? degraded.map((p) => `${p.provider} ${statusLabel(p.outcome)}${p.reason ? color.dim(` — ${truncate(p.reason, 90)}`) : ""}`).join("; ")
              : color.dim(s.reason ?? "no detail recorded");
          return [`  ${statusSymbol(s.status)}`, color.dim(index), name, `${statusLabel(s.status)}  ${why}`];
        }),
      ),
    );
  }

  const next: string[][] = [];
  if (incomplete.length > 0) next.push([color.dim("coverage"), `reconnexus coverage ${summary.scanId}`]);
  next.push([color.dim("report"), `reconnexus report ${summary.scanId}`]);
  lines.push("", ...table(next).map((l) => `  ${l}`));
  return lines.join("\n");
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

/** `2026-10-13 19:36` — local-free, second-free, sortable. */
function formatTimestamp(at: Date | string): string {
  return new Date(at).toISOString().slice(0, 16).replace("T", " ");
}

async function runOrResume(ctx: Context, scanId: string, opts: ScanRunOptions): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  const controller = new AbortController();
  const onSigint = (): void => {
    process.stderr.write(`\n${color.yellow("cancelling…")}\n`);
    controller.abort();
  };
  process.once("SIGINT", onSigint);
  try {
    const progress = progressPrinter(ctx);
    const showedProgress = progress !== undefined;
    const orchestrator = buildOrchestrator(ctx, db, opts, controller.signal, progress);
    const summary = await orchestrator.runScan(scanId);
    const exitCode =
      summary.status === "SUCCEEDED" ? ExitCode.SUCCESS : summary.status === "PARTIAL" ? ExitCode.PARTIAL : summary.status === "CANCELLED" ? ExitCode.CANCELLED : ExitCode.GENERAL_ERROR;
    return result({
      exitCode,
      data: summary,
      warnings: summary.status === "PARTIAL" ? ["scan completed partially; some stages were skipped or failed — see coverage"] : [],
      render: () => renderRunSummary(summary, showedProgress),
    });
  } finally {
    process.removeListener("SIGINT", onSigint);
    await db.close();
  }
}

export async function scanRunCommand(ctx: Context, scanId: string, opts: ScanRunOptions): Promise<CommandResult<unknown>> {
  return runOrResume(ctx, scanId, opts);
}

export async function scanResumeCommand(ctx: Context, scanId: string, opts: ScanRunOptions): Promise<CommandResult<unknown>> {
  return runOrResume(ctx, scanId, opts);
}

export async function scanListCommand(ctx: Context, opts: { limit?: number }): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const scans = await new Repository(db).listScans(opts.limit ?? 20);
    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scans },
      render: () =>
        scans.length === 0
          ? `No scans yet. Create one with:  ${color.bold("reconnexus scan start <url>")}`
          : [
              heading(`${scans.length} most recent scan${scans.length === 1 ? "" : "s"}`),
              ...table(
                scans.map((s) => [
                  `  ${statusSymbol(s.status)}`,
                  s.id,
                  statusLabel(s.status),
                  s.root_domain,
                  color.dim(formatTimestamp(s.created_at)),
                ]),
              ),
              "",
              color.dim("  run one:  ") + "reconnexus scan run <scanId>",
            ].join("\n"),
    });
  } finally {
    await db.close();
  }
}

export async function scanStatusCommand(ctx: Context, scanId: string): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);
    const jobs = await repo.listJobs(scanId);
    const coverage = await repo.listCoverage(scanId);
    const outcomes = await repo.listProviderOutcomes(scanId);
    const payload = { scan, jobs, coverage, providers: outcomes };
    return result({
      exitCode: ExitCode.SUCCESS,
      data: payload,
      render: () =>
        [
          `${statusSymbol(scan.status)} scan ${statusLabel(scan.status)}  ${color.dim(scan.id)}`,
          "",
          ...table(
            [
              [color.dim("target"), scan.root_domain],
              [color.dim("start url"), scan.start_url],
              ...(scan.error ? [[color.dim("error"), color.red(scan.error)]] : []),
            ],
            ["left", "left"],
          ).map((l) => `  ${l}`),
          "",
          heading("stages"),
          ...table(
            jobs.map((j) => {
              const { index, name } = stageParts(j.stage);
              const note = j.last_error ? color.dim(`— ${truncate(j.last_error, 80)}`) : "";
              const attempts = j.attempts > 1 ? color.dim(`${j.attempts} attempts`) : "";
              return [`  ${statusSymbol(j.status)}`, color.dim(index), name, statusLabel(j.status), attempts, note];
            }),
          ),
          "",
          heading("coverage"),
          ...table(
            coverage.map((c) => {
              const { index, name } = stageParts(c.stage);
              return [`  ${statusSymbol(c.status)}`, color.dim(index), name, statusLabel(c.status), `${c.collected}/${c.expected}`, color.dim(truncate(c.notes ?? "", 70))];
            }),
          ),
          "",
          heading("providers"),
          ...table(
            outcomes.map((o) => {
              const { index } = stageParts(o.stage);
              return [`  ${statusSymbol(o.outcome)}`, color.dim(index), o.provider, statusLabel(o.outcome), padVisible(formatCount(o.records_count), 7, "right") + color.dim(" records"), color.dim(truncate(o.reason ?? "", 60))];
            }),
          ),
          "",
          color.dim("  report:  ") + `reconnexus report ${scan.id}`,
        ].join("\n"),
    });
  } finally {
    await db.close();
  }
}

export async function scanCancelCommand(ctx: Context, scanId: string): Promise<CommandResult<unknown>> {
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);
    await repo.updateScanStatus(scanId, "CANCELLED");
    return result({
      exitCode: ExitCode.SUCCESS,
      data: { scanId, status: "CANCELLED" },
      render: () => `scan ${scanId} cancelled`,
    });
  } finally {
    await db.close();
  }
}
