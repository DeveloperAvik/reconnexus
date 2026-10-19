import { hostname } from "node:os";
import {
  CorrelationRecordSchema,
  DiscoveryJobKind,
  RECONNEXUS_VERSION,
  JobStatus,
  OrderedStages,
  ScopePolicySchema,
  StageId,
  type CorrelationRecord,
  type DiscoveryJob,
  type DiscoveryJobKindValue,
  type DiscoveryResult,
  type Report,
  type ScopePolicy,
} from "@reconnexus/contracts";
import type { ReconNexusConfig } from "@reconnexus/configuration";
import type { ArtifactStore } from "@reconnexus/evidence-contracts";
import type { Logger } from "@reconnexus/logging";
import type { Db } from "../db/pool.js";
import { Repository, type JobRow, type ScanRow } from "../repository.js";
import type { DiscoveryRunner } from "../worker/client.js";
import { ingestDiscoveryResult, recordProviderExecution, upsertAsset, insertObservation, upsertCoverageInternal, upsertProviderOutcome, upsertRelationship, sha256Hex } from "./ingest.js";
import { buildReport, redactReport, ReportRedactionError, type Redactor } from "../reporting/report.js";

export interface OrchestratorDeps {
  db: Db;
  runner: DiscoveryRunner;
  store: ArtifactStore;
  logger: Logger;
  config: ReconNexusConfig;
  providerOverrides?: Partial<Record<DiscoveryJobKindValue, string[]>>;
  workerId?: string;
  signal?: AbortSignal;
  maxAttempts?: number;
  now?: () => Date;
  sleep?: (ms: number) => Promise<void>;
  /** Report-boundary redactor (defaults to the centralized redactor); injectable for tests. */
  redactor?: (value: unknown) => unknown;
  /** Optional progress callback (used by the CLI to render human-readable progress). */
  onEvent?: (event: OrchestratorEvent) => void;
}

/**
 * Progress events. Consumers render them; they are never the source of truth for a result (the
 * persisted job/coverage/provider rows are), and emitting one must never affect the scan.
 */
export type OrchestratorEvent =
  | {
      type: "scan-start";
      scanId: string;
      rootDomain: string;
      startUrl: string;
      /** Number of stages in this run's plan, and their ids in execution order. */
      stages: number;
      stageIds: string[];
      profile: string;
      startedAt: string;
    }
  | { type: "stage-start"; stage: string; attempt: number }
  | { type: "provider-start"; stage: string; provider: string }
  | {
      type: "provider-end";
      stage: string;
      provider: string;
      status: string;
      records: number;
      durationMs: number;
      /** Record counts by discovery record type, exactly as returned by the provider. */
      recordsByType: Record<string, number>;
      /** True when a previously persisted result was reused instead of re-running the provider. */
      reused: boolean;
    }
  | { type: "stage-retry"; stage: string; attempt: number; backoffMs: number }
  | { type: "stage-end"; stage: string; status: string; durationMs: number; records: number; attempts: number; reason?: string }
  | { type: "scan-end"; status: string; durationMs: number };

export interface ProviderOutcomeSummary {
  stage: string;
  provider: string;
  outcome: string;
  records: number;
  reason: string;
  providerVersion: string;
  /** `null` when the provider's result was reused and no fresh duration was measured. */
  durationMs: number | null;
  timedOut: boolean;
  truncated: boolean;
}

export interface ScanRunSummary {
  scanId: string;
  status: string;
  stages: Array<{ stage: string; status: string; providers: ProviderOutcomeSummary[]; reason?: string; durationMs?: number }>;
  assetsCreated: number;
  observations: number;
  relationships: number;
  /** Where this run's outputs live, so a caller can tell an operator what to open next. */
  artifactsRoot: string;
  profile: string;
}

const IMPLEMENTED_STAGES = new Set<string>([
  StageId.INPUT_AUTHORIZATION,
  StageId.TARGET_INTELLIGENCE,
  StageId.SUBDOMAIN_DISCOVERY,
  StageId.DNS_INFRA,
  StageId.HTTP_PROBE,
  StageId.URL_COLLECTION,
  StageId.URL_CATEGORIZATION,
  StageId.JS_INTELLIGENCE,
  StageId.API_DISCOVERY,
  StageId.SECRET_DETECTION,
  StageId.SECURITY_CHECKS,
  StageId.CORRELATION,
  StageId.TAKEOVER,
  StageId.LOGIN_FINDER,
  StageId.REPORTING,
]);

const DEFAULT_PROVIDERS: Record<DiscoveryJobKindValue, string[]> = {
  SUBDOMAINS: ["subfinder", "assetfinder"],
  DNS: ["builtin-dns"],
  IP_METADATA: ["rdap"],
  HTTP_PROBE: ["builtin-http"],
  URL_COLLECTION: ["builtin-crawler", "builtin-static", "gau", "waybackurls"],
  JS_ANALYSIS: ["builtin-js"],
  API_SPEC: ["builtin-api"],
  SECURITY_META: ["builtin-security-meta"],
  SECRET_SCAN: ["builtin-secret-scan"],
  TAKEOVER: ["builtin-takeover"],
  LOGIN_FINDER: ["builtin-login-finder"],
};

const MAX_NAMES = 1000;
const MAX_ADDRESSES = 50;
const MAX_HTTP_HOSTS = 300;
const MAX_HTTP_TARGETS = 500;
const MAX_SEED_URLS = 200;
const MAX_CRAWL_REQUESTS = 800;
const MAX_JS_URLS = 200;
const MAX_SPEC_URLS = 100;
/** Origins that may be checked for well-known specification paths, and the total probe budget. */
const MAX_SPEC_PROBE_ORIGINS = 25;
const MAX_SPEC_PROBE_URLS = 200;
const MAX_SECURITY_TARGETS = 200;
const MAX_SECRET_ARTIFACTS = 300;
const MAX_CORR_ASSETS = 2000;
const MAX_TAKEOVER_HOSTS = 300;
const MAX_LOGIN_ORIGINS = 25;
const MAX_FINGERPRINT_GROUP = 10;
const MAX_CORR_EDGES = 500;

function looksLikeJs(url: string): boolean {
  return /\.m?js(\?|$)/i.test(url);
}

function originOfUrl(raw: string): string | null {
  try {
    const u = new URL(raw);
    return `${u.protocol}//${u.host}`;
  } catch {
    return null;
  }
}

function looksLikeSpec(url: string): boolean {
  return /(^|\/)(openapi|swagger|api[-_]?docs)(\.json|\.yaml|\.yml)?(\?|$)|\/(openapi|swagger)\.(json|yaml|yml)(\?|$)/i.test(url);
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Deterministic ordering so a probe list is reproducible across runs. */
function sorted(values: Iterable<string>): string[] {
  return Array.from(values).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/**
 * ScanOrchestrator executes the implemented Phase 2 stages. It persists results through the
 * existing data model, records provider executions and coverage, retries retryable failures
 * with bounded exponential backoff, honors cancellation, and reconciles the scan status from
 * actual job outcomes (never from a provider's zero exit code alone).
 */
export class ScanOrchestrator {
  private readonly repo: Repository;
  private readonly workerId: string;
  private readonly maxAttempts: number;
  private readonly now: () => Date;
  private readonly sleep: (ms: number) => Promise<void>;
  private totals = { assetsCreated: 0, observations: 0, relationships: 0 };
  /** Wall-clock window of the stage currently executing, so coverage can persist its duration. */
  private stageClock: { stage: string; startedMs: number; startedAt: Date } | null = null;
  /**
   * Provider outcomes that a retry of the *current* stage must not repeat: permanent or
   * environmental results (unavailable source, skipped, blocked). Scoped to one runStageWithRetries
   * call, so a later explicit resume still re-evaluates them (e.g. a tool that has since been installed).
   */
  private settledProviders = new Map<string, ProviderOutcomeSummary>();

  constructor(private readonly deps: OrchestratorDeps) {
    this.repo = new Repository(deps.db);
    this.workerId = deps.workerId ?? `${hostname()}-${process.pid}`;
    this.maxAttempts = deps.maxAttempts ?? 3;
    this.now = deps.now ?? (() => new Date());
    this.sleep = deps.sleep ?? defaultSleep;
  }

  async runScan(scanId: string): Promise<ScanRunSummary> {
    const scan = await this.repo.getScan(scanId);
    if (!scan) throw new Error(`scan not found: ${scanId}`);
    const policyRow = await this.repo.getPolicyById(scan.policy_id);
    if (!policyRow) throw new Error(`policy not found for scan ${scanId}`);
    const policy = ScopePolicySchema.parse(policyRow.document) as ScopePolicy;

    if (scan.status === JobStatus.CANCELLED) {
      return this.summary(scan, []);
    }
    await this.repo.updateScanStatus(scanId, JobStatus.RUNNING);

    // Resume: re-queue failed jobs that still have attempts remaining.
    for (const job of await this.repo.getJobRows(scanId)) {
      if ((job.status === JobStatus.FAILED || job.status === JobStatus.SOURCE_UNAVAILABLE) && job.attempts < job.max_attempts) {
        await this.repo.requeueJob(scanId, job.job_key, this.now());
      }
    }

    const jobs = await this.repo.getJobRows(scanId);
    // Execute in the declared pipeline order, not lexicographic job_key order (stage ids such as
    // "13-subdomain-takeover" and "14-login-finder" sort before "12-reporting" but must run after
    // it).
    const stageOrder = new Map<string, number>(OrderedStages.map((s, i) => [s as string, i]));
    jobs.sort((a, b) => (stageOrder.get(a.stage) ?? 999) - (stageOrder.get(b.stage) ?? 999));
    const scanStartedMs = this.now().getTime();
    // Record what this run actually used, so the report describes the executed run rather than
    // the configured defaults. Failure to annotate must not stop the scan.
    const profile = this.profile();
    try {
      await this.repo.mergeScanConfigSnapshot(scanId, {
        profile,
        providerOverrides: this.deps.providerOverrides ?? {},
        maxAttempts: this.maxAttempts,
        toolVersion: RECONNEXUS_VERSION,
      });
    } catch (err) {
      this.deps.logger.warn("could not record run profile", { scanId, error: (err as Error).message });
    }
    this.emitEvent({
      type: "scan-start",
      scanId,
      rootDomain: scan.root_domain,
      startUrl: scan.start_url,
      stages: jobs.length,
      stageIds: jobs.map((j) => j.stage),
      profile,
      startedAt: new Date(scanStartedMs).toISOString(),
    });
    const completed = new Set<string>();
    const stageSummaries: ScanRunSummary["stages"] = [];
    const terminalSuccess = new Set<string>([JobStatus.SUCCEEDED, JobStatus.PARTIAL, JobStatus.SKIPPED, JobStatus.CANCELLED]);

    for (const job of jobs) {
      if (terminalSuccess.has(job.status)) {
        completed.add(job.job_key);
        stageSummaries.push({ stage: job.stage, status: job.status, providers: [], reason: "completed before this run" });
        this.emitEvent({ type: "stage-end", stage: job.stage, status: job.status, durationMs: 0, records: 0, attempts: job.attempts, reason: "completed before this run" });
        continue;
      }
      const cancelled = await this.isCancelled(scanId);
      if (cancelled) {
        await this.repo.setJobStatus(scanId, job.job_key, JobStatus.CANCELLED);
        stageSummaries.push({ stage: job.stage, status: JobStatus.CANCELLED, providers: [] });
        this.emitEvent({ type: "stage-end", stage: job.stage, status: JobStatus.CANCELLED, durationMs: 0, records: 0, attempts: job.attempts });
        continue;
      }
      if (completed.has(job.job_key) || !this.dependenciesSatisfied(job, jobs, completed)) {
        // Dependencies failed or not yet satisfied.
        if (!this.dependenciesSatisfied(job, jobs, completed)) {
          await this.repo.setJobStatus(scanId, job.job_key, JobStatus.BLOCKED, "a prerequisite stage did not succeed");
          stageSummaries.push({ stage: job.stage, status: JobStatus.BLOCKED, providers: [], reason: "a prerequisite stage did not succeed" });
          this.emitEvent({ type: "stage-end", stage: job.stage, status: JobStatus.BLOCKED, durationMs: 0, records: 0, attempts: job.attempts, reason: "a prerequisite stage did not succeed" });
        }
        continue;
      }
      if (!IMPLEMENTED_STAGES.has(job.stage)) {
        await this.repo.setJobStatus(scanId, job.job_key, JobStatus.SKIPPED, "stage not implemented in this build (Phase 2 covers stages 00-03)");
        await upsertCoverageInternal(this.deps.db, { scanId, projectId: scan.project_id, stage: job.stage, status: "NOT_ATTEMPTED", expected: 0, collected: 0, notes: "not implemented in this build" });
        stageSummaries.push({ stage: job.stage, status: JobStatus.SKIPPED, providers: [], reason: "not implemented in this build" });
        completed.add(job.job_key);
        this.emitEvent({ type: "stage-end", stage: job.stage, status: JobStatus.SKIPPED, durationMs: 0, records: 0, attempts: job.attempts, reason: "not implemented in this build" });
        continue;
      }

      this.emitEvent({ type: "stage-start", stage: job.stage, attempt: job.attempts + 1 });
      const stageStartedAt = this.now();
      const stageStartedMs = stageStartedAt.getTime();
      this.stageClock = { stage: job.stage, startedMs: stageStartedMs, startedAt: stageStartedAt };
      const stageResult = await this.runStageWithRetries(scan, job, policy);
      const stageDurationMs = this.now().getTime() - stageStartedMs;
      this.stageClock = null;
      stageSummaries.push({
        stage: job.stage,
        status: stageResult.status,
        providers: stageResult.providers,
        durationMs: stageDurationMs,
        ...(stageResult.reason ? { reason: stageResult.reason } : {}),
      });
      completed.add(job.job_key);
      this.emitEvent({
        type: "stage-end",
        stage: job.stage,
        status: stageResult.status,
        durationMs: stageDurationMs,
        records: stageResult.providers.reduce((n, p) => n + p.records, 0),
        attempts: stageResult.attempts,
        ...(stageResult.reason ? { reason: stageResult.reason } : {}),
      });
    }

    const finalStatus = await this.reconcileScanStatus(scanId, scan);
    await this.repo.updateScanStatus(scanId, finalStatus);
    this.emitEvent({ type: "scan-end", status: finalStatus, durationMs: this.now().getTime() - scanStartedMs });
    return this.summary(scan, stageSummaries, finalStatus);
  }

  private summary(scan: ScanRow, stages: ScanRunSummary["stages"], status = scan.status): ScanRunSummary {
    return {
      scanId: scan.id,
      status,
      stages,
      assetsCreated: this.totals.assetsCreated,
      observations: this.totals.observations,
      relationships: this.totals.relationships,
      artifactsRoot: this.deps.config.artifacts.root,
      profile: this.profile(),
    };
  }

  /**
   * The provider-selection profile for this run: `default` when every stage uses its configured
   * provider set, `custom` when the caller overrode providers or the attempt budget.
   */
  private profile(): string {
    const overrides = this.deps.providerOverrides ?? {};
    const overridden = Object.keys(overrides).filter((k) => (overrides as Record<string, string[] | undefined>)[k]?.length);
    if (overridden.length === 0 && this.deps.maxAttempts === undefined) return "default";
    return "custom";
  }

  private emitEvent(event: OrchestratorEvent): void {
    try {
      this.deps.onEvent?.(event);
    } catch {
      /* progress rendering must never affect the scan */
    }
  }

  private async isCancelled(scanId: string): Promise<boolean> {
    if (this.deps.signal?.aborted) return true;
    const scan = await this.repo.getScan(scanId);
    return scan?.status === JobStatus.CANCELLED;
  }

  private dependenciesSatisfied(job: JobRow, all: JobRow[], completed: Set<string>): boolean {
    if (job.depends_on.length === 0) return true;
    return job.depends_on.every((dep) => {
      const depJob = all.find((j) => j.job_key === dep);
      if (!depJob) return true;
      return [JobStatus.SUCCEEDED, JobStatus.PARTIAL, JobStatus.SKIPPED].includes(depJob.status as never) || completed.has(dep);
    });
  }

  private async runStageWithRetries(
    scan: ScanRow,
    job: JobRow,
    policy: ScopePolicy,
  ): Promise<{ status: string; providers: ProviderOutcomeSummary[]; attempts: number; reason?: string }> {
    let lastProviders: ProviderOutcomeSummary[] = [];
    let attemptsUsed = job.attempts;
    this.settledProviders = new Map();
    // An explicit maxAttempts (scan --max-attempts) is the per-stage limit; otherwise the job's own.
    // Previously the stage predicate always compared against job.max_attempts, so the option could
    // neither lower nor raise the number of attempts that actually ran.
    const attemptCap = this.deps.maxAttempts ?? job.max_attempts;
    for (let attempt = job.attempts + 1; attempt <= attemptCap; attempt++) {
      attemptsUsed = attempt;
      if (await this.isCancelled(scan.id)) {
        await this.repo.setJobStatus(scan.id, job.job_key, JobStatus.CANCELLED);
        return { status: JobStatus.CANCELLED, providers: lastProviders, attempts: attemptsUsed };
      }
      const claimed = await this.repo.claimJob(scan.id, job.job_key, this.workerId, 300);
      if (!claimed) {
        const rows = await this.repo.getJobRows(scan.id);
        const current = rows.find((j) => j.job_key === job.job_key);
        return { status: current?.status ?? JobStatus.FAILED, providers: lastProviders, attempts: current?.attempts ?? attemptsUsed };
      }
      const result = await this.executeStage(scan, job, policy);
      lastProviders = result.providers;
      // Stage results are persisted by the stage itself (records, coverage, provider outcomes)
      // before the job is marked terminal, so a crash between the two never reports success for
      // data that was not written.
      // Retry policy (stage-level loop, provider-level work): a stage is retried when at least one
      // provider ended FAILED, whatever the stage-level aggregate is (FAILED, or PARTIAL because a
      // sibling succeeded). Providers that finished SUCCEEDED/PARTIAL are reused from their persisted
      // outcome, and SOURCE_UNAVAILABLE/SKIPPED/BLOCKED providers are settled for this run, so only
      // the FAILED providers execute again. See isRetryableProviderOutcome.
      const retryable = shouldRetryStage(result.providers);
      if (!retryable || attempt >= attemptCap) {
        const finished = result.status === JobStatus.SUCCEEDED || result.status === JobStatus.PARTIAL || result.status === JobStatus.SKIPPED || result.status === JobStatus.BLOCKED;
        if (finished) await this.repo.setJobStatus(scan.id, job.job_key, result.status);
        else await this.repo.setJobStatus(scan.id, job.job_key, result.status, result.reason ?? result.status);
        return { ...result, attempts: attemptsUsed };
      }
      const backoff = Math.min(30000, 500 * 2 ** (attempt - 1)) + Math.floor(Math.random() * 250);
      this.deps.logger.warn("stage failed; retrying", { scanId: scan.id, stage: job.stage, attempt, backoffMs: backoff });
      this.emitEvent({ type: "stage-retry", stage: job.stage, attempt, backoffMs: backoff });
      await this.repo.requeueJob(scan.id, job.job_key, this.now());
      await this.sleep(backoff);
    }
    await this.repo.setJobStatus(scan.id, job.job_key, JobStatus.FAILED, "exhausted retries");
    return { status: JobStatus.FAILED, providers: lastProviders, attempts: attemptsUsed, reason: "exhausted retries" };
  }

  private async executeStage(scan: ScanRow, job: JobRow, policy: ScopePolicy): Promise<{ status: string; providers: ProviderOutcomeSummary[]; reason?: string }> {
    switch (job.stage) {
      case StageId.TARGET_INTELLIGENCE:
        return this.runTargetIntelligence(scan, job);
      case StageId.SUBDOMAIN_DISCOVERY:
        return this.runSubdomainDiscovery(scan, job, policy);
      case StageId.DNS_INFRA:
        return this.runDnsInfra(scan, job, policy);
      case StageId.HTTP_PROBE:
        return this.runHttpProbe(scan, job, policy);
      case StageId.URL_COLLECTION:
        return this.runUrlCollection(scan, job, policy);
      case StageId.URL_CATEGORIZATION:
        return this.runUrlCategorization(scan, job);
      case StageId.JS_INTELLIGENCE:
        return this.runJsIntelligence(scan, job, policy);
      case StageId.API_DISCOVERY:
        return this.runApiDiscovery(scan, job, policy);
      case StageId.SECRET_DETECTION:
        return this.runSecretDetection(scan, job, policy);
      case StageId.TAKEOVER:
        return this.runTakeover(scan, job, policy);
      case StageId.LOGIN_FINDER:
        return this.runLoginFinder(scan, job, policy);
      case StageId.SECURITY_CHECKS:
        return this.runSecurityChecks(scan, job, policy);
      case StageId.CORRELATION:
        return this.runCorrelation(scan, job);
      case StageId.REPORTING:
        return this.runReporting(scan, job);
      default:
        return { status: JobStatus.SKIPPED, providers: [] };
    }
  }

  /**
   * Stage 12 — deterministic, evidence-backed reporting. Builds a redacted report from persisted
   * state, re-applies redaction at the report boundary (fail-closed), and persists a single
   * `report` observation on the root domain asset (delete+insert ⇒ idempotent). It does not change
   * upstream coverage or scan status. On redaction failure it fails closed and records MISSING
   * coverage rather than persisting an unredacted report.
   */
  private async runReporting(scan: ScanRow, job: JobRow): Promise<{ status: string; providers: ProviderOutcomeSummary[]; reason?: string }> {
    let redacted: Report;
    try {
      const report = await buildReport(this.repo, scan.id, { now: this.now() });
      if (!report) throw new ReportRedactionError("scan not found");
      redacted = redactReport(report, (this.deps.redactor as Redactor | undefined) ?? undefined);
    } catch (err) {
      this.deps.logger.error("reporting failed closed", { scanId: scan.id, error: (err as Error).message });
      await this.deps.db.withTransaction((c) =>
        upsertCoverageInternal(c, { scanId: scan.id, projectId: scan.project_id, stage: job.stage, status: "MISSING", expected: 1, collected: 0, notes: "report generation failed (redaction fail-closed)" }),
      );
      return { status: JobStatus.FAILED, providers: [], reason: "report generation failed" };
    }

    const now = this.now();
    await this.deps.db.withTransaction(async (client) => {
      await client.query("DELETE FROM observations WHERE scan_id = $1 AND kind = 'report'", [scan.id]);
      const a = await upsertAsset(client, { projectId: scan.project_id, type: "DOMAIN", canonicalKey: scan.root_domain, value: scan.root_domain, seenAt: now });
      await insertObservation(client, {
        projectId: scan.project_id,
        scanId: scan.id,
        assetId: a.id,
        source: "stage-12-reporting",
        sourceReliability: "AUTHORITATIVE",
        observedAt: now,
        kind: "report",
        data: redacted as unknown as Record<string, unknown>,
      });
      await upsertCoverageInternal(client, {
        scanId: scan.id,
        projectId: scan.project_id,
        stage: job.stage,
        status: "COLLECTED",
        expected: 1,
        collected: 1,
        notes: `reportStatus=${redacted.reportStatus}`,
        details: { reportStatus: redacted.reportStatus, secretFindings: redacted.secretFindings.length, correlations: redacted.correlations.length, ...this.stageTiming(job.stage) },
      });
    });
    return { status: JobStatus.SUCCEEDED, providers: [] };
  }

  /**
   * Stage 11 — deterministic, evidence-backed correlation over persisted records. It does NOT
   * recreate the asset graph built inline during ingestion (host→IP, service→certificate,
   * url→endpoint, …). It adds the dimensions not established inline:
   *   1. secret-fingerprint equivalence across artifacts (keyed HMAC fingerprints only);
   *   2. multi-source corroboration (the same asset observed by ≥2 distinct sources);
   *   3. a coverage-gap summary.
   * It performs no network requests, never uses or verifies credentials, and never promotes a
   * candidate secret into a validated/active finding. Results are derived purely from persisted
   * records, so runs are idempotent and reproducible.
   */
  private async runCorrelation(scan: ScanRow, job: JobRow): Promise<{ status: string; providers: ProviderOutcomeSummary[]; reason?: string }> {
    if (this.deps.signal?.aborted) {
      await this.repo.setJobStatus(scan.id, job.job_key, JobStatus.CANCELLED);
      return { status: JobStatus.CANCELLED, providers: [] };
    }
    const findings = await this.repo.listSecretFingerprintFindings(scan.id);
    const keyed = new Map((await this.repo.listArtifactHmacKeyed(scan.id)).map((r) => [r.artifact, r.hmac_keyed]));
    const corroboration = await this.repo.listAssetCorroboration(scan.id, MAX_CORR_ASSETS);
    const coverage = await this.repo.listCoverage(scan.id);

    if (findings.length === 0 && corroboration.length === 0) {
      await this.deps.db.withTransaction((c) =>
        upsertCoverageInternal(c, { scanId: scan.id, projectId: scan.project_id, stage: job.stage, status: "NOT_ATTEMPTED", expected: 0, collected: 0, notes: "no persisted records to correlate" }),
      );
      return { status: JobStatus.SKIPPED, providers: [], reason: "no records" };
    }

    let groups = 0;
    let edges = 0;
    let corroborated = 0;
    let truncated = false;
    let groupSeq = 0;

    await this.deps.db.withTransaction(async (client) => {
      // Idempotency: correlation observations are fully derived, so replace them each run.
      await client.query("DELETE FROM observations WHERE scan_id = $1 AND kind = 'correlation'", [scan.id]);

      // 1. Secret-fingerprint equivalence. Only non-empty, HMAC-keyed fingerprints correlate.
      const byGroup = new Map<string, { ruleId: string; fingerprint: string; items: Map<string, { observationId: string; artifact: string }> }>();
      for (const f of findings) {
        if (!f.fingerprint) continue; // empty fingerprint never correlates
        if (keyed.get(f.artifact) !== true) continue; // provenance must be keyed
        const key = `${f.rule_id}\u0000${f.fingerprint}`;
        const g = byGroup.get(key) ?? { ruleId: f.rule_id, fingerprint: f.fingerprint, items: new Map() };
        if (!g.items.has(f.asset_id)) g.items.set(f.asset_id, { observationId: f.observation_id, artifact: f.artifact });
        byGroup.set(key, g);
      }

      const sortedGroups = Array.from(byGroup.values()).sort((a, b) => (a.ruleId + a.fingerprint < b.ruleId + b.fingerprint ? -1 : 1));
      for (const g of sortedGroups) {
        const assets = Array.from(g.items.entries()).sort((a, b) => (a[0] < b[0] ? -1 : 1));
        if (assets.length < 2) continue;
        if (edges >= MAX_CORR_EDGES) {
          truncated = true;
          break;
        }
        groups++;
        groupSeq++;
        const correlationGroup = sha256Hex(`${g.ruleId}|${g.fingerprint}`).slice(0, 16);
        const subjectKey = assets[0]![1].artifact;
        const relatedKeys = assets.slice(1).map(([, v]) => v.artifact);
        const pairs: Array<[string, string]> = [];
        if (assets.length <= MAX_FINGERPRINT_GROUP) {
          for (let i = 0; i < assets.length; i++) {
            for (let j = i + 1; j < assets.length; j++) pairs.push([assets[i]![0], assets[j]![0]]);
          }
        } else {
          truncated = true;
          for (let j = 1; j < assets.length; j++) pairs.push([assets[0]![0], assets[j]![0]]);
        }
        for (const [from, to] of pairs) {
          if (edges >= MAX_CORR_EDGES) {
            truncated = true;
            break;
          }
          await upsertRelationship(client, { projectId: scan.project_id, fromAssetId: from, toAssetId: to, relation: "shares_secret_fingerprint", confidence: 0.9, source: "stage-11-correlation" });
          edges++;
        }
        const rec: CorrelationRecord = {
          relation: "SHARES_SECRET_FINGERPRINT",
          status: "OBSERVED",
          subject: subjectKey,
          related: relatedKeys,
          ruleId: g.ruleId,
          hmacKeyed: true,
          correlationGroup,
          sourceRecordIds: assets.map(([, v]) => v.observationId),
          sourceStage: "11-correlation",
          evidence: `rule ${g.ruleId}; correlation group ${correlationGroup} (${assets.length} artifacts)`,
          confidence: 0.9,
        };
        CorrelationRecordSchema.parse(rec);
        await insertObservation(client, { projectId: scan.project_id, scanId: scan.id, assetId: assets[0]![0], source: "stage-11-correlation", sourceReliability: "HIGH", observedAt: this.now(), kind: "correlation", data: rec as unknown as Record<string, unknown> });
        void groupSeq;
      }

      // 2. Multi-source corroboration (cross-provider duplicate detection).
      for (const a of corroboration) {
        const sources = [...a.sources].sort();
        const rec: CorrelationRecord = {
          relation: "MULTI_SOURCE_CORROBORATION",
          status: "OBSERVED",
          subject: a.canonical_key,
          related: sources,
          ruleId: "",
          hmacKeyed: false,
          correlationGroup: "",
          sourceRecordIds: [],
          sourceStage: "11-correlation",
          evidence: `asset observed by ${sources.length} sources: ${sources.join(", ")}`,
          confidence: 0.6,
        };
        CorrelationRecordSchema.parse(rec);
        await insertObservation(client, { projectId: scan.project_id, scanId: scan.id, assetId: a.asset_id, source: "stage-11-correlation", sourceReliability: "HIGH", observedAt: this.now(), kind: "correlation", data: rec as unknown as Record<string, unknown> });
        corroborated++;
      }

      // 3. Coverage-gap summary.
      const gaps = coverage.filter((c) => c.status !== "COLLECTED" && c.stage !== job.stage).map((c) => `${c.stage}:${c.status}`);
      await upsertCoverageInternal(client, {
        scanId: scan.id,
        projectId: scan.project_id,
        stage: job.stage,
        status: truncated ? "PARTIAL" : "COLLECTED",
        expected: findings.length + corroboration.length,
        collected: groups + corroborated,
        notes: `secretGroups=${groups} edges=${edges} corroborated=${corroborated}${truncated ? " (truncated)" : ""}`,
        details: { secretGroups: groups, edges, corroborated, coverageGaps: gaps, ...this.stageTiming(job.stage) },
      });
    });

    return { status: truncated ? JobStatus.PARTIAL : JobStatus.SUCCEEDED, providers: [] };
  }

  /**
   * Stage 09 — secret detection. Eligible artifacts are the persisted JS artifacts and API
   * specifications from stages 07/08. Raw artifact bodies are intentionally not persisted
   * (secret-safety); the worker re-collects eligible content in-memory through the connection-bound
   * transport and persists only redacted findings with a keyed fingerprint.
   */
  private async runSecretDetection(scan: ScanRow, job: JobRow, policy: ScopePolicy): Promise<{ status: string; providers: ProviderOutcomeSummary[]; reason?: string }> {
    const js = await this.repo.listJsArtifacts(scan.id);
    const specs = await this.repo.listApiSpecs(scan.id);
    const artifactSet = new Set<string>();
    for (const a of js) if (a.url) artifactSet.add(a.url);
    for (const s of specs) if (s.url) artifactSet.add(s.url);
    const artifactUrls = Array.from(artifactSet).slice(0, MAX_SECRET_ARTIFACTS);
    if (artifactUrls.length === 0) {
      await this.deps.db.withTransaction((c) => upsertCoverageInternal(c, { scanId: scan.id, projectId: scan.project_id, stage: job.stage, status: "NOT_ATTEMPTED", expected: 0, collected: 0, notes: "no eligible artifacts to scan" }));
      return { status: JobStatus.SKIPPED, providers: [], reason: "no artifacts" };
    }
    const outcomes: ProviderOutcomeSummary[] = [];
    for (const provider of this.providersFor(DiscoveryJobKind.SECRET_SCAN)) {
      outcomes.push(await this.runProvider({ scan, job, policy, kind: DiscoveryJobKind.SECRET_SCAN, provider, inputs: { artifactUrls } }));
    }
    const status = aggregate(outcomes.map((o) => o.outcome));
    await this.writeStageCoverage(scan, job, status, outcomes);
    return { status, providers: outcomes };
  }

  /**
   * Stage 06 — URL categorization. Classification is computed during URL collection (stage 05);
   * this stage materializes the categorization dimension as coverage and confirms every discovered
   * URL carries at least one classification. It performs no network requests.
   */
  private async runUrlCategorization(scan: ScanRow, job: JobRow): Promise<{ status: string; providers: ProviderOutcomeSummary[]; reason?: string }> {
    const rows = await this.repo.listUrlObservations(scan.id);
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
    await this.deps.db.withTransaction((c) =>
      upsertCoverageInternal(c, {
        scanId: scan.id,
        projectId: scan.project_id,
        stage: job.stage,
        status: cov,
        expected: total,
        collected: classified,
        notes: total === 0 ? "no URLs to categorize" : `${classified}/${total} URLs classified`,
        details: { byCategory, ...this.stageTiming(job.stage) },
      }),
    );
    return { status, providers: [] };
  }

  /**
   * Stage 13 — non-destructive subdomain-takeover detection. Seeds the discovered in-scope
   * subdomains; the worker resolves each CNAME, matches a takeover-prone service, and issues one
   * bounded HTTP request to look for that service's unclaimed marker. Candidate-only.
   */
  private async runTakeover(scan: ScanRow, job: JobRow, policy: ScopePolicy): Promise<{ status: string; providers: ProviderOutcomeSummary[]; reason?: string }> {
    const hostAssets = await this.repo.listAssets(scan.project_id, ["SUBDOMAIN", "HOST"]);
    const hosts = Array.from(new Set(hostAssets.map((a) => a.value)))
      .filter((h) => h === scan.root_domain || h.endsWith(`.${scan.root_domain}`))
      .slice(0, MAX_TAKEOVER_HOSTS);
    if (hosts.length === 0) {
      await this.deps.db.withTransaction((c) => upsertCoverageInternal(c, { scanId: scan.id, projectId: scan.project_id, stage: job.stage, status: "NOT_ATTEMPTED", expected: 0, collected: 0, notes: "no in-scope hosts to check" }));
      return { status: JobStatus.SKIPPED, providers: [], reason: "no hosts" };
    }
    const urls = hosts.map((h) => `https://${h}/`);
    const outcomes: ProviderOutcomeSummary[] = [];
    for (const provider of this.providersFor(DiscoveryJobKind.TAKEOVER)) {
      outcomes.push(await this.runProvider({ scan, job, policy, kind: DiscoveryJobKind.TAKEOVER, provider, inputs: { urls } }));
    }
    const status = aggregate(outcomes.map((o) => o.outcome));
    await this.writeStageCoverage(scan, job, status, outcomes);
    return { status, providers: outcomes };
  }

  /**
   * Stage 14 — read-only admin-login and cPanel/WHM/webmail interface discovery. Seeds the
   * origins observed during HTTP probing and asks the worker to request a small, fixed set of
   * well-known administrative paths and control-panel ports. No credentials are submitted and
   * every candidate URL is reauthorized by the worker.
   */
  private async runLoginFinder(scan: ScanRow, job: JobRow, policy: ScopePolicy): Promise<{ status: string; providers: ProviderOutcomeSummary[]; reason?: string }> {
    const probes = await this.repo.listHttpObservations(scan.id);
    const origins = new Set<string>();
    for (const p of probes) {
      if (p.probe_status === "OK" || p.probe_status === "OVERSIZED" || p.probe_status === "REDIRECT_DENIED") {
        const o = originOfUrl(p.final_url || p.url);
        if (o) origins.add(o);
      }
    }
    const urls = Array.from(origins).sort().slice(0, MAX_LOGIN_ORIGINS);
    if (urls.length === 0) {
      await this.deps.db.withTransaction((c) =>
        upsertCoverageInternal(c, { scanId: scan.id, projectId: scan.project_id, stage: job.stage, status: "NOT_ATTEMPTED", expected: 0, collected: 0, notes: "no eligible HTTP origins observed" }),
      );
      return { status: JobStatus.SKIPPED, providers: [], reason: "no origins" };
    }
    const outcomes: ProviderOutcomeSummary[] = [];
    for (const provider of this.providersFor(DiscoveryJobKind.LOGIN_FINDER)) {
      outcomes.push(await this.runProvider({ scan, job, policy, kind: DiscoveryJobKind.LOGIN_FINDER, provider, inputs: { urls } }));
    }
    const status = aggregate(outcomes.map((o) => o.outcome));
    await this.writeStageCoverage(scan, job, status, outcomes);
    return { status, providers: outcomes };
  }

  private async runSecurityChecks(scan: ScanRow, job: JobRow, policy: ScopePolicy): Promise<{ status: string; providers: ProviderOutcomeSummary[]; reason?: string }> {
    const probes = await this.repo.listHttpObservations(scan.id);
    const originSet = new Set<string>();
    for (const p of probes) {
      if (p.probe_status === "OK" || p.probe_status === "OVERSIZED" || p.probe_status === "REDIRECT_DENIED") {
        const o = originOfUrl(p.final_url || p.url);
        if (o) originSet.add(o);
      }
    }
    const urls = Array.from(originSet).slice(0, MAX_SECURITY_TARGETS);
    if (urls.length === 0) {
      await this.deps.db.withTransaction((c) => upsertCoverageInternal(c, { scanId: scan.id, projectId: scan.project_id, stage: job.stage, status: "NOT_ATTEMPTED", expected: 0, collected: 0, notes: "no eligible HTTP services observed" }));
      return { status: JobStatus.SKIPPED, providers: [], reason: "no services" };
    }
    const outcomes: ProviderOutcomeSummary[] = [];
    for (const provider of this.providersFor(DiscoveryJobKind.SECURITY_META)) {
      outcomes.push(await this.runProvider({ scan, job, policy, kind: DiscoveryJobKind.SECURITY_META, provider, inputs: { urls } }));
    }
    const status = aggregate(outcomes.map((o) => o.outcome));
    await this.writeStageCoverage(scan, job, status, outcomes);
    return { status, providers: outcomes };
  }

  private async runJsIntelligence(scan: ScanRow, job: JobRow, policy: ScopePolicy): Promise<{ status: string; providers: ProviderOutcomeSummary[]; reason?: string }> {
    const rows = await this.repo.listUrlObservations(scan.id);
    const jsSet = new Set<string>();
    for (const r of rows) {
      const data = r.data as { url?: string; scriptRef?: boolean; classifications?: Array<{ category: string }> };
      // Only URLs classified JAVASCRIPT, referenced by a <script src>, or with a script extension
      // are analysed. STATIC_ASSET covers images, CSS, fonts and video, and feeding those here made
      // the JS stage fetch and "analyse" a WordPress .jpg. Non-script content is re-checked in the
      // worker (defence in depth) so a misclassification cannot cause binary parsing.
      const isJs = (data.classifications ?? []).some((c) => c.category === "JAVASCRIPT") || data.scriptRef === true;
      if (isJs || looksLikeJs(r.url)) jsSet.add(r.url);
    }
    const jsUrls = Array.from(jsSet).slice(0, MAX_JS_URLS);
    if (jsUrls.length === 0) {
      await this.deps.db.withTransaction((c) => upsertCoverageInternal(c, { scanId: scan.id, projectId: scan.project_id, stage: job.stage, status: "NOT_ATTEMPTED", expected: 0, collected: 0, notes: "no JavaScript URLs discovered" }));
      return { status: JobStatus.SKIPPED, providers: [], reason: "no JS URLs" };
    }
    const outcomes: ProviderOutcomeSummary[] = [];
    for (const provider of this.providersFor(DiscoveryJobKind.JS_ANALYSIS)) {
      outcomes.push(await this.runProvider({ scan, job, policy, kind: DiscoveryJobKind.JS_ANALYSIS, provider, inputs: { jsUrls, fetchSourceMaps: true } }));
    }
    const status = aggregate(outcomes.map((o) => o.outcome));
    await this.writeStageCoverage(scan, job, status, outcomes);
    return { status, providers: outcomes };
  }

  private async runApiDiscovery(scan: ScanRow, job: JobRow, policy: ScopePolicy): Promise<{ status: string; providers: ProviderOutcomeSummary[]; reason?: string }> {
    const rows = await this.repo.listUrlObservations(scan.id);
    const specSet = new Set<string>();
    for (const r of rows) {
      const data = r.data as { classifications?: Array<{ category: string }> };
      const isSpec = (data.classifications ?? []).some((c) => c.category === "API_SPEC" || c.category === "DOCUMENTATION");
      if (isSpec || looksLikeSpec(r.url)) specSet.add(r.url);
    }
    const specUrls = Array.from(specSet).slice(0, MAX_SPEC_URLS);
    const specProbeUrls = await this.specProbeCandidates(scan, policy, specSet);

    if (specUrls.length === 0 && specProbeUrls.length === 0) {
      await this.deps.db.withTransaction((c) => upsertCoverageInternal(c, { scanId: scan.id, projectId: scan.project_id, stage: job.stage, status: "NOT_ATTEMPTED", expected: 0, collected: 0, notes: "no API specification URLs discovered and no origin showed evidence of an API" }));
      return { status: JobStatus.SKIPPED, providers: [], reason: "no spec URLs" };
    }

    const outcomes: ProviderOutcomeSummary[] = [];
    for (const provider of this.providersFor(DiscoveryJobKind.API_SPEC)) {
      outcomes.push(await this.runProvider({ scan, job, policy, kind: DiscoveryJobKind.API_SPEC, provider, inputs: { specUrls, specProbeUrls } }));
    }
    const status = aggregate(outcomes.map((o) => o.outcome));
    await this.writeStageCoverage(scan, job, status, outcomes, {
      referencedSpecUrls: specUrls.length,
      probedWellKnownPaths: specProbeUrls.length,
    });
    return { status, providers: outcomes };
  }

  /**
   * Well-known specification paths to check on an origin that shows evidence of an API. These are
   * speculative — nothing referenced them — so the worker records an absent one as coverage only.
   */
  private static readonly WELL_KNOWN_SPEC_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/api/openapi.json",
    "/.well-known/openapi.json",
  ];

  /** Hostname tokens that, on their own, suggest an origin serves an API. */
  private static readonly API_HOST_TOKENS = ["api", "apigateway", "apigw", "gateway", "graphql", "rest", "service", "services"];

  /**
   * Builds the speculative probe list. Origins are ranked by the strength of the evidence that an
   * API lives there — endpoints already discovered in JavaScript first, then API-shaped hostnames,
   * then the authorized root origins — and the list is capped so a wide subdomain enumeration
   * cannot turn this stage into a sweep. Probing is skipped entirely when the policy does not
   * authorize API discovery.
   */
  private async specProbeCandidates(scan: ScanRow, policy: ScopePolicy, alreadyDiscovered: Set<string>): Promise<string[]> {
    if (!policy.authorization.capabilities.includes("API_DISCOVERY" as never)) return [];

    const inScope = (host: string): boolean => host === scan.root_domain || host.endsWith(`.${scan.root_domain}`);
    const hostOf = (origin: string): string => {
      try {
        return new URL(origin).hostname;
      } catch {
        return "";
      }
    };

    // Tier 1: origins hosting an endpoint discovered in JavaScript — the strongest evidence.
    const endpointOrigins = new Set<string>();
    for (const e of await this.repo.listApiEndpoints(scan.id)) {
      const data = e.data as { origin?: unknown; url?: unknown };
      const raw = typeof data.origin === "string" && data.origin ? data.origin : typeof data.url === "string" ? data.url : "";
      const origin = raw ? originOfUrl(raw) : null;
      if (origin && inScope(hostOf(origin))) endpointOrigins.add(origin);
    }

    // Tiers 2 and 3 come from origins that actually answered an HTTP probe.
    const apiNamed = new Set<string>();
    const rootOrigins = new Set<string>();
    for (const p of await this.repo.listHttpObservations(scan.id)) {
      if (p.probe_status !== "OK" && p.probe_status !== "OVERSIZED") continue;
      const origin = originOfUrl(p.final_url || p.url);
      if (!origin) continue;
      const host = hostOf(origin);
      if (!host || !inScope(host)) continue;
      if (endpointOrigins.has(origin)) continue;
      const labels = host.split(".");
      if (labels.some((l) => ScanOrchestrator.API_HOST_TOKENS.includes(l)) || /(^|[-.])api([-.]|\d|$)/.test(host)) apiNamed.add(origin);
      else if (host === scan.root_domain || host === `www.${scan.root_domain}`) rootOrigins.add(origin);
    }

    const ranked = [...sorted(endpointOrigins), ...sorted(apiNamed), ...sorted(rootOrigins)].slice(0, MAX_SPEC_PROBE_ORIGINS);
    const candidates: string[] = [];
    for (const origin of ranked) {
      for (const path of ScanOrchestrator.WELL_KNOWN_SPEC_PATHS) {
        const candidate = `${origin}${path}`;
        if (alreadyDiscovered.has(candidate)) continue;
        candidates.push(candidate);
        if (candidates.length >= MAX_SPEC_PROBE_URLS) return candidates;
      }
    }
    return candidates;
  }

  private async runUrlCollection(scan: ScanRow, job: JobRow, policy: ScopePolicy): Promise<{ status: string; providers: ProviderOutcomeSummary[]; reason?: string }> {
    // Seed from HTTP observations that got a response; fall back to resolved hosts.
    const probes = await this.repo.listHttpObservations(scan.id);
    const seedSet = new Set<string>();
    for (const p of probes) {
      if (p.probe_status === "OK" || p.probe_status === "OVERSIZED") {
        seedSet.add(p.final_url || p.url);
      }
    }
    if (seedSet.size === 0) {
      const hosts = (await this.repo.listResolvedHosts(scan.project_id, MAX_HTTP_HOSTS)).filter(
        (h) => h === scan.root_domain || h.endsWith(`.${scan.root_domain}`),
      );
      for (const h of hosts) seedSet.add(`https://${h}/`);
    }
    const seedUrls = Array.from(seedSet).slice(0, MAX_SEED_URLS);

    if (seedUrls.length === 0) {
      await this.deps.db.withTransaction((c) =>
        upsertCoverageInternal(c, { scanId: scan.id, projectId: scan.project_id, stage: job.stage, status: "NOT_ATTEMPTED", expected: 0, collected: 0, notes: "no eligible seed URLs for collection" }),
      );
      return { status: JobStatus.SKIPPED, providers: [], reason: "no seed URLs" };
    }

    const inputs = {
      seedUrls,
      domains: [scan.root_domain],
      crawlDepth: policy.limits.crawlDepth,
      requestBudget: MAX_CRAWL_REQUESTS,
    };
    const outcomes: ProviderOutcomeSummary[] = [];
    for (const provider of this.providersFor(DiscoveryJobKind.URL_COLLECTION)) {
      outcomes.push(await this.runProvider({ scan, job, policy, kind: DiscoveryJobKind.URL_COLLECTION, provider, inputs }));
    }
    const status = aggregate(outcomes.map((o) => o.outcome));
    await this.writeStageCoverage(scan, job, status, outcomes);
    return { status, providers: outcomes };
  }

  private async runHttpProbe(scan: ScanRow, job: JobRow, policy: ScopePolicy): Promise<{ status: string; providers: ProviderOutcomeSummary[]; reason?: string }> {
    // Eligible targets are discovered hosts that were resolved in the DNS stage and remain in
    // the authorized registrable domain. Each host is reauthorized inside the worker.
    const resolvedHosts = await this.repo.listResolvedHosts(scan.project_id, MAX_HTTP_HOSTS);
    const hosts = resolvedHosts.filter((h) => h === scan.root_domain || h.endsWith(`.${scan.root_domain}`));

    const outcomes: ProviderOutcomeSummary[] = [];
    if (hosts.length === 0) {
      await this.deps.db.withTransaction((c) =>
        upsertCoverageInternal(c, { scanId: scan.id, projectId: scan.project_id, stage: job.stage, status: "NOT_ATTEMPTED", expected: 0, collected: 0, notes: "no resolved in-scope hosts to probe" }),
      );
      return { status: JobStatus.SKIPPED, providers: outcomes, reason: "no eligible hosts" };
    }

    const urls: string[] = [];
    for (const h of hosts) {
      urls.push(`https://${h}/`);
      if (urls.length >= MAX_HTTP_TARGETS) break;
      urls.push(`http://${h}/`);
      if (urls.length >= MAX_HTTP_TARGETS) break;
    }

    for (const provider of this.providersFor(DiscoveryJobKind.HTTP_PROBE)) {
      outcomes.push(await this.runProvider({ scan, job, policy, kind: DiscoveryJobKind.HTTP_PROBE, provider, inputs: { urls } }));
    }

    const status = aggregate(outcomes.map((o) => o.outcome));
    await this.writeStageCoverage(scan, job, status, outcomes);
    return { status, providers: outcomes };
  }

  private async runTargetIntelligence(scan: ScanRow, job: JobRow): Promise<{ status: string; providers: ProviderOutcomeSummary[]; reason?: string }> {
    const now = this.now();
    await this.deps.db.withTransaction(async (client) => {
      const a = await upsertAsset(client, { projectId: scan.project_id, type: "DOMAIN", canonicalKey: scan.root_domain, value: scan.root_domain, seenAt: now });
      if (a.inserted) this.totals.assetsCreated++;
      await insertObservation(client, { projectId: scan.project_id, scanId: scan.id, assetId: a.id, source: "control-plane", sourceReliability: "AUTHORITATIVE", observedAt: now, kind: "target", data: { startUrl: scan.start_url, rootDomain: scan.root_domain } });
      this.totals.observations++;
      await upsertCoverageInternal(client, { scanId: scan.id, projectId: scan.project_id, stage: job.stage, status: "COLLECTED", expected: 1, collected: 1, notes: "root target recorded", details: this.stageTiming(job.stage) });
    });
    return { status: JobStatus.SUCCEEDED, providers: [] };
  }

  private providersFor(kind: DiscoveryJobKindValue): string[] {
    const override = this.deps.providerOverrides?.[kind];
    const names = override ?? DEFAULT_PROVIDERS[kind];
    return names.filter((n) => this.deps.config.providers[n]?.enabled !== false);
  }

  private async runSubdomainDiscovery(scan: ScanRow, job: JobRow, policy: ScopePolicy): Promise<{ status: string; providers: ProviderOutcomeSummary[]; reason?: string }> {
    const providers = this.providersFor(DiscoveryJobKind.SUBDOMAINS);
    const outcomes: ProviderOutcomeSummary[] = [];
    for (const provider of providers) {
      const outcome = await this.runProvider({
        scan,
        job,
        policy,
        kind: DiscoveryJobKind.SUBDOMAINS,
        provider,
        inputs: { rootDomain: scan.root_domain },
      });
      outcomes.push(outcome);
    }
    const status = aggregate(outcomes.map((o) => o.outcome));
    await this.writeStageCoverage(scan, job, status, outcomes);
    return { status, providers: outcomes };
  }

  private async runDnsInfra(scan: ScanRow, job: JobRow, policy: ScopePolicy): Promise<{ status: string; providers: ProviderOutcomeSummary[]; reason?: string }> {
    const now = this.now();
    // Gather discovered hostnames and drop any that leave the authorized registrable domain.
    const hostAssets = await this.repo.listAssets(scan.project_id, ["SUBDOMAIN", "HOST"]);
    const names = Array.from(new Set(hostAssets.map((a) => a.value)))
      .filter((h) => h === scan.root_domain || h.endsWith(`.${scan.root_domain}`))
      .slice(0, MAX_NAMES);

    const outcomes: ProviderOutcomeSummary[] = [];
    if (names.length === 0) {
      await this.deps.db.withTransaction((c) => upsertCoverageInternal(c, { scanId: scan.id, projectId: scan.project_id, stage: job.stage, status: "NOT_ATTEMPTED", expected: 0, collected: 0, notes: "no in-scope hosts to resolve" }));
      return { status: JobStatus.SKIPPED, providers: outcomes, reason: "no discovered hosts" };
    }

    for (const provider of this.providersFor(DiscoveryJobKind.DNS)) {
      outcomes.push(await this.runProvider({ scan, job, policy, kind: DiscoveryJobKind.DNS, provider, inputs: { names } }));
    }

    // Correlate infrastructure only for addresses of in-scope hosts (relationships established
    // by the DNS stage). Discovered IPs are never treated as authorized active targets.
    const pairs = await this.repo.listResolvedIpHostPairs(scan.project_id, MAX_ADDRESSES);
    if (pairs.length > 0) {
      for (const provider of this.providersFor(DiscoveryJobKind.IP_METADATA)) {
        outcomes.push(
          await this.runProvider({
            scan,
            job,
            policy,
            kind: DiscoveryJobKind.IP_METADATA,
            provider,
            inputs: { addresses: pairs.map((p) => ({ ip: p.ip, viaHost: p.host })) },
          }),
        );
      }
    } else {
      this.deps.logger.info("no resolved addresses to correlate", { scanId: scan.id });
    }

    const status = aggregate(outcomes.map((o) => o.outcome));
    await this.writeStageCoverage(scan, job, status, outcomes);
    void now;
    return { status, providers: outcomes };
  }

  private async runProvider(args: {
    scan: ScanRow;
    job: JobRow;
    policy: ScopePolicy;
    kind: DiscoveryJobKindValue;
    provider: string;
    inputs: DiscoveryJob["inputs"];
  }): Promise<ProviderOutcomeSummary> {
    const { scan, job, policy, kind, provider, inputs } = args;

    // Idempotency: reuse a provider that already produced results for this stage. A reused result
    // reports no duration (it was not measured in this run) rather than a misleading zero.
    const existing = (await this.repo.listProviderOutcomes(scan.id)).find((o) => o.stage === job.stage && o.provider === provider);
    if (existing && (existing.outcome === JobStatus.SUCCEEDED || existing.outcome === JobStatus.PARTIAL)) {
      this.emitEvent({
        type: "provider-end",
        stage: job.stage,
        provider,
        status: existing.outcome,
        records: existing.records_count,
        durationMs: 0,
        recordsByType: {},
        reused: true,
      });
      return {
        stage: job.stage,
        provider,
        outcome: existing.outcome,
        records: existing.records_count,
        reason: "reused previous result",
        providerVersion: existing.provider_version ?? "",
        durationMs: null,
        timedOut: false,
        truncated: false,
      };
    }

    const settled = this.settledProviders.get(`${job.stage}\u0000${provider}`);
    if (settled) {
      this.emitEvent({ type: "provider-end", stage: job.stage, provider, status: settled.outcome, records: settled.records, durationMs: 0, recordsByType: {}, reused: true });
      return { ...settled, durationMs: null, reason: `${settled.outcome} on an earlier attempt; not retried${settled.reason ? `: ${settled.reason}` : ""}` };
    }

    this.emitEvent({ type: "provider-start", stage: job.stage, provider });

    const runtimeMs = policy.limits.maxRuntimeSeconds * 1000;
    // Give the worker an inner deadline shorter than the control-plane kill, so it can return
    // partial results gracefully instead of being terminated with nothing persisted.
    const innerTimeoutMs = Math.max(5000, Math.floor(runtimeMs * 0.85));

    const discoveryJob: DiscoveryJob = {
      schemaVersion: 1,
      scanId: scan.id,
      projectId: scan.project_id,
      stage: job.stage,
      jobKey: `${job.job_key}:${provider}`,
      kind,
      provider,
      policy,
      inputs,
      limits: policy.limits,
      allowRestrictedAddresses: this.deps.config.network.allowRestrictedAddresses,
      timeoutMs: innerTimeoutMs,
      maxRedirects: this.deps.config.network.maxRedirects,
      requestTimeoutMs: this.deps.config.network.requestTimeoutMs,
      ...(this.deps.config.providers[provider]?.binaryPath ? { binaryPath: this.deps.config.providers[provider]!.binaryPath! } : {}),
    };

    const startedMs = this.now().getTime();
    const result = await this.deps.runner.run(discoveryJob, { ...(this.deps.signal ? { signal: this.deps.signal } : {}), timeoutMs: runtimeMs + 15000 });
    const durationMs = this.now().getTime() - startedMs;
    const observedAt = this.now();

    await this.deps.db.withTransaction(async (client) => {
      const ingest = await ingestDiscoveryResult(client, this.deps.store, {
        projectId: scan.project_id,
        scanId: scan.id,
        rootDomain: scan.root_domain,
        provider,
        result,
        observedAt,
      });
      this.totals.assetsCreated += ingest.assetsCreated;
      this.totals.observations += ingest.observations;
      this.totals.relationships += ingest.relationships;
      await recordProviderExecution(client, { scanId: scan.id, jobId: job.id, provider, providerVersion: result.providerVersion, result, status: result.status, durationMs });
      await upsertProviderOutcome(client, {
        scanId: scan.id,
        projectId: scan.project_id,
        jobId: job.id,
        stage: job.stage,
        provider,
        providerVersion: result.providerVersion,
        outcome: result.status,
        recordsCount: result.records.length,
        reason: result.diagnostics.slice(0, 3).join(" | "),
      });
    });

    this.deps.logger.info("provider executed", { scanId: scan.id, stage: job.stage, provider, status: result.status, records: result.records.length, durationMs });
    this.emitEvent({
      type: "provider-end",
      stage: job.stage,
      provider,
      status: result.status,
      records: result.records.length,
      durationMs,
      recordsByType: countRecordsByType(result.records),
      reused: false,
    });
    const summary: ProviderOutcomeSummary = {
      stage: job.stage,
      provider,
      outcome: result.status,
      records: result.records.length,
      reason: result.diagnostics.slice(0, 2).join(" | "),
      providerVersion: result.providerVersion,
      durationMs,
      timedOut: result.execution.timedOut,
      truncated: result.execution.truncated,
    };
    if (!isRetryableProviderOutcome(result.status) && NON_RETRYABLE_SETTLED.has(result.status)) {
      this.settledProviders.set(`${job.stage}\u0000${provider}`, summary);
    }
    return summary;
  }

  private async writeStageCoverage(
    scan: ScanRow,
    job: JobRow,
    stageStatus: string,
    outcomes: ProviderOutcomeSummary[],
    extraDetails?: Record<string, unknown>,
  ): Promise<void> {
    const expected = outcomes.length;
    const collected = outcomes.filter((o) => o.outcome === JobStatus.SUCCEEDED || o.outcome === JobStatus.PARTIAL).length;
    const covStatus = coverageStatusFor(stageStatus);
    await this.deps.db.withTransaction((c) =>
      upsertCoverageInternal(c, {
        scanId: scan.id,
        projectId: scan.project_id,
        stage: job.stage,
        status: covStatus,
        expected,
        collected,
        notes: outcomes.map((o) => `${o.provider}:${o.outcome}`).join(" "),
        details: { providers: outcomes, ...this.stageTiming(job.stage), ...(extraDetails ?? {}) },
      }),
    );
  }

  /**
   * Execution timing for the stage being run, persisted alongside coverage so reporting reads a
   * measured duration rather than recomputing one. Returns nothing when the clock is not this
   * stage's, so a stale or absent measurement is never presented as a real one.
   */
  private stageTiming(stage: string): { startedAt?: string; finishedAt?: string; durationMs?: number } {
    const clock = this.stageClock;
    if (!clock || clock.stage !== stage) return {};
    const finished = this.now();
    return {
      startedAt: clock.startedAt.toISOString(),
      finishedAt: finished.toISOString(),
      durationMs: Math.max(0, finished.getTime() - clock.startedMs),
    };
  }

  private async reconcileScanStatus(scanId: string, scan: ScanRow): Promise<string> {
    const current = await this.repo.getScan(scanId);
    if (current?.status === JobStatus.CANCELLED) return JobStatus.CANCELLED;
    const jobs = await this.repo.getJobRows(scanId);
    const statuses = jobs.map((j) => j.status);
    if (statuses.some((s) => s === JobStatus.RUNNING || s === JobStatus.QUEUED)) {
      // Something was left incomplete by an unexpected stop.
      return JobStatus.PARTIAL;
    }
    const anySuccess = statuses.some((s) => s === JobStatus.SUCCEEDED || s === JobStatus.PARTIAL);
    const anyFail = statuses.some((s) => s === JobStatus.FAILED || s === JobStatus.SOURCE_UNAVAILABLE || s === JobStatus.BLOCKED);
    const anySkipped = statuses.some((s) => s === JobStatus.SKIPPED);
    const allSucceeded = statuses.every((s) => s === JobStatus.SUCCEEDED);
    if (allSucceeded) return JobStatus.SUCCEEDED;
    if (anySuccess && (anyFail || anySkipped)) return JobStatus.PARTIAL;
    if (anyFail && !anySuccess) return JobStatus.FAILED;
    if (anySkipped) return JobStatus.PARTIAL;
    void scan;
    return JobStatus.PARTIAL;
  }
}

/** Record counts by discovery record type, taken verbatim from a provider result. */
export function countRecordsByType(records: ReadonlyArray<{ type: string }>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const r of records) out[r.type] = (out[r.type] ?? 0) + 1;
  const sorted: Record<string, number> = {};
  for (const k of Object.keys(out).sort()) sorted[k] = out[k]!;
  return sorted;
}

/**
 * Retry semantics per provider outcome:
 *  - FAILED: transient/unknown execution failure -> retryable.
 *  - SUCCEEDED / PARTIAL: work was done (PARTIAL means truncated/timed-out coverage, which a rerun
 *    with the same limits would not improve) -> never retried; the persisted result is reused.
 *  - SOURCE_UNAVAILABLE: the tool/source is missing or down, a permanent condition for this run
 *    -> not retried (an explicit resume re-evaluates it).
 *  - SKIPPED / BLOCKED: a deliberate decision (nothing to do, scope or prerequisite) -> not retried.
 *  - CANCELLED: the operator stopped the scan -> never retried.
 */
export function isRetryableProviderOutcome(outcome: string): boolean {
  return outcome === JobStatus.FAILED;
}

/** A stage is retried only when at least one of its providers ended in a retryable outcome. */
export function shouldRetryStage(providers: ReadonlyArray<{ outcome: string }>): boolean {
  return providers.some((p) => isRetryableProviderOutcome(p.outcome));
}

const NON_RETRYABLE_SETTLED: ReadonlySet<string> = new Set([JobStatus.SOURCE_UNAVAILABLE, JobStatus.SKIPPED, JobStatus.BLOCKED]);

export function aggregate(outcomes: string[]): string {
  if (outcomes.length === 0) return JobStatus.SKIPPED;
  const count = (s: string): number => outcomes.filter((o) => o === s).length;
  const ok = count(JobStatus.SUCCEEDED);
  const partial = count(JobStatus.PARTIAL);
  const failed = count(JobStatus.FAILED);
  const unavailable = count(JobStatus.SOURCE_UNAVAILABLE);
  const skipped = count(JobStatus.SKIPPED);
  const blocked = count(JobStatus.BLOCKED);
  const cancelled = count(JobStatus.CANCELLED);
  if (cancelled === outcomes.length) return JobStatus.CANCELLED;
  if (blocked === outcomes.length) return JobStatus.BLOCKED;
  if (skipped === outcomes.length) return JobStatus.SKIPPED;
  if (unavailable === outcomes.length) return JobStatus.SOURCE_UNAVAILABLE;
  if (failed === outcomes.length) return JobStatus.FAILED;
  if (ok === outcomes.length) return JobStatus.SUCCEEDED;
  // Any provider that returned PARTIAL, or any mix that is not all-success, means this stage's
  // coverage is incomplete. Reporting it SUCCEEDED would let one provider's partial result be
  // masked by its siblings (or by itself, for a single-provider stage).
  if (ok + partial > 0) return JobStatus.PARTIAL;
  return JobStatus.FAILED;
}

export function coverageStatusFor(stageStatus: string): string {
  switch (stageStatus) {
    case JobStatus.SUCCEEDED:
      return "COLLECTED";
    case JobStatus.PARTIAL:
      return "PARTIAL";
    case JobStatus.SKIPPED:
      return "NOT_ATTEMPTED";
    case JobStatus.BLOCKED:
      return "BLOCKED";
    default:
      return "MISSING";
  }
}

export type { DiscoveryResult };
