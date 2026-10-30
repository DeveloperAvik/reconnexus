import { randomUUID } from "node:crypto";
import {
  Capability,
  type CapabilityName,
  OrderedStages,
  SCAN_MANIFEST_SCHEMA_VERSION,
  ScopeDecisionCode,
  StageId,
  type ScanManifest,
  type ScopeDecision,
  type ScopePolicy,
} from "@reconnexus/contracts";
import { parseUrl, registrableDomain, type NormalizedUrl } from "@reconnexus/normalization";
import { ScopeEngine } from "@reconnexus/scope-policy";
import type { Db } from "./db/pool.js";
import { resolveScanProfile, type ScanProfile } from "./orchestration/profiles.js";
import { Repository } from "./repository.js";

export class InvalidTargetError extends Error {
  constructor(message: string, readonly url: string) {
    super(message);
    this.name = "InvalidTargetError";
  }
}

export class ScopeDeniedError extends Error {
  constructor(readonly decision: ScopeDecision) {
    super(decision.reason);
    this.name = "ScopeDeniedError";
  }
}

export class PolicyVersionConflictError extends Error {
  constructor(readonly projectId: string, readonly version: number) {
    super(
      `policy version ${version} already exists for project ${projectId} with a different policyId; bump the policy version`,
    );
    this.name = "PolicyVersionConflictError";
  }
}

/**
 * Stages that exist only when the policy grants the capability they need. A policy that never asked
 * for one keeps the same plan, and the same truthful scan status, as before the stage existed.
 */
const OPT_IN_STAGES: Record<string, string> = {
  [StageId.PORT_SCAN]: "PORT_SCAN",
  [StageId.TEMPLATE_CHECKS]: "ACTIVE_TEMPLATE_CHECK",
  [StageId.CONTENT_DISCOVERY]: "CONTENT_DISCOVERY",
};

export function plannedStagesFor(capabilities: readonly string[], profile?: ScanProfile | null): string[] {
  const excluded = new Set(profile?.excludeStages ?? []);
  return (OrderedStages as string[]).filter((s) => !excluded.has(s) && (!(s in OPT_IN_STAGES) || capabilities.includes(OPT_IN_STAGES[s]!)));
}

export interface CreateScanRequest {
  startUrl: string;
  policy: ScopePolicy;
  workspaceName?: string;
  configSnapshot?: Record<string, unknown>;
  now?: Date;
  allowRestrictedAddresses?: boolean;
  /** Scan profile name (quick, standard, deep, stealth); omitted plans every authorized stage. */
  profile?: string;
}

export interface CreateScanResult {
  scanId: string;
  projectId: string;
  policyId: string;
  rootDomain: string;
  manifest: ScanManifest;
  /** Stage 00 is completed by this call; downstream stages are QUEUED. */
  completedStage: string;
}

const PRIMARY_CAPABILITY_ORDER = [
  Capability.ACTIVE_HTTP,
  Capability.CRAWL,
  Capability.API_DISCOVERY,
  Capability.DNS,
  Capability.PASSIVE,
] as const;

function primaryCapability(policy: ScopePolicy): CapabilityName {
  for (const c of PRIMARY_CAPABILITY_ORDER) {
    if (policy.authorization.capabilities.includes(c)) return c;
  }
  return policy.authorization.capabilities[0]!;
}

/**
 * Stage 00 — validate the starting URL, resolve the registrable domain, enforce scope
 * BEFORE any network execution, create the scan, and persist the configuration snapshot.
 */
export class ScanService {
  private readonly repo: Repository;

  constructor(private readonly db: Db) {
    this.repo = new Repository(db);
  }

  validateStartUrl(startUrl: string): NormalizedUrl {
    let parsed: NormalizedUrl;
    try {
      parsed = parseUrl(startUrl, { allowedSchemes: ["http", "https"] });
    } catch (err) {
      throw new InvalidTargetError((err as Error).message, startUrl);
    }
    if (parsed.host.length === 0) throw new InvalidTargetError("missing host", startUrl);
    return parsed;
  }

  async createScan(req: CreateScanRequest): Promise<CreateScanResult> {
    const now = req.now ?? new Date();
    const parsed = this.validateStartUrl(req.startUrl);
    const rootDomain = parsed.registrableDomain ?? parsed.host;

    const engine = new ScopeEngine(req.policy, {
      ...(req.allowRestrictedAddresses !== undefined
        ? { allowRestrictedAddresses: req.allowRestrictedAddresses }
        : {}),
    });
    const capability = primaryCapability(req.policy);
    const decision = engine.check({
      kind: "URL",
      value: parsed.canonical,
      capability,
      now,
      ...(parsed.isIpLiteral ? { resolvedAddresses: [parsed.host] } : {}),
    });
    if (!decision.allowed) throw new ScopeDeniedError(decision);

    const profile = req.profile ? resolveScanProfile(req.profile) : null;
    const plannedStages = plannedStagesFor(req.policy.authorization.capabilities, profile);
    const scanId = randomUUID();
    const manifest: ScanManifest = {
      schemaVersion: SCAN_MANIFEST_SCHEMA_VERSION,
      scanId,
      projectId: req.policy.projectId,
      policyId: req.policy.policyId,
      policyVersion: req.policy.policyVersion,
      startUrl: parsed.canonical,
      rootDomain,
      createdAt: now.toISOString(),
      stages: plannedStages,
      requestedCapabilities: req.policy.authorization.capabilities,
      enabledProviders: {},
      limits: req.policy.limits,
    };

    return this.db.withTransaction(async (client) => {
      const repo = new Repository(client);
      const workspaceId = await repo.ensureDefaultWorkspace(req.workspaceName ?? "default");
      const project = await repo.ensureProject(workspaceId, rootDomain);

      const existing = await repo.findPolicyByVersion(project.id, req.policy.policyVersion);
      let policyId: string;
      if (existing) {
        if (existing.document.policyId && existing.document.policyId !== req.policy.policyId) {
          throw new PolicyVersionConflictError(project.id, req.policy.policyVersion);
        }
        policyId = existing.id;
      } else {
        policyId = await repo.insertPolicy(project.id, req.policy.policyVersion, req.policy);
        await repo.insertAuthorization(project.id, req.policy);
      }

      const scan = await repo.createScan({
        projectId: project.id,
        policyId,
        startUrl: parsed.canonical,
        rootDomain,
        configSnapshot: { ...manifest, ...(profile ? { scanProfile: profile.name } : {}), ...(req.configSnapshot ?? {}) },
      });

      const stages = plannedStages.map((stage, i) => ({
        stage,
        dependsOn: i === 0 ? [] : [plannedStages[i - 1]!],
      }));
      await repo.createJobs(scan.id, project.id, stages);
      await repo.markJobStatus(scan.id, StageId.INPUT_AUTHORIZATION, "SUCCEEDED");
      await repo.upsertCoverage(scan.id, project.id, StageId.INPUT_AUTHORIZATION, "COLLECTED", 1, 1, "start URL validated and authorized");
      await repo.appendAudit(project.id, scan.id, "SCOPE_ALLOWED", parsed.canonical, decision.code, {
        capability,
        matchedRule: decision.matchedRule ?? null,
      });

      return {
        scanId: scan.id,
        projectId: project.id,
        policyId,
        rootDomain,
        manifest: { ...manifest, projectId: project.id, scanId: scan.id },
        completedStage: StageId.INPUT_AUTHORIZATION,
      };
    });
  }

  async getScanStatus(scanId: string): Promise<{ scan: unknown; jobs: unknown[] } | null> {
    const scan = await this.repo.getScan(scanId);
    if (!scan) return null;
    const jobs = await this.repo.listJobs(scanId);
    return { scan, jobs };
  }
}

export { ScopeDecisionCode };
