import { StageId } from "@reconnexus/contracts";

/**
 * Scan profiles trade coverage against speed and noise. A profile can only make a scan *more
 * conservative than its policy*: it never raises a rate, concurrency or depth above what the scope
 * policy allows, and it never adds a capability. Stages a profile leaves out are not planned at
 * all (like opt-in stages the policy does not grant), so a deliberately lighter scan is not
 * reported as PARTIAL for work it was never meant to do.
 */
export const SCAN_PROFILE_NAMES = ["quick", "standard", "deep", "stealth"] as const;
export type ScanProfileName = (typeof SCAN_PROFILE_NAMES)[number];

export interface ScanProfile {
  name: ScanProfileName;
  description: string;
  /** Stages left out of the plan. */
  excludeStages: string[];
  /** Upper bounds applied on top of the policy limits (the lower value wins). */
  maxRequestsPerSecond?: number;
  maxConcurrency?: number;
  maxCrawlDepth?: number;
  /** Crawler request budget for the URL-collection stage. */
  crawlRequestBudget?: number;
  /** Default TCP port selection for the port-scan stage; an explicit `--ports` wins. */
  ports?: string;
  /** Default template tags for the template-check stage; an explicit `--template-tags` wins. */
  templateTags?: string;
}

/** Common service ports plus the well-known range, within the worker's 2048-port limit. */
const DEEP_PORTS =
  "1-1000,1433,1521,2049,2375,2376,3000,3306,3389,5000,5432,5601,5672,5900,5985,6379,6443,7001,8000-8100,8443,8888,9000,9042,9090,9200,9300,10250,11211,15672,27017";

export const SCAN_PROFILES: Record<ScanProfileName, ScanProfile> = {
  quick: {
    name: "quick",
    description: "Fast first pass: no port scan, template checks, login or content discovery; shallow, small crawl.",
    excludeStages: [StageId.PORT_SCAN, StageId.TEMPLATE_CHECKS, StageId.LOGIN_FINDER, StageId.CONTENT_DISCOVERY],
    maxCrawlDepth: 1,
    crawlRequestBudget: 200,
  },
  standard: {
    name: "standard",
    description: "Every stage the policy authorizes, at the policy's own limits.",
    excludeStages: [],
    crawlRequestBudget: 800,
  },
  deep: {
    name: "deep",
    description: "Thorough: larger crawl budget, the full well-known port range and extra CVE-tagged templates.",
    excludeStages: [],
    crawlRequestBudget: 2000,
    ports: DEEP_PORTS,
    templateTags: "exposure,misconfig,tech,panel,cve",
  },
  stealth: {
    name: "stealth",
    description: "Low and slow: at most 2 requests/s and 2 connections, shallow crawl, and no port scan, template checks, login or content discovery.",
    excludeStages: [StageId.PORT_SCAN, StageId.TEMPLATE_CHECKS, StageId.LOGIN_FINDER, StageId.CONTENT_DISCOVERY],
    maxRequestsPerSecond: 2,
    maxConcurrency: 2,
    maxCrawlDepth: 1,
    crawlRequestBudget: 100,
  },
};

export function isScanProfileName(v: unknown): v is ScanProfileName {
  return typeof v === "string" && (SCAN_PROFILE_NAMES as readonly string[]).includes(v);
}

export class UnknownProfileError extends Error {
  constructor(public readonly profile: string) {
    super(`unknown scan profile '${profile}' (expected one of: ${SCAN_PROFILE_NAMES.join(", ")})`);
    this.name = "UnknownProfileError";
  }
}

export function resolveScanProfile(name: string): ScanProfile {
  if (!isScanProfileName(name)) throw new UnknownProfileError(name);
  return SCAN_PROFILES[name];
}

/** The profile recorded in a scan's config snapshot, or null for a scan created without one. */
export function profileFromSnapshot(snapshot: unknown): ScanProfile | null {
  const name = (snapshot as { scanProfile?: unknown } | null)?.scanProfile;
  return isScanProfileName(name) ? SCAN_PROFILES[name] : null;
}

export interface LimitsLike {
  maxConcurrency: number;
  requestsPerSecond: number;
  crawlDepth: number;
  maxRuntimeSeconds: number;
  maxArtifactBytes: number;
}

/** Policy limits tightened by the profile. Never raises a value. */
export function applyProfileLimits<T extends LimitsLike>(limits: T, profile: ScanProfile | null): T {
  if (!profile) return limits;
  return {
    ...limits,
    requestsPerSecond: Math.min(limits.requestsPerSecond, profile.maxRequestsPerSecond ?? limits.requestsPerSecond),
    maxConcurrency: Math.min(limits.maxConcurrency, profile.maxConcurrency ?? limits.maxConcurrency),
    crawlDepth: Math.min(limits.crawlDepth, profile.maxCrawlDepth ?? limits.crawlDepth),
  };
}
