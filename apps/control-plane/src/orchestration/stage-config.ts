import { StageId, type DiscoveryJobKindValue } from "@reconnexus/contracts";

export const IMPLEMENTED_STAGES = new Set<string>([
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

export const DEFAULT_PROVIDERS: Record<DiscoveryJobKindValue, string[]> = {
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

export const MAX_NAMES = 1000;
export const MAX_ADDRESSES = 50;
export const MAX_HTTP_HOSTS = 300;
export const MAX_HTTP_TARGETS = 500;
export const MAX_SEED_URLS = 200;
export const MAX_CRAWL_REQUESTS = 800;
export const MAX_JS_URLS = 200;
export const MAX_SPEC_URLS = 100;
/** Origins that may be checked for well-known specification paths, and the total probe budget. */
export const MAX_SPEC_PROBE_ORIGINS = 25;
export const MAX_SPEC_PROBE_URLS = 200;
export const MAX_SECURITY_TARGETS = 200;
export const MAX_SECRET_ARTIFACTS = 300;
export const MAX_CORR_ASSETS = 2000;
export const MAX_TAKEOVER_HOSTS = 300;
export const MAX_LOGIN_ORIGINS = 25;
export const MAX_FINGERPRINT_GROUP = 10;
export const MAX_CORR_EDGES = 500;

export function looksLikeJs(url: string): boolean {
  return /\.m?js(\?|$)/i.test(url);
}

export function originOfUrl(raw: string): string | null {
  try {
    const u = new URL(raw);
    return `${u.protocol}//${u.host}`;
  } catch {
    return null;
  }
}

export function looksLikeSpec(url: string): boolean {
  return /(^|\/)(openapi|swagger|api[-_]?docs)(\.json|\.yaml|\.yml)?(\?|$)|\/(openapi|swagger)\.(json|yaml|yml)(\?|$)/i.test(url);
}

export function defaultSleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Deterministic ordering so a probe list is reproducible across runs. */
export function sorted(values: Iterable<string>): string[] {
  return Array.from(values).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}
