import { StageId, type DiscoveryJobKindValue } from "@reconnexus/contracts";

export const IMPLEMENTED_STAGES = new Set<string>([
  StageId.INPUT_AUTHORIZATION,
  StageId.TARGET_INTELLIGENCE,
  StageId.SUBDOMAIN_DISCOVERY,
  StageId.DNS_INFRA,
  StageId.PORT_SCAN,
  StageId.HTTP_PROBE,
  StageId.URL_COLLECTION,
  StageId.URL_CATEGORIZATION,
  StageId.JS_INTELLIGENCE,
  StageId.API_DISCOVERY,
  StageId.SECRET_DETECTION,
  StageId.SECURITY_CHECKS,
  StageId.TEMPLATE_CHECKS,
  StageId.CORRELATION,
  StageId.TAKEOVER,
  StageId.LOGIN_FINDER,
  StageId.CONTENT_DISCOVERY,
  StageId.CLOUD_STORAGE,
  StageId.CORS_REDIRECT,
  StageId.EMAIL_SECURITY,
  StageId.REPORTING,
]);

export const DEFAULT_PROVIDERS: Record<DiscoveryJobKindValue, string[]> = {
  SUBDOMAINS: ["subfinder", "assetfinder"],
  DNS: ["builtin-dns"],
  IP_METADATA: ["rdap"],
  PORT_SCAN: ["nmap"],
  TEMPLATE_CHECK: ["nuclei"],
  HTTP_PROBE: ["builtin-http"],
  URL_COLLECTION: ["builtin-crawler", "builtin-static", "gau", "waybackurls"],
  JS_ANALYSIS: ["builtin-js"],
  API_SPEC: ["builtin-api"],
  SECURITY_META: ["builtin-security-meta"],
  SECRET_SCAN: ["builtin-secret-scan"],
  TAKEOVER: ["builtin-takeover"],
  LOGIN_FINDER: ["builtin-login-finder"],
  CONTENT_DISCOVERY: ["builtin-content"],
  CLOUD_STORAGE: ["builtin-cloud-storage"],
  CORS_REDIRECT: ["builtin-cors-redirect"],
  EMAIL_SECURITY: ["builtin-email-security"],
};

export const MAX_NAMES = 1000;
export const MAX_ADDRESSES = 50;
/** Distinct (host, address) pairs a port scan may cover; each address is scanned over the whole port list. */
export const MAX_PORT_SCAN_ADDRESSES = 50;
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
export const MAX_TEMPLATE_TARGETS = 100;
export const MAX_SECRET_ARTIFACTS = 300;
export const MAX_CORR_ASSETS = 2000;
export const MAX_TAKEOVER_HOSTS = 300;
export const MAX_LOGIN_ORIGINS = 25;
/** Origins that may be probed with the content-discovery path list (about 90 requests each). */
export const MAX_CONTENT_ORIGINS = 25;
/** CNAME-derived candidates the cloud-storage stage may check in one scan. */
export const MAX_CLOUD_STORAGE_CANDIDATES = 25;
/** Origins the CORS reflection probe may check in one scan. */
export const MAX_CORS_TARGETS = 50;
/** Open-redirect-shaped URLs the open-redirect probe may check in one scan. */
export const MAX_REDIRECT_CANDIDATES = 50;

/**
 * Query parameter names commonly used to carry a post-action redirect target. Matching is
 * case-insensitive and exact (no substring matching), to keep the candidate list precise.
 */
const REDIRECT_PARAMETER_NAMES = new Set([
  "redirect", "redirect_uri", "redirecturl", "redirect_url", "redirect_to",
  "return", "returnurl", "return_url", "returnto", "return_to",
  "next", "nexturl", "next_url",
  "continue", "continueurl", "continue_url",
  "dest", "destination", "redir",
  "checkout_url", "success_url", "successurl",
  "callback", "callback_url", "forward", "forward_url",
  "login_url", "logout_url", "target", "url", "u", "link", "rurl", "navigate", "goto", "out", "view",
]);

/**
 * Checks a URL's query string for the first parameter whose name matches a known open-redirect
 * pattern and has a non-empty value. The worker never guesses a parameter name beyond what this
 * returns, so a false negative here only means the URL isn't tested, never a false positive.
 */
export function openRedirectCandidateFor(rawUrl: string): { parameter: string } | null {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    return null;
  }
  for (const [name, value] of u.searchParams) {
    if (value && REDIRECT_PARAMETER_NAMES.has(name.toLowerCase())) {
      return { parameter: name };
    }
  }
  return null;
}

/**
 * Derives a best-effort bucket name from a CNAME target that fronts a cloud storage bucket on a
 * custom domain. Only REST-style S3 endpoints are matched (never `s3-website-*`, which answers a
 * plain GET with the site's own public content, not a listing, and is never a finding here).
 *
 * A leading label before `.s3` is the (legacy) per-bucket virtual-host pattern, so that label is
 * the bucket name. Otherwise (a bare CNAME to the shared S3 or GCS endpoint) the bucket name must
 * equal the custom domain itself: both providers require that for a bare CNAME to route at all.
 */
export function cloudStorageCandidateFor(host: string, cnameTarget: string): { provider: "S3" | "GCS"; bucket: string } | null {
  const target = cnameTarget.toLowerCase().replace(/\.$/, "");
  if (target.endsWith(".amazonaws.com") && !target.includes("website")) {
    const vhost = target.match(/^([a-z0-9.-]+)\.s3[.-]/);
    if (vhost?.[1]) return { provider: "S3", bucket: vhost[1] };
    if (/^s3[.-]/.test(target)) return { provider: "S3", bucket: host };
    return null;
  }
  if (target === "storage.googleapis.com" || target === "c.storage.googleapis.com") {
    return { provider: "GCS", bucket: host };
  }
  return null;
}

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
