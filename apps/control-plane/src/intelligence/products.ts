import { CpeMapping, VersionCertainty, type CpeMappingValue, type TechnologyFingerprint, type VersionCertaintyValue } from "./types.js";

/**
 * Product normalization and version extraction from existing technology evidence.
 *
 * ReconNexus fingerprints technologies but does not (yet) extract versions in the worker, so this
 * module derives a best-effort product/version from the evidence string already persisted. It is a
 * *normalization* layer only: the original evidence is carried through untouched, and a version is
 * only claimed when it was actually present in the evidence.
 */

interface ProductEntry {
  key: string;
  vendor: string;
  /** CPE 2.3 product component candidates (the `<product>` field). */
  cpes: string[];
  /** Alternate names/aliases seen in banners and fingerprints. */
  aliases: string[];
}

/** Small curated dictionary. Absence is fine — unmatched products are reported, never guessed. */
const PRODUCTS: ProductEntry[] = [
  { key: "nginx", vendor: "nginx", cpes: ["nginx"], aliases: ["nginx"] },
  { key: "apache_http_server", vendor: "apache", cpes: ["http_server"], aliases: ["apache", "httpd", "apache httpd", "apache http server"] },
  { key: "openssl", vendor: "openssl", cpes: ["openssl"], aliases: ["openssl"] },
  { key: "iis", vendor: "microsoft", cpes: ["internet_information_services"], aliases: ["iis", "microsoft-iis"] },
  { key: "tomcat", vendor: "apache", cpes: ["tomcat"], aliases: ["tomcat", "apache-coyote"] },
  { key: "php", vendor: "php", cpes: ["php"], aliases: ["php"] },
  { key: "wordpress", vendor: "wordpress", cpes: ["wordpress"], aliases: ["wordpress", "wp"] },
  { key: "drupal", vendor: "drupal", cpes: ["drupal"], aliases: ["drupal"] },
  { key: "joomla", vendor: "joomla", cpes: ["joomla"], aliases: ["joomla"] },
  { key: "jquery", vendor: "jquery", cpes: ["jquery"], aliases: ["jquery"] },
  { key: "bootstrap", vendor: "getbootstrap", cpes: ["bootstrap"], aliases: ["bootstrap"] },
  { key: "react", vendor: "facebook", cpes: ["react"], aliases: ["react", "reactjs", "react.js"] },
  { key: "vue", vendor: "vuejs", cpes: ["vue.js", "vue"], aliases: ["vue", "vue.js", "vuejs"] },
  { key: "angular", vendor: "google", cpes: ["angular", "angular.js"], aliases: ["angular", "angularjs"] },
  { key: "express", vendor: "expressjs", cpes: ["express"], aliases: ["express", "expressjs"] },
  { key: "node.js", vendor: "nodejs", cpes: ["node.js"], aliases: ["node.js", "nodejs", "node"] },
  { key: "spring", vendor: "vmware", cpes: ["spring_framework"], aliases: ["spring", "spring framework", "spring boot"] },
  { key: "mysql", vendor: "oracle", cpes: ["mysql"], aliases: ["mysql"] },
  { key: "mariadb", vendor: "mariadb", cpes: ["mariadb"], aliases: ["mariadb"] },
  { key: "postgresql", vendor: "postgresql", cpes: ["postgresql"], aliases: ["postgresql", "postgres", "pgsql"] },
  { key: "redis", vendor: "redis", cpes: ["redis"], aliases: ["redis"] },
  { key: "mongodb", vendor: "mongodb", cpes: ["mongodb"], aliases: ["mongodb", "mongo"] },
  { key: "elasticsearch", vendor: "elastic", cpes: ["elasticsearch"], aliases: ["elasticsearch"] },
  { key: "grafana", vendor: "grafana", cpes: ["grafana"], aliases: ["grafana"] },
  { key: "jenkins", vendor: "jenkins", cpes: ["jenkins"], aliases: ["jenkins"] },
  { key: "gitlab", vendor: "gitlab", cpes: ["gitlab"], aliases: ["gitlab"] },
  { key: "liferay", vendor: "liferay", cpes: ["liferay_portal", "liferay"], aliases: ["liferay"] },
  { key: "kubernetes", vendor: "kubernetes", cpes: ["kubernetes"], aliases: ["kubernetes", "k8s"] },
  { key: "caddy", vendor: "caddyserver", cpes: ["caddy"], aliases: ["caddy"] },
  { key: "traefik", vendor: "traefik", cpes: ["traefik"], aliases: ["traefik"] },
  { key: "haproxy", vendor: "haproxy", cpes: ["haproxy"], aliases: ["haproxy"] },
  { key: "varnish", vendor: "varnish-software", cpes: ["varnish"], aliases: ["varnish"] },
  { key: "cloudflare", vendor: "cloudflare", cpes: ["cloudflare"], aliases: ["cloudflare"] },
];

const BY_ALIAS = new Map<string, ProductEntry>();
for (const p of PRODUCTS) {
  for (const a of p.aliases) BY_ALIAS.set(a.toLowerCase(), p);
  BY_ALIAS.set(p.key, p);
}

/** Lowercase, collapse separators, and trim — a stable key for matching products to advisories. */
export function normalizeProductKey(name: string): string {
  return (name ?? "")
    .toLowerCase()
    .trim()
    .replace(/[\s_]+/g, "-")
    .replace(/-+/g, "-");
}

export interface ProductLookup {
  key: string;
  vendor: string;
  cpe: string | null;
  mapping: CpeMappingValue;
  candidates: string[];
}

function cpe23(vendor: string, product: string): string {
  return `cpe:2.3:a:${vendor}:${product}:*:*:*:*:*:*:*:*`;
}

/** Map a product name to a CPE, disclosing ambiguity instead of picking arbitrarily. */
export function mapProductToCpe(name: string): ProductLookup {
  const entry = BY_ALIAS.get((name ?? "").toLowerCase().trim());
  if (!entry) return { key: normalizeProductKey(name), vendor: "", cpe: null, mapping: CpeMapping.UNMATCHED, candidates: [] };
  const candidates = entry.cpes.map((c) => cpe23(entry.vendor, c));
  if (candidates.length === 1) return { key: entry.key, vendor: entry.vendor, cpe: candidates[0]!, mapping: CpeMapping.EXACT, candidates };
  // Multiple plausible CPEs for the same product name → a human must disambiguate.
  return { key: entry.key, vendor: entry.vendor, cpe: null, mapping: CpeMapping.AMBIGUOUS, candidates };
}

/** Alias list for a normalised product name (used to find the version near the product token). */
function aliasesFor(name: string): string[] {
  const entry = BY_ALIAS.get((name ?? "").toLowerCase().trim());
  return entry ? entry.aliases : [name];
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export interface VersionEvidence {
  version: string | null;
  certainty: VersionCertaintyValue;
}

/**
 * Extract a version for a product from an evidence string such as `server: nginx/1.25.3` or
 * `X-Powered-By: PHP/8.1.2`. Returns UNKNOWN when no version is visible; a banner with a generic or
 * masked version (e.g. `nginx`) never yields a version.
 */
export function extractVersion(name: string, evidence: string, evidenceSource: string): VersionEvidence {
  const text = evidence ?? "";
  if (text.trim() === "") return { version: null, certainty: VersionCertainty.UNKNOWN };
  // A version is `product[/ or space]v?<digits>`; the number must start a token.
  for (const alias of aliasesFor(name)) {
    const re = new RegExp(`${escapeRe(alias)}[/\\s-]*v?(\\d[\\w.\\-]*)`, "i");
    const m = re.exec(text);
    if (m && /\d/.test(m[1]!)) {
      const raw = m[1]!.replace(/[.,;]+$/, "");
      return { version: raw, certainty: VersionCertainty.EXACT };
    }
  }
  // A bare version in a header value that references this product family (e.g. `Server: 1.2.3`).
  if (/header|server|banner/i.test(evidenceSource)) {
    const m = /\bv?(\d+\.\d+(?:\.\d+)?[\w.\-]*)/.exec(text);
    if (m) return { version: m[1]!, certainty: VersionCertainty.INFERRED };
  }
  return { version: null, certainty: VersionCertainty.UNKNOWN };
}

export interface TechnologyObservation {
  name: string;
  host: string;
  category: string;
  evidenceType: string;
  evidence: string;
  confidence: number;
}

/** Build a provenance-carrying fingerprint from a persisted technology observation. */
export function fingerprintFromTechnology(obs: TechnologyObservation): TechnologyFingerprint {
  const lookup = mapProductToCpe(obs.name);
  const versionEvidence = extractVersion(obs.name, obs.evidence, obs.evidenceType);
  const productKey = lookup.mapping === CpeMapping.UNMATCHED ? normalizeProductKey(obs.name) : lookup.key;
  return {
    product: obs.name,
    vendor: lookup.vendor,
    productKey,
    observedVersion: versionEvidence.version,
    versionCertainty: versionEvidence.certainty,
    host: obs.host,
    category: obs.category,
    evidenceSource: obs.evidenceType || "unknown",
    evidence: obs.evidence,
    confidence: Number.isFinite(obs.confidence) ? Math.min(1, Math.max(0, obs.confidence)) : 0,
    evidenceRef: `technology:${obs.host}:${obs.name}`,
  };
}

export function knownProductKeys(): string[] {
  return PRODUCTS.map((p) => p.key);
}
