import { z } from "zod";
import { ScopePolicySchema, LimitsSchema } from "./scope.js";

/** Kinds of discovery work a worker can perform. */
export const DiscoveryJobKind = {
  SUBDOMAINS: "SUBDOMAINS",
  DNS: "DNS",
  IP_METADATA: "IP_METADATA",
  HTTP_PROBE: "HTTP_PROBE",
  URL_COLLECTION: "URL_COLLECTION",
  JS_ANALYSIS: "JS_ANALYSIS",
  API_SPEC: "API_SPEC",
  SECURITY_META: "SECURITY_META",
  SECRET_SCAN: "SECRET_SCAN",
  TAKEOVER: "TAKEOVER",
  LOGIN_FINDER: "LOGIN_FINDER",
  PORT_SCAN: "PORT_SCAN",
  TEMPLATE_CHECK: "TEMPLATE_CHECK",
  CONTENT_DISCOVERY: "CONTENT_DISCOVERY",
  CLOUD_STORAGE: "CLOUD_STORAGE",
  CORS_REDIRECT: "CORS_REDIRECT",
} as const;
export type DiscoveryJobKindValue = (typeof DiscoveryJobKind)[keyof typeof DiscoveryJobKind];

export const AddressInputSchema = z.object({
  ip: z.string().min(1),
  /** The in-scope host through which this address was discovered. */
  viaHost: z.string().min(1),
});

export const DiscoveryJobSchema = z.object({
  schemaVersion: z.literal(1),
  scanId: z.string().uuid(),
  projectId: z.string().uuid(),
  stage: z.string().min(1),
  jobKey: z.string().min(1),
  kind: z.enum(["SUBDOMAINS", "DNS", "IP_METADATA", "HTTP_PROBE", "URL_COLLECTION", "JS_ANALYSIS", "API_SPEC", "SECURITY_META", "SECRET_SCAN", "TAKEOVER", "LOGIN_FINDER", "PORT_SCAN", "TEMPLATE_CHECK", "CONTENT_DISCOVERY", "CLOUD_STORAGE", "CORS_REDIRECT"]),
  provider: z.string().min(1),
  /** The full policy is passed so the worker can enforce scope independently. */
  policy: ScopePolicySchema,
  inputs: z.object({
    rootDomain: z.string().optional(),
    names: z.array(z.string()).optional(),
    addresses: z.array(AddressInputSchema).optional(),
    /** Fully-qualified target URLs for HTTP probing. */
    urls: z.array(z.string()).optional(),
    /** Seed URLs / origins for URL collection (crawling, robots.txt, sitemaps). */
    seedUrls: z.array(z.string()).optional(),
    /** Domains for passive URL collection (gau/waybackurls). */
    domains: z.array(z.string()).optional(),
    /** Maximum crawl depth (default 2). */
    crawlDepth: z.number().int().nonnegative().optional(),
    /** Maximum number of requests the crawler may issue (default 500). */
    requestBudget: z.number().int().positive().optional(),
    /** JavaScript artifact URLs to retrieve and analyse. */
    jsUrls: z.array(z.string()).optional(),
    /** API specification URLs (OpenAPI/Swagger) discovered from evidence, to retrieve and parse. */
    specUrls: z.array(z.string()).optional(),
    /**
     * Speculative well-known specification paths to check on origins that show evidence of an
     * API. Unlike `specUrls` these were never referenced by anything, so an absent one is
     * recorded as coverage only — it never becomes an asset or an observation.
     */
    specProbeUrls: z.array(z.string()).optional(),
    /** Whether to retrieve and parse source maps referenced by analysed JavaScript. */
    fetchSourceMaps: z.boolean().optional(),
    /** Eligible artifact URLs to analyse for potential secrets. */
    artifactUrls: z.array(z.string()).optional(),
    /**
     * TCP port selection for PORT_SCAN: a comma-separated list of ports and ranges (for example
     * "80,443,8000-8100"). Omitted means the provider's bounded default list. Digits, commas and
     * hyphens only, so it can never carry scanner flags.
     */
    /**
     * Template tags to include for TEMPLATE_CHECK (lowercase letters, digits, `_`, `-`, comma
     * separated). Omitted means the provider's safe default set. The provider always excludes
     * intrusive, fuzzing, brute-force, default-login and out-of-band tags regardless of this value.
     */
    templateTags: z.string().regex(/^[a-z0-9_-]+(,[a-z0-9_-]+)*$/).max(256).optional(),
    ports: z.string().regex(/^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$/).max(512).optional(),
    /**
     * CLOUD_STORAGE candidates: in-scope hosts whose CNAME the control plane matched against a
     * known cloud-storage suffix. `url` is always the in-scope host's own origin, never the
     * bucket's own cloud-provider hostname.
     */
    cloudCandidates: z
      .array(z.object({ url: z.string().min(1), provider: z.enum(["S3", "GCS"]), bucket: z.string().min(1) }))
      .optional(),
    /**
     * CORS_REDIRECT open-redirect candidates: an already-observed URL together with the single
     * query parameter the control plane matched against a known open-redirect parameter name.
     * The worker overwrites only that parameter with its canary value; it never guesses a
     * parameter name beyond this.
     */
    redirectCandidates: z.array(z.object({ url: z.string().min(1), parameter: z.string().min(1) })).optional(),
  }),
  limits: LimitsSchema,
  allowRestrictedAddresses: z.boolean().default(false),
  /** Absolute path to a fixed provider binary; from config, never user scan input. */
  binaryPath: z.string().optional(),
  /** Working directory for the provider process. */
  workDir: z.string().optional(),
  /** Test-only fixture path; honored only by the `mock` and `offline-ipmeta` providers. */
  fixturePath: z.string().optional(),
  /** Optional resolver address (host:port) for the `builtin-dns` provider. */
  resolverAddress: z.string().optional(),
  /** RDAP base URL override (default https://rdap.org). */
  rdapBaseUrl: z.string().optional(),
  /** Per-job timeout override in milliseconds. */
  timeoutMs: z.number().int().positive().optional(),
  /** Per-job output byte limit override. */
  maxOutputBytes: z.number().int().positive().optional(),
  /** Maximum redirects to follow per HTTP request (default 5, capped by the worker). */
  maxRedirects: z.number().int().nonnegative().optional(),
  /** Per-request HTTP timeout in milliseconds (default 20000). */
  requestTimeoutMs: z.number().int().positive().optional(),
  /** PEM CA bundle to trust for TLS verification (test/config only; never disables validation). */
  tlsCaFile: z.string().optional(),
});
export type DiscoveryJob = z.infer<typeof DiscoveryJobSchema>;

export const HostStatus = {
  DISCOVERED: "DISCOVERED",
  RESOLVED: "RESOLVED",
  UNRESOLVED: "UNRESOLVED",
  WILDCARD: "WILDCARD",
} as const;

export const DnsRecordType = z.enum(["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "PTR"]);
export const DnsQueryStatus = z.enum(["NOERROR", "NXDOMAIN", "TIMEOUT", "ERROR", "UNSUPPORTED"]);

export const HostObservationRecordSchema = z.object({
  type: z.literal("HOST_OBSERVATION"),
  host: z.string().min(1),
  source: z.string().min(1),
  provider: z.string().min(1),
  status: z.enum(Object.values(HostStatus) as [string, ...string[]]),
  addresses: z.array(z.string()).default([]),
  notes: z.string().default(""),
});
export type HostObservationRecord = z.infer<typeof HostObservationRecordSchema>;

export const DnsRecordSchema = z.object({
  type: z.literal("DNS_RECORD"),
  name: z.string().min(1),
  recordType: DnsRecordType,
  value: z.string().default(""),
  ttl: z.number().int().nonnegative().nullable().default(null),
  status: DnsQueryStatus,
  resolver: z.string().min(1),
  error: z.string().default(""),
});
export type DnsRecord = z.infer<typeof DnsRecordSchema>;

export const IpMetadataRecordSchema = z.object({
  type: z.literal("IP_METADATA"),
  ip: z.string().min(1),
  prefix: z.string().nullable().default(null),
  asn: z.number().int().positive().nullable().default(null),
  asnOrg: z.string().nullable().default(null),
  networkName: z.string().nullable().default(null),
  country: z.string().nullable().default(null),
  source: z.string().min(1),
  confidence: z.number().min(0).max(1),
  limitations: z.array(z.string()).default([]),
});
export type IpMetadataRecord = z.infer<typeof IpMetadataRecordSchema>;

export const ProbeStatus = {
  OK: "OK",
  REDIRECT_DENIED: "REDIRECT_DENIED",
  TOO_MANY_REDIRECTS: "TOO_MANY_REDIRECTS",
  TIMEOUT: "TIMEOUT",
  CONNECTION_ERROR: "CONNECTION_ERROR",
  TLS_ERROR: "TLS_ERROR",
  OVERSIZED: "OVERSIZED",
  BLOCKED_ADDRESS: "BLOCKED_ADDRESS",
  ERROR: "ERROR",
} as const;

export const TechnologyCategory = z.enum([
  "WEB_SERVER",
  "FRAMEWORK",
  "CMS",
  "FRONTEND_FRAMEWORK",
  "CDN_WAF",
  "API_GATEWAY",
  "LOGIN_INTERFACE",
  "DOCUMENTATION",
  "DEV_SERVICE",
  "OTHER",
]);

export const RedirectHopSchema = z.object({
  from: z.string().min(1),
  to: z.string().min(1),
  statusCode: z.number().int().nullable().default(null),
});

export const TlsInfoSchema = z.object({
  subject: z.string().default(""),
  issuer: z.string().default(""),
  notBefore: z.string().default(""),
  notAfter: z.string().default(""),
  sha256: z.string().default(""),
  protocol: z.string().default(""),
  sans: z.array(z.string()).default([]),
});

export const HttpDetailsSchema = z.object({
  finalUrl: z.string().default(""),
  statusCode: z.number().int().nullable().default(null),
  statusText: z.string().default(""),
  contentType: z.string().default(""),
  title: z.string().default(""),
  /** Selected response headers; sensitive headers (cookies, auth) are removed. */
  headers: z.record(z.string(), z.string()).default({}),
  redirectChain: z.array(RedirectHopSchema).default([]),
  tls: TlsInfoSchema.nullable().default(null),
  probeStatus: z.enum(Object.values(ProbeStatus) as [string, ...string[]]),
  error: z.string().default(""),
  /** Whether the response body exceeded the configured limit (title/tech still captured). */
  bodyTruncated: z.boolean().default(false),
});

export const HttpObservationRecordSchema = z.object({
  type: z.literal("HTTP_OBSERVATION"),
  url: z.string().min(1),
  host: z.string().min(1),
  provider: z.string().min(1),
  source: z.string().min(1),
  http: HttpDetailsSchema,
});
export type HttpObservationRecord = z.infer<typeof HttpObservationRecordSchema>;

export const TechnologyDetailsSchema = z.object({
  name: z.string().min(1),
  category: TechnologyCategory,
  evidenceType: z.string().min(1),
  evidence: z.string().default(""),
  confidence: z.number().min(0).max(1),
});

export const TechnologyRecordSchema = z.object({
  type: z.literal("TECHNOLOGY"),
  url: z.string().default(""),
  host: z.string().default(""),
  provider: z.string().min(1),
  technology: TechnologyDetailsSchema,
});
export type TechnologyRecord = z.infer<typeof TechnologyRecordSchema>;

export const UrlMethod = z.enum(["CRAWL", "PASSIVE", "ROBOTS", "SITEMAP", "SEED"]);

export const UrlCategory = z.enum([
  "HTML_PAGE",
  "NAVIGATION",
  "API_ENDPOINT",
  "GRAPHQL",
  "JAVASCRIPT",
  "STATIC_ASSET",
  "AUTHENTICATION",
  "REGISTRATION",
  "PASSWORD_RECOVERY",
  "SESSION",
  "SEARCH",
  "FILTER",
  "PAGINATION",
  "EXPORT",
  "UPLOAD",
  "DOWNLOAD",
  "DOCUMENTATION",
  "API_SPEC",
  "DEVELOPER",
  "ADMIN",
  "REDIRECT",
  "UNKNOWN",
]);

/** A single classification hypothesis. Reconnaissance context, never a vulnerability claim. */
export const UrlClassificationSchema = z.object({
  category: UrlCategory,
  confidence: z.number().min(0).max(1),
  evidenceType: z.string().min(1),
  evidence: z.string().default(""),
});

export const UrlParameterRoleSchema = z.object({
  role: z.string().min(1),
  confidence: z.number().min(0).max(1),
  evidence: z.string().default(""),
});

export const UrlParameterSchema = z.object({
  name: z.string().min(1),
  roles: z.array(UrlParameterRoleSchema).default([]),
});

export const UrlObservationRecordSchema = z.object({
  type: z.literal("URL_OBSERVATION"),
  /** Original observed URL, preserved verbatim. */
  url: z.string().min(1),
  /** Canonical identity used for deduplication. */
  canonicalUrl: z.string().min(1),
  host: z.string().default(""),
  method: UrlMethod,
  depth: z.number().int().nonnegative().default(0),
  statusCode: z.number().int().nullable().default(null),
  source: z.string().min(1),
  provider: z.string().min(1),
  classifications: z.array(UrlClassificationSchema).default([]),
  parameters: z.array(UrlParameterSchema).default([]),
  /**
   * True when this URL was referenced by a `<script src>` attribute in an HTML document. It is
   * evidence that the resource was loaded as JavaScript, even when the path has no script
   * extension (extensionless bundles); the content is still validated before any parsing.
   */
  scriptRef: z.boolean().default(false),
  /** Absolute URL of the HTML document that referenced this resource, for provenance. */
  parentUrl: z.string().default(""),
});
export type UrlObservationRecord = z.infer<typeof UrlObservationRecordSchema>;

export const ArtifactStatus = z.enum(["RETRIEVED", "NOT_FOUND", "ERROR", "SKIPPED", "OVERSIZED", "MISMATCHED_MIME"]);

export const JsArtifactRecordSchema = z.object({
  type: z.literal("JS_ARTIFACT"),
  url: z.string().min(1),
  canonicalUrl: z.string().min(1),
  contentHash: z.string().default(""),
  contentType: z.string().default(""),
  sizeBytes: z.number().int().nonnegative().default(0),
  sourceUrl: z.string().default(""),
  discoveryMethod: z.string().default(""),
  status: ArtifactStatus,
  error: z.string().default(""),
  truncated: z.boolean().default(false),
  provider: z.string().min(1),
  source: z.string().min(1),
});

export const SourceMapRecordSchema = z.object({
  type: z.literal("SOURCE_MAP"),
  jsUrl: z.string().min(1),
  sourceMapUrl: z.string().min(1),
  status: z.enum(["PARSED", "NOT_FOUND", "ERROR", "SKIPPED", "DISABLED"]),
  sourcesCount: z.number().int().nonnegative().default(0),
  sources: z.array(z.string()).default([]),
  sourceRoot: z.string().default(""),
  hasContent: z.boolean().default(false),
  error: z.string().default(""),
  provider: z.string().min(1),
});

export const ApiSpecRecordSchema = z.object({
  type: z.literal("API_SPEC"),
  url: z.string().min(1),
  specVersion: z.string().default(""),
  title: z.string().default(""),
  format: z.enum(["JSON", "YAML", "UNKNOWN"]).default("UNKNOWN"),
  servers: z.array(z.string()).default([]),
  pathCount: z.number().int().nonnegative().default(0),
  operationCount: z.number().int().nonnegative().default(0),
  securitySchemes: z.array(z.string()).default([]),
  unresolvedRefs: z.number().int().nonnegative().default(0),
  parseStatus: z.enum(["PARSED", "NOT_FOUND", "MALFORMED", "ERROR", "SKIPPED"]),
  error: z.string().default(""),
  provider: z.string().min(1),
});

export const ApiParameterSchema = z.object({
  name: z.string().min(1),
  location: z.enum(["query", "path", "header", "cookie", "body", "unknown"]).default("unknown"),
  required: z.boolean().default(false),
  type: z.string().default(""),
  evidence: z.string().default(""),
});

export const EndpointSourceSchema = z.enum(["JS", "SPEC", "HTTP"]);

export const ApiEndpointRecordSchema = z.object({
  type: z.literal("API_ENDPOINT"),
  /** HTTP method, or ANY when unidentified. */
  method: z.string().min(1),
  origin: z.string().default(""),
  path: z.string().min(1),
  url: z.string().default(""),
  discoveredVia: EndpointSourceSchema,
  /** True for endpoints declared in an API specification. */
  documented: z.boolean().default(false),
  /** True when the path is concrete; false for unresolved dynamic candidates. */
  resolved: z.boolean().default(true),
  operationId: z.string().default(""),
  tags: z.array(z.string()).default([]),
  parameters: z.array(ApiParameterSchema).default([]),
  contentTypes: z.array(z.string()).default([]),
  authSchemes: z.array(z.string()).default([]),
  sourceUrl: z.string().default(""),
  evidence: z.string().default(""),
  evidenceType: z.string().default(""),
  provider: z.string().min(1),
});

export const SecurityCategory = z.enum(["TLS", "HEADER", "COOKIE", "CORS", "HSTS", "CONTENT_TYPE"]);

/** Metadata observation states. `NOT_OBSERVED` never means "control is absent". */
export const MetadataStatus = z.enum([
  "OBSERVED",
  "INFERRED",
  "INCONSISTENT",
  "NOT_OBSERVED",
  "UNKNOWN",
  "COLLECTION_FAILED",
]);

export const SecurityMetadataRecordSchema = z.object({
  type: z.literal("SECURITY_METADATA"),
  url: z.string().default(""),
  host: z.string().default(""),
  category: SecurityCategory,
  /** Header name, cookie name, cert field, etc. */
  name: z.string().default(""),
  status: MetadataStatus,
  observed: z.boolean().default(true),
  /** Primitive value where safe (never a cookie value or secret). */
  value: z.string().default(""),
  detail: z.record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.null()])).default({}),
  /** Whether the observation is internally consistent (null = not applicable). */
  consistent: z.boolean().nullable().default(null),
  evidence: z.string().default(""),
  evidenceType: z.string().default(""),
  provider: z.string().min(1),
  source: z.string().min(1),
});
export type SecurityMetadataRecord = z.infer<typeof SecurityMetadataRecordSchema>;

export const SecretCategory = z.enum([
  "CLOUD_CREDENTIAL",
  "API_KEY",
  "PRIVATE_KEY",
  "DATABASE_URL",
  "OAUTH_SECRET",
  "BEARER_TOKEN",
  "WEBHOOK_SECRET",
  "PASSWORD",
  "GENERIC_HIGH_ENTROPY",
  "OTHER",
]);

/**
 * Finding lifecycle. `VALIDATED`/`ACTIVE` are deliberately absent: no credential verification is
 * permitted. `REDACTED` is enforced as an invariant (all evidence is redacted) rather than a state.
 */
export const SecretStatus = z.enum(["CANDIDATE", "HIGH_CONFIDENCE", "SUPPRESSED", "ANALYSIS_FAILED"]);

export const SecretCandidateRecordSchema = z.object({
  type: z.literal("SECRET_CANDIDATE"),
  ruleId: z.string().min(1),
  category: SecretCategory,
  status: SecretStatus,
  confidence: z.number().min(0).max(1),
  artifactUrl: z.string().default(""),
  host: z.string().default(""),
  /** Line:column (1-based) or byte offset. */
  location: z.string().default(""),
  /** Context with the matched value replaced; the raw value is never present. */
  redactedSnippet: z.string().default(""),
  /** Safe correlation identity (HMAC of rule+value); empty when no key is configured. */
  fingerprint: z.string().default(""),
  /** Number of identical matches collapsed into this finding. */
  occurrences: z.number().int().positive().default(1),
  rationale: z.string().default(""),
  suppressionReason: z.string().default(""),
  provider: z.string().min(1),
  source: z.string().min(1),
});
export type SecretCandidateRecord = z.infer<typeof SecretCandidateRecordSchema>;

export const SecretScanArtifactSchema = z.object({
  type: z.literal("SECRET_SCAN_ARTIFACT"),
  artifactUrl: z.string().min(1),
  host: z.string().default(""),
  status: z.enum(["ANALYZED", "ANALYSIS_FAILED", "SKIPPED", "OVERSIZED"]),
  findingsCount: z.number().int().nonnegative().default(0),
  rawBytes: z.number().int().nonnegative().default(0),
  hmacKeyed: z.boolean().default(false),
  error: z.string().default(""),
  provider: z.string().min(1),
  source: z.string().min(1),
});
export type SecretScanArtifactRecord = z.infer<typeof SecretScanArtifactSchema>;

/**
 * Stage 11 correlation relations. Only relationships directly supported by persisted evidence are
 * represented. There is deliberately no CONFIRMED/VALIDATED/ACTIVE relation.
 */
export const CorrelationRelation = z.enum(["SHARES_SECRET_FINGERPRINT", "MULTI_SOURCE_CORROBORATION"]);

export const CorrelationStatus = z.enum(["OBSERVED", "PARTIAL", "FAILED"]);

/**
 * A deterministic, evidence-backed correlation record. `confidence` measures the strength of the
 * stated relationship only (e.g. fingerprint equality) — never credential validity or exploitability.
 * `correlationGroup` is an opaque, non-reversible group id derived from the keyed fingerprint; the
 * fingerprint and any raw secret value are never stored here.
 */
export const CorrelationRecordSchema = z.object({
  relation: CorrelationRelation,
  status: CorrelationStatus,
  /** Canonical key of the primary asset (subject). */
  subject: z.string().min(1),
  /** Canonical keys of related assets/sources. */
  related: z.array(z.string()).default([]),
  /** Rule id for secret-fingerprint correlations; empty otherwise. */
  ruleId: z.string().default(""),
  /** True only when fingerprints were produced with a configured HMAC key. */
  hmacKeyed: z.boolean().default(false),
  /** Opaque correlation group id (hex); never the fingerprint itself. */
  correlationGroup: z.string().default(""),
  /** Persisted observation ids that support this correlation. */
  sourceRecordIds: z.array(z.string().uuid()).default([]),
  /** Stage that produced the supporting records. */
  sourceStage: z.string().min(1),
  /** Redacted, human-readable explanation. */
  evidence: z.string().default(""),
  confidence: z.number().min(0).max(1),
});
export type CorrelationRecord = z.infer<typeof CorrelationRecordSchema>;

/**
 * A potential subdomain-takeover candidate. This is NEVER proof the subdomain is takeoverable:
 * it records that a subdomain points (via CNAME) at a takeover-prone service and what the service
 * returned. Its absence is not proof that no takeover exists.
 */
export const TakeoverStatus = z.enum(["SUSPECTED", "CANDIDATE", "NOT_VULNERABLE", "INCONCLUSIVE"]);

export const TakeoverCandidateRecordSchema = z.object({
  type: z.literal("TAKEOVER_CANDIDATE"),
  host: z.string().min(1),
  cname: z.string().default(""),
  service: z.string().default(""),
  status: TakeoverStatus,
  confidence: z.number().min(0).max(1),
  httpStatus: z.number().int().nullable().default(null),
  /** Redacted, human-readable evidence (never a raw credential). */
  evidence: z.string().default(""),
  evidenceType: z.string().default(""),
  provider: z.string().min(1),
  source: z.string().min(1),
});
export type TakeoverCandidateRecord = z.infer<typeof TakeoverCandidateRecordSchema>;

export const LoginInterfaceKind = z.enum(["ADMIN", "CPANEL"]);

/**
 * `DETECTED` means a concrete interface marker was observed (e.g. a password form on an admin
 * path, or a cPanel/WHM response marker). `POSSIBLE` means only weaker evidence was available
 * (for example an authentication-required status on a known administrative path). Neither state
 * is a vulnerability claim, and no credentials are ever submitted.
 */
export const LoginInterfaceStatus = z.enum(["DETECTED", "POSSIBLE"]);

export const LoginInterfaceRecordSchema = z.object({
  type: z.literal("LOGIN_INTERFACE"),
  url: z.string().min(1),
  finalUrl: z.string().default(""),
  host: z.string().min(1),
  kind: LoginInterfaceKind,
  status: LoginInterfaceStatus,
  confidence: z.number().min(0).max(1),
  httpStatus: z.number().int().nullable().default(null),
  title: z.string().default(""),
  evidence: z.string().default(""),
  evidenceType: z.string().default(""),
  provider: z.string().min(1),
  source: z.string().min(1),
});
export type LoginInterfaceRecord = z.infer<typeof LoginInterfaceRecordSchema>;

export const PortState = z.enum(["OPEN", "FILTERED", "OPEN_FILTERED"]);

/**
 * A TCP port observed on an address that resolves from an in-scope host. `OPEN` means a connection
 * was accepted. `product`/`version` come from service-version detection and are claims by the
 * scanner, not proof of what is running. Closed ports are not recorded, and the absence of a port
 * is not proof that it is closed.
 */
export const PortObservationRecordSchema = z.object({
  type: z.literal("PORT_OBSERVATION"),
  /** The in-scope host through which the address was reached. */
  host: z.string().min(1),
  ip: z.string().min(1),
  port: z.number().int().min(1).max(65535),
  protocol: z.literal("tcp").default("tcp"),
  state: PortState,
  /** Service name from the scanner (for example "http", "ssh"); empty when unidentified. */
  service: z.string().default(""),
  product: z.string().default(""),
  version: z.string().default(""),
  extraInfo: z.string().default(""),
  /** True when the service is wrapped in TLS. */
  tls: z.boolean().default(false),
  /** Scanner confidence in the service identification, 0-1. */
  confidence: z.number().min(0).max(1).default(0),
  provider: z.string().min(1),
  source: z.string().min(1),
});
export type PortObservationRecord = z.infer<typeof PortObservationRecordSchema>;

export const TemplateSeverity = z.enum(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);

/**
 * A template match from a template-based checker (nuclei). The severity is the template author's
 * rating of the issue *if* it is real; a match is a detection by a signature, not a verified
 * vulnerability. Request/response bodies are never carried, and extracted values are redacted and
 * truncated by the worker.
 */
export const TemplateFindingRecordSchema = z.object({
  type: z.literal("TEMPLATE_FINDING"),
  host: z.string().min(1),
  /** The URL the template matched at. */
  url: z.string().min(1),
  templateId: z.string().min(1),
  name: z.string().default(""),
  severity: TemplateSeverity,
  description: z.string().default(""),
  tags: z.array(z.string()).default([]),
  references: z.array(z.string()).default([]),
  matcherName: z.string().default(""),
  extracted: z.array(z.string()).default([]),
  templateType: z.string().default(""),
  confidence: z.number().min(0).max(1).default(0.7),
  provider: z.string().min(1),
  source: z.string().min(1),
});
export type TemplateFindingRecord = z.infer<typeof TemplateFindingRecordSchema>;

export const CloudStorageProvider = z.enum(["S3", "GCS"]);

/**
 * Whether a CNAME-fronted bucket is publicly listable. `LISTABLE` means the response carried an
 * actual object listing; `NOT_LISTABLE` means it answered but declined (access denied, or no
 * bucket by that name — a dangling-CNAME/takeover question, not an exposure); `INCONCLUSIVE` means
 * the response matched neither. The request target is always the in-scope host itself.
 */
export const CloudStorageStatus = z.enum(["LISTABLE", "NOT_LISTABLE", "INCONCLUSIVE"]);

export const CloudStorageRecordSchema = z.object({
  type: z.literal("CLOUD_STORAGE"),
  url: z.string().min(1),
  host: z.string().min(1),
  cloudProvider: CloudStorageProvider,
  bucket: z.string().default(""),
  origin: z.literal("CUSTOM_DOMAIN").default("CUSTOM_DOMAIN"),
  status: CloudStorageStatus,
  confidence: z.number().min(0).max(1),
  httpStatus: z.number().int().nullable().default(null),
  objectCount: z.number().int().nonnegative().default(0),
  evidence: z.string().default(""),
  evidenceType: z.string().default(""),
  provider: z.string().min(1),
  source: z.string().min(1),
});
export type CloudStorageRecord = z.infer<typeof CloudStorageRecordSchema>;

export const ContentCategory = z.enum(["VCS", "CONFIG", "BACKUP", "DEBUG", "LOG", "DIRECTORY_LISTING", "METADATA"]);

/**
 * A path on an in-scope origin that answered differently from a missing path. `CONFIRMED` means the
 * response carried the path's content marker (or a directory index); `POSSIBLE` means only a
 * differing response was seen. Severity is the impact *if* the exposure is real. Response bodies are
 * never carried: evidence names the marker, so an exposed secret file does not leak into the store.
 */
export const ContentDiscoveryRecordSchema = z.object({
  type: z.literal("CONTENT_DISCOVERY"),
  url: z.string().min(1),
  host: z.string().min(1),
  path: z.string().min(1),
  category: ContentCategory,
  status: z.enum(["CONFIRMED", "POSSIBLE"]),
  severity: z.enum(["INFO", "LOW", "MEDIUM", "HIGH"]),
  confidence: z.number().min(0).max(1),
  httpStatus: z.number().int(),
  contentLength: z.number().int().nonnegative().default(0),
  contentType: z.string().default(""),
  title: z.string().default(""),
  evidence: z.string().default(""),
  evidenceType: z.string().default(""),
  provider: z.string().min(1),
  source: z.string().min(1),
});
export type ContentDiscoveryRecord = z.infer<typeof ContentDiscoveryRecordSchema>;

/**
 * Whether an in-scope origin reflects an arbitrary, caller-supplied Origin header back in
 * Access-Control-Allow-Origin. `NOT_VULNERABLE` is recorded (not omitted) so the probe's
 * coverage is auditable. Reflection combined with `Access-Control-Allow-Credentials: true` lets
 * any origin read authenticated responses; without credentials it is weaker but still unusual.
 */
export const CorsStatus = z.enum(["REFLECTS_ARBITRARY_ORIGIN_WITH_CREDENTIALS", "REFLECTS_ARBITRARY_ORIGIN", "NOT_VULNERABLE"]);

export const CorsMisconfigurationRecordSchema = z.object({
  type: z.literal("CORS_MISCONFIGURATION"),
  url: z.string().min(1),
  host: z.string().min(1),
  status: CorsStatus,
  confidence: z.number().min(0).max(1),
  allowOrigin: z.string().default(""),
  allowCredentials: z.boolean().default(false),
  testedOrigin: z.string().min(1),
  httpStatus: z.number().int().nullable().default(null),
  evidence: z.string().default(""),
  evidenceType: z.string().default(""),
  provider: z.string().min(1),
  source: z.string().min(1),
});
export type CorsMisconfigurationRecord = z.infer<typeof CorsMisconfigurationRecordSchema>;

/**
 * Whether overwriting one query parameter on an in-scope URL with an externally-controlled
 * canary value causes the response to redirect there. `NOT_VULNERABLE` is recorded (not
 * omitted) so the probe's coverage is auditable.
 */
export const OpenRedirectStatus = z.enum(["CONFIRMED", "NOT_VULNERABLE"]);

export const OpenRedirectRecordSchema = z.object({
  type: z.literal("OPEN_REDIRECT"),
  url: z.string().min(1),
  testedUrl: z.string().min(1),
  host: z.string().min(1),
  parameter: z.string().min(1),
  status: OpenRedirectStatus,
  confidence: z.number().min(0).max(1),
  httpStatus: z.number().int().nullable().default(null),
  location: z.string().default(""),
  evidence: z.string().default(""),
  evidenceType: z.string().default(""),
  provider: z.string().min(1),
  source: z.string().min(1),
});
export type OpenRedirectRecord = z.infer<typeof OpenRedirectRecordSchema>;

export const DiscoveryRecordSchema = z.discriminatedUnion("type", [
  HostObservationRecordSchema,
  DnsRecordSchema,
  IpMetadataRecordSchema,
  HttpObservationRecordSchema,
  TechnologyRecordSchema,
  UrlObservationRecordSchema,
  JsArtifactRecordSchema,
  SourceMapRecordSchema,
  ApiSpecRecordSchema,
  ApiEndpointRecordSchema,
  SecurityMetadataRecordSchema,
  SecretCandidateRecordSchema,
  SecretScanArtifactSchema,
  TakeoverCandidateRecordSchema,
  LoginInterfaceRecordSchema,
  PortObservationRecordSchema,
  TemplateFindingRecordSchema,
  ContentDiscoveryRecordSchema,
  CloudStorageRecordSchema,
  CorsMisconfigurationRecordSchema,
  OpenRedirectRecordSchema,
]);
export type DiscoveryRecord = z.infer<typeof DiscoveryRecordSchema>;

export const ExecutionRecordSchema = z.object({
  argv: z.array(z.string()).default([]),
  exitCode: z.number().int().nullable().default(null),
  exitDescription: z.string().default(""),
  durationMs: z.number().int().nonnegative().default(0),
  stdoutBytes: z.number().int().nonnegative().default(0),
  stderrBytes: z.number().int().nonnegative().default(0),
  truncated: z.boolean().default(false),
  timedOut: z.boolean().default(false),
  spawnError: z.string().default(""),
});
export type ExecutionRecord = z.infer<typeof ExecutionRecordSchema>;

export const ProviderCoverageSchema = z.object({
  attempted: z.number().int().nonnegative().default(0),
  succeeded: z.number().int().nonnegative().default(0),
  failed: z.number().int().nonnegative().default(0),
  skipped: z.number().int().nonnegative().default(0),
  unavailable: z.number().int().nonnegative().default(0),
});
export type ProviderCoverage = z.infer<typeof ProviderCoverageSchema>;

export const DiscoveryResultSchema = z.object({
  schemaVersion: z.literal(1),
  status: z.enum([
    "SUCCEEDED",
    "PARTIAL",
    "FAILED",
    "SKIPPED",
    "BLOCKED",
    "CANCELLED",
    "SOURCE_UNAVAILABLE",
  ]),
  provider: z.string().min(1),
  providerVersion: z.string().default("unknown"),
  execution: ExecutionRecordSchema,
  coverage: ProviderCoverageSchema,
  records: z.array(DiscoveryRecordSchema).default([]),
  diagnostics: z.array(z.string()).default([]),
});
export type DiscoveryResult = z.infer<typeof DiscoveryResultSchema>;

/** Retry classification for a failed provider invocation. */
export const RetryClass = {
  RETRYABLE: "RETRYABLE",
  PERMANENT: "PERMANENT",
  POLICY: "POLICY",
} as const;
export type RetryClassValue = (typeof RetryClass)[keyof typeof RetryClass];
