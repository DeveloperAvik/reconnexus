import { createHash } from "node:crypto";
import type { ReportFinding, ReportFindingTotals, ReportSecretFinding, ReportTakeover } from "@reconnexus/contracts";
import type { Repository } from "../repository.js";

/**
 * Derivation of reportable findings from persisted candidate records.
 *
 * ReconNexus performs no exploitation and verifies no credential, so a finding derived here is
 * never `VALIDATED`. `severity` expresses the impact *if* the candidate is real, `confidence` is
 * the detector's confidence as persisted, and `validation` states how far the evidence goes. The
 * three are independent dimensions and are reported separately, never collapsed into one score.
 *
 * Secret candidates (Stage 09), takeover candidates (Stage 13), non-INFO template matches (Stage 16)
 * and open ports on an exposure list (Stage 15, `OBSERVED` only) become findings. Security
 * metadata, technologies, URLs and endpoints are *discovered assets and observations*, reported as
 * inventory — turning an absent header into a "finding" would present a single response at a point
 * in time as a confirmed weakness.
 */

/** Impact if the candidate is a real, live credential. Capped below CRITICAL: nothing is validated. */
const SECRET_SEVERITY: Record<string, string> = {
  CLOUD_CREDENTIAL: "HIGH",
  PRIVATE_KEY: "HIGH",
  DATABASE_URL: "HIGH",
  OAUTH_SECRET: "HIGH",
  API_KEY: "MEDIUM",
  BEARER_TOKEN: "MEDIUM",
  WEBHOOK_SECRET: "MEDIUM",
  PASSWORD: "MEDIUM",
  GENERIC_HIGH_ENTROPY: "LOW",
  OTHER: "LOW",
};

const SECRET_REMEDIATION: Record<string, string> = {
  CLOUD_CREDENTIAL:
    "Treat the key as compromised: revoke and rotate it at the cloud provider, review audit logs for use, then remove it from the bundle and inject it server-side instead of shipping it to browsers.",
  PRIVATE_KEY:
    "Revoke and reissue the key pair, remove the key from the artifact and its build inputs, and rewrite history if it was committed to a repository.",
  DATABASE_URL:
    "Rotate the database credentials, restrict network access to the database, and move the connection string into server-side configuration.",
  OAUTH_SECRET:
    "Rotate the client secret with the identity provider and move the exchange server-side; a public client must not hold a confidential secret.",
  API_KEY:
    "Rotate the key, scope it to the minimum required permissions, and proxy the call server-side if the key cannot be made public-safe.",
  BEARER_TOKEN: "Invalidate the token, shorten token lifetimes, and keep tokens out of static artifacts.",
  WEBHOOK_SECRET: "Rotate the signing secret and verify signatures server-side only.",
  PASSWORD: "Rotate the credential, remove it from the artifact, and move it into a secret manager.",
  GENERIC_HIGH_ENTROPY:
    "Confirm whether the value is a credential. If it is, rotate it and move it server-side; if it is not, add a suppression rule so later scans stay actionable.",
  OTHER: "Confirm whether the value is sensitive, then rotate and relocate it if so.",
};

/**
 * Validation state for a secret candidate. `HIGH_CONFIDENCE` raises confidence, never validation:
 * a strong pattern match is still only a suspicion until someone checks the credential.
 */
function secretValidation(status: string): string {
  switch (status) {
    case "SUPPRESSED":
      return "REJECTED";
    case "ANALYSIS_FAILED":
      return "INDETERMINATE";
    case "HIGH_CONFIDENCE":
    case "CANDIDATE":
    default:
      return "SUSPECTED";
  }
}

const TAKEOVER_SEVERITY: Record<string, string> = {
  SUSPECTED: "HIGH",
  CANDIDATE: "MEDIUM",
  INCONCLUSIVE: "INFO",
  NOT_VULNERABLE: "INFO",
};

function takeoverValidation(status: string): string {
  switch (status) {
    case "NOT_VULNERABLE":
      return "REJECTED";
    case "INCONCLUSIVE":
      return "INDETERMINATE";
    case "SUSPECTED":
    case "CANDIDATE":
    default:
      return "SUSPECTED";
  }
}

/** Stable, deterministic id so the same persisted state always yields the same finding ids. */
function findingId(parts: string[]): string {
  return createHash("sha256").update(parts.join("\u0000")).digest("hex").slice(0, 16);
}

export function secretFindingToFinding(f: ReportSecretFinding): ReportFinding {
  const severity = f.status === "SUPPRESSED" ? "INFO" : (SECRET_SEVERITY[f.category] ?? "LOW");
  return {
    id: findingId(["secret", f.ruleId, f.artifact, f.location]),
    title: `Secret candidate (${f.category.toLowerCase().replace(/_/g, " ")}) in ${f.artifact || "artifact"}`,
    category: f.category,
    severity,
    confidence: f.confidence,
    validation: secretValidation(f.status),
    subject: f.artifact,
    sourceStage: "09-secret-detection",
    sourceKind: "secret-finding",
    evidence: f.redactedSnippet,
    evidenceRefs: [f.artifact, f.host, f.location].filter((x) => x.length > 0),
    remediation: SECRET_REMEDIATION[f.category] ?? SECRET_REMEDIATION.OTHER!,
    references: [`rule:${f.ruleId}`],
  };
}

export function takeoverToFinding(t: ReportTakeover): ReportFinding {
  return {
    id: findingId(["takeover", t.host, t.cname, t.service]),
    title: `Subdomain-takeover candidate: ${t.host} → ${t.service || t.cname || "unknown service"}`,
    category: "SUBDOMAIN_TAKEOVER",
    severity: TAKEOVER_SEVERITY[t.status] ?? "INFO",
    confidence: t.confidence,
    validation: takeoverValidation(t.status),
    subject: t.host,
    sourceStage: "13-subdomain-takeover",
    sourceKind: "takeover-candidate",
    evidence: t.evidence,
    evidenceRefs: [t.host, t.cname ? `cname:${t.cname}` : "", t.httpStatus === null ? "" : `http:${t.httpStatus}`].filter((x) => x.length > 0),
    remediation:
      "Reclaim or remove the dangling DNS record: delete the CNAME if the service is no longer used, or re-create the resource at the provider so the name cannot be claimed by someone else. Verify ownership before any takeover is attempted.",
    references: [t.service ? `service:${t.service}` : "service:unknown"],
  };
}

/**
 * A security-metadata observation reduced to the fields a finding rule needs. Only genuinely
 * applicable, evidence-backed conditions become findings; a `NOT_OBSERVED` control never does.
 */
export interface SecurityMetadataFindingInput {
  service: string;
  category: string;
  name: string;
  status: string;
  url: string;
  detail: Record<string, unknown>;
}

function isHttps(url: string): boolean {
  return url.trim().toLowerCase().startsWith("https://");
}

/**
 * Derive the one conservative security-metadata finding rule: an HTTPS response that sets a cookie
 * without the `Secure` attribute. Applicability is explicit (the response was served over TLS and
 * the cookie was actually set), the evidence is the Set-Cookie attributes themselves, and the
 * finding is a LOW-severity candidate — never a claim that the cookie is exposed, because that
 * needs HTTP reachability and the cookie's purpose, which a single response cannot establish.
 * Missing headers, CORS wildcards and other single-response observations deliberately do NOT
 * become findings.
 */
export function insecureCookieFindings(rows: readonly SecurityMetadataFindingInput[]): ReportFinding[] {
  const seen = new Set<string>();
  const findings: ReportFinding[] = [];
  for (const row of rows) {
    if (row.category !== "COOKIE" || row.status !== "OBSERVED") continue;
    if (!row.name || !isHttps(row.url)) continue;
    if (row.detail.secure !== false) continue;
    const key = `${row.service}\u0000${row.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({
      id: findingId(["insecure-cookie", row.service, row.name]),
      title: `Cookie "${row.name}" set without the Secure attribute over HTTPS`,
      category: "INSECURE_COOKIE",
      severity: "LOW",
      confidence: 0.6,
      validation: "SUSPECTED",
      subject: row.service,
      sourceStage: "10-security-checks",
      sourceKind: "security-metadata",
      evidence: `Set-Cookie for "${row.name}" on ${row.url} has Secure=absent; SameSite=${String(row.detail.sameSite ?? "unknown")}`,
      evidenceRefs: [row.url, `cookie:${row.name}`],
      remediation:
        "Add the Secure attribute so the browser only sends the cookie over TLS; also confirm SameSite and HttpOnly are set for session cookies. This is a configuration observation, not a demonstrated exposure.",
      references: ["https://owasp.org/www-community/controls/SecureCookieAttribute"],
    });
  }
  return findings;
}

export interface TemplateFindingInput {
  url: string;
  host: string;
  templateId: string;
  name: string;
  severity: string;
  description: string;
  tags: string[];
  references: string[];
  matcherName: string;
  extracted: string[];
  confidence: number;
}

/**
 * Template matches become findings except INFO-rated ones, which are technology/detection hits and
 * stay inventory (observations), like other single-response observations. Severity is the template
 * author's rating if the match is real, capped at HIGH: a signature match is never validated.
 */
export function templateFindings(rows: readonly TemplateFindingInput[]): ReportFinding[] {
  const seen = new Set<string>();
  const findings: ReportFinding[] = [];
  for (const r of rows) {
    if (r.severity === "INFO") continue;
    const id = findingId(["template", r.templateId, r.url, r.matcherName]);
    if (seen.has(id)) continue;
    seen.add(id);
    findings.push({
      id,
      title: `${r.name || r.templateId} (${r.templateId}) at ${r.url}`,
      category: "TEMPLATE_MATCH",
      severity: r.severity === "CRITICAL" ? "HIGH" : r.severity,
      confidence: r.confidence,
      validation: "SUSPECTED",
      subject: r.host,
      sourceStage: "16-template-checks",
      sourceKind: "template-finding",
      evidence: [r.description, r.extracted.length > 0 ? `extracted: ${r.extracted.join(", ")}` : ""].filter((x) => x.length > 0).join(" | "),
      evidenceRefs: [r.url, `template:${r.templateId}`, ...(r.matcherName ? [`matcher:${r.matcherName}`] : [])],
      remediation:
        "Confirm the match manually, then fix or remove the exposed resource or misconfiguration the template describes. A template match is a signature detection and can be a false positive.",
      references: r.references,
    });
  }
  return findings;
}

export interface CloudStorageFindingInput {
  url: string;
  host: string;
  cloudProvider: string;
  bucket: string;
  status: string;
  confidence: number;
  httpStatus: number | null;
  objectCount: number;
  evidence: string;
}

/**
 * Only a LISTABLE bucket becomes a finding: a real connection was made to the in-scope host and
 * the response carried an actual object listing, not just a status-code guess. NOT_LISTABLE
 * (access denied, or no bucket by that name) and INCONCLUSIVE stay inventory.
 */
export function cloudStorageFindings(rows: readonly CloudStorageFindingInput[]): ReportFinding[] {
  const seen = new Set<string>();
  const findings: ReportFinding[] = [];
  for (const r of rows) {
    if (r.status !== "LISTABLE") continue;
    const id = findingId(["cloud-storage", r.host, r.bucket]);
    if (seen.has(id)) continue;
    seen.add(id);
    findings.push({
      id,
      title: `Publicly listable ${r.cloudProvider} bucket "${r.bucket}" behind ${r.host}`,
      category: "EXPOSED_CLOUD_STORAGE",
      severity: "HIGH",
      confidence: r.confidence,
      validation: "SUSPECTED",
      subject: r.host,
      sourceStage: "18-cloud-storage",
      sourceKind: "cloud-storage",
      evidence: `HTTP ${r.httpStatus}; ${r.evidence}${r.objectCount > 0 ? ` (${r.objectCount} object(s) listed)` : ""}`,
      evidenceRefs: [r.url, `bucket:${r.cloudProvider}:${r.bucket}`],
      remediation: `Disable public listing on the "${r.bucket}" ${r.cloudProvider} bucket (block public ACLs/bucket policy, or an equivalent IAM binding on GCS) and review what it currently exposes. The request reached the bucket through ${r.host}'s own CNAME, confirming it fronts a real target asset.`,
      references:
        r.cloudProvider === "S3"
          ? ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"]
          : ["https://cloud.google.com/storage/docs/access-control/making-data-public"],
    });
  }
  return findings;
}

export interface CorsFindingInput {
  url: string;
  host: string;
  status: string;
  confidence: number;
  allowOrigin: string;
  allowCredentials: boolean;
  testedOrigin: string;
  httpStatus: number | null;
  evidence: string;
}

/**
 * Only an origin that reflects the probe's arbitrary Origin becomes a finding. Reflection with
 * `Access-Control-Allow-Credentials: true` is HIGH (any origin can read authenticated
 * responses); reflection alone is MEDIUM. NOT_VULNERABLE stays inventory.
 */
export function corsFindings(rows: readonly CorsFindingInput[]): ReportFinding[] {
  const seen = new Set<string>();
  const findings: ReportFinding[] = [];
  for (const r of rows) {
    if (r.status === "NOT_VULNERABLE") continue;
    const id = findingId(["cors", r.url]);
    if (seen.has(id)) continue;
    seen.add(id);
    const withCredentials = r.status === "REFLECTS_ARBITRARY_ORIGIN_WITH_CREDENTIALS";
    findings.push({
      id,
      title: `CORS reflects an arbitrary Origin${withCredentials ? " with credentials" : ""} at ${r.url}`,
      category: "CORS_MISCONFIGURATION",
      severity: withCredentials ? "HIGH" : "MEDIUM",
      confidence: r.confidence,
      validation: "SUSPECTED",
      subject: r.host,
      sourceStage: "19-cors-redirect",
      sourceKind: "cors",
      evidence: `HTTP ${r.httpStatus}; ${r.evidence} (tested Origin: ${r.testedOrigin})`,
      evidenceRefs: [r.url],
      remediation: withCredentials
        ? "Validate the Origin header against an explicit allowlist before reflecting it, and never combine a reflected or wildcard origin with Access-Control-Allow-Credentials: true."
        : "Validate the Origin header against an explicit allowlist before reflecting it in Access-Control-Allow-Origin, even without credentialed access.",
      references: ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_Cross_Origin_Resource_Sharing"],
    });
  }
  return findings;
}

export interface OpenRedirectFindingInput {
  url: string;
  testedUrl: string;
  host: string;
  parameter: string;
  status: string;
  confidence: number;
  httpStatus: number | null;
  location: string;
  evidence: string;
}

/**
 * Only a CONFIRMED redirect (the response actually redirected to the injected canary value)
 * becomes a finding. NOT_VULNERABLE stays inventory.
 */
export function openRedirectFindings(rows: readonly OpenRedirectFindingInput[]): ReportFinding[] {
  const seen = new Set<string>();
  const findings: ReportFinding[] = [];
  for (const r of rows) {
    if (r.status !== "CONFIRMED") continue;
    const id = findingId(["open-redirect", r.host, r.parameter]);
    if (seen.has(id)) continue;
    seen.add(id);
    findings.push({
      id,
      title: `Open redirect via "${r.parameter}" parameter at ${r.url}`,
      category: "OPEN_REDIRECT",
      severity: "MEDIUM",
      confidence: r.confidence,
      validation: "SUSPECTED",
      subject: r.host,
      sourceStage: "19-cors-redirect",
      sourceKind: "open-redirect",
      evidence: `HTTP ${r.httpStatus}; ${r.evidence} (Location: ${r.location})`,
      evidenceRefs: [r.url, `param:${r.parameter}`],
      remediation: `Validate the "${r.parameter}" redirect target against an explicit allowlist of in-application paths or domains before issuing the redirect.`,
      references: ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect"],
    });
  }
  return findings;
}

export interface EmailSecurityFindingInput {
  host: string;
  category: string;
  status: string;
  confidence: number;
  value: string;
  evidence: string;
}

const EMAIL_SECURITY_REMEDIATION: Record<string, string> = {
  SPF: "Publish a single SPF TXT record ending in '-all' that lists every legitimate sending source; avoid '+all' or a missing 'all' mechanism, which leave the policy effectively open.",
  DMARC: "Publish a DMARC TXT record at _dmarc.<domain> with p=quarantine or p=reject once SPF/DKIM alignment is confirmed; p=none only monitors and does not stop spoofed mail from being delivered.",
};

/**
 * Only SPF/DMARC `ABSENT`, `WEAK` and `MISCONFIGURED` become findings — a domain's email can be
 * spoofed more easily without an enforced policy. DKIM's `NOT_DETECTED` never becomes a finding:
 * it only means none of a fixed, common selector list resolved, which is not evidence DKIM is
 * absent. `STRONG` and `DETECTED` stay inventory (good posture, not an issue to report).
 */
export function emailSecurityFindings(rows: readonly EmailSecurityFindingInput[]): ReportFinding[] {
  const seen = new Set<string>();
  const findings: ReportFinding[] = [];
  for (const r of rows) {
    if (r.category === "DKIM" || r.status === "STRONG" || r.status === "DETECTED") continue;
    const id = findingId(["email-security", r.host, r.category]);
    if (seen.has(id)) continue;
    seen.add(id);
    const severity = r.status === "MISCONFIGURED" ? "MEDIUM" : r.category === "DMARC" ? "MEDIUM" : "LOW";
    findings.push({
      id,
      title: `${r.category} ${r.status === "ABSENT" ? "is missing" : "is weak"} for ${r.host}`,
      category: "EMAIL_SECURITY_WEAKNESS",
      severity,
      confidence: r.confidence,
      validation: "SUSPECTED",
      subject: r.host,
      sourceStage: "20-email-security",
      sourceKind: "email-security",
      evidence: r.evidence + (r.value ? ` (record: ${r.value})` : ""),
      evidenceRefs: [r.host],
      remediation: EMAIL_SECURITY_REMEDIATION[r.category] ?? "Review the domain's email authentication configuration.",
      references: ["https://datatracker.ietf.org/doc/html/rfc7208", "https://datatracker.ietf.org/doc/html/rfc7489"],
    });
  }
  return findings;
}

export interface GraphQLFindingInput {
  url: string;
  host: string;
  status: string;
  confidence: number;
  httpStatus: number | null;
  queryType: string;
  mutationType: string;
  queryFieldCount: number;
  mutationFieldCount: number;
  evidence: string;
}

/**
 * Only INTROSPECTION_ENABLED becomes a finding: the schema was actually disclosed, not merely
 * guessed. INTROSPECTION_DISABLED is a good outcome, and NOT_GRAPHQL stays inventory.
 */
export function graphQLFindings(rows: readonly GraphQLFindingInput[]): ReportFinding[] {
  const seen = new Set<string>();
  const findings: ReportFinding[] = [];
  for (const r of rows) {
    if (r.status !== "INTROSPECTION_ENABLED") continue;
    const id = findingId(["graphql", r.url]);
    if (seen.has(id)) continue;
    seen.add(id);
    const opCounts = [r.queryFieldCount ? `${r.queryFieldCount} query field(s)` : "", r.mutationFieldCount ? `${r.mutationFieldCount} mutation field(s)` : ""].filter(Boolean).join(", ");
    findings.push({
      id,
      title: `GraphQL introspection enabled at ${r.url}`,
      category: "GRAPHQL_INTROSPECTION_ENABLED",
      severity: "MEDIUM",
      confidence: r.confidence,
      validation: "SUSPECTED",
      subject: r.host,
      sourceStage: "21-graphql-intelligence",
      sourceKind: "graphql",
      evidence: `HTTP ${r.httpStatus}; ${r.evidence}${opCounts ? ` (${opCounts})` : ""}`,
      evidenceRefs: [r.url],
      remediation: "Disable introspection in production (most GraphQL servers offer a flag for this), or restrict it to authenticated administrators. A disclosed schema makes the full query/mutation surface, including undocumented fields, trivial to enumerate.",
      references: ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"],
    });
  }
  return findings;
}

export interface ParamDiscoveryFindingInput {
  url: string;
  host: string;
  parameter: string;
  confidence: number;
  httpStatus: number | null;
  evidence: string;
  evidenceType: string;
}

/**
 * Every row here is already a positive discovery (the worker never emits a record for a
 * parameter that showed no difference), so every row becomes a finding. Confidence carries the
 * strength of the signal (reflected value > status-code change > length delta).
 */
export function paramDiscoveryFindings(rows: readonly ParamDiscoveryFindingInput[]): ReportFinding[] {
  const seen = new Set<string>();
  const findings: ReportFinding[] = [];
  for (const r of rows) {
    const id = findingId(["param-discovery", r.url, r.parameter]);
    if (seen.has(id)) continue;
    seen.add(id);
    findings.push({
      id,
      title: `Undocumented parameter "${r.parameter}" discovered at ${r.url}`,
      category: "UNDOCUMENTED_PARAMETER",
      severity: "LOW",
      confidence: r.confidence,
      validation: "SUSPECTED",
      subject: r.host,
      sourceStage: "22-parameter-discovery",
      sourceKind: "param-discovery",
      evidence: `HTTP ${r.httpStatus}; ${r.evidence}`,
      evidenceRefs: [r.url, `param:${r.parameter}`],
      remediation: `Confirm manually whether "${r.parameter}" is an intentional, documented parameter. If not, remove the behavior it triggers or make sure it goes through the same validation and authorization as documented parameters.`,
      references: [],
    });
  }
  return findings;
}

export interface ContentFindingInput {
  url: string;
  host: string;
  path: string;
  category: string;
  status: string;
  severity: string;
  confidence: number;
  httpStatus: number;
  evidence: string;
}

const CONTENT_REMEDIATION: Record<string, string> = {
  VCS: "Remove version-control metadata from the web root and block access to dot-directories; assume any secrets in the repository history are compromised and rotate them.",
  CONFIG: "Remove the file from the web root, deny access to configuration files at the web server, and rotate any credentials it contained.",
  BACKUP: "Remove backups and database dumps from the web root, store them off-server, and rotate credentials that appear in them.",
  DEBUG: "Disable the debug or management endpoint in production, or restrict it to administrators behind authentication and a network control.",
  LOG: "Move logs out of the web root and deny direct access; review them for credentials and personal data.",
  DIRECTORY_LISTING: "Disable directory indexing (for example `Options -Indexes` or `autoindex off`) and review the listed files.",
};

/**
 * Content-discovery hits become findings only when there is evidence of exposure: a CONFIRMED hit
 * (content marker or directory index) at LOW or above, or a POSSIBLE hit rated MEDIUM or above.
 * INFO hits (access-denied paths, metadata files) and weak LOW possibilities stay inventory.
 * Severity is the worker's rating if the exposure is real; nothing here is validated.
 */
export function contentFindings(rows: readonly ContentFindingInput[]): ReportFinding[] {
  const seen = new Set<string>();
  const findings: ReportFinding[] = [];
  for (const r of rows) {
    const actionable = r.severity !== "INFO" && (r.status === "CONFIRMED" || r.severity === "MEDIUM" || r.severity === "HIGH");
    if (!actionable) continue;
    const id = findingId(["content", r.url]);
    if (seen.has(id)) continue;
    seen.add(id);
    findings.push({
      id,
      title: `${r.status === "CONFIRMED" ? "Exposed" : "Possibly exposed"} ${r.category.toLowerCase().replace("_", " ")} content at ${r.url}`,
      category: "EXPOSED_CONTENT",
      severity: r.severity,
      confidence: r.confidence,
      validation: "SUSPECTED",
      subject: r.host,
      sourceStage: "17-content-discovery",
      sourceKind: "content-discovery",
      evidence: `HTTP ${r.httpStatus}; ${r.evidence}`,
      evidenceRefs: [r.url, `path:${r.path}`],
      remediation: CONTENT_REMEDIATION[r.category] ?? "Remove or restrict the exposed resource. Confirm manually first: this is an automated, path-based detection.",
      references: ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"],
    });
  }
  return findings;
}

interface ExposureRule {
  label: string;
  severity: string;
  remediation: string;
}

const DB_REMEDIATION = "Restrict the port to the application tier with a firewall or security group, require authentication and TLS, and never expose it to the internet.";

/** Ports whose public exposure is normally unintended. Severity is the impact if exposure is unintended. */
const EXPOSURE_RULES: Record<number, ExposureRule> = {
  21: { label: "FTP", severity: "MEDIUM", remediation: "Replace FTP with SFTP/FTPS and restrict access, or close the port if unused." },
  23: { label: "Telnet", severity: "HIGH", remediation: "Disable Telnet and use SSH; Telnet sends credentials in clear text." },
  111: { label: "RPC portmapper", severity: "MEDIUM", remediation: "Block rpcbind from the internet; it discloses service details and aids amplification." },
  135: { label: "MS-RPC", severity: "MEDIUM", remediation: "Block Windows RPC from the internet." },
  139: { label: "NetBIOS", severity: "MEDIUM", remediation: "Block NetBIOS from the internet." },
  445: { label: "SMB", severity: "HIGH", remediation: "Block SMB from the internet and patch the host; exposed SMB has a long history of wormable flaws." },
  1433: { label: "Microsoft SQL Server", severity: "HIGH", remediation: DB_REMEDIATION },
  1521: { label: "Oracle database", severity: "HIGH", remediation: DB_REMEDIATION },
  2049: { label: "NFS", severity: "MEDIUM", remediation: "Restrict NFS exports to internal hosts." },
  2375: { label: "Docker API (unencrypted)", severity: "HIGH", remediation: "Do not expose the Docker daemon over TCP without TLS client authentication; unauthenticated access is host takeover." },
  2376: { label: "Docker API (TLS)", severity: "MEDIUM", remediation: "Confirm mutual TLS is enforced and restrict the port to administrators." },
  3306: { label: "MySQL/MariaDB", severity: "HIGH", remediation: DB_REMEDIATION },
  3389: { label: "RDP", severity: "HIGH", remediation: "Put RDP behind a VPN or gateway with MFA and network-level authentication." },
  5432: { label: "PostgreSQL", severity: "HIGH", remediation: DB_REMEDIATION },
  5601: { label: "Kibana", severity: "MEDIUM", remediation: "Place Kibana behind authentication and a VPN or proxy." },
  5672: { label: "AMQP broker", severity: "LOW", remediation: "Restrict broker access to application hosts." },
  5900: { label: "VNC", severity: "HIGH", remediation: "Do not expose VNC directly; tunnel it over SSH or a VPN." },
  5985: { label: "WinRM (HTTP)", severity: "MEDIUM", remediation: "Restrict WinRM to management networks." },
  6379: { label: "Redis", severity: "HIGH", remediation: DB_REMEDIATION },
  6443: { label: "Kubernetes API", severity: "MEDIUM", remediation: "Restrict API-server access to trusted networks and disable anonymous access." },
  9042: { label: "Cassandra", severity: "HIGH", remediation: DB_REMEDIATION },
  9200: { label: "Elasticsearch", severity: "HIGH", remediation: DB_REMEDIATION },
  9300: { label: "Elasticsearch transport", severity: "HIGH", remediation: DB_REMEDIATION },
  10250: { label: "Kubelet API", severity: "HIGH", remediation: "Disable anonymous kubelet access and restrict the port to the control plane." },
  11211: { label: "Memcached", severity: "HIGH", remediation: "Do not expose Memcached; it has no authentication and is abused for amplification." },
  15672: { label: "RabbitMQ management", severity: "MEDIUM", remediation: "Restrict the management UI to administrators and change default credentials." },
  27017: { label: "MongoDB", severity: "HIGH", remediation: DB_REMEDIATION },
};

export interface PortFindingInput {
  host: string;
  ip: string;
  port: number;
  protocol: string;
  state: string;
  service: string;
  product: string;
  version: string;
}

/**
 * An open port from the exposure list becomes an `OBSERVED` finding: a TCP connection was accepted,
 * which is a fact, but whether the service is intended to be public, authenticated or vulnerable is
 * not established. One finding per address and port, not per host name that reaches it.
 */
export function exposedServiceFindings(rows: readonly PortFindingInput[]): ReportFinding[] {
  const byKey = new Map<string, { row: PortFindingInput; hosts: Set<string> }>();
  for (const r of rows) {
    if (r.state !== "OPEN" || r.protocol !== "tcp" || !(r.port in EXPOSURE_RULES)) continue;
    const key = `${r.ip}:${r.port}`;
    const entry = byKey.get(key) ?? { row: r, hosts: new Set<string>() };
    entry.hosts.add(r.host);
    byKey.set(key, entry);
  }
  return Array.from(byKey.values()).map(({ row, hosts }) => {
    const rule = EXPOSURE_RULES[row.port]!;
    const detail = [row.product, row.version].filter((x) => x.length > 0).join(" ");
    return {
      id: findingId(["exposed-service", row.ip, String(row.port)]),
      title: `${rule.label} reachable on ${row.ip}:${row.port}/tcp`,
      category: "EXPOSED_SERVICE",
      severity: rule.severity,
      confidence: 0.9,
      validation: "OBSERVED",
      subject: sortedHosts(hosts)[0] ?? row.ip,
      sourceStage: "15-port-scan",
      sourceKind: "port-observation",
      evidence: `TCP connection accepted on ${row.ip}:${row.port}${detail ? ` (service detection: ${detail})` : ""}; reached via ${sortedHosts(hosts).join(", ")}`,
      evidenceRefs: [`${row.ip}:${row.port}/tcp`, ...sortedHosts(hosts)],
      remediation: rule.remediation,
      references: [],
    };
  });
}

function sortedHosts(hosts: Set<string>): string[] {
  return Array.from(hosts).sort();
}

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

/**
 * Build the findings list. Order is deterministic: severity, then validation, then id — so two
 * reports from identical persisted state are byte-identical.
 */
export function buildFindings(secrets: ReportSecretFinding[], takeovers: ReportTakeover[], security: ReportFinding[] = []): ReportFinding[] {
  // Only SUSPECTED/CANDIDATE takeovers are findings. NOT_VULNERABLE and INCONCLUSIVE are inventory
  // (they remain in the report's takeoverCandidates section): listing "not vulnerable" or
  // "inconclusive" as a finding inflates the findings count and misleads the reader.
  const actionableTakeovers = takeovers.filter((t) => t.status === "SUSPECTED" || t.status === "CANDIDATE");
  const findings = [...secrets.map(secretFindingToFinding), ...actionableTakeovers.map(takeoverToFinding), ...security];
  return findings.sort((a, b) => {
    const s = (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9);
    if (s !== 0) return s;
    if (a.validation !== b.validation) return a.validation < b.validation ? -1 : 1;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });
}

/**
 * Loads a scan's secret, takeover and security-metadata records from the repository and reduces
 * them to the same finding list the `report` command embeds. Shared by `report` and the standalone
 * `findings` command so both derive findings from one place rather than two independent readings
 * of the persisted rows drifting apart.
 */
export async function loadScanFindings(repo: Repository, scanId: string): Promise<ReportFinding[]> {
  const [secretRows, takeoverRows, securityMetaRows, templateRows, portRows, contentRows, cloudRows, corsRows, redirectRows, emailRows, graphqlRows, paramRows] = await Promise.all([
    repo.listSecretFindings(scanId),
    repo.listTakeoverCandidates(scanId),
    repo.listSecurityMetadata(scanId, 5000),
    repo.listTemplateFindings(scanId),
    repo.listPortObservations(scanId),
    repo.listContentDiscoveries(scanId),
    repo.listCloudStorageFindings(scanId),
    repo.listCorsFindings(scanId),
    repo.listOpenRedirectFindings(scanId),
    repo.listEmailSecurityFindings(scanId),
    repo.listGraphQLFindings(scanId),
    repo.listParamDiscoveryFindings(scanId),
  ]);

  const secretFindings: ReportSecretFinding[] = secretRows
    .map((r) => {
      const d = r.data as { ruleId?: string; category?: string; status?: string; confidence?: number; host?: string; location?: string; redactedSnippet?: string };
      return {
        ruleId: d.ruleId ?? "unknown",
        category: d.category ?? "OTHER",
        status: d.status ?? "CANDIDATE",
        confidence: typeof d.confidence === "number" ? d.confidence : 0,
        artifact: r.artifact,
        host: d.host ?? "",
        location: d.location ?? "",
        redactedSnippet: d.redactedSnippet ?? "",
      };
    })
    .sort((a, b) => (a.ruleId + a.artifact + a.location < b.ruleId + b.artifact + b.location ? -1 : 1));

  const takeoverCandidates: ReportTakeover[] = takeoverRows
    .map((r) => {
      const d = r.data as { cname?: string; service?: string; status?: string; confidence?: number; httpStatus?: number | null; evidence?: string };
      return {
        host: r.host,
        cname: d.cname ?? "",
        service: d.service ?? "",
        status: d.status ?? "CANDIDATE",
        confidence: typeof d.confidence === "number" ? d.confidence : 0,
        httpStatus: typeof d.httpStatus === "number" ? d.httpStatus : null,
        evidence: d.evidence ?? "",
      };
    })
    .sort((a, b) => (a.host < b.host ? -1 : 1));

  const securityFindingInputs: SecurityMetadataFindingInput[] = securityMetaRows.map((r) => {
    const d = (r.data ?? {}) as { category?: string; name?: string; status?: string; url?: string; detail?: unknown };
    return {
      service: r.service,
      category: d.category ?? "",
      name: d.name ?? "",
      status: d.status ?? "",
      url: d.url ?? r.service,
      detail: (typeof d.detail === "object" && d.detail !== null ? d.detail : {}) as Record<string, unknown>,
    };
  });

  const templateInputs: TemplateFindingInput[] = templateRows.map((r) => {
    const d = r.data as Partial<TemplateFindingInput>;
    return {
      url: r.url,
      host: d.host ?? "",
      templateId: d.templateId ?? "unknown",
      name: d.name ?? "",
      severity: d.severity ?? "INFO",
      description: d.description ?? "",
      tags: d.tags ?? [],
      references: d.references ?? [],
      matcherName: d.matcherName ?? "",
      extracted: d.extracted ?? [],
      confidence: typeof d.confidence === "number" ? d.confidence : 0.5,
    };
  });
  const portInputs: PortFindingInput[] = portRows.map((r) => {
    const d = r.data as Partial<PortFindingInput>;
    return { host: d.host ?? "", ip: d.ip ?? "", port: d.port ?? 0, protocol: d.protocol ?? "tcp", state: d.state ?? "", service: d.service ?? "", product: d.product ?? "", version: d.version ?? "" };
  });

  const contentInputs: ContentFindingInput[] = contentRows.map((r) => {
    const d = r.data as Partial<ContentFindingInput>;
    return { url: r.url, host: d.host ?? "", path: d.path ?? "", category: d.category ?? "", status: d.status ?? "POSSIBLE", severity: d.severity ?? "INFO", confidence: typeof d.confidence === "number" ? d.confidence : 0.3, httpStatus: d.httpStatus ?? 0, evidence: d.evidence ?? "" };
  });

  const cloudInputs: CloudStorageFindingInput[] = cloudRows.map((r) => {
    const d = r.data as Partial<CloudStorageFindingInput>;
    return { url: r.url, host: d.host ?? "", cloudProvider: d.cloudProvider ?? "", bucket: d.bucket ?? "", status: d.status ?? "INCONCLUSIVE", confidence: typeof d.confidence === "number" ? d.confidence : 0.3, httpStatus: typeof d.httpStatus === "number" ? d.httpStatus : null, objectCount: d.objectCount ?? 0, evidence: d.evidence ?? "" };
  });

  const corsInputs: CorsFindingInput[] = corsRows.map((r) => {
    const d = r.data as Partial<CorsFindingInput>;
    return { url: r.url, host: d.host ?? "", status: d.status ?? "NOT_VULNERABLE", confidence: typeof d.confidence === "number" ? d.confidence : 0.3, allowOrigin: d.allowOrigin ?? "", allowCredentials: d.allowCredentials ?? false, testedOrigin: d.testedOrigin ?? "", httpStatus: typeof d.httpStatus === "number" ? d.httpStatus : null, evidence: d.evidence ?? "" };
  });

  const redirectInputs: OpenRedirectFindingInput[] = redirectRows.map((r) => {
    const d = r.data as Partial<OpenRedirectFindingInput>;
    return { url: r.url, testedUrl: d.testedUrl ?? "", host: d.host ?? "", parameter: d.parameter ?? "", status: d.status ?? "NOT_VULNERABLE", confidence: typeof d.confidence === "number" ? d.confidence : 0.3, httpStatus: typeof d.httpStatus === "number" ? d.httpStatus : null, location: d.location ?? "", evidence: d.evidence ?? "" };
  });

  const emailInputs: EmailSecurityFindingInput[] = emailRows.map((r) => {
    const d = r.data as Partial<EmailSecurityFindingInput>;
    return { host: r.host, category: d.category ?? "", status: d.status ?? "ABSENT", confidence: typeof d.confidence === "number" ? d.confidence : 0.3, value: d.value ?? "", evidence: d.evidence ?? "" };
  });

  const graphqlInputs: GraphQLFindingInput[] = graphqlRows.map((r) => {
    const d = r.data as Partial<GraphQLFindingInput>;
    return { url: r.url, host: d.host ?? "", status: d.status ?? "NOT_GRAPHQL", confidence: typeof d.confidence === "number" ? d.confidence : 0.3, httpStatus: typeof d.httpStatus === "number" ? d.httpStatus : null, queryType: d.queryType ?? "", mutationType: d.mutationType ?? "", queryFieldCount: d.queryFieldCount ?? 0, mutationFieldCount: d.mutationFieldCount ?? 0, evidence: d.evidence ?? "" };
  });

  const paramInputs: ParamDiscoveryFindingInput[] = paramRows.map((r) => {
    const d = r.data as Partial<ParamDiscoveryFindingInput>;
    return { url: r.url, host: d.host ?? "", parameter: d.parameter ?? "", confidence: typeof d.confidence === "number" ? d.confidence : 0.3, httpStatus: typeof d.httpStatus === "number" ? d.httpStatus : null, evidence: d.evidence ?? "", evidenceType: d.evidenceType ?? "" };
  });

  return buildFindings(secretFindings, takeoverCandidates, [
    ...insecureCookieFindings(securityFindingInputs),
    ...templateFindings(templateInputs),
    ...contentFindings(contentInputs),
    ...cloudStorageFindings(cloudInputs),
    ...corsFindings(corsInputs),
    ...openRedirectFindings(redirectInputs),
    ...emailSecurityFindings(emailInputs),
    ...graphQLFindings(graphqlInputs),
    ...paramDiscoveryFindings(paramInputs),
    ...exposedServiceFindings(portInputs),
  ]);
}

/** Counts by severity and validation. Always includes every key, so zero is explicit. */
export function findingTotals(findings: ReportFinding[]): ReportFindingTotals {
  const bySeverity: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  const byValidation: Record<string, number> = { VALIDATED: 0, SUSPECTED: 0, OBSERVED: 0, INDETERMINATE: 0, REJECTED: 0 };
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    byValidation[f.validation] = (byValidation[f.validation] ?? 0) + 1;
  }
  return { total: findings.length, bySeverity, byValidation, validated: byValidation.VALIDATED ?? 0 };
}
