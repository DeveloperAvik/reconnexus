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
 * Only secret candidates (Stage 09) and takeover candidates (Stage 13) become findings. Security
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
  const [secretRows, takeoverRows, securityMetaRows] = await Promise.all([
    repo.listSecretFindings(scanId),
    repo.listTakeoverCandidates(scanId),
    repo.listSecurityMetadata(scanId, 5000),
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

  return buildFindings(secretFindings, takeoverCandidates, insecureCookieFindings(securityFindingInputs));
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
