import { createHash } from "node:crypto";
import type { DiscoveryRecord, DiscoveryResult, SourceReliabilityValue } from "@reconnexus/contracts";
import type { ArtifactStore } from "@reconnexus/evidence-contracts";
import { redactString } from "@reconnexus/logging";
import type { Queryable } from "../db/pool.js";

export interface AssetUpsert {
  id: string;
  inserted: boolean;
}

export async function upsertAsset(
  db: Queryable,
  input: { projectId: string; type: string; canonicalKey: string; value: string; seenAt: Date },
): Promise<AssetUpsert> {
  const res = await db.query<{ id: string; inserted: boolean }>(
    `INSERT INTO assets (project_id, type, canonical_key, value, first_seen, last_seen)
     VALUES ($1,$2,$3,$4,$5,$5)
     ON CONFLICT (project_id, type, canonical_key)
     DO UPDATE SET last_seen = GREATEST(assets.last_seen, EXCLUDED.last_seen),
                   value = EXCLUDED.value
     RETURNING id, (xmax = 0) AS inserted`,
    [input.projectId, input.type, input.canonicalKey, input.value, input.seenAt],
  );
  return res.rows[0]!;
}

export async function insertObservation(
  db: Queryable,
  input: {
    projectId: string;
    scanId: string;
    assetId: string;
    source: string;
    sourceReliability: SourceReliabilityValue;
    observedAt: Date;
    kind: string;
    data: Record<string, unknown>;
  },
): Promise<string> {
  const res = await db.query<{ id: string }>(
    `INSERT INTO observations (project_id, scan_id, asset_id, source, source_reliability, observed_at, kind, data)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
    [input.projectId, input.scanId, input.assetId, input.source, input.sourceReliability, input.observedAt, input.kind, JSON.stringify(input.data)],
  );
  return res.rows[0]!.id;
}

export async function upsertRelationship(
  db: Queryable,
  input: { projectId: string; fromAssetId: string; toAssetId: string; relation: string; confidence: number; source: string },
): Promise<void> {
  if (input.fromAssetId === input.toAssetId) return;
  await db.query(
    `INSERT INTO asset_relationships (project_id, from_asset_id, to_asset_id, relation, confidence, source)
     VALUES ($1,$2,$3,$4,$5,$6)
     ON CONFLICT (project_id, from_asset_id, to_asset_id, relation) DO NOTHING`,
    [input.projectId, input.fromAssetId, input.toAssetId, input.relation, input.confidence, input.source],
  );
}

export async function storeEvidence(
  db: Queryable,
  store: ArtifactStore,
  input: { projectId: string; scanId: string; content: string; contentType: string; redacted?: boolean },
): Promise<{ id: string; sha256: string; sizeBytes: number }> {
  const buf = Buffer.from(input.content, "utf8");
  const stored = await store.put(buf);
  const res = await db.query<{ id: string }>(
    `INSERT INTO evidence_artifacts (project_id, scan_id, sha256, content_type, size_bytes, storage_uri, redacted)
     VALUES ($1,$2,$3,$4,$5,$6,$7)
     ON CONFLICT (project_id, sha256) DO UPDATE SET storage_uri = EXCLUDED.storage_uri
     RETURNING id`,
    [input.projectId, input.scanId, stored.sha256, input.contentType, stored.sizeBytes, stored.storageUri, input.redacted ?? false],
  );
  return { id: res.rows[0]!.id, sha256: stored.sha256, sizeBytes: stored.sizeBytes };
}

export async function linkEvidence(
  db: Queryable,
  input: { projectId: string; artifactId: string; observationId?: string; findingId?: string; note?: string },
): Promise<void> {
  if (!input.observationId && !input.findingId) return;
  await db.query(
    `INSERT INTO evidence_links (project_id, artifact_id, observation_id, finding_id, note)
     VALUES ($1,$2,$3,$4,$5)`,
    [input.projectId, input.artifactId, input.observationId ?? null, input.findingId ?? null, input.note ?? ""],
  );
}

export async function recordProviderExecution(
  db: Queryable,
  input: {
    scanId: string;
    jobId: string | null;
    provider: string;
    providerVersion: string;
    result: DiscoveryResult;
    status: string;
    /** Wall-clock duration measured by the control plane; falls back to the worker's own figure. */
    durationMs?: number;
  },
): Promise<void> {
  const exec = input.result.execution;
  // Persist the measured duration. It used to fall through to the column default, which made an
  // unmeasured run indistinguishable from one that took no time.
  const durationMs = Math.max(0, Math.round(input.durationMs ?? exec.durationMs ?? 0));
  // Re-redact at the persistence boundary: provider diagnostics may echo fragments of parsed
  // content (e.g. parser error messages), so never store them verbatim.
  const stderrExcerpt = redactString(input.result.diagnostics.slice(0, 10).join("\n").slice(0, 4000));
  // `$16` (duration_ms) must have a single inferred type: the integer column and the interval
  // expression get separate parameters so Postgres does not report an inconsistent type for $16.
  await db.query(
    `INSERT INTO provider_executions
       (scan_id, job_id, provider, provider_version, argv, exit_code, status, stdout_bytes, stderr_bytes,
        truncated, timed_out, records_count, coverage, stderr_excerpt, error, duration_ms, started_at, finished_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
             now() - ($17::text || ' milliseconds')::interval, now())`,
    [
      input.scanId,
      input.jobId,
      input.provider,
      input.providerVersion,
      exec.argv,
      exec.exitCode,
      input.status,
      exec.stdoutBytes,
      exec.stderrBytes,
      exec.truncated,
      exec.timedOut,
      input.result.records.length,
      JSON.stringify(input.result.coverage),
      stderrExcerpt,
      exec.spawnError || null,
      durationMs,
      String(durationMs),
    ],
  );
}

export async function upsertProviderOutcome(
  db: Queryable,
  input: { scanId: string; projectId: string; jobId: string | null; stage: string; provider: string; providerVersion: string; outcome: string; recordsCount: number; reason: string },
): Promise<void> {
  await db.query(
    `INSERT INTO job_provider_outcomes (scan_id, project_id, job_id, stage, provider, provider_version, outcome, records_count, reason)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
     ON CONFLICT (scan_id, stage, provider) DO UPDATE
       SET outcome = EXCLUDED.outcome, records_count = EXCLUDED.records_count,
           reason = EXCLUDED.reason, provider_version = EXCLUDED.provider_version, job_id = EXCLUDED.job_id`,
    [input.scanId, input.projectId, input.jobId, input.stage, input.provider, input.providerVersion, input.outcome, input.recordsCount, input.reason],
  );
}

export async function upsertCoverageInternal(
  db: Queryable,
  input: { scanId: string; projectId: string; stage: string; status: string; expected: number; collected: number; notes: string; details?: unknown },
): Promise<void> {
  await db.query(
    `INSERT INTO coverage_records (project_id, scan_id, stage, status, expected, collected, notes, details)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
     ON CONFLICT (scan_id, stage) DO UPDATE
       SET status = EXCLUDED.status, expected = EXCLUDED.expected,
           collected = EXCLUDED.collected, notes = EXCLUDED.notes, details = EXCLUDED.details`,
    [input.projectId, input.scanId, input.stage, input.status, input.expected, input.collected, input.notes, JSON.stringify(input.details ?? {})],
  );
}

export function reliabilityFor(source: string, score?: number): SourceReliabilityValue {
  if (score !== undefined) {
    if (score >= 0.9) return "HIGH";
    if (score >= 0.6) return "MEDIUM";
    if (score > 0) return "LOW";
    return "UNKNOWN";
  }
  switch (source) {
    case "dns":
    case "builtin-dns":
      return "HIGH";
    case "passive":
    case "subfinder":
    case "amass":
    case "assetfinder":
      return "MEDIUM";
    case "dnsx":
      return "HIGH";
    case "rdap":
      return "MEDIUM";
    case "http":
    case "builtin-http":
      return "HIGH";
    case "fingerprint":
    case "url":
    case "builtin-crawler":
      return "MEDIUM";
    case "gau":
    case "waybackurls":
      return "LOW";
    case "js":
    case "builtin-js":
    case "api-endpoint":
      return "MEDIUM";
    case "api-spec":
    case "builtin-api":
    case "security-metadata":
    case "builtin-security-meta":
      return "HIGH";
    case "secret-scan":
    case "builtin-secret-scan":
    case "takeover":
    case "builtin-takeover":
      return "MEDIUM";
    default:
      return "LOW";
  }
}

function originOf(raw: string): string | null {
  try {
    const u = new URL(raw);
    return `${u.protocol}//${u.host}`;
  } catch {
    return null;
  }
}

function hostOfUrl(raw: string): string {
  try {
    return new URL(raw).hostname;
  } catch {
    return "";
  }
}

export function sha256Hex(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

export interface IngestSummary {
  assetsCreated: number;
  observations: number;
  relationships: number;
  records: number;
  assetIds: string[];
  observationIds: string[];
}

/**
 * Persist a discovery result idempotently: canonical assets dedupe by unique key, and
 * observations are appended with provenance. Relationships are deduplicated.
 */
export async function ingestDiscoveryResult(
  db: Queryable,
  store: ArtifactStore,
  input: { projectId: string; scanId: string; rootDomain: string; provider: string; result: DiscoveryResult; observedAt: Date },
): Promise<IngestSummary> {
  const { projectId, scanId, rootDomain, provider, result, observedAt } = input;
  const summary: IngestSummary = { assetsCreated: 0, observations: 0, relationships: 0, records: result.records.length, assetIds: [], observationIds: [] };
  const assetCache = new Map<string, string>();

  const upsert = async (type: string, canonicalKey: string, value: string): Promise<string> => {
    const cacheKey = `${type}\u0000${canonicalKey}`;
    const cached = assetCache.get(cacheKey);
    if (cached) return cached;
    const a = await upsertAsset(db, { projectId, type, canonicalKey, value, seenAt: observedAt });
    if (a.inserted) summary.assetsCreated++;
    assetCache.set(cacheKey, a.id);
    summary.assetIds.push(a.id);
    return a.id;
  };

  const recordObservation = async (assetId: string, source: string, reliability: SourceReliabilityValue, kind: string, data: Record<string, unknown>): Promise<void> => {
    const id = await insertObservation(db, { projectId, scanId, assetId, source, sourceReliability: reliability, observedAt, kind, data });
    summary.observations++;
    summary.observationIds.push(id);
  };

  const hostType = (host: string): string =>
    host === rootDomain || !host.endsWith(`.${rootDomain}`) ? "HOST" : "SUBDOMAIN";

  for (const rec of result.records) {
    await ingestRecord(rec);
  }

  async function ingestRecord(rec: DiscoveryRecord): Promise<void> {
    if (rec.type === "HOST_OBSERVATION") {
      const assetId = await upsert(hostType(rec.host), rec.host, rec.host);
      await recordObservation(assetId, rec.source || provider, reliabilityFor(rec.source || provider), "host", {
        status: rec.status,
        addresses: rec.addresses,
        provider,
        notes: rec.notes,
      });
      for (const addr of rec.addresses) {
        const ipId = await upsert("IP", addr, addr);
        await upsertRelationship(db, { projectId, fromAssetId: assetId, toAssetId: ipId, relation: "resolves_to", confidence: 0.9, source: provider });
        summary.relationships++;
      }
      return;
    }
    if (rec.type === "DNS_RECORD") {
      const rel = rec.recordType;
      if (rel === "PTR") {
        const ipId = await upsert("IP", rec.name, rec.name);
        await recordObservation(ipId, "dns", "HIGH", "dns:PTR", { value: rec.value, status: rec.status, resolver: rec.resolver, error: rec.error });
        if (rec.value) {
          const hostId = await upsert(hostType(rec.value), rec.value, rec.value);
          await upsertRelationship(db, { projectId, fromAssetId: ipId, toAssetId: hostId, relation: "ptr", confidence: 0.8, source: provider });
          summary.relationships++;
        }
        return;
      }
      const nameId = await upsert(hostType(rec.name), rec.name, rec.name);
      await recordObservation(nameId, "dns", "HIGH", `dns:${rel}`, { value: rec.value, ttl: rec.ttl, status: rec.status, resolver: rec.resolver, error: rec.error });
      if ((rel === "A" || rel === "AAAA") && rec.value) {
        const ipId = await upsert("IP", rec.value, rec.value);
        await upsertRelationship(db, { projectId, fromAssetId: nameId, toAssetId: ipId, relation: "resolves_to", confidence: 0.95, source: provider });
        summary.relationships++;
      } else if (rel === "CNAME" && rec.value) {
        const targetId = await upsert(hostType(rec.value), rec.value, rec.value);
        await upsertRelationship(db, { projectId, fromAssetId: nameId, toAssetId: targetId, relation: "cname_to", confidence: 0.9, source: provider });
        summary.relationships++;
      } else if ((rel === "MX" || rel === "NS") && rec.value) {
        const target = rec.value.split(" ").pop()!.replace(/\.$/, "");
        const targetId = await upsert(hostType(target), target, target);
        await upsertRelationship(db, { projectId, fromAssetId: nameId, toAssetId: targetId, relation: rel === "MX" ? "mx_to" : "ns_to", confidence: 0.8, source: provider });
        summary.relationships++;
      }
      return;
    }
    if (rec.type === "SECRET_CANDIDATE") {
      const artifactUrl = rec.artifactUrl;
      const assetId = await upsert("URL", artifactUrl, artifactUrl);
      await recordObservation(assetId, "builtin-secret-scan", reliabilityFor("secret-scan"), "secret-finding", {
        ruleId: rec.ruleId,
        category: rec.category,
        status: rec.status,
        confidence: rec.confidence,
        artifactUrl,
        host: rec.host,
        location: rec.location,
        redactedSnippet: rec.redactedSnippet,
        fingerprint: rec.fingerprint,
        occurrences: rec.occurrences,
        rationale: rec.rationale,
        suppressionReason: rec.suppressionReason,
        provider: rec.provider,
      });
      return;
    }
    if (rec.type === "SECRET_SCAN_ARTIFACT") {
      const assetId = await upsert("URL", rec.artifactUrl, rec.artifactUrl);
      await recordObservation(assetId, "builtin-secret-scan", reliabilityFor("secret-scan"), "secret-scan-artifact", {
        status: rec.status,
        findingsCount: rec.findingsCount,
        rawBytes: rec.rawBytes,
        hmacKeyed: rec.hmacKeyed,
        error: rec.error,
        host: rec.host,
        provider: rec.provider,
      });
      return;
    }
    if (rec.type === "TAKEOVER_CANDIDATE") {
      const hostAssetId = await upsert(hostType(rec.host), rec.host, rec.host);
      await recordObservation(hostAssetId, "builtin-takeover", reliabilityFor("takeover"), "takeover-candidate", {
        host: rec.host,
        cname: rec.cname,
        service: rec.service,
        status: rec.status,
        confidence: rec.confidence,
        httpStatus: rec.httpStatus,
        evidence: rec.evidence,
        evidenceType: rec.evidenceType,
        provider: rec.provider,
      });
      return;
    }
    if (rec.type === "SECURITY_METADATA") {
      const serviceKey = (rec.url ? originOf(rec.url) : null) ?? rec.host ?? rec.url ?? "unknown";
      const serviceId = await upsert("SERVICE", serviceKey, serviceKey);
      await recordObservation(serviceId, "builtin-security-meta", reliabilityFor("security-metadata"), "security-metadata", {
        category: rec.category,
        name: rec.name,
        status: rec.status,
        observed: rec.observed,
        value: rec.value,
        detail: rec.detail,
        consistent: rec.consistent,
        evidence: rec.evidence,
        evidenceType: rec.evidenceType,
        url: rec.url,
        host: rec.host,
        provider: rec.provider,
      });
      // Link a TLS certificate observation to the certificate asset it represents.
      const sha = rec.category === "TLS" ? (rec.detail as { sha256?: unknown }).sha256 : undefined;
      if (typeof sha === "string" && sha.length > 0) {
        const certId = await upsert("CERTIFICATE", sha, sha);
        await upsertRelationship(db, { projectId, fromAssetId: serviceId, toAssetId: certId, relation: "presents_certificate", confidence: 0.95, source: rec.provider });
        summary.relationships++;
      }
      return;
    }
    if (rec.type === "JS_ARTIFACT") {
      const artifactUrl = rec.canonicalUrl || rec.url;
      const jsId = await upsert("JS_ARTIFACT", artifactUrl, artifactUrl);
      await recordObservation(jsId, "builtin-js", reliabilityFor("js"), "js-artifact", {
        url: rec.url,
        contentHash: rec.contentHash,
        contentType: rec.contentType,
        sizeBytes: rec.sizeBytes,
        sourceUrl: rec.sourceUrl,
        discoveryMethod: rec.discoveryMethod,
        status: rec.status,
        error: rec.error,
        truncated: rec.truncated,
        provider: rec.provider,
      });
      if (rec.sourceUrl) {
        const srcId = await upsert(hostType(hostOfUrl(rec.sourceUrl)), hostOfUrl(rec.sourceUrl), hostOfUrl(rec.sourceUrl));
        await upsertRelationship(db, { projectId, fromAssetId: srcId, toAssetId: jsId, relation: "references", confidence: 0.7, source: rec.provider });
        summary.relationships++;
      }
      return;
    }
    if (rec.type === "SOURCE_MAP") {
      const jsId = await upsert("JS_ARTIFACT", rec.jsUrl, rec.jsUrl);
      await recordObservation(jsId, "builtin-js", reliabilityFor("js"), "source-map", {
        sourceMapUrl: rec.sourceMapUrl,
        status: rec.status,
        sourcesCount: rec.sourcesCount,
        sources: rec.sources,
        sourceRoot: rec.sourceRoot,
        hasContent: rec.hasContent,
        error: rec.error,
        provider: rec.provider,
      });
      if (rec.sourceMapUrl) {
        const smId = await upsert("URL", rec.sourceMapUrl, rec.sourceMapUrl);
        await upsertRelationship(db, { projectId, fromAssetId: jsId, toAssetId: smId, relation: "has_source_map", confidence: 0.8, source: rec.provider });
        summary.relationships++;
      }
      return;
    }
    if (rec.type === "API_SPEC") {
      const specId = await upsert("URL", rec.url, rec.url);
      await recordObservation(specId, "builtin-api", reliabilityFor("api-spec"), "api-spec", {
        specVersion: rec.specVersion,
        title: rec.title,
        format: rec.format,
        servers: rec.servers,
        pathCount: rec.pathCount,
        operationCount: rec.operationCount,
        securitySchemes: rec.securitySchemes,
        unresolvedRefs: rec.unresolvedRefs,
        parseStatus: rec.parseStatus,
        error: rec.error,
        provider: rec.provider,
      });
      return;
    }
    if (rec.type === "API_ENDPOINT") {
      const key = `${rec.method} ${rec.origin}${rec.path}`;
      const value = rec.url || `${rec.method} ${rec.path}`;
      const epId = await upsert("API_ENDPOINT", key, value);
      await recordObservation(epId, rec.provider, reliabilityFor("api-endpoint", rec.documented ? 0.9 : 0.6), "api-endpoint", {
        method: rec.method,
        origin: rec.origin,
        path: rec.path,
        url: rec.url,
        discoveredVia: rec.discoveredVia,
        documented: rec.documented,
        resolved: rec.resolved,
        operationId: rec.operationId,
        tags: rec.tags,
        parameters: rec.parameters,
        contentTypes: rec.contentTypes,
        authSchemes: rec.authSchemes,
        sourceUrl: rec.sourceUrl,
        evidence: rec.evidence,
        evidenceType: rec.evidenceType,
        provider: rec.provider,
      });
      if (rec.origin) {
        const host = hostOfUrl(rec.origin);
        if (host) {
          const hostId = await upsert(hostType(host), host, host);
          await upsertRelationship(db, { projectId, fromAssetId: hostId, toAssetId: epId, relation: "exposes", confidence: 0.7, source: rec.provider });
          summary.relationships++;
        }
      }
      if (rec.sourceUrl) {
        const srcId = await upsert("URL", rec.sourceUrl, rec.sourceUrl);
        await upsertRelationship(db, { projectId, fromAssetId: srcId, toAssetId: epId, relation: "documents", confidence: 0.8, source: rec.provider });
        summary.relationships++;
      }
      return;
    }
    if (rec.type === "URL_OBSERVATION") {
      const urlId = await upsert("URL", rec.canonicalUrl, rec.canonicalUrl);
      await recordObservation(urlId, rec.provider, reliabilityFor("url"), "url", {
        originalUrl: rec.url,
        method: rec.method,
        depth: rec.depth,
        statusCode: rec.statusCode,
        classifications: rec.classifications,
        parameters: rec.parameters,
        provider: rec.provider,
        host: rec.host,
      });
      if (rec.host) {
        const hostAssetId = await upsert(hostType(rec.host), rec.host, rec.host);
        await upsertRelationship(db, { projectId, fromAssetId: hostAssetId, toAssetId: urlId, relation: "contains_url", confidence: 0.8, source: rec.provider });
        summary.relationships++;
      }
      return;
    }
    if (rec.type === "HTTP_OBSERVATION") {
      const hostAssetId = await upsert(hostType(rec.host), rec.host, rec.host);
      const origin = originOf(rec.http.finalUrl || rec.url) ?? rec.host;
      const serviceId = await upsert("SERVICE", origin, origin);
      await upsertRelationship(db, { projectId, fromAssetId: hostAssetId, toAssetId: serviceId, relation: "serves", confidence: 0.9, source: provider });
      summary.relationships++;
      await recordObservation(serviceId, "http", reliabilityFor("http"), "http", {
        url: rec.url,
        finalUrl: rec.http.finalUrl,
        statusCode: rec.http.statusCode,
        statusText: rec.http.statusText,
        contentType: rec.http.contentType,
        title: rec.http.title,
        server: rec.http.headers?.["server"] ?? "",
        headers: rec.http.headers,
        redirectChain: rec.http.redirectChain,
        tls: rec.http.tls,
        probeStatus: rec.http.probeStatus,
        error: rec.http.error,
        bodyTruncated: rec.http.bodyTruncated,
        provider,
      });
      if (rec.http.tls && rec.http.tls.sha256) {
        const certId = await upsert("CERTIFICATE", rec.http.tls.sha256, rec.http.tls.sha256);
        await recordObservation(certId, "tls", "HIGH", "tls", { ...rec.http.tls });
        await upsertRelationship(db, { projectId, fromAssetId: serviceId, toAssetId: certId, relation: "presents_certificate", confidence: 0.95, source: provider });
        summary.relationships++;
      }
      return;
    }
    if (rec.type === "TECHNOLOGY") {
      const t = rec.technology;
      const techId = await upsert("TECHNOLOGY", t.name, t.name);
      await recordObservation(techId, "fingerprint", reliabilityFor("fingerprint", t.confidence), "technology", {
        host: rec.host,
        url: rec.url,
        category: t.category,
        evidenceType: t.evidenceType,
        evidence: t.evidence,
        confidence: t.confidence,
        provider,
      });
      if (rec.host) {
        const hostAssetId = await upsert(hostType(rec.host), rec.host, rec.host);
        await upsertRelationship(db, { projectId, fromAssetId: hostAssetId, toAssetId: techId, relation: "runs", confidence: t.confidence, source: provider });
        summary.relationships++;
      }
      return;
    }
    if (rec.type === "IP_METADATA") {
      const ipId = await upsert("IP", rec.ip, rec.ip);
      await recordObservation(ipId, rec.source || provider, reliabilityFor(rec.source || provider, rec.confidence), "ip-metadata", {
        prefix: rec.prefix,
        asn: rec.asn,
        asnOrg: rec.asnOrg,
        networkName: rec.networkName,
        country: rec.country,
        confidence: rec.confidence,
        limitations: rec.limitations,
      });
      let cidrId: string | undefined;
      if (rec.prefix) {
        cidrId = await upsert("CIDR", rec.prefix, rec.prefix);
        await upsertRelationship(db, { projectId, fromAssetId: ipId, toAssetId: cidrId, relation: "in_prefix", confidence: rec.confidence, source: rec.source || provider });
        summary.relationships++;
      }
      if (rec.asn) {
        const asnKey = `AS${rec.asn}`;
        const asnId = await upsert("ASN", asnKey, asnKey);
        await upsertRelationship(db, { projectId, fromAssetId: cidrId ?? ipId, toAssetId: asnId, relation: "announced_by", confidence: rec.confidence, source: rec.source || provider });
        summary.relationships++;
      }
    }
  }

  // Preserve the normalized worker output as evidence, linked to the observations it produced.
  if (result.records.length > 0) {
    const artifact = await storeEvidence(db, store, {
      projectId,
      scanId,
      content: JSON.stringify({ provider, providerVersion: result.providerVersion, records: result.records }),
      contentType: "application/json",
    });
    for (const obsId of summary.observationIds) {
      await linkEvidence(db, { projectId, artifactId: artifact.id, observationId: obsId, note: `provider ${provider}` });
    }
  }

  return summary;
}
