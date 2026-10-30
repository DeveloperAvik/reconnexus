import type { ScopePolicy } from "@reconnexus/contracts";
import type { Queryable } from "./db/pool.js";

export interface ProjectRow {
  id: string;
  workspace_id: string;
  name: string;
  root_domain: string;
}

export interface ScanRow {
  id: string;
  project_id: string;
  policy_id: string;
  status: string;
  start_url: string;
  root_domain: string;
  config_snapshot: unknown;
  coverage: unknown;
  error: string | null;
  created_at: Date;
  started_at: Date | null;
  finished_at: Date | null;
}

export class Repository {
  constructor(private readonly db: Queryable) {}

  async ensureDefaultWorkspace(name = "default"): Promise<string> {
    const existing = await this.db.query<{ id: string }>("SELECT id FROM workspaces WHERE name = $1 LIMIT 1", [name]);
    if (existing.rows[0]) return existing.rows[0].id;
    const created = await this.db.query<{ id: string }>(
      "INSERT INTO workspaces (name) VALUES ($1) RETURNING id",
      [name],
    );
    return created.rows[0]!.id;
  }

  async ensureProject(workspaceId: string, rootDomain: string, name?: string): Promise<ProjectRow> {
    const projName = name ?? rootDomain;
    const existing = await this.db.query<ProjectRow>(
      "SELECT * FROM projects WHERE workspace_id = $1 AND root_domain = $2 LIMIT 1",
      [workspaceId, rootDomain],
    );
    if (existing.rows[0]) return existing.rows[0];
    const created = await this.db.query<ProjectRow>(
      "INSERT INTO projects (workspace_id, name, root_domain) VALUES ($1, $2, $3) RETURNING *",
      [workspaceId, projName, rootDomain],
    );
    return created.rows[0]!;
  }

  async insertPolicy(projectId: string, version: number, document: ScopePolicy): Promise<string> {
    const res = await this.db.query<{ id: string }>(
      "INSERT INTO scope_policies (project_id, version, document) VALUES ($1, $2, $3) RETURNING id",
      [projectId, version, JSON.stringify(document)],
    );
    return res.rows[0]!.id;
  }

  async findPolicyByVersion(projectId: string, version: number): Promise<{ id: string; document: ScopePolicy } | null> {
    const res = await this.db.query<{ id: string; document: ScopePolicy }>(
      "SELECT id, document FROM scope_policies WHERE project_id = $1 AND version = $2 LIMIT 1",
      [projectId, version],
    );
    return res.rows[0] ?? null;
  }

  async latestPolicy(projectId: string): Promise<{ id: string; version: number; document: ScopePolicy } | null> {
    const res = await this.db.query<{ id: string; version: number; document: ScopePolicy }>(
      "SELECT id, version, document FROM scope_policies WHERE project_id = $1 ORDER BY version DESC LIMIT 1",
      [projectId],
    );
    return res.rows[0] ?? null;
  }

  async insertAuthorization(projectId: string, policy: ScopePolicy): Promise<string> {
    const a = policy.authorization;
    const res = await this.db.query<{ id: string }>(
      `INSERT INTO authorization_records
         (project_id, reference, authorized_by, valid_from, valid_until, capabilities)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [projectId, a.reference, a.authorizedBy, a.validFrom, a.validUntil, a.capabilities],
    );
    return res.rows[0]!.id;
  }

  async createScan(input: {
    projectId: string;
    policyId: string;
    startUrl: string;
    rootDomain: string;
    configSnapshot: unknown;
  }): Promise<ScanRow> {
    const res = await this.db.query<ScanRow>(
      `INSERT INTO scan_runs (project_id, policy_id, start_url, root_domain, config_snapshot, status)
       VALUES ($1, $2, $3, $4, $5, 'QUEUED') RETURNING *`,
      [input.projectId, input.policyId, input.startUrl, input.rootDomain, JSON.stringify(input.configSnapshot)],
    );
    return res.rows[0]!;
  }

  /** Insert the job DAG. Idempotent on (scan_id, job_key). */
  async createJobs(
    scanId: string,
    projectId: string,
    stages: Array<{ stage: string; dependsOn: string[] }>,
  ): Promise<void> {
    for (const s of stages) {
      await this.db.query(
        `INSERT INTO jobs (scan_id, project_id, stage, job_key, depends_on, status)
         VALUES ($1, $2, $3, $4, $5, 'QUEUED')
         ON CONFLICT (scan_id, job_key) DO NOTHING`,
        [scanId, projectId, s.stage, s.stage, s.dependsOn],
      );
    }
  }

  async listScans(limit = 20): Promise<Array<{ id: string; status: string; root_domain: string; start_url: string; created_at: Date; finished_at: Date | null }>> {
    const res = await this.db.query(
      "SELECT id, status, root_domain, start_url, created_at, finished_at FROM scan_runs ORDER BY created_at DESC LIMIT $1",
      [limit],
    );
    return res.rows as never;
  }

  async getScan(scanId: string): Promise<ScanRow | null> {
    const res = await this.db.query<ScanRow>("SELECT * FROM scan_runs WHERE id = $1", [scanId]);
    return res.rows[0] ?? null;
  }

  async markJobStatus(scanId: string, jobKey: string, status: string, lastError?: string): Promise<void> {
    await this.db.query(
      `UPDATE jobs SET status = $3, last_error = $4, updated_at = now() WHERE scan_id = $1 AND job_key = $2`,
      [scanId, jobKey, status, lastError ?? null],
    );
  }

  async updateScanStatus(scanId: string, status: string, error?: string): Promise<void> {
    await this.db.query(
      `UPDATE scan_runs SET status = $2, error = $3,
         started_at = COALESCE(started_at, now()),
         finished_at = CASE WHEN $2 IN ('SUCCEEDED','PARTIAL','FAILED','SKIPPED','BLOCKED','CANCELLED','SOURCE_UNAVAILABLE')
                            THEN now() ELSE finished_at END
       WHERE id = $1`,
      [scanId, status, error ?? null],
    );
  }

  async upsertCoverage(scanId: string, projectId: string, stage: string, status: string, expected: number, collected: number, notes = ""): Promise<void> {
    await this.db.query(
      `INSERT INTO coverage_records (project_id, scan_id, stage, status, expected, collected, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (scan_id, stage) DO UPDATE
         SET status = EXCLUDED.status, expected = EXCLUDED.expected,
             collected = EXCLUDED.collected, notes = EXCLUDED.notes`,
      [projectId, scanId, stage, status, expected, collected, notes],
    );
  }

  async appendAudit(projectId: string, scanId: string | null, eventType: string, subject: string, decision: string | null, detail: unknown): Promise<void> {
    await this.db.query(
      `INSERT INTO audit_events (project_id, scan_id, event_type, subject, decision, detail)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [projectId, scanId, eventType, subject, decision, JSON.stringify(detail)],
    );
  }

  async listJobs(scanId: string): Promise<Array<{ stage: string; job_key: string; status: string; attempts: number; last_error: string | null }>> {
    const res = await this.db.query(
      "SELECT stage, job_key, status, attempts, last_error FROM jobs WHERE scan_id = $1 ORDER BY job_key",
      [scanId],
    );
    return res.rows as never;
  }

  async getPolicyById(policyId: string): Promise<{ id: string; version: number; document: ScopePolicy } | null> {
    const res = await this.db.query<{ id: string; version: number; document: ScopePolicy }>(
      "SELECT id, version, document FROM scope_policies WHERE id = $1",
      [policyId],
    );
    return res.rows[0] ?? null;
  }

  async getJobRows(scanId: string): Promise<JobRow[]> {
    const res = await this.db.query<JobRow>("SELECT * FROM jobs WHERE scan_id = $1 ORDER BY job_key", [scanId]);
    return res.rows;
  }

  async claimJob(scanId: string, jobKey: string, workerId: string, leaseSeconds: number): Promise<boolean> {
    const res = await this.db.query(
      `UPDATE jobs SET status='RUNNING', worker_id=$3,
         attempts = attempts + 1,
         lease_expires_at = now() + ($4 || ' seconds')::interval,
         updated_at = now()
       WHERE scan_id=$1 AND job_key=$2 AND status IN ('QUEUED','RUNNING')
         AND (lease_expires_at IS NULL OR lease_expires_at < now())
         AND not_before <= now()
       RETURNING id`,
      [scanId, jobKey, workerId, String(leaseSeconds)],
    );
    return res.rowCount === 1;
  }

  async setJobStatus(scanId: string, jobKey: string, status: string, lastError?: string): Promise<void> {
    await this.db.query(
      `UPDATE jobs SET status=$3, last_error=$4, lease_expires_at=NULL, updated_at=now()
       WHERE scan_id=$1 AND job_key=$2`,
      [scanId, jobKey, status, lastError ?? null],
    );
  }

  async requeueJob(scanId: string, jobKey: string, notBefore: Date): Promise<void> {
    await this.db.query(
      `UPDATE jobs SET status='QUEUED', not_before=$3, lease_expires_at=NULL, updated_at=now()
       WHERE scan_id=$1 AND job_key=$2`,
      [scanId, jobKey, notBefore],
    );
  }

  async listAssets(projectId: string, types: string[]): Promise<Array<{ id: string; type: string; canonical_key: string; value: string }>> {
    const res = await this.db.query<{ id: string; type: string; canonical_key: string; value: string }>(
      "SELECT id, type, canonical_key, value FROM assets WHERE project_id=$1 AND type = ANY($2) ORDER BY value",
      [projectId, types],
    );
    return res.rows;
  }

  /**
   * Assets observed during a single scan (assets have project scope, so "seen in this scan" means
   * the asset is the subject of at least one observation whose scan_id is this scan). Ordered
   * deterministically so scan-to-scan comparisons are stable.
   */
  async listScanAssets(scanId: string, types?: string[]): Promise<Array<{ id: string; type: string; canonical_key: string; value: string }>> {
    const res = await this.db.query<{ id: string; type: string; canonical_key: string; value: string }>(
      `SELECT DISTINCT a.id, a.type, a.canonical_key, a.value
         FROM observations o
         JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND ($2::text[] IS NULL OR a.type = ANY($2))
        ORDER BY a.type, a.value`,
      [scanId, types ?? null],
    );
    return res.rows;
  }

  /**
   * Observations of a single scan filtered by exact `kinds` and/or a `kindPrefix` (e.g. `dns:`),
   * joined to their subject asset. Read-only; returns only the columns comparison needs, in a
   * deterministic order, so a scan-to-scan comparison is stable and bounded to the kinds asked for.
   */
  async listScanObservations(
    scanId: string,
    filter: { kinds?: string[]; kindPrefix?: string } = {},
  ): Promise<Array<{ asset_type: string; asset_value: string; canonical_key: string; kind: string; data: Record<string, unknown>; source: string; observed_at: Date }>> {
    const res = await this.db.query<{ asset_type: string; asset_value: string; canonical_key: string; kind: string; data: Record<string, unknown>; source: string; observed_at: Date }>(
      `SELECT a.type AS asset_type, a.value AS asset_value, a.canonical_key, o.kind, o.data, o.source, o.observed_at
         FROM observations o
         JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1
          AND ($2::text[] IS NULL OR o.kind = ANY($2))
          AND ($3::text IS NULL OR o.kind LIKE $3 || '%')
        ORDER BY o.kind, a.value, o.observed_at, o.id`,
      [scanId, filter.kinds ?? null, filter.kindPrefix ?? null],
    );
    return res.rows;
  }

  async listResolvedIpHostPairs(projectId: string, limit: number): Promise<Array<{ ip: string; host: string }>> {
    const res = await this.db.query<{ ip: string; host: string }>(
      `SELECT DISTINCT i.value AS ip, h.value AS host
         FROM asset_relationships r
         JOIN assets i ON i.id = r.to_asset_id AND i.type = 'IP'
         JOIN assets h ON h.id = r.from_asset_id AND h.type IN ('HOST','SUBDOMAIN')
        WHERE r.project_id = $1 AND r.relation = 'resolves_to'
        ORDER BY i.value
        LIMIT $2`,
      [projectId, limit],
    );
    return res.rows;
  }

  async listResolvedHosts(projectId: string, limit: number): Promise<string[]> {
    const res = await this.db.query<{ host: string }>(
      `SELECT DISTINCT h.value AS host
         FROM asset_relationships r
         JOIN assets h ON h.id = r.from_asset_id AND h.type IN ('HOST','SUBDOMAIN')
        WHERE r.project_id = $1 AND r.relation = 'resolves_to'
        ORDER BY h.value
        LIMIT $2`,
      [projectId, limit],
    );
    return res.rows.map((r) => r.host);
  }

  async listTechnologyObservations(scanId: string, limit = 20000): Promise<Array<{ name: string; host: string; category: string; evidence_type: string; evidence: string; confidence: number }>> {
    const res = await this.db.query(
      `SELECT a.value AS name,
              COALESCE(o.data->>'host','') AS host,
              COALESCE(o.data->>'category','') AS category,
              COALESCE(o.data->>'evidenceType','') AS evidence_type,
              COALESCE(o.data->>'evidence','') AS evidence,
              COALESCE((o.data->>'confidence')::numeric, 0) AS confidence
         FROM observations o
         JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND o.kind = 'technology'
        ORDER BY name, host
        LIMIT $2`,
      [scanId, limit],
    );
    return res.rows as never;
  }

  async listHttpObservations(scanId: string, limit = 20000): Promise<Array<{ url: string; host: string; status_code: number | null; title: string; server: string; probe_status: string; final_url: string; data: unknown }>> {
    const res = await this.db.query(
      `SELECT COALESCE(o.data->>'url','') AS url,
              COALESCE(o.data->>'finalUrl','') AS final_url,
              COALESCE((o.data->>'statusCode')::int, NULL) AS status_code,
              COALESCE(o.data->>'title','') AS title,
              COALESCE(o.data->>'server','') AS server,
              COALESCE(o.data->>'probeStatus','') AS probe_status,
              o.data AS data
         FROM observations o
        WHERE o.scan_id = $1 AND o.kind = 'http'
        ORDER BY status_code NULLS LAST, url
        LIMIT $2`,
      [scanId, limit],
    );
    return res.rows as never;
  }

  async listUrlObservations(scanId: string, limit = 20000): Promise<Array<{ url: string; data: Record<string, unknown> }>> {
    const res = await this.db.query(
      `SELECT a.value AS url, o.data AS data
         FROM observations o JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND o.kind = 'url'
        ORDER BY a.value
        LIMIT $2`,
      [scanId, limit],
    );
    return res.rows as never;
  }

  async listJsArtifacts(scanId: string, limit = 5000): Promise<Array<{ url: string; data: Record<string, unknown> }>> {
    const res = await this.db.query(
      `SELECT a.value AS url, o.data AS data
         FROM observations o JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND o.kind = 'js-artifact'
        ORDER BY a.value LIMIT $2`,
      [scanId, limit],
    );
    return res.rows as never;
  }

  async listApiSpecs(scanId: string, limit = 5000): Promise<Array<{ url: string; data: Record<string, unknown> }>> {
    const res = await this.db.query(
      `SELECT a.value AS url, o.data AS data
         FROM observations o JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND o.kind = 'api-spec'
        ORDER BY a.value
        LIMIT $2`,
      [scanId, limit],
    );
    return res.rows as never;
  }

  /**
   * Distinct API endpoints (one row per `method origin path` canonical identity), regardless of how
   * many observations or sources reported them. When several source observations exist for one
   * endpoint, a documented one is preferred, then the earliest observation, so the row is
   * deterministic. Raw observation counts are available separately via `countApiEndpointObservations`.
   */
  async listApiEndpoints(scanId: string, limit = 20000): Promise<Array<{ key: string; data: Record<string, unknown> }>> {
    const res = await this.db.query(
      `SELECT DISTINCT ON (a.canonical_key) a.canonical_key AS key, o.data AS data
         FROM observations o JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND o.kind = 'api-endpoint'
        ORDER BY a.canonical_key, COALESCE((o.data->>'documented')::boolean, false) DESC, o.observed_at ASC, o.id
        LIMIT $2`,
      [scanId, limit],
    );
    return res.rows as never;
  }

  /** Distinct API endpoints by canonical identity (deduplicated across observations and sources). */
  async countDistinctApiEndpoints(scanId: string): Promise<number> {
    const res = await this.db.query<{ n: number }>(
      `SELECT count(DISTINCT a.canonical_key)::int AS n
         FROM observations o JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND o.kind = 'api-endpoint'`,
      [scanId],
    );
    return Number(res.rows[0]?.n ?? 0);
  }

  /** Raw persisted API-endpoint observations, before deduplication by canonical identity. */
  async countApiEndpointObservations(scanId: string): Promise<number> {
    const res = await this.db.query<{ n: string }>(
      "SELECT count(*)::text AS n FROM observations WHERE scan_id = $1 AND kind = 'api-endpoint'",
      [scanId],
    );
    return Number(res.rows[0]?.n ?? 0);
  }

  /** Distinct endpoints per discovery source and per provider (endpoints may appear in several). */
  async apiEndpointBreakdown(scanId: string): Promise<Array<{ source: string; provider: string; n: number }>> {
    const res = await this.db.query<{ source: string; provider: string; n: number }>(
      `SELECT COALESCE(o.data->>'discoveredVia','') AS source,
              COALESCE(o.data->>'provider','') AS provider,
              count(DISTINCT a.canonical_key)::int AS n
         FROM observations o JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND o.kind = 'api-endpoint'
        GROUP BY COALESCE(o.data->>'discoveredVia',''), COALESCE(o.data->>'provider','')
        ORDER BY COALESCE(o.data->>'discoveredVia',''), COALESCE(o.data->>'provider','')`,
      [scanId],
    );
    return res.rows;
  }

  async listSourceMaps(scanId: string, limit = 5000): Promise<Array<{ url: string; data: Record<string, unknown> }>> {
    const res = await this.db.query(
      `SELECT a.value AS url, o.data AS data
         FROM observations o JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND o.kind = 'source-map'
        ORDER BY a.value
        LIMIT $2`,
      [scanId, limit],
    );
    return res.rows as never;
  }

  async listSecurityMetadata(scanId: string, limit = 20000): Promise<Array<{ service: string; data: Record<string, unknown> }>> {
    const res = await this.db.query(
      `SELECT a.value AS service, o.data AS data
         FROM observations o JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND o.kind = 'security-metadata'
        ORDER BY a.value, (o.data->>'category'), (o.data->>'name')
        LIMIT $2`,
      [scanId, limit],
    );
    return res.rows as never;
  }

  async listSecretFindings(scanId: string, limit = 20000): Promise<Array<{ artifact: string; data: Record<string, unknown> }>> {
    const res = await this.db.query(
      `SELECT a.value AS artifact, o.data AS data
         FROM observations o JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND o.kind = 'secret-finding'
        ORDER BY (o.data->>'ruleId'), a.value, (o.data->>'location') LIMIT $2`,
      [scanId, limit],
    );
    return res.rows as never;
  }

  async listSecretScanArtifacts(scanId: string): Promise<Array<{ artifact: string; data: Record<string, unknown> }>> {
    const res = await this.db.query(
      `SELECT a.value AS artifact, o.data AS data
         FROM observations o JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND o.kind = 'secret-scan-artifact'
        ORDER BY a.value`,
      [scanId],
    );
    return res.rows as never;
  }

  async listSecretFingerprintFindings(scanId: string): Promise<Array<{ observation_id: string; asset_id: string; artifact: string; rule_id: string; fingerprint: string }>> {
    const res = await this.db.query(
      `SELECT o.id AS observation_id, o.asset_id, a.value AS artifact,
              COALESCE(o.data->>'ruleId','') AS rule_id,
              COALESCE(o.data->>'fingerprint','') AS fingerprint,
              COALESCE(o.data->>'status','') AS status
         FROM observations o JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND o.kind = 'secret-finding'`,
      [scanId],
    );
    return res.rows as never;
  }

  async listArtifactHmacKeyed(scanId: string): Promise<Array<{ artifact: string; hmac_keyed: boolean }>> {
    const res = await this.db.query(
      `SELECT a.value AS artifact, COALESCE((o.data->>'hmacKeyed')::boolean, false) AS hmac_keyed
         FROM observations o JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND o.kind = 'secret-scan-artifact'`,
      [scanId],
    );
    return res.rows as never;
  }

  async listAssetCorroboration(scanId: string, limit: number): Promise<Array<{ asset_id: string; canonical_key: string; value: string; type: string; sources: string[] }>> {
    const res = await this.db.query(
      `SELECT a.id AS asset_id, a.canonical_key AS canonical_key, a.value, a.type,
              array_agg(DISTINCT o.source) AS sources
         FROM observations o JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1
        GROUP BY a.id, a.canonical_key, a.value, a.type
       HAVING count(DISTINCT o.source) >= 2
        ORDER BY a.value
        LIMIT $2`,
      [scanId, limit],
    );
    return res.rows as never;
  }

  async deleteCorrelationObservations(scanId: string): Promise<void> {
    await this.db.query("DELETE FROM observations WHERE scan_id = $1 AND kind = 'correlation'", [scanId]);
  }

  async listCorrelationObservations(scanId: string): Promise<Array<{ subject: string; data: Record<string, unknown> }>> {
    const res = await this.db.query(
      `SELECT a.value AS subject, o.data AS data
         FROM observations o JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND o.kind = 'correlation'
        ORDER BY a.value, (o.data->>'relation')`,
      [scanId],
    );
    return res.rows as never;
  }

  async listCorrelationEdges(scanId: string): Promise<Array<{ from_key: string; to_key: string; relation: string; confidence: number; source: string }>> {
    const res = await this.db.query(
      `SELECT f.canonical_key AS from_key, t.canonical_key AS to_key, r.relation, r.confidence, r.source
         FROM scan_runs sr
         JOIN asset_relationships r ON r.project_id = sr.project_id
         JOIN assets f ON f.id = r.from_asset_id
         JOIN assets t ON t.id = r.to_asset_id
        WHERE sr.id = $1 AND r.source = 'stage-11-correlation'
        ORDER BY f.canonical_key, t.canonical_key`,
      [scanId],
    );
    return res.rows as never;
  }

  async countAssetsByType(projectId: string): Promise<Record<string, number>> {
    const res = await this.db.query<{ type: string; n: number }>(
      "SELECT type, count(*)::int AS n FROM assets WHERE project_id = $1 GROUP BY type ORDER BY type",
      [projectId],
    );
    const out: Record<string, number> = {};
    for (const r of res.rows) out[r.type] = Number(r.n);
    return out;
  }

  async countObservations(scanId: string): Promise<{ total: number; byKind: Record<string, number>; bySource: Record<string, number> }> {
    const total = await this.db.query<{ n: string }>("SELECT count(*)::text AS n FROM observations WHERE scan_id = $1", [scanId]);
    const kinds = await this.db.query<{ kind: string; n: number }>("SELECT kind, count(*)::int AS n FROM observations WHERE scan_id = $1 GROUP BY kind ORDER BY kind", [scanId]);
    const sources = await this.db.query<{ source: string; n: number }>("SELECT source, count(*)::int AS n FROM observations WHERE scan_id = $1 GROUP BY source ORDER BY source", [scanId]);
    const byKind: Record<string, number> = {};
    for (const r of kinds.rows) byKind[r.kind] = Number(r.n);
    const bySource: Record<string, number> = {};
    for (const r of sources.rows) bySource[r.source] = Number(r.n);
    return { total: Number(total.rows[0]?.n ?? 0), byKind, bySource };
  }

  async findAssetId(projectId: string, type: string, canonicalKey: string): Promise<string | null> {
    const res = await this.db.query<{ id: string }>(
      "SELECT id FROM assets WHERE project_id = $1 AND type = $2 AND canonical_key = $3 LIMIT 1",
      [projectId, type, canonicalKey],
    );
    return res.rows[0]?.id ?? null;
  }

  async listTakeoverCandidates(scanId: string): Promise<Array<{ host: string; data: Record<string, unknown> }>> {
    const res = await this.db.query(
      `SELECT a.value AS host, o.data AS data
         FROM observations o JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND o.kind = 'takeover-candidate'
        ORDER BY a.value`,
      [scanId],
    );
    return res.rows as never;
  }

  async listLoginInterfaces(scanId: string): Promise<Array<{ url: string; data: Record<string, unknown> }>> {
    const res = await this.db.query(
      `SELECT a.value AS url, o.data AS data
         FROM observations o JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND o.kind = 'login-interface'
        ORDER BY (o.data->>'kind'), a.value`,
      [scanId],
    );
    return res.rows as never;
  }

  async listTemplateFindings(scanId: string, limit = 20000): Promise<Array<{ url: string; data: Record<string, unknown> }>> {
    const res = await this.db.query(
      `SELECT a.value AS url, o.data AS data
         FROM observations o JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND o.kind = 'template-finding'
        ORDER BY (o.data->>'templateId'), a.value
        LIMIT $2`,
      [scanId, limit],
    );
    return res.rows as never;
  }

  async listContentDiscoveries(scanId: string, limit = 20000): Promise<Array<{ url: string; data: Record<string, unknown> }>> {
    const res = await this.db.query(
      `SELECT a.value AS url, o.data AS data
         FROM observations o JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND o.kind = 'content-discovery'
        ORDER BY (o.data->>'category'), a.value
        LIMIT $2`,
      [scanId, limit],
    );
    return res.rows as never;
  }

  async listPortObservations(scanId: string): Promise<Array<{ data: Record<string, unknown> }>> {
    const res = await this.db.query(
      `SELECT o.data AS data
         FROM observations o
        WHERE o.scan_id = $1 AND o.kind = 'port-observation'
        ORDER BY (o.data->>'ip'), (o.data->>'port')::int, (o.data->>'host')`,
      [scanId],
    );
    return res.rows as never;
  }

  async sumProviderSkipped(scanId: string): Promise<number> {
    const res = await this.db.query<{ n: string }>(
      "SELECT COALESCE(SUM(COALESCE((coverage->>'skipped')::int,0)),0)::text AS n FROM provider_executions WHERE scan_id = $1",
      [scanId],
    );
    return Number(res.rows[0]?.n ?? 0);
  }

  async listProviderOutcomes(scanId: string): Promise<Array<{ stage: string; provider: string; provider_version: string | null; outcome: string; records_count: number; reason: string }>> {
    const res = await this.db.query(
      "SELECT stage, provider, provider_version, outcome, records_count, reason FROM job_provider_outcomes WHERE scan_id=$1 ORDER BY stage, provider",
      [scanId],
    );
    return res.rows as never;
  }

  async listCoverage(scanId: string): Promise<Array<{ stage: string; status: string; expected: number; collected: number; notes: string; details: unknown }>> {
    const res = await this.db.query(
      "SELECT stage, status, expected, collected, notes, details FROM coverage_records WHERE scan_id=$1 ORDER BY stage",
      [scanId],
    );
    return res.rows as never;
  }

  /**
   * Per-invocation provider execution metrics, as persisted when the provider ran. Used by
   * reporting for durations, timeouts and attempt counts; it is never re-derived at report time.
   */
  async listProviderExecutions(scanId: string): Promise<ProviderExecutionRow[]> {
    const res = await this.db.query<ProviderExecutionRow>(
      `SELECT COALESCE(j.stage, '') AS stage,
              pe.provider,
              pe.provider_version,
              pe.status,
              pe.duration_ms,
              pe.records_count,
              pe.timed_out,
              pe.truncated,
              pe.exit_code,
              pe.started_at,
              pe.finished_at
         FROM provider_executions pe
         LEFT JOIN jobs j ON j.id = pe.job_id
        WHERE pe.scan_id = $1
        ORDER BY stage, pe.provider, pe.started_at`,
      [scanId],
    );
    return res.rows;
  }

  /** Content-addressed evidence artifacts collected by a scan. References only — never contents. */
  async listEvidenceArtifacts(scanId: string, limit = 500): Promise<EvidenceArtifactRow[]> {
    const res = await this.db.query<EvidenceArtifactRow>(
      `SELECT sha256, storage_uri, content_type, size_bytes, redacted, created_at
         FROM evidence_artifacts
        WHERE scan_id = $1
        ORDER BY sha256
        LIMIT $2`,
      [scanId, limit],
    );
    return res.rows;
  }

  async countEvidenceArtifacts(scanId: string): Promise<number> {
    const res = await this.db.query<{ n: string }>("SELECT count(*)::text AS n FROM evidence_artifacts WHERE scan_id = $1", [scanId]);
    return Number(res.rows[0]?.n ?? 0);
  }

  /** The workspace a project belongs to, for assessment metadata. */
  async getWorkspaceName(projectId: string): Promise<string> {
    const res = await this.db.query<{ name: string }>(
      "SELECT w.name FROM projects p JOIN workspaces w ON w.id = p.workspace_id WHERE p.id = $1",
      [projectId],
    );
    return res.rows[0]?.name ?? "";
  }

  /** DNS observations for a scan (`dns:A`, `dns:CNAME`, …), used for the host inventory. */
  async listDnsObservations(scanId: string, limit = 20000): Promise<Array<{ name: string; record_type: string; value: string; status: string }>> {
    const res = await this.db.query(
      `SELECT a.value AS name,
              substring(o.kind from 5) AS record_type,
              COALESCE(o.data->>'value','') AS value,
              COALESCE(o.data->>'status','') AS status
         FROM observations o JOIN assets a ON a.id = o.asset_id
        WHERE o.scan_id = $1 AND o.kind LIKE 'dns:%'
        ORDER BY a.value, o.kind, value
        LIMIT $2`,
      [scanId, limit],
    );
    return res.rows as never;
  }

  /**
   * Merge a patch into a scan's `config_snapshot`. Used to record what a run actually used
   * (provider profile, overrides) so the report describes the executed run, not the defaults.
   */
  async mergeScanConfigSnapshot(scanId: string, patch: Record<string, unknown>): Promise<void> {
    await this.db.query("UPDATE scan_runs SET config_snapshot = config_snapshot || $2::jsonb WHERE id = $1", [scanId, JSON.stringify(patch)]);
  }
}

export interface ProviderExecutionRow {
  stage: string;
  provider: string;
  provider_version: string | null;
  status: string;
  duration_ms: number;
  records_count: number;
  timed_out: boolean;
  truncated: boolean;
  exit_code: number | null;
  started_at: Date;
  finished_at: Date | null;
}

export interface EvidenceArtifactRow {
  sha256: string;
  storage_uri: string;
  content_type: string;
  size_bytes: string | number;
  redacted: boolean;
  created_at: Date;
}

export interface JobRow {
  id: string;
  scan_id: string;
  project_id: string;
  stage: string;
  job_key: string;
  depends_on: string[];
  status: string;
  attempts: number;
  max_attempts: number;
  not_before: Date;
  deadline: Date | null;
  lease_expires_at: Date | null;
  worker_id: string | null;
  last_error: string | null;
  created_at: Date;
  updated_at: Date;
}
