# Data Model

PostgreSQL is the authoritative structured store. Migrations live in `db/migrations` and are
applied by `reconnexus config migrate` (idempotent, advisory-locked).

## Core concepts (kept strictly separate)

| Concept | Table | Meaning |
| --- | --- | --- |
| Asset | `assets` | Canonical identity (domain, host, IP, URL, service, …), unique per project. |
| Observation | `observations` | A *source's* report at a *time*, with provenance. Many per asset. |
| Evidence artifact | `evidence_artifacts` | Content-addressed supporting data (hash + storage URI). |
| Finding | `findings` | An interpreted issue. Severity, confidence, validation, reliability are independent. |
| Coverage record | `coverage_records` | What was and was not collected per stage. |

Raw artifacts are stored via the `ArtifactStore` abstraction (content-addressed local filesystem in
Phase 1) and referenced by hash — never inlined into relational rows.

## Tables

### `0001_core.sql`

- `workspaces` — top-level tenancy boundary.
- `users`, `workspace_members` — optional multi-user support with roles (`OWNER`…`VIEWER`).
- `projects` — unique `(workspace_id, name)`, carries `root_domain`.
- `authorization_records` — reference, authorizer, validity window, capability array (validated
  against the known capability set, with `valid_until > valid_from`).
- `scope_policies` — immutable, versioned policy documents; **unique `(project_id, version)`**.
- `scan_runs` — status, start URL, root domain, config snapshot (JSONB), coverage (JSONB).
- `jobs` — the dependency DAG: `depends_on text[]`, `job_key`, status, attempts, `not_before`,
  deadline, lease, worker id. **Unique `(scan_id, job_key)`** for idempotent creation.
- `provider_executions` — per-invocation audit: argv (as text[]), exit code, output byte count,
  stderr excerpt, status.

### `0002_intelligence.sql`

- `assets` — **unique `(project_id, type, canonical_key)`**.
- `asset_relationships` — typed edges with confidence, unique per edge, no self-loops.
- `observations` — provenance (`source`, `source_reliability`), `observed_at`, `first_seen`,
  `last_seen`, `kind`, JSONB `data`.
- `evidence_artifacts` — `sha256` (checked 64-hex), `size_bytes >= 0`, `storage_uri`, `redacted`;
  **unique `(project_id, sha256)`**.
- `findings` — `severity` and `validation` enumerated; `confidence` in `[0,1]`.
- `finding_evidence`, `evidence_links` — join tables.
- `coverage_records` — **unique `(scan_id, stage)`**, `expected`/`collected` nonnegative.
- `audit_events` — append-only record of decisions (e.g. scope allow/deny).

## Constraints summary

- UUID primary keys (`gen_random_uuid()`).
- Foreign keys with `ON DELETE CASCADE`/`SET NULL` as appropriate.
- Status CHECK constraints matching the canonical status vocabularies.
- Nonnegative counters (`attempts`, `size_bytes`, `expected`, `collected`, `stdout_bytes`).
- Confidence in `[0,1]`; relationship confidence `numeric(4,3)`.
- Indexes: `(project_id, observed_at)` on observations, `(project_id, type)` on assets,
  `(project_id, severity)` and `(validation)` on findings, claimable jobs partial index on
  `(status, not_before)`, lease index for abandoned-job recovery, plus project/scan indexes.

## JSONB usage

JSONB is used for provider-specific payloads (`observations.data`, `scan_runs.config_snapshot`,
`audit_events.detail`) **without** replacing relational constraints — canonical identity and
query-critical fields remain typed columns.

## Planned additions

Phase 7 adds historical-diff support (finding lifecycle transitions, asset first/last-seen
rollups). Any schema change ships as a new numbered migration; no migration is edited after being
applied.
