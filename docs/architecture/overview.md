# Architecture Overview

ReconNexus is a CLI-only reconnaissance platform. This document describes the components that
exist in the **Phase 1** build and how they fit together. Components marked *(planned)* are not
implemented yet and are explicitly not represented as working.

## High-level shape

```
                 ┌─────────────────────────────┐
                 │        apps/cli (TS)        │  operator interface, JSON output, exit codes
                 └──────────────┬──────────────┘
                                │ uses
        ┌───────────────────────┼────────────────────────────────┐
        ▼                       ▼                                ▼
 packages/configuration   packages/scope-policy          apps/control-plane
 (layered config)         (enforcement engine)            (repo, migrations, diagnostics,
        │                       │                           scan service / Stage 00)
        │                       ▼                                │
        │             packages/normalization                    │
        │             (URL / domain / IP)                       ▼
        │                                                PostgreSQL (authoritative)
        │
        ▼
 packages/contracts          packages/logging          packages/evidence-contracts
 (zod schemas + types)       (structured + redaction)  (content-addressed artifacts)

 workers/ (Go): independent scope enforcement, provider adapters, structured exec, telemetry
 (worker job execution is Phase 2; Phase 1 ships the skeleton + provider-check)
```

## Component responsibilities

| Component | Responsibility |
| --- | --- |
| `apps/cli` | Command parsing, output formatting (human + `--json`), exit codes, error classification. |
| `apps/control-plane` | The CLI-oriented backend: database access, migrations, repositories, scan/Stage-00 service, provider catalog, dependency diagnostics. |
| `packages/contracts` | Single source of truth for schemas (zod) and shared types: scope policy, scan manifest, provider descriptor, findings, coverage, exit codes. |
| `packages/normalization` | Deterministic canonicalization of URLs, domains (PSL-aware via `tldts`), IPv4/IPv6, and CIDR. |
| `packages/scope-policy` | The authorization enforcement engine (10 checks) plus DNS reauthorization/resolution helpers. |
| `packages/configuration` | Defaults → file → environment → overrides merging, validation, path resolution. |
| `packages/logging` | Structured JSON logging with centralized secret redaction. |
| `packages/evidence-contracts` | `ArtifactStore` abstraction and a content-addressed local filesystem implementation. |
| `workers` (Go) | Independent scope enforcement (defence in depth), structured process adapters, provider health checks. |

## Orchestration model

There is a **single authoritative orchestration model**: PostgreSQL. Phase 1 persists a
dependency-aware job DAG per scan. Phase 2 claims jobs with `SELECT … FOR UPDATE SKIP LOCKED`
(persist-before-dispatch, at-least-once, idempotent). Redis/BullMQ is optional and, when enabled,
must be fed via a transactional outbox — it is never a second source of truth.

## Security posture (Phase 1)

- Scope enforcement happens in-process **before** network execution (Stage 00), at the CLI.
- The same policy is enforced **again** independently in Go on the worker side (defence in depth).
- Destination addresses are validated at connection time (loopback, link-local, private, CGNAT,
  metadata, IPv4-mapped IPv6), catching DNS rebinding and redirect pivots.
- Restricted address space is denied by default and requires an explicit in-scope IP/CIDR entry,
  the `INTERNAL_NETWORK` capability **and** an operator override (documentation ranges need only
  the explicit entry); see `docs/threat-model/scope-enforcement.md`.
- Provider processes are invoked with argv arrays — never a shell.

See [threat-model/scope-enforcement.md](../threat-model/scope-enforcement.md).

## Data flow for a scan (current build)

1. `scan start <url> --policy <file>` (CLI) loads and validates the policy.
2. `ScanService.validateStartUrl` normalizes the URL (http/https only).
3. `ScopeEngine.check` authorizes the start URL for the primary capability.
4. On allow: within a transaction, ensure workspace/project, reuse or insert the policy version
   (idempotent), create the scan, persist the manifest, and build the 13-stage job DAG.
5. Stage 00 is marked `SUCCEEDED`; stages 01–12 remain `QUEUED` (execution is Phase 2).
6. An `audit_events` row records the allow decision.

## Phase 2 additions

- **`workers/cmd/reconnexus-worker`** — the Go discovery worker. It accepts a `DiscoveryJob` on
  stdin, enforces scope independently, runs a provider via structured argv, and emits a normalized
  `DiscoveryResult` on stdout. See [discovery.md](discovery.md).
- **`workers/internal/matching`** — Go canonicalization (PSL via `golang.org/x/net/publicsuffix`,
  IP classification) verified against the same fixtures as `packages/normalization`.
- **`workers/internal/conformance` + `cmd/conformance`** — evaluate shared fixtures so the Go and
  TypeScript scope engines are provably in agreement.
- **`apps/control-plane/src/orchestration`** — job claiming/leases, retries, cancellation, resume,
  coverage, provider outcomes, status reconciliation, and idempotent ingestion.
- **`apps/control-plane/src/worker/client.ts`** — spawns the worker and validates its output.
- **`db/migrations/0003_discovery.sql`** — execution metrics, coverage `details`,
  `job_provider_outcomes`.

## Phase 3A additions

- **`workers/internal/discovery/http.go`** — the `builtin-http` HTTP probing provider with
  connection-bound scope enforcement and per-hop redirect reauthorization.
- **`workers/internal/discovery/fingerprint.go`** — evidence-backed technology signatures.
- **`HTTP_OBSERVATION` / `TECHNOLOGY`** discovery records and stage `04-http-probe` orchestration.
- Ingestion of `SERVICE`/`TECHNOLOGY`/`CERTIFICATE` assets, `http`/`technology`/`tls` observations,
  and `serves`/`runs`/`presents_certificate` relationships.
- **CLI**: `http <scanId>`, `technologies <scanId>`, `--http-providers`.

## Phase 4 additions

- **`workers/internal/matching/url.go`** — URL canonicalization (verified by conformance fixtures).
- **`workers/internal/discovery/urlcollect.go`** — `builtin-crawler`, `builtin-static`, `gau`,
  `waybackurls`, opt-in `katana`, and `mock-url` providers.
- **`workers/internal/discovery/urlclassify.go`** — URL category and parameter-role classification.
- **`URL` assets / `url` observations / `contains_url` relationships** and stage `05-url-collection`.
- **CLI**: `urls <scanId>` (filters + `--stats`), `params <scanId>`, `--url-providers`.
- See [url-intelligence.md](url-intelligence.md).

## Phase 5 additions

- **`workers/internal/discovery/jsanalysis.go`** — `builtin-js`: artifact retrieval/hashing, bounded
  static analysis, source-map analysis.
- **`workers/internal/discovery/apispec.go`** — `builtin-api`: OpenAPI/Swagger JSON+YAML parsing.
- **`JS_ARTIFACT` / `API_ENDPOINT` assets** and `js-artifact`/`source-map`/`api-spec`/`api-endpoint`
  observations + relationships; stages `07-js-intelligence` and `08-api-discovery`.
- **CLI**: `js`, `apis`, `specs`, `--js-providers`, `--api-providers`; `params` includes endpoint
  parameters.
- See [js-api-intelligence.md](js-api-intelligence.md).

## Phase 6 additions

- **`workers/internal/discovery/securitymeta.go`** — `builtin-security-meta`: TLS/HSTS/header/cookie
  attribute/CORS/content-type metadata.
- **Stage `06-url-categorization`** implemented (categorization coverage) and **Stage
  `10-security-checks`** implemented (security metadata).
- **`security-metadata` observations** on `SERVICE` assets, plus `CERTIFICATE` correlation.
- **CLI**: `security <scanId>`, `--security-providers`.
- See [security-metadata.md](security-metadata.md).

## Phase 7 additions

- **`workers/internal/discovery/secretscan.go`** — `builtin-secret-scan`: maintained rule set +
  entropy heuristic, redacted-only findings with keyed HMAC fingerprints.
- **Stage `09-secret-detection`** implemented; `secret-finding` / `secret-scan-artifact`
  observations (no migration).
- **CLI**: `secrets <scanId>`, `--secret-providers`.
- See [secret-detection.md](secret-detection.md).

## Stage 11 additions

- **`ScanOrchestrator.runCorrelation`** — deterministic, control-plane correlation over persisted
  records (no provider, no network).
- **`CorrelationRecordSchema`** + `shares_secret_fingerprint` edges and `correlation` observations.
- **CLI**: `correlations <scanId>`.
- See [correlation.md](correlation.md).

## Stage 12 additions

- **`apps/control-plane/src/reporting/report.ts`** — `buildReport`, `deriveReportStatus`,
  `redactReport` (structure-preserving, fail-closed).
- **`ReportSchema`** + Stage `12-reporting` and `report` observations.
- **CLI**: `report <scanId> --format human|json|jsonl|csv`.
- See [reporting.md](reporting.md).

## Deviations from the reference layout

- **npm workspaces** instead of pnpm (pnpm is not installed on the dev host).
- `workers/internal/scope` added for independent worker-side enforcement.
- `packages/logging` added as a shared structured-logging module.
- `workers/internal/matching` + `workers/internal/conformance` added to enforce TS/Go parity.

These are recorded in [implementation-audit.md](../implementation-audit.md).
