# ReconNexus — Phased Implementation Plan

This plan is the authoritative roadmap. Each item is marked with its **actual** state. Nothing is
marked `DONE` until it is implemented **and** covered by passing tests.

Legend: `TODO` · `WIP` · `DONE` · `BLOCKED`

---

## Phase 0 — Repository audit ✅ DONE

- [x] Inspect host, toolchain, external providers.
- [x] Produce `docs/implementation-audit.md`.
- [x] Produce `docs/implementation-plan.md` (this file).
- [x] Record deviations from reference layout.

## Phase 1 — Foundation ✅ DONE (verified 2026-10-13)

**Verification:** `npm test` → 63/63 passing (8 files); `make test-go` → all packages passing;
`reconnexus doctor` → healthy; `scope check` returns correct allow/deny with exit codes 0/4;
migrations apply and are idempotent; security suite passes with zero out-of-scope allowances.

Deliverable: a working CLI skeleton, versioned config, scope-policy engine, DB migrations,
structured logging, and a test harness — all tested.

- [x] Monorepo scaffold (npm workspaces + `go.work`).
- [x] `packages/contracts` — zod schemas + TS types for scan manifest, providers, findings, coverage.
- [x] `packages/configuration` — layered, versioned config loader + validator.
- [x] `packages/scope-policy` — scope enforcement engine (§8 checks 1–10) with network-disabled mode.
- [x] `packages/normalization` — URL/domain/IP canonicalization primitives used by scope + tests.
- [x] `packages/logging` — structured JSON logger with redaction.
- [x] `db/migrations` — SQL migrations for the full §9 data model.
- [x] Migration runner (`reconnexus config migrate` / internal runner).
- [x] CLI skeleton: `scan`, `scope`, `assets`, `urls`, `apis`, `secrets`, `findings`, `coverage`,
      `report`, `providers`, `config`, `doctor` — with `--json`, exit codes, non-interactive mode.
- [x] Go worker skeleton + `provider-check` binary + `internal/scope` mirror.
- [x] Unit tests for scope, normalization, config, contracts.
- [x] Security tests: private/loopback/link-local/metadata blocking, DNS-rebinding guard,
      redirect reauthorization, IPv4-mapped IPv6.
- [x] Docs: architecture overview, data model, provider contracts, threat model, ops.

**Phase 1 acceptance criteria**
1. `npm test` passes with zero failures.
2. `go test ./...` passes.
3. `reconnexus doctor` reports real dependency status (Postgres/Redis/tools) with correct exit codes.
4. `reconnexus scope check <url>` denies out-of-scope targets and explains why, in text and `--json`.
5. Migrations apply cleanly to a fresh Postgres and are idempotent on re-run.
6. Zero out-of-scope network actions in the security test suite.

## Phase 2 — Orchestration + asset discovery ✅ DONE (verified 2026-10-13)

**Verification:** `npm test` → 80/80 passing (12 files); `make test-go` → all packages passing;
`make conformance` → TS and Go scope engines agree on every fixture; real end-to-end run persisted
22,249 subdomain observations via `subfinder` and real A/AAAA DNS observations + an RDAP CIDR via
the built-in DNS and RDAP providers.

### Orchestration
- [x] Dependency-aware job DAG persisted at scan creation; idempotent creation via `(scan_id, job_key)`.
- [x] Worker job claiming with leases (`status='RUNNING'`, `lease_expires_at`, `attempts`).
- [x] Bounded retries with exponential backoff + jitter; retried only for fully-failed, retryable
      stages; policy/BLOCKED outcomes are never retried.
- [x] Cooperative cancellation (`scan cancel` and SIGINT → `AbortController` → worker `SIGTERM`).
- [x] Checkpointing / scan resumption (`scan resume` re-queues failed jobs with attempts remaining;
      completed stages and provider results are reused, so assets are not duplicated).
- [x] Coverage accounting per stage + per-provider outcomes (`job_provider_outcomes`).
- [x] Scan status reconciled from actual job outcomes (`SUCCEEDED`/`PARTIAL`/`FAILED`/`CANCELLED`).
- [x] Status vocabulary + DB CHECK constraints.

### Provider execution lifecycle
- [x] Capability validation, typed config validation, executable + version checks.
- [x] Structured argv invocation (no shell), timeouts, bounded output, cancellation.
- [x] Exit-code interpretation, stdout/stderr handling, schema-validated result ingestion.
- [x] Retry classification, structured execution records, truthful failure states.
- [x] Missing binary → `SOURCE_UNAVAILABLE`; non-zero exit → `FAILED`; malformed output → `FAILED`.

### Discovery
- [x] Subdomain discovery adapters: subfinder, assetfinder, amass (passive) + mock.
- [x] DNS: builtin-dns (Go resolver, concurrent) + dnsx adapter; A/AAAA/CNAME/MX/NS/TXT/PTR;
      wildcard detection; NXDOMAIN/TIMEOUT/ERROR statuses; resolver metadata.
- [x] Infrastructure correlation: RDAP IP lookups → prefix/name/country + `offline-ipmeta` fixture
      provider; IP→CIDR→ASN relationships only when evidence exists, with stated limitations.
- [x] Idempotent ingestion: canonical assets dedupe, observations append with provenance.
- [x] CLI: `scan run`, `scan resume`, `scan status` (jobs+coverage+providers), `coverage`, `assets list`.

### Not implemented (Phase 3B+)
- [ ] URL collection, JS/API analysis, secret detection, reporting (Phases 4–7).

## Phase 3A — HTTP probing & fingerprinting ✅ DONE (verified 2026-10-13)

**Verification:** `npm test` → 85/85 (14 files); `make test-go` → all packages; `make conformance` →
TS/Go agree; Go `httptest` security suite (redirect/SSRF/rebinding/TLS) passes; real worker binary
probed a local mock server (200 + title + server + 4 fingerprints) and denied a redirect to a
private address (`REDIRECT_DENIED`) while preserving the pre-redirect response.

- [x] `builtin-http` provider (kind `HTTP_PROBE`, capability `ACTIVE_HTTP`, bounded concurrency).
      Documented reason for not using httpx: per-hop redirect reauthorization and binding a
      validated IP decision to the actual socket require a custom transport; httpx resolves and
      follows internally.
- [x] HTTP/HTTPS probing: status, final URL, redirect chain, content type, title, selected headers,
      TLS subject/issuer/validity/SHA-256/protocol/SANs, timings, outcome and failure reason.
- [x] Connection timeouts, overall per-request timeout, response-size limit, redirect limit,
      cancellation.
- [x] Mandatory SSRF protection (release gate): normalize → hostname scope check → resolve →
      address scope check → bind decision to connection → reauthorize every redirect hop → enforce
      redirect count → block loopback/private/link-local/metadata; TLS verification never globally
      disabled; cookies/auth headers never persisted.
- [x] Evidence-backed technology fingerprinting (web servers, frameworks, CMS, frontend frameworks,
      CDN/WAF, API gateways, login/docs/dev services) with category, evidence type, evidence,
      confidence; generic strings never assert a technology; competing hypotheses allowed.
- [x] Ingestion: `SERVICE`, `TECHNOLOGY`, `CERTIFICATE` assets; `http`/`technology`/`tls`
      observations with provenance; `serves`/`runs`/`presents_certificate` relationships; evidence
      artifacts linked to observations; idempotent canonical assets.
- [x] Orchestration: HTTP stage (04) consumes resolved in-scope hosts, reauthorizes each, bounded
      target count, per-provider coverage, truthful partial/failure reporting.
- [x] CLI: `http <scanId>`, `technologies <scanId>`, `--http-providers` on `scan run`/`resume`.
- [x] Tests: Go httptest (status, redirects, excluded/out-of-scope/loopback/private/metadata/mapped,
      DNS rebinding, TLS trusted/untrusted, timeout, oversize, cancellation, scope skip) and TS
      contract + HTTP-stage integration.

### Not implemented (Phase 3B / later)
- [ ] HTTPX adapter (optional; would need an external redirect-reauth strategy).
- [ ] URL collection, JS/API analysis, secret detection, reporting (Phases 4–7).

## Phase 4 — URL intelligence ✅ DONE (verified 2026-10-13)

**Verification:** `npm test` → 92/92 (17 files); `make test-go` → all packages; `make conformance` →
TS/Go agree (now including URL canonicalization); live `waybackurls` returned 18 scope-filtered
URLs for a documentation domain; live `gau` timed out and was reported `FAILED` (not empty
success); the compiled worker crawled a local mock server (4 unique URLs, correct classifications
and parameters, out-of-scope link rejected).

- [x] URL canonicalization in the shared Go matching package + TS mirror, verified by conformance
      fixtures (scheme/host lowercasing, IDN→punycode, default-port removal, RFC 3986 dot-segment
      removal, fragment removal; query order/repeats and percent-encoding preserved; trailing slash
      preserved).
- [x] Active collection: `builtin-crawler` (connection-bound DialContext + per-hop redirect
      reauthorization, depth/budget/concurrency/timeout/response limits, cancellation) and an
      opt-in `katana` adapter (`-dr -jsonl`, scope regex, post-filter) — documented as not
      connection-bound.
- [x] Passive collection: `gau` and `waybackurls` adapters; honest handling of timeout,
      unavailability, malformed output; no fabricated URLs.
- [x] Static discovery: `builtin-static` parses robots.txt and sitemap XML (`<urlset>` and bounded
      `<sitemapindex>` recursion, document/URL caps); robots paths recorded as candidates only.
- [x] Scope/SSRF: every discovered URL (active or passive) is re-checked against the policy;
      out-of-scope candidates are counted as skipped and never persisted or crawled; redirects and
      addresses are enforced with the Phase 3A connection-bound controls.
- [x] Classification: URL categories and parameter roles with confidence + evidence; multiple
      hypotheses allowed; no vulnerability claims.
- [x] Persistence: `URL` assets, `url` observations with provenance (per provider), `contains_url`
      relationships; dedup by canonical identity without losing observations; idempotent.
- [x] Orchestration: Stage 05 consumes HTTP observations / resolved hosts as seeds; per-provider
      coverage; resume/cancel; partial/empty/failed reported distinctly.
- [x] CLI: `urls <scanId>` (filters + `--stats`), `params <scanId>`, `--url-providers`.
- [x] Tests: Go (crawler depth/dedup/SSRF/rebinding/cancellation, static robots/sitemap/malformed,
      passive parsing/fake-binary/unavailable, URL normalization, classification + confusion
      matrix) and TS (contract, stage orchestration/idempotency, CLI + JSON envelope).
- [x] Measurement: collection stats command (`urls --stats`) and a labeled classification fixture
      confusion-matrix test.

## Phase 5 — JavaScript & API intelligence ✅ DONE (verified 2026-10-13)

Implemented as the existing DAG stages **`07-js-intelligence`** and **`08-api-discovery`** (Stage
`06-url-categorization` is satisfied during URL collection; no duplicate stage IDs were invented).

**Verification:** `npm test` → 99/99 (20 files); `make test-go` → all packages; `make conformance`
→ TS/Go agree; the compiled worker retrieved and hashed a real JS artifact, extracted GET/POST/
WebSocket endpoints and parsed a source map (with secret redaction), and parsed a live OpenAPI JSON
document into documented endpoints with parameters.

- [x] JS artifact discovery from Stage 05 URL observations (JAVASCRIPT/STATIC_ASSET classifications
      or `.js`/`.mjs`), retrieved with connection-bound scope enforcement and bounded
      concurrency/size/timeout/cancellation. Preserves URL, canonical URL, SHA-256 content hash,
      MIME type, size, source URL, discovery method, status, provenance.
- [x] Honest artifact outcomes: `RETRIEVED`, `NOT_FOUND`, `ERROR`, `OVERSIZED`,
      `MISMATCHED_MIME`; no fabricated success.
- [x] Bounded static analysis (RE2 lexical scan; no JS execution/browser/package install):
      `fetch()`, `axios.<method>()`, `XMLHttpRequest.open()`, `WebSocket`, absolute/relative URL and
      path literals, GraphQL/API-doc references. Dynamic template literals are retained as
      **unresolved candidates**, never invented endpoints. Evidence is minimal and secret-redacted.
- [x] Source-map analysis via `sourceMappingURL`: parse JSON, size/recursion limits, cycle-safe,
      configurable (`fetchSourceMaps`), scope-checked, and does **not** fetch listed sources.
- [x] API specification intelligence: OpenAPI/Swagger JSON **and YAML**, version/title/servers/
      paths/methods/operationIds/tags/parameters/request-body/responses/content-types/auth schemes;
      local `$ref` resolution with depth/cycle limits, remote `$ref` never fetched; GraphQL paths
      surfaced as endpoints (no live introspection).
- [x] Endpoint identity is **method-aware** (`METHOD origin path`) and distinguishes JS-extracted vs
      SPEC-documented vs HTTP-observed; unresolved dynamic candidates flagged `resolved=false`.
- [x] Persistence: `JS_ARTIFACT`/`API_ENDPOINT` assets, `js-artifact`/`source-map`/`api-spec`/
      `api-endpoint` observations with provenance, `references`/`has_source_map`/`exposes`/`documents`
      relationships; idempotent, multi-source observations retained.
- [x] Orchestration Stage 07 (JS) and Stage 08 (API) with per-provider coverage, resume/cancel,
      and distinct empty/partial/failed reporting.
- [x] CLI: `js <scanId>`, `apis <scanId>` (filters), `specs <scanId>`, `params` now includes endpoint
      parameters, `--js-providers` / `--api-providers`.
- [x] Tests: Go (JS extraction incl. dynamic/adversarial/oversized, source maps/disabled, honest
      failures, OpenAPI JSON+YAML, Swagger 2, `$ref` resolution + unresolved remote refs, out-of-scope
      origin dropping, capability blocking) and TS (contract, stages 07/08 orchestration + idempotency,
      CLI + JSON envelope).

### Not implemented (Phase 6+)
- [ ] Secret detection, security checks, correlation, reporting (Phases 6–7).

## Stage 06 discrepancy — RESOLVED (2026-10-13)

`06-url-categorization` was previously left `SKIPPED` because URL classification is computed inside
Stage 05. Rather than leave an unexplained gap in the DAG, Stage 06 is now **implemented as a real,
network-free stage** that materializes the categorization dimension: it reads Stage 05 URL
observations, records category counts and coverage (`COLLECTED`/`PARTIAL`), and confirms every
discovered URL carries at least one classification. Dependencies and resume are unaffected
(Stage 07 depends on 06; a `SKIPPED` node already satisfied that). Stage 09 (`09-secret-detection`)
remains intentionally `SKIPPED` and is not implemented in Phase 6.

## Phase 6 — Security metadata & exposure intelligence ✅ DONE (verified 2026-10-13)

Implemented as **Stage `10-security-checks`** (capability `SECURITY_CHECKS`). It reuses existing
observations and issues a single bounded, connection-bound GET per in-scope service.

**Verification:** `npm test` → 105/105 (23 files); `make test-go` → all packages; `make
conformance` → TS/Go agree; the compiled worker observed HSTS, `X-Content-Type-Options`, a
wildcard+credentials CORS `INCONSISTENT`, cookie attributes (no value), a consistent content type,
and `NOT_OBSERVED` for absent headers/TLS with explicit limitations.

- [x] **Categories**: TLS certificate metadata (subject/issuer/notBefore/notAfter/sha256/protocol/
      selfSigned/hostnameMatch/daysToExpiry/validNow), security headers (HSTS, CSP, X-Frame-Options,
      X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-*), cookie
      attributes (Secure/HttpOnly/SameSite/Domain/Path/Max-Age — **values never stored**), CORS
      policy (origin/credentials/methods/headers, wildcard flag), HSTS parsing, and content-type vs
      observed-body consistency.
- [x] **Status model**: `OBSERVED`, `INFERRED`, `INCONSISTENT`, `NOT_OBSERVED`, `UNKNOWN`,
      `COLLECTION_FAILED`. A missing header is recorded `NOT_OBSERVED` with an explicit limitation,
      never as "control absent".
- [x] **Evidence & correlation**: each observation records source/evidence/evidence-type; TLS
      metadata is correlated to a `CERTIFICATE` asset via a `presents_certificate` relationship;
      observations link to the stored (redacted) evidence artifact.
- [x] **Scope/safety**: connection-bound transport, per-hop redirect reauthorization, bounded
      concurrency/size/timeout, cancellation; no target-set expansion; no cookie values, secrets, or
      auth headers persisted; TLS verification never disabled.
- [x] **Orchestration**: Stage 10 seeds from HTTP observations; per-provider coverage; idempotent,
      resumable, partial-aware.
- [x] **CLI**: `security <scanId>` with `--category`/`--status`/`--host`/`--limit`; `--security-providers`.
- [x] **Tests**: Go (headers/HSTS/cookies/CORS/content-type/TLS validity boundaries/collection
      failure/out-of-scope/cancellation/capability blocking) and TS (contract, stages 06+10
      orchestration + idempotency, CLI + JSON).
- [x] **Stage 06** implemented (categorization coverage) — see above.

### Not implemented (Phase 7+)
- [ ] Version↔CVE correlation, approved template checks.
- [ ] Correlation and reporting.

## Phase 7 — Secret detection & sensitive artifact analysis ✅ DONE (verified 2026-10-13)

Implemented as **Stage `09-secret-detection`** (capability `SECRET_SCAN`). It depends on Stage 08 and
feeds Stage 10; Stage 10's dependency on 09 is satisfied when 09 succeeds.

**Design decision:** raw artifact bodies are **not persisted** (they may contain credentials).
Stage 09 selects the persisted JS artifacts and API specifications from stages 07/08, re-collects
their content **in-memory** through the connection-bound transport, scans it, and persists only
redacted findings plus a keyed fingerprint.

**Verification:** `npm test` → 112/112 (26 files); `make test-go` → all packages; `make
conformance` → TS/Go agree; the compiled worker detected AWS key/private-key/DB-URL/password
candidates in a served artifact and confirmed every raw fixture value was absent from its output
including the private-key body.

- [x] **Detection rules**: maintained, high-signal patterns (AWS key id + secret, Google, Slack,
      GitHub, Stripe, Twilio, SendGrid, npm, Azure account key, private-key markers, database
      connection strings, OAuth client secrets, webhook signing secrets, JWTs, bearer tokens,
      embedded credentials, password assignments) plus a single entropy heuristic for generic
      `api_key`/`token`/`secret_key` assignments.
- [x] **Context & confidence**: rule id, category, confidence, rationale; high-confidence vs
      candidate; entropy threshold; overlapping generic matches suppressed by more specific ones;
      placeholder/example suppression; rule-specific suppression via configuration.
- [x] **Secret-safe evidence**: only a **line-scoped** redacted snippet (raw value replaced, every
      rule match in the snippet re-redacted, global redactor last), a safe HMAC fingerprint, and the
      source location are stored. Private keys and over-long (minified) lines store a context-free
      marker. Raw values never reach findings, logs, errors, or the database.
- [x] **Lifecycle**: `CANDIDATE`, `HIGH_CONFIDENCE`, `SUPPRESSED`, `ANALYSIS_FAILED`. There is no
      `VALIDATED`/`ACTIVE` state — no credential verification is performed.
- [x] **Deduplication & provenance**: identical rule+value matches collapse with an occurrence
      count; findings remain per-artifact.
- [x] **Orchestration**: Stage 09 selects eligible artifacts, bounds size/concurrency, persists
      incrementally and idempotently, records per-provider coverage, and reports empty vs failed
      distinctly.
- [x] **CLI**: `secrets <scanId>` with `--rule`/`--category`/`--status`/`--confidence`/`--artifact`/
      `--host`/`--limit`, redacted output only; `--secret-providers`.
- [x] **Tests**: Go (rule detection, entropy, suppression, dedup, oversized, malformed/Unicode,
      analysis failure, out-of-scope, cancellation, capability blocking, HMAC on/off, and a
      raw-value-absence release gate) and TS (contract, Stage 09 orchestration + DB-wide redaction
      regression + idempotency, CLI filters + JSON).

### Not implemented (Phase 8 / later)
- [ ] Correlation and reporting (canonical relationships, historical diffs, exports).

## Stage 11 — Evidence correlation ✅ DONE (verified 2026-10-13)

Implemented as **Stage `11-correlation`** — a deterministic, control-plane pass over persisted
records (no network, no new provider).

**Discrepancy noted during audit:** the plan bundled "Correlation & reporting" together; the prompt
splits correlation (Stage 11) from reporting (Stage 12). Also, the **asset graph is already built
inline during ingestion** (`resolves_to`, `serves`, `runs`, `presents_certificate`, `references`,
`has_source_map`, `exposes`, `documents`, `contains_url`, `cname_to`, `mx_to`, `ns_to`, `ptr`,
`in_prefix`, `announced_by`). Stage 11 must not recreate it.

**Verification:** `npm test` → 119/119 (29 files); `make conformance` → TS/Go agree; `make test-go`
→ all packages; `tsc` clean; CLI `correlations` distinguishes not-run/partial/failed/complete-empty.

- [x] **Shared secret-fingerprint equivalence**: two artifacts with the same `(ruleId, non-empty
      HMAC fingerprint)` where both artifacts' `secret-scan-artifact` records report `hmacKeyed`
      produce a `shares_secret_fingerprint` edge (asset relationship) and a correlation observation.
      Empty fingerprints, unkeyed artifacts, and different rules never correlate.
- [x] **Multi-source corroboration** (cross-provider duplicate detection): an asset observed by ≥2
      distinct sources produces a `MULTI_SOURCE_CORROBORATION` correlation observation.
- [x] **Coverage-gap summary**: stages whose coverage is not `COLLECTED` are recorded in the Stage 11
      coverage `details` so incomplete upstream work is visible and not mistaken for completeness.
- [x] **Typed contract** `CorrelationRecordSchema` (`relation`, `status` ∈ OBSERVED/PARTIAL/FAILED,
      `subject`, `related`, `ruleId`, `hmacKeyed`, opaque `correlationGroup`, `sourceRecordIds`,
      `sourceStage`, redacted `evidence`, `confidence`). No `VALIDATED`/`CONFIRMED`/`ACTIVE`.
- [x] **Persistence** reuses `asset_relationships` (edges) and `observations` (kind `correlation`).
      No schema migration.
- [x] **Idempotent & deterministic**: correlation observations are fully derived and replaced each
      run; edges use `ON CONFLICT DO NOTHING`; results are reproducible.
- [x] **Security**: the `correlationGroup` is an opaque `sha256(rule|fingerprint)[:16]` — the
      fingerprint and any raw value are never stored; the stage never uses or validates credentials.
- [x] **CLI**: `correlations <scanId>` with `--relation`/`--subject`/`--limit`, redacted output,
      and distinct not-run / partial / failed / complete-empty / populated states.
- [x] **Tests**: correlation contract, Stage 11 correctness + idempotency + security regressions,
      CLI state machine + JSON.

### Not implemented (later)
- [ ] Historical diffs and cross-scan trend analysis.
- [ ] Static HTML export (not required; CLI-only product).

## Stage 12 — Evidence-based reporting ✅ DONE (verified 2026-10-13)

Implemented as **Stage `12-reporting`** — a deterministic, control-plane stage that generates a
redacted, evidence-backed report from persisted state (no network). It is the final stage of the DAG.

**Contract gap analysis:** the existing model (scan_runs, jobs, coverage_records, observations,
assets) fully represents the report lifecycle, so **no migration** was required. Reports are stored
as a single `report` observation (kind `report`) on the root domain asset; report generation is also
available on demand via the CLI.

**Verification:** `npm test` → 135/135 (33 files); `make conformance` → TS/Go agree; `make test-go`
→ all packages; `tsc` clean; CLI `report` distinguishes not-run/partial and supports human/json/
jsonl/csv.

- [x] **Typed contract** `ReportSchema` (scan identity/context, `scanStatus`, `reportStatus`, stages
      with job+coverage, coverage gaps, asset/observation counts, redacted secret findings,
      correlations, limitations, summary).
- [x] **Report-status derivation** (six states) from authoritative records: `COMPLETE_WITH_FINDINGS`,
      `COMPLETE_NO_FINDINGS`, `PARTIAL`, `FAILED`, `REPORTING_NOT_RUN`, `REPORTING_FAILED`. The
      analysis status is reconciled from the **non-reporting** stages, so a scan is never labelled
      complete merely because reporting succeeded; a skipped/failed stage is never reported as
      "found nothing".
- [x] **Redaction at the report boundary, fail-closed**: a structure-preserving redactor applies the
      centralized string redactor to every string value and re-validates; on any error it throws and
      **never** emits an unredacted report. No raw secret values, HMAC fingerprints, or artifact
      bodies appear; correlation groups remain opaque.
- [x] **Deterministic**: sections/records sorted; injectable clock; idempotent persistence
      (delete+insert) with no duplication on retries.
- [x] **CLI**: `report <scanId>` with `--format human|json|jsonl|csv`; distinguishes missing scan,
      not-run, empty, partial, and failure with stable exit codes.
- [x] **Tests**: report contract; status derivation for all six states; boundary redaction
      fail-closed; Stage 12 persistence + determinism/idempotency + DB redaction regression;
      CLI formats + exit codes.

## Phase 8 — Release hardening & security assurance ✅ DONE (verified 2026-10-13)

Repository-wide audit with verified fixes and regression tests. See
`docs/testing/failure-injection.md`, `docs/operations/provider-compatibility.md`,
`docs/testing/benchmarks.md`, and `docs/testing/evaluation-corpus.md`.

- [x] **Fixed (High): TS/Go URL-canonicalization + scope path parity** — WHATWG dot-segment rules
      implemented in Go (`matching.resolvePathWHATWG`, `matching.NormalizePath`) and used by the Go
      scope engine; adversarial conformance fixtures added.
- [x] **Hardened:** re-redact persisted provider diagnostics; CSV formula-injection guard.
- [x] **Failure-injection suite** (database unavailable, transaction rollback, cancellation).
- [x] **Provider compatibility matrix** + `providers matrix` command.
- [x] **Benchmarks** (Go + TS) with recorded baselines; no invented targets.
- [x] **Evaluation corpus** (24-case secret-detection set) with measured P/R/F1 on the curated set.
- [x] **Docs:** provider compatibility, benchmarks, evaluation, failure injection.

### Residual (documented)

- No labelled real-world corpus ⇒ no production accuracy claim.
- No minimum-version enforcement for external binaries; archive providers unreliable.
- Distributed execution and full-platform certification remain out of scope.

## Phase 10 — Subdomain-takeover detection ✅ DONE (verified 2026-10-13)

New stage `13-subdomain-takeover` + capability `TAKEOVER_CHECK`, run after correlation and before
reporting.

- [x] `builtin-takeover` provider: CNAME resolution + curated takeover-prone service fingerprints +
      a single bounded HTTP GET for the service's "unclaimed" marker.
- [x] Candidate-only statuses (`SUSPECTED`/`CANDIDATE`/`NOT_VULNERABLE`/`INCONCLUSIVE`); never a
      confirmed takeover; no claim/registration/exploitation.
- [x] `TAKEOVER_CANDIDATE` record + `takeover-candidate` observations; report `takeoverCandidates`
      section; CLI `takeover`.
- [x] Migration `0004_takeover` (capability constraint).
- [x] Fixed orchestrator DAG iteration to use `OrderedStages` order (was lexicographic job_key).
- [x] Go + TS tests with local mock TLS servers and an injectable resolver.

## Phase 11 — Admin login & cPanel finder ✅ DONE

New stage `14-login-finder` (capability `ACTIVE_HTTP`), run after takeover and before reporting.

- [x] `builtin-login-finder` provider: fixed, bounded path probes for administrative login pages
      plus cPanel/WHM/webmail paths and well-known control-panel ports.
- [x] Read-only: unauthenticated GET only; no credentials submitted. Connection-bound transport and
      per-hop redirect reauthorization.
- [x] Per-candidate scope reauthorization (including path exclusions) and shared request-rate
      limiting.
- [x] Evidence-backed statuses `DETECTED`/`POSSIBLE` (never a vulnerability claim); generic pages
      are not reported.
- [x] `LOGIN_INTERFACE` record + `login-interface` observations; CLI `admin <scanId>` and
      `cpanel <scanId>` with host/status/confidence filters.
- [x] Go provider tests (admin, cPanel, generic-page rejection, path exclusion) and TS
      contract/integration tests.

## Phase 9 — Hardening (remaining) ⏳ TODO

- [ ] Failure-injection, DNS-rebinding, rebind/redirect fuzz, benchmark suite.
- [ ] Compatibility matrix, docs review, release gate verification.

## Correctness pass — status, endpoint accounting, JS classification ✅ DONE (2026-10-15)

Verified against an existing generated report (`5b1edc77…html`) that showed all four symptoms.

- [x] **Report status vs findings.** `buildReport` counted correlations into the value passed to
      `deriveReportStatus`, producing `COMPLETE_WITH_FINDINGS` with zero findings. Now driven by
      `buildFindings(...).length`, so status, headline and `findingTotals` agree.
- [x] **Provider `PARTIAL` masking.** `aggregate()` returned `SUCCEEDED` when no provider hard-failed,
      hiding a `PARTIAL` provider. Now any non-all-success mix with a success/partial is `PARTIAL`.
- [x] **JS stage content selection.** Stage 07 no longer selects `STATIC_ASSET` (images/CSS/fonts);
      the worker additionally rejects HTML/binary content as `SKIPPED` with a rationale.
- [x] **API endpoint accounting.** Distinct `method origin path` identities are counted; raw
      observation and per-source/per-provider breakdowns are exposed as `reconciliation`.
- [x] **Zero-result diagnostics.** External providers record why a run parsed zero records.
- [x] Regression tests (TS + Go); `npm run typecheck`, `npm test` (247), `go test ./...` all pass.

### Known gaps (this pass)

- [ ] Extensionless JavaScript endpoints referenced only by `<script src>` are not yet discovered
      (URL collection does not parse script tags), so stage 07 still relies on `.js`/classification.
- [ ] Security-metadata findings remain inventory-only; no finding type is derived for
      `NOT_OBSERVED` headers (by design), so "0 findings" is expected for header-only scans.
- [ ] The status vocabulary still maps onto `JobStatus`/`coverageStatus`/`reportStatus` rather than a
      single dedicated scan-lifecycle enum; the three dimensions are reported separately but are not
      unified in one type.

---

## Definition of Done traceability

| # | Requirement | Phase | State |
| --- | --- | --- | --- |
| 1 | CLI accepts/validates starting URL | 1 | DONE |
| 2 | Authorization/scope checked before active collection | 1–2 | DONE (control plane + worker) |
| 3 | Scan executes through implemented stages | 2–9 | DONE (stages 00–12) |
| 4 | Results persisted, recoverable after interruption | 2 | DONE (resume + idempotent ingestion) |
| 5 | Queryable subdomains/infra/URLs/JS/APIs | 2–5 | DONE (subdomains/DNS/infra/HTTP/technologies/URLs/params/JS artifacts/API endpoints+specs queryable) |
| 6 | Secrets safely redacted | 6 | PARTIAL (redaction framework DONE; detector TODO) |
| 7 | Provenance on every observation | 1–2 | DONE (source, reliability, observed_at persisted) |
| 8 | Finding states observed/suspected/validated/rejected/indeterminate | 1 | DONE (schema + constraints) |
| 9 | Failed providers visible in reports | 2 | DONE (coverage + provider outcomes) |
| 10 | JSON/JSONL/CSV/human exports | 9 | DONE (report command; no HTML) |
| 11 | Critical scope-enforcement tests pass | 1–2 | DONE (incl. TS/Go conformance) |
| 12 | Test suite passes on dev env | 1–2 | DONE |
| 13 | Install/troubleshooting docs accurate | 1–2 | DONE |
| 14 | No fabricated output | all | Enforced |
