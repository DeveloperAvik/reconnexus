# Testing and Benchmark Methodology

> **No performance numbers or coverage claims in this project are fabricated.** This document
> describes how results are (and will be) measured. At the Phase 1 stage, the numbers below are
> the actual test counts from the suite; no throughput/latency benchmarks have been run yet.

## Test layers

| Layer | Location | Tool | Scope |
| --- | --- | --- | --- |
| Unit | `test/unit`, `packages/**/*.test.ts`, `workers/**/*_test.go` | vitest / `go test` | Pure functions: normalization, scope, config, redaction, evidence store. |
| Integration | `test/integration` | vitest | Migrations against a real Postgres (skipped when unavailable). |
| Security | `test/security` | vitest | Scope-enforcement release gate. |
| Contract | `test/contract` (planned) | vitest | Provider output parsing against recorded fixtures. |
| End-to-end | Phase 3+ | — | Full pipeline against local mock servers. |
| Benchmark | `test/benchmark` (planned) | — | Extractors/classifiers precision & recall. |

Run everything with `make test-all` (`npm test` + `make test-go`).

## Determinism rules

- Unit and security tests perform **no network I/O**. DNS is injectable
  (`resolveAndCheck({ resolver })`); local fixtures provide all inputs.
- Integration tests require a local Postgres and **skip** (not fail) when it is unreachable.
- Fixtures use **synthetic, non-functional** credentials only (`test/fixtures/secrets.synthetic.txt`).
- Time-dependent checks accept an injected `now`.

## Measuring extractors and classifiers (Phase 4+)

For any classifier or extractor (URL categories, parameter names, secret detection, endpoint
extraction) we will report **precision and recall independently** against a labeled fixture corpus:

- `precision = TP / (TP + FP)` — of the items flagged, how many were real.
- `recall = TP / (TP + FN)` — of the real items, how many were found.
- A confusion-matrix JSON artifact is produced per run and checked into `test/benchmark/results/`.

Corpus contents: known domains, URLs, endpoints, technologies, synthetic secret patterns, malformed
files, and expected relationships.

## Coverage measurement (runtime)

Phase 2 introduces `coverage_records`: each stage records `expected` vs `collected`. Reports
surface `MISSING`/`PARTIAL`/`BLOCKED` stages so a run is never presented as complete when it is not.
Zero-exit providers are not treated as full success.

## Cross-language conformance gate

`test/conformance/scope-conformance.test.ts` evaluates the shared fixtures in
`test/fixtures/conformance/` with the TypeScript engine and with the Go
`cmd/conformance` binary, and asserts the two outputs are **deep-equal**. This is how TS/Go
agreement on registrable domains, subdomain matching, IPv4/IPv6 canonicalization, IPv4-mapped
handling, restricted-address classification, and policy decisions is enforced. Run with
`make conformance`.

## Release gate

`test/security/scope-security.test.ts` must pass with **zero** out-of-scope network decisions before
any release. It is treated as a hard gate, not a best-effort check.

## Deterministic provider testing

Provider execution is tested without relying on the public Internet:

- **Go** (`workers/internal/discovery`): fake resolver injection for DNS statuses and wildcard
  detection; temporary shell scripts as fake provider binaries to exercise argv recording,
  non-zero exit, timeout, output truncation, and cancellation; scope-filtering tests that assert
  out-of-scope names never reach the provider.
- **TypeScript** (`test/unit/worker-client.test.ts`): a fake worker script exercises malformed
  output, timeout, `AbortSignal` cancellation, and missing-binary handling.
- **Orchestration** (`test/integration/orchestration.test.ts`): a deterministic `FakeRunner`
  covers persistence, idempotency, provider-failure visibility, retry-then-succeed, and
  cancelled-scan handling.

## HTTP security testing (Phase 3A)

`workers/internal/discovery/http_test.go` uses local `httptest` servers and an injectable resolver —
no public sites — to cover: basic probe, redirect chain, redirects to excluded hosts, out-of-scope
domains, loopback/private/metadata/IPv4-mapped destinations, DNS rebinding blocked at the connection
boundary, trusted vs untrusted TLS (proving no global bypass), timeout, oversized bodies,
cancellation, out-of-scope skip, and fingerprint false positives.

## URL collection and classification (Phase 4)

- Go (`workers/internal/discovery/urlcollect_test.go`, `urlclassify_test.go`) uses local `httptest`
  servers and fake provider binaries to cover crawler link discovery, depth limiting, intra-provider
  dedup, out-of-scope drop, redirect-to-private denial, DNS rebinding, cancellation, robots/sitemap
  parsing (including sitemap indexes and malformed XML), passive parsing, provider-unavailable, and
  URL canonicalization edge cases.
- Classification is measured against a small hand-labeled fixture (24 cases) with a printed
  confusion matrix; top-1 accuracy is 1.00 on that set. This is a **regression guard**, not a
  real-world precision/recall benchmark, and no such claim is made.
- Collection metrics are exposed at runtime via `reconnexus urls <scanId> --stats` (raw vs unique,
  duplicate rate, skipped candidates, method/host/classification/parameter distributions).

## JavaScript & API intelligence (Phase 5)

- Go (`workers/internal/discovery/jsanalysis_test.go`, `apispec_test.go`) uses local `httptest`
  servers to cover: JS endpoint extraction (`fetch`/`axios`/`XHR`/WebSocket/absolute+relative
  literals), dynamic template literals (retained unresolved, not fabricated), secret redaction,
  out-of-scope origin dropping, honest artifact failures (`NOT_FOUND`, `MISMATCHED_MIME`),
  oversized/adversarial input with a bounded-time assertion, source-map parse/disabled, capability
  blocking, OpenAPI 3 JSON, Swagger 2 YAML, parameter extraction, `$ref` resolution plus unresolved
  remote `$ref` counting, and out-of-scope server dropping.
- TypeScript: JS/API result contract validation, stages 07/08 orchestration + idempotency +
  multi-source provenance, and CLI + JSON envelope tests.

## Security metadata (Phase 6)

- Go (`workers/internal/discovery/securitymeta_test.go`) uses local `httptest` servers to cover:
  security-header present/absent, HSTS parsing, cookie attributes without value leakage, CORS
  wildcard+credentials inconsistency, content-type mismatch, TLS via a trusted test CA, certificate
  validity boundaries (valid/expired/not-yet-valid via a synthetic certificate), collection failure,
  out-of-scope skip, cancellation, and capability blocking.
- TypeScript: security-metadata contract, Stage 06 (categorization coverage) + Stage 10
  orchestration/idempotency/certificate correlation, and CLI filters + JSON envelope.

## Secret detection (Phase 7)

- Go (`workers/internal/discovery/secretscan_test.go`) uses local `httptest` servers and synthetic
  secrets to cover: high-confidence rule matches, entropy candidate, placeholder/config suppression,
  overlap suppression, dedup with occurrence counts, oversized artifacts, malformed/Unicode bytes,
  analysis failure, out-of-scope skip, cancellation, capability blocking, and HMAC keyed/unkeyed.
  A **release-gate test** marshals the full worker output and asserts no raw fixture value (including
  a private-key body) is present.
- TypeScript: secret-scan contract, Stage 09 orchestration + **DB-wide redaction regression**
  (scans every text column for synthetic raw markers) + idempotency, and CLI filters + JSON.

## Evidence correlation (Stage 11)

- TypeScript: correlation-record contract; Stage 11 correctness (shared keyed fingerprint
  correlates; unrelated, empty-fingerprint, and unkeyed cases do not; multi-source corroboration;
  edge endpoints), idempotency across reruns, coverage, and security regressions (no raw value, no
  fingerprint, no VALIDATED/CONFIRMED persisted anywhere); CLI state machine (not-run/failed/
  partial/complete-empty/populated) + JSON envelope.

## Reporting (Stage 12)

- TypeScript: report contract; `deriveReportStatus` for all six states; boundary redaction
  fail-closed (throwing redactor never returns the original); Stage 12 persistence + determinism +
  idempotency; a DB redaction regression (report text contains redacted snippets only, no raw marker
  or fingerprint); CLI formats (human/json/jsonl/csv) and exit codes.

## Current baseline (Stage 12)

- TypeScript suite: 33 files, 135 tests passing.
- Full pipeline stages 00–12 implemented. This is a completeness statement, **not** a
  production-readiness or accuracy claim (no labelled corpus for tracking precision/recall).
- Go suite: `scope`, `adapters`, `telemetry`, `matching`, `conformance`, `discovery` packages
  passing.
- TS/Go conformance: identical output on every fixture (domains, IPs, scope decisions, URL
  canonicalization).
- Local deterministic tests only for JS/API parsing and retrieval. Separately (not part of the
  deterministic suite) a live passive `waybackurls` run returned 18 scope-filtered URLs, a live
  `gau` run timed out and was reported `FAILED`, and the compiled worker parsed a live OpenAPI JSON
  document and a served JS artifact end-to-end.
- No throughput/latency benchmark and no precision/recall metric for JS/API extraction have been
  established; none is claimed.
