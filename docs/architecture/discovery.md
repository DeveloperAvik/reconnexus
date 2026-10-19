# Discovery Pipeline (Phase 2)

Phase 2 implements stages **01 (target intelligence)**, **02 (subdomain discovery)** and
**03 (DNS / infrastructure correlation)**; this document covers that slice of the pipeline in
detail. The pipeline has since grown well past Phase 2 — stages 04–14 (HTTP probing, URL/JS/API
intelligence, security metadata, secret detection, correlation, subdomain takeover, login/cPanel
finding and reporting) are implemented; see [implementation-plan.md](../implementation-plan.md)
for their current status and the other `docs/architecture/*.md` files for their designs. A stage
that fails or is skipped in a given run is still reported as such rather than hidden.

## Execution model

```
CLI (TS control plane)                     Go worker (reconnexus-worker)
  scan run <id>
    │
    ├─ claim job (SELECT … FOR UPDATE SKIP LOCKED semantics via lease)
    ├─ build DiscoveryJob (policy + inputs + limits)
    ├─ spawn worker (argv array, no shell) ──▶  enforce scope independently
    │                                           run provider (structured argv)
    │                                           parse + normalize output
    │◀────────── DiscoveryResult JSON ───────── validate records / coverage / status
    ├─ validate with zod (DiscoveryResultSchema)
    ├─ persist in one transaction:
    │     assets (upsert, unique canonical key)
    │     observations (append, with provenance)
    │     relationships, evidence artifact, provider_execution, coverage
    └─ set job status; retry retryable failures; reconcile scan status
```

A job is persisted (created) before it is executed. Provider execution happens **outside** the
persistence transaction; the results are written in a single transaction together with the job
status, so a crash either loses the provider call (re-run safely) or commits everything
(idempotent on re-delivery).

## Stages

| Stage | Provider(s) (default) | Network | Notes |
| --- | --- | --- | --- |
| 01 target-intelligence | control-plane | none | Records the root domain asset and target observation. |
| 02 subdomain-discovery | subfinder, assetfinder (amass optional) | PASSIVE | Passive only by default. Discovered hosts are recorded, never auto-authorized. |
| 03 dns-infra | builtin-dns (dnsx optional), rdap | ACTIVE (DNS) / PASSIVE (RDAP) | Resolves in-scope hosts; correlates IP → CIDR → ASN where evidence exists. |

A **mock** provider (fixture-driven) and an **offline-ipmeta** provider exist for deterministic
tests; they never perform network I/O.

## Scope enforcement (worker-side)

The Go worker re-checks scope independently of the control plane before any provider runs:

- SUBDOMAINS: the root domain must be authorized for the provider's capability.
- DNS: every name to resolve must pass a `DNS` scope check; out-of-scope names are skipped and
  counted (`coverage.skipped`).
- IP_METADATA: an address is only correlated when the **in-scope** host it was discovered through
  passes a `PASSIVE` scope check.

Discovered hosts/IPs are recorded as *discovered* — never as authorized active targets. The DNS
stage is the only place discovered hosts are actively contacted, and only after an independent
scope check on each name.

## Status semantics

The scan status is reconciled from actual job outcomes, never from a provider exit code alone:

- `SUCCEEDED` — every job succeeded.
- `PARTIAL` — some results collected, but stages failed/skipped (the normal Phase 2 outcome,
  because 04–12 are unimplemented).
- `FAILED` — all executed stages failed.
- `CANCELLED` — the scan was cancelled.

Provider outcomes are recorded per `(scan, stage, provider)` in `job_provider_outcomes` and surface
in `reconnexus coverage <scanId>` with counts of succeeded / partial / failed / unavailable /
skipped / blocked providers.

## Coverage

Each stage writes a `coverage_records` row (`COLLECTED` / `PARTIAL` / `MISSING` / `NOT_ATTEMPTED`
/ `BLOCKED`) with `expected`/`collected` provider counts and a per-provider `details` JSON blob.
A stage that produced nothing because a provider was unavailable is `MISSING`, never `COLLECTED`.

## HTTP probing and fingerprinting (Phase 3A, stage 04)

Stage 04 consumes the discovered hosts that were **resolved in the DNS stage** and remain in the
authorized registrable domain, then probes `https://host/` and `http://host/` (bounded count). Each
host is reauthorized inside the worker; unresolved hosts are not probed.

The `builtin-http` provider:

- emits an `HTTP_OBSERVATION` per target (status, final URL, redirect chain, content type, title,
  selected headers, TLS metadata, outcome/failure reason);
- enforces scope at the connection boundary and on every redirect hop (see
  [threat-model/scope-enforcement.md](../threat-model/scope-enforcement.md));
- runs evidence-backed fingerprinting over the response and emits `TECHNOLOGY` records.

Ingestion maps these to `SERVICE` (per origin), `TECHNOLOGY`, and `CERTIFICATE` assets, with
`http`/`technology`/`tls` observations, `serves`/`runs`/`presents_certificate` relationships, and
the worker output stored as evidence linked to each observation. Probing is best-effort per target:
one host failing does not discard the others, and the stage is `PARTIAL` when some probes fail.

## URL collection (Phase 4, stage 05)

Stage 05 discovers URLs by active crawl (`builtin-crawler`, connection-bound), static discovery
(`builtin-static`: robots.txt + sitemaps), and passive archives (`gau`, `waybackurls`), then
canonicalizes, deduplicates (preserving per-provider provenance) and classifies them. See
[url-intelligence.md](url-intelligence.md) for the normalization rules, category/parameter model and
measurement. Every discovered URL is re-checked against the scope policy before persistence.

## JavaScript & API intelligence (Phase 5, stages 07 & 08)

Stage 07 retrieves and statically analyses JavaScript artifacts (with source maps); stage 08 parses
OpenAPI/Swagger specifications (JSON and YAML) and extracts documented endpoints and parameters.
Both use the connection-bound transport, scope-check extracted endpoint origins, and persist
method-aware `API_ENDPOINT` assets with provenance. See
[js-api-intelligence.md](js-api-intelligence.md).

## Secret detection (Phase 7, stage 09)

Stage 09 re-collects eligible JS artifacts and API specifications in-memory and scans them for
potential secrets, persisting only redacted findings (line-scoped snippet) and keyed HMAC
fingerprints. Raw values and raw artifact bodies are never retained. See
[secret-detection.md](secret-detection.md).

## Infrastructure correlation

RDAP IP lookups yield a network prefix, registry name and country when present; the ASN is only
recorded if the response actually contains it (RDAP IP responses generally do not, which is stated
as a limitation). Correlation never scans a CIDR and never infers that every host in a prefix
belongs to the target organization.

## Stage retry policy

Retries are decided per stage but executed per provider. After each attempt, a stage is retried
(bounded exponential backoff, at most `--max-attempts`, default 3) when **at least one provider
ended `FAILED`**, whatever the stage aggregate is (`FAILED`, or `PARTIAL` because a sibling
succeeded). Only the failed providers run again:

| Provider outcome | Retried? | On a retry of the stage |
| --- | --- | --- |
| `FAILED` | yes | executed again |
| `SUCCEEDED`, `PARTIAL` | no | persisted result reused (no re-run, no duplicate observations) |
| `SOURCE_UNAVAILABLE` | no | not re-run during this stage run (a later explicit `resume` re-evaluates it) |
| `SKIPPED`, `BLOCKED` | no | not re-run |
| `CANCELLED` | no | cancellation is checked before every attempt and ends the stage |

When attempts are exhausted the stage keeps its honest aggregate: `PARTIAL` if any provider
produced data, `FAILED` otherwise; failed providers stay recorded as `FAILED` in the persisted
provider outcomes. A stage with no providers (internal stages) is not retried.
