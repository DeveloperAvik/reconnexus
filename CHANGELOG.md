# Changelog

All notable changes are documented here. This project distinguishes implemented functionality from
planned functionality; entries only describe what is actually implemented and tested.


## [Unreleased]

### Fixed

- **Restricted-address scope policy (P2-1):** an explicit `inScope.ips`/`cidrs` entry no longer
  bypasses the `INTERNAL_NETWORK` capability and restricted-address override. Restricted classes now
  require the entry, the capability and the override together (as documented), and the override no
  longer opens unlisted restricted space. Documentation ranges remain allowed by explicit entry
  alone. Applied identically in the TypeScript and Go engines; conformance fixtures extended.
  **Behavior change:** policies relying on a bare `127.0.0.1`/private entry now need
  `INTERNAL_NETWORK` plus `--allow-restricted`.

## [0.20.0] — Admin login & cPanel finder

### Added

- **Stage `14-login-finder`** (`builtin-login-finder`, capability `ACTIVE_HTTP`): probes a fixed,
  bounded set of administrative login paths and cPanel/WHM/webmail paths and ports on origins
  observed during HTTP probing. Read-only: unauthenticated GET only, no credentials submitted.
- **`LOGIN_INTERFACE` record** with `kind` (`ADMIN`/`CPANEL`), status (`DETECTED`/`POSSIBLE`),
  confidence, HTTP status, final URL, title and redacted evidence. Persisted as `login-interface`
  observations on `URL` assets.
- **`admin <scanId>`** and **`cpanel <scanId>`** CLI commands with `--status`, `--host`,
  `--confidence` and `--limit` filters, plus `--login-providers` on `scan run`/`resume`.
- Scope and safety: every candidate URL is reauthorized (including path exclusions), the shared
  rate limiter paces requests, and redirects use the connection-bound transport with per-hop
  reauthorization. Speculative control-panel ports that refuse connections are counted as skipped.

### Fixed

- **Early-return worker results now satisfy the discovery contract.** Unknown providers, blocked
  capabilities and all-out-of-scope inputs returned `execution.argv: null`, so the control plane
  rejected the entire result with a schema error and hid the real reason. All return paths now
  normalize array fields.
- **Missing `robots.txt`/`sitemap.xml` is no longer a provider failure.** `builtin-static` treats
  4xx responses (typically 404) as not-found coverage, so a normal absence no longer makes the
  URL-collection stage `PARTIAL`.
- Rebuild the worker after updating: `make worker-build`.

### Tests

- Go: admin and cPanel detection, generic-page rejection, path-exclusion enforcement, early-return
  contract shape, and 404 robots/sitemap handling.
- TypeScript: record contract and DB-backed stage/CLI integration (skipped when Postgres is not
  available).

## [0.19.2] — Enforce request rate, track fixtures, fix CVE over-match

### Fixed

- **`limits.requestsPerSecond` is now enforced by every active provider.** Only RDAP paced its
  lookups before; the HTTP probe, crawler, JS, API-spec, security-metadata, secret-scan and takeover
  providers were bounded only by concurrency, so the authorized request rate could be exceeded. A
  shared, non-bursting `rateLimiter` (`workers/internal/discovery/ratelimit.go`) now paces all
  outgoing requests via `doRequest(...)`, carrying the policy rate through `ProviderContext`.
- **NVD CVE ranges are filtered to the queried product.** A single CVE can list `cpeMatch` entries
  for several products; the engine evaluated all of them, so a multi-product CVE could produce a
  candidate for an unrelated component. Ranges are now restricted to the queried `vendor:product`
  (CPE 2.3 and URI bindings both parsed).

### Added

- **Test fixtures are tracked.** The `test/fixtures/*` rule was removed from `.gitignore`, so the
  conformance fixtures and secret-detection evaluation corpus are versioned and a clean checkout can
  run the full suite.
- **CI workflow** (`.github/workflows/ci.yml`): TypeScript type check, tests and scope conformance
  against a live Postgres service, plus a separate Go job (`build`, `vet`, `test`).

### Tests

- Go: rate-limiter pacing / nil-unlimited / cancellation. TypeScript: NVD multi-product CVE keeps
  only the queried product's range; CPE binding parsing. Totals: TypeScript 265 tests across 56
  files; Go all packages; typecheck clean.

## [0.19.1] — Reduce subdomain-takeover and JS secret false positives

### Fixed

- **Subdomain takeover: a matching HTTP status alone is no longer a candidate.** A plain 404/403 on a
  CNAME to a shared service (CloudFront, Traffic Manager, Statuspage, …) was reported `CANDIDATE`
  because the status matched, even with no service-specific unclaimed marker — the main
  false-positive source. Status-only responses are now `INCONCLUSIVE` (`evidenceType: STATUS_ONLY`).
  Only a service-specific unclaimed marker raises `SUSPECTED`.
- **Generic takeover markers removed.** "bad request", "not found", "page not found", "doesn't
  exist" and similar strings appear on ordinary error pages; they were dropped from the fingerprint
  set so a claimed resource is not flagged.
- **Non-actionable takeovers are no longer findings.** `NOT_VULNERABLE` and `INCONCLUSIVE` takeover
  records stay in the `takeoverCandidates` inventory but are excluded from the report's findings, so
  "not vulnerable" no longer inflates the finding count.
- **JS secret detection: weak assignment rules now require entropy.** `password-assignment`,
  `bearer-token`, `oauth-client-secret`, `webhook-signing-secret` and `jwt-token` require Shannon
  entropy ≥ 3.5, dropping config/UI values (`password = 'required'`, repeated characters) that
  produced false positives in minified JavaScript. Placeholder suppression still runs first so
  suppressed values remain observable.
- **Twilio API key requires context.** The bare `SK` + 32-hex pattern matched hashes and generated
  ids; it now requires a nearby `twilio`/`account_sid`/`auth_token`/`api_key` token.

### Tests

- Go: status-only → `INCONCLUSIVE`; generic markers no longer suspected; benign-value secret
  non-detection; Twilio context requirement; expanded evaluation corpus with bare-`SK`,
  low-entropy-password and repeated-bearer negatives.
- TypeScript: `buildFindings` excludes non-actionable takeovers.
- Totals: TypeScript 263 tests across 56 files; Go all packages; typecheck clean.

## [0.19.0] — Phase 2 deep audit: script-reference discovery, CVE-intel fix, failure injection

### Added

- **HTML `<script src>` reference discovery.** The crawler now extracts script references from
  in-scope HTML documents (resolving relative, root-relative, protocol-relative and query-bearing
  URLs against the *effective* post-redirect document URL), marks them `scriptRef` with the parent
  document URL, and feeds extensionless JavaScript (bundler output such as `/assets/bundle`) into
  Stage 07. Inline script text is never treated as a URL; non-script assets referenced from a script
  tag are not relabelled. Script/static URLs are recorded in the inventory but no longer consume the
  crawl request budget. New `UrlObservationRecord` fields `scriptRef`/`parentUrl`.
- **Conservative security-metadata finding.** A single, strictly-gated rule: an HTTPS response that
  sets a cookie without the `Secure` attribute yields a LOW/`SUSPECTED` candidate scoped to that
  endpoint. Missing headers and CORS wildcards deliberately remain inventory.
- **Benchmarks** for the new Go script-reference scan (`BenchmarkExtractScriptRefs`).

### Fixed

- **CVE intelligence silently dropped ambiguous products.** An ambiguous product mapping (multiple
  plausible CPEs) has no CPE to query, so a source that returns no advisories (e.g. the NVD path)
  never produced a match entry — the ambiguity disappeared and implied the product was clean.
  Ambiguous products are now surfaced in `coverage.ambiguousProducts`, counted as `NEEDS_APPLICABILITY_REVIEW`,
  and called out in the limitations.

### Tests

- Go: script-reference resolution/filtering, crawler provenance + dedup + off-scope skip + inline
  rejection, effective-URL resolution across redirects; HTTP redirect-loop bound; partial-output-
  then-nonzero-exit is FAILED and not partially ingested; IPv6 restricted-address scope denials.
- TypeScript: script-ref → Stage 07 selection; comparison determinism, failed-current-scan and
  missing-coverage handling; CVE ambiguity regression; report finalization idempotency +
  stale-coverage; insecure-cookie finding false-positive/negative guards.
- Totals: TypeScript 262 tests across 56 files; Go all packages; typecheck clean.

## [0.18.0] — Assessment-status, endpoint-accounting and JS-classification correctness

### Fixed

- **Report status no longer contradicts the findings section.** `buildReport` passed
  `secretFindings + correlations + actionableTakeovers` to `deriveReportStatus`, while the findings
  section and `findingTotals` were derived from `buildFindings`. A scan with correlations but no
  findings (observed: `COMPLETE_WITH_FINDINGS`, "0 candidate findings", body text "assessment is
  incomplete") is now `COMPLETE_NO_FINDINGS` and renders consistently in human/JSON/HTML.
- **Provider `PARTIAL` outcomes now propagate to the stage, coverage and scan status.**
  `aggregate()` returned `SUCCEEDED` whenever no provider had hard-failed, so a lone `PARTIAL`
  provider (or a mix of `SUCCEEDED` + `PARTIAL`) was masked. It now returns `PARTIAL`, so a stage
  whose provider only partially completed is never reported `SUCCEEDED` and the assessment is not
  `SUCCEEDED`.
- **Non-script assets are never fed to JavaScript analysis.** Stage 07 selected URLs classified
  `STATIC_ASSET` (images, CSS, fonts, video) as well as `JAVASCRIPT`, which made the worker fetch and
  "analyse" a WordPress `.jpg`. Selection is now `JAVASCRIPT`/script-extension only, and the worker
  independently rejects HTML and binary/asset content types (with magic-byte sniffing) as
  `SKIPPED`, recording the classification rationale instead of parsing binary data.

### Added

- **API endpoint reconciliation.** `listApiEndpoints` now returns distinct `method origin path`
  identities (a documented observation is preferred for the shared row), and the report exposes
  `reconciliation` (`raw observations → distinct endpoints → rows shown`, plus per-source and
  per-provider breakdowns). This explains the observed "942 API endpoints vs 9 provider records"
  gap: the card counted every `api-endpoint` observation across the JS and API-spec stages, while
  the provider count was per-provider per-stage.
- **Zero-result diagnostics for external providers.** A successful run that parses zero records now
  records why ("no output" vs "output present but did not parse") without changing the
  `SUCCEEDED` status, so an empty result is distinguishable from a failure.

### Tests

- New: `test/unit/orchestrator-aggregate.test.ts`, `test/integration/provider-partial.test.ts`,
  `test/integration/report-status-consistency.test.ts`,
  `test/integration/api-endpoint-reconciliation.test.ts`, and the Go
  `TestJsAnalysisRejectsNonScriptContent`. TypeScript: 247 tests across 52 files; Go: all packages.

## [0.17.0] — Vulnerability intelligence: technology → CVE candidates

### Added

- **CVE-intelligence module** (`apps/control-plane/src/intelligence/`): deterministic version parsing
  and range evaluation (`version.ts`), technology→product/version normalization with CPE mapping
  (`products.ts`), injectable sources (`source.ts`) and the correlation engine (`engine.ts`).
- **`vulns <scanId>`** CLI: correlates the scan's observed technologies with CVE advisories and prints
  a human or `json` report. Sources: `--advisories <file.json>` (offline local database) or
  `--online` (NVD 2.0 API, optional `NVD_API_KEY`), with `--kev <file>` to mark CISA KEV membership.
  Filters `--product` and `--state`.
- **Applicability states** — `MATCH_CANDIDATE`, `NEEDS_VERSION_CONFIRMATION`,
  `NEEDS_APPLICABILITY_REVIEW`, `VALIDATED`, `NOT_APPLICABLE`, `INCONCLUSIVE`, `SOURCE_UNAVAILABLE` —
  each with one meaning and never silently converted. **`VALIDATED` is never set automatically.**
- **Version certainty** — `EXACT` / `INFERRED` / `RANGE` / `UNKNOWN`, computed from persisted
  technology evidence; conflicting banners become a bounded `RANGE`.
- **Graceful source handling** — a TTL cache (`CachingVulnerabilitySource`) serves a stale entry,
  clearly flagged, when the upstream fails; a hard outage yields `SOURCE_UNAVAILABLE`, never a false
  negative. Sources, freshness and unmatched products are surfaced in coverage and limitations.

### Design

- CPE mapping is conservative: an ambiguous product (multiple plausible CPEs) is reported as
  `NEEDS_APPLICABILITY_REVIEW`, an unmapped product is listed as unmatched — never guessed.
- Affected ranges come from the source (NVD `versionStart/End`), evaluated with correct version
  ordering; a vendor backport note forces applicability review.
- Evidence is version-accurate: a host whose banner carried no version is **not** cited as a matched
  host.
- No schema migration and nothing persisted: the report is computed on demand from existing
  technology observations.

### Tests

- TypeScript: 238 tests across 48 files. New: `test/unit/vuln-version.test.ts` (ordering, ranges,
  wildcards, unparseable input), `test/unit/vuln-intel.test.ts` (12 engine scenarios incl.
  out-of-range, ambiguity, conflicting banners, backport, KEV, dedup, missing version, persistence
  round-trip) and `test/unit/vuln-source.test.ts` (NVD parsing with a mocked `fetch`, retry on 429,
  timeout→`SOURCE_UNAVAILABLE`, KEV parsing, cache TTL and stale-on-error).

### Docs

- `docs/architecture/vulnerability-intelligence.md`; README capability table + quick start.

## [0.16.0] — Professional, easier-to-read HTML report

### Improved

- **Headline verdict panel.** The executive summary now leads with a colour-coded verdict
  (`verdict-clean` / `-findings` / `-warn` / `-bad`) and a plain-language one-line conclusion
  ("Assessment complete — N candidate findings", "Assessment partial — results are incomplete",
  …) so the outcome is readable at a glance.
- **Prominent coverage warning.** When the assessment did not complete every stage, a highlighted
  banner states that absence of a result is not evidence of absence, instead of burying it in a note.
- **Header and table of contents.** The document opens with the target as the title, report/analysis
  status badges and generation time, followed by a bordered contents panel (§1–§9) with live counts
  for Findings and Errors. Sections are auto-numbered via CSS counters.
- **Reading legend.** The "How to read this report" section now includes a legend of outcome badges
  and severity badges, plus the existing limitations.
- **Scope section intro** explaining what the section establishes.

### Unchanged (safety invariants preserved)

- Still a single self-contained document: no `<script>`, no external references, no inline event
  handlers, and **no inline styles** except the confidence-bar width. Every model value is escaped;
  URLs remain text, never `href`. The 19-report safety suite (`test/unit/report-html.test.ts`) passes
  unchanged.

## [0.15.0] — Reliable scan-to-scan change intelligence (Phase E)

### Added

- **`changes <baselineScanId> <currentScanId>`** — read-only, evidence-backed comparison across
  `assets`, `dns`, `http`, `tls`, `technology`, `api`, `js` and `findings` records, with filters
  (`--category`, `--status`) and a per-category `--limit` (totals stay exact). Outputs `human`,
  `json` (full structured model) and a self-contained `html` report. The engine is
  `apps/control-plane/src/comparison/engine.ts`; the CLI is `apps/cli/src/commands/changes.ts`.
- **Explicit comparison outcomes** `ADDED | REMOVED | CHANGED | UNCHANGED | UNKNOWN`. A verdict is
  only `REMOVED`/`CHANGED` when the stage that produces the category was fully `COLLECTED` in **both**
  scans; otherwise the item is `UNKNOWN` with the reason and the category reports a `COVERAGE_GAP`
  limitation. A skipped/failed/partial/blocked stage is therefore never treated as absence.
- **`Repository.listScanObservations(scanId, { kinds?, kindPrefix? })`** — the read-only, indexed
  query that backs the engine (assets are project-scoped, so "seen in a scan" means the subject of an
  observation with that `scan_id`). No migration: the existing `observations`/`coverage_records`
  schema fully supports the comparison.

### Correctness

- Comparison categories use stable, per-kind identities (DNS by name+record type, HTTP by service
  origin, TLS by certificate hash, API by method+origin+path, JS by URL, findings by
  rule/artifact/location/fingerprint or host+CNAME). Duplicate observations are collapsed
  deterministically (latest `observed_at`, then a stable tie-break). Output ordering is
  deterministic (outcome group, then key). Provenance (`source`, `observed_at`) is preserved on both
  sides. The engine performs no network requests and writes nothing.

### Tests

- TypeScript: 212 tests across 45 files. New: `test/unit/comparison-engine.test.ts` (10 scenarios:
  coverage-gated removal, DNS change vs DNS failure, HTTP/TLS change, JS hash + API route change,
  finding resolution/regression, dedup, `--limit`, missing/cross-project, filtering),
  `test/unit/changes-cli.test.ts` (HTML escaping + human rendering) and
  `test/integration/changes.test.ts` (two real scans: DNS value change, unchanged asset).

### Docs

- `README.md` (capability table + quick start) and `docs/architecture/comparison.md` added.

## [0.14.0] — Professional CLI console and HTML reporting

### Added

- **Live assessment console.** `scan run`/`scan start --run` now draw a per-stage console on stderr
  (`apps/cli/src/render/live.ts`): a header (target, status, scan id, profile, elapsed, stages
  finished/planned), one row per stage (status, duration, retries, per-provider records), a record
  counter by type, and recent notices. It consumes the orchestrator's real event stream — no number
  is invented: an unmeasured stage shows `pending`/`—`, never `0`, and there is no fake overall
  percentage (only "stages finished / stages planned"). On a non-TTY (or `--json`) it degrades to
  timestamped one-line structured events; the frame is redrawn on a timer the caller owns, so a slow
  terminal can never delay a stage.
- **Self-contained `html` report format.** `reconnexus report <scanId> --format html`, rendered from
  the same canonical redacted model as `human`/`json`/`jsonl`/`csv` (`apps/control-plane/src/reporting/`).
  Single file, inline CSS, no scripts, no external references (no `<link>`, `@import`, `src` or remote
  `url()`); responsive and print-friendly. Every interpolated value goes through `esc()`, so a
  hostile hostname/title/evidence fragment renders as text, not markup; the only `href`s are
  in-document anchors. Redaction is applied upstream and fails closed, so the HTML cannot re-introduce
  a secret.
- **`report --out <path>`** writes any format to a file (mode `0600`) instead of stdout, and
  **`--max-rows <n>`** bounds rows per inventory section while totals stay exact.
- **`assets diff <baselineScanId> <currentScanId>`** — read-only comparison of the assets observed
  in two scans of the same project (`--type`, `--limit`), reporting added / removed / unchanged by
  asset identity (type + canonical key) with deterministic ordering. It is explicitly an
  observation-set comparison: a stage skipped in either scan is not treated as evidence of absence.
  Backed by `Repository.listScanAssets(scanId, types?)` (assets are project-scoped, so "observed in
  a scan" means the subject of an observation with that `scan_id`).

### Fixed

- **Provider-execution persistence (High):** `recordProviderExecution` reused the Postgres parameter
  `$16` both as the integer `duration_ms` column and inside a text concatenation
  (`$16 || ' milliseconds'`), so Postgres rejected the insert with *"inconsistent types deduced for
  parameter $16"*. Every DB-backed stage failed to persist provider executions, which failed the
  orchestration, reporting and per-stage integration suites. The interval expression now uses its own
  parameter.
- **Console truncation (Low):** the live frame truncated rows by raw string length, which could cut an
  ANSI escape sequence in half and garble the terminal. Added `truncateVisible` (visible-width aware,
  copies escapes whole, closes colour with a reset) and used it for every truncated frame line.
- **Subdomain-takeover record contract (High):** the Go worker serialized `TAKEOVER_CANDIDATE`
  records nested under a `takeover` object, while the TypeScript contract and the ingest path expect
  the takeover fields flat on the record. Every stage-13 run failed with *"worker output failed
  schema validation"* and the whole stage was recorded `FAILED`. `flatPayloads()` now flattens the
  takeover payload like the other stage payloads. The drift was invisible because `SampleRecords()`
  omitted the takeover record, so the cross-language record-shape check never saw it — the sample was
  added, which is what now guards this shape.

### Tests

- TypeScript: 197 tests across 41 files (adds HTML-report safety suite — escaping, no `<script>`/
  event handlers, `javascript:` rendered as text, self-containment, redaction fail-through — and a
  `truncateVisible` escape-safety test).
- Go: the record-shape conformance sample set now includes `TAKEOVER_CANDIDATE`, so a future Go↔TS
  field drift in the takeover record fails conformance instead of a live scan.

### Docs

- `README.md` and `docs/architecture/reporting.md` updated: HTML export and the live console are now
  documented as implemented.

## [0.13.0] — Subdomain-takeover detection (new stage 13)

### Added

- **New capability `TAKEOVER_CHECK`** and **new stage `13-subdomain-takeover`**, placed after
  correlation and before reporting so reports include its findings.
- **`builtin-takeover` provider** — non-destructive, candidate-only detection: resolve the CNAME,
  match a maintained set of takeover-prone services (GitHub Pages, Heroku, Amazon S3/CloudFront,
  Azure, Fastly, Netlify, Vercel, Surge, Pantheon, Read the Docs, Shopify, Tumblr, Zendesk, Ghost,
  UserVoice, Statuspage, WordPress.com), then a single bounded HTTP GET for the service's
  "unclaimed" marker. Statuses: `SUSPECTED`, `CANDIDATE`, `NOT_VULNERABLE`, `INCONCLUSIVE`.
- **`TAKEOVER_CANDIDATE`** discovery record with host/CNAME/service/status/confidence/HTTP-status and
  redacted evidence; persisted as `takeover-candidate` observations.
- **CLI `takeover <scanId>`** with `--status`/`--service`/`--host`/`--limit`; reports gain a
  `takeoverCandidates` section (human/json/jsonl/csv).
- **Migration `0004_takeover`** extends the `authorization_records` capability constraint with
  `TAKEOVER_CHECK` (constraint-only; no data altered).

### Fixed

- **DAG ordering (High):** the orchestrator iterated jobs by lexicographic `job_key`, so
  `12-reporting` ran before `13-subdomain-takeover`, blocking it. It now iterates in `OrderedStages`
  order; the report stage's stage list is ordered the same way.

### Tests

- Go: suspected (marker), candidate (status-only), not-vulnerable, inconclusive (fetch failure),
  no-CNAME/unknown-service ignored, out-of-scope skip, capability blocking, cancellation (using a
  TLS mock server and an injectable resolver).
- TypeScript: takeover record contract; stage 13 orchestration + report inclusion + CLI filters;
  156 TS tests across 39 files.

### Safety

Candidate-only and non-destructive: DNS read + one GET, no claim/registration, no exploitability
claim, connection-bound + scope-enforced. See `docs/architecture/subdomain-takeover.md`.

## [0.12.0] — API specification discovery & operator output

### Added

- **Stage 08 now discovers specifications instead of waiting to be handed one.** Previously the
  stage only parsed specification URLs that crawling had already found, so a target that
  references no `openapi.json` anywhere skipped the stage entirely — even when stage 07 had
  already proved, from JavaScript, which origins serve an API. The stage now also checks a fixed
  set of well-known paths (`/openapi.json`, `/openapi.yaml`, `/swagger.json`,
  `/swagger/v1/swagger.json`, `/v3/api-docs`, `/api-docs`, `/api/openapi.json`,
  `/.well-known/openapi.json`) on origins ranked by the evidence that an API lives there:
  origins with endpoints discovered in JavaScript first, then API-shaped hostnames, then the
  authorized root origins. Capped at 25 origins and 200 requests so a wide subdomain enumeration
  cannot turn the stage into a sweep, deterministically ordered, and skipped entirely when the
  policy does not authorize `API_DISCOVERY`.
- **`inputs.specProbeUrls`** separates speculative paths from referenced ones in the discovery
  contract. A referenced specification URL that turns out to be absent is still recorded —
  something pointed at it, so its absence is evidence. A speculative path that holds nothing is
  recorded as coverage only and never becomes an asset or an observation.

### Changed

- **"Is this actually a specification?" is now decided explicitly.** Real origins answer an
  unknown path with their single-page-app shell or a config blob rather than a 404, which the
  parser previously reported as `MALFORMED` — 47 bogus `API_SPEC` records in one trial run. A
  response is treated as a specification only when it decodes and declares `openapi`, `swagger`,
  or a non-empty `paths` mapping; HTML and non-specification JSON are now `NOT_FOUND`, and only a
  document served as JSON/YAML can be called malformed.
- **Specification coverage is counted honestly.** A path that answers 404/405/410 — or serves
  something that is plainly not a specification — is a *completed* check, not a collection
  failure. An origin that refuses to answer (401/403/5xx) costs no coverage on a speculative path,
  because nothing referenced it; on a referenced URL it is still a failure.
- **Redesigned human output for `scan start`/`run`/`resume`/`list`/`status`.** One aligned line
  per stage as it finishes, with a status glyph, elapsed time, and each provider's record count
  (`✓ 02 subdomain discovery  6.4s · subfinder 894 · assetfinder 59`); on a terminal the running
  stage shows on a transient line that its result overwrites. The closing block gives the verdict,
  what was persisted, and a section naming every stage that did not fully succeed with its reason,
  instead of repeating the stage list. `--json` output is unchanged.
- **Per-provider `info` log lines are suppressed while progress is rendered**, since the progress
  stream now carries the same information more legibly. Warnings and errors still reach the log,
  and `--log-level debug` keeps everything.

### Tests

- `test/unit/cli-output.test.ts`: duration and count formatting, colour-aware column alignment,
  and a distinct symbol plus readable label for every status the CLI can show.
- `workers/internal/discovery/apispec_test.go`: a probe sweep over a found specification, an SPA
  shell, non-specification JSON, a 404 and a 403 — asserting that only the real specification
  becomes a record and that coverage distinguishes absent from undetermined.
- `test/integration/js-api-stage.test.ts`: stage 08 probes well-known paths on an origin whose
  endpoints came from JavaScript, records the probe count in coverage, and creates no asset for a
  path that holds nothing.

## [0.11.1] — Worker/contract parity fixes

### Fixed

- **Flat record payloads (Critical).** The Go worker emitted `JS_ARTIFACT`, `SOURCE_MAP`,
  `API_SPEC`, `API_ENDPOINT`, `SECURITY_METADATA`, `SECRET_CANDIDATE` and
  `SECRET_SCAN_ARTIFACT` with their fields nested under a payload object (`artifact`,
  `sourceMap`, …), while `DiscoveryRecordSchema` and the ingestion boundary both expect them
  flat on the record. Every such record failed schema validation, so the control plane
  discarded the whole provider run: **stage 07 (js-intelligence) failed outright** and took
  08/09 down with it (no artifacts to feed them). `Record.MarshalJSON` now flattens those
  payloads; `http` and `technology` stay nested, as the contract declares.
- **Nil slices emitted as `null` (Critical).** Go marshals a nil slice or map as `null`, which
  the contract rejects for a field declared as an array or an object. An HTTP probe that errored
  before reading a header produced `"headers": null`, and every probe produced
  `"redirectChain": null`, so **stage 04 (http-probe) failed for all 500 targets** — and with no
  HTTP observations persisted, stage 10 had no services to check. Records are now normalized
  before they are emitted (`NormalizeRecords`). Both this and the nesting failure above were
  classified as retryable, so each stage re-ran its full target list twice before giving up.
- **RDAP responses could not be parsed (High).** The `cidr0_cidrs` struct declared `v4prefix` as
  an array of objects; RFC 8977 defines it as a string alongside `length`. Every lookup failed
  with `rdap response was not valid JSON`, failing the `rdap` provider and leaving stage 03
  PARTIAL. The struct now matches the RFC, and the parse error is reported instead of an opaque
  "not valid JSON".
- **RDAP lookups throttled themselves out of coverage (Medium).** The provider issued one request
  per discovered address as fast as the loop ran, so a public registry answered most of them with
  `429` and the stage lost more than half its coverage. Requests are now paced (never faster than
  2/s, slower when the policy's request budget is lower) and a throttled lookup is retried once,
  honoring `Retry-After` up to 10s.
- **Fabricated RDAP prefixes (High).** When a prefix could not be read from the response, the
  provider inferred one from the start address by assuming `/24` (IPv4) or `/48` (IPv6) — an
  invented network boundary presented as registry data. The registered CIDR is now taken from
  `cidr0_cidrs`; an unstated prefix is reported as a limitation instead.
- **NXDOMAIN counted as a DNS collection failure (Medium).** A name that does not exist is an
  authoritative answer, not an uncovered unit of work, but `builtin-dns` counted it as
  `coverage.failed`. Any host list containing a single non-resolving name (i.e. every real
  subdomain enumeration) forced stage 03 to PARTIAL and understated coverage. NXDOMAIN — on both
  forward and PTR lookups — now counts as succeeded; timeouts and resolver errors still count as
  failures.

### Tests

- `test/conformance/record-shape.test.ts`: marshals one record of **every** record type through
  the real Go worker (`cmd/record-samples`) and validates it against `DiscoveryRecordSchema`.
  The rest of the suite drives the orchestrator with an in-process runner that already speaks the
  TypeScript shape, which is why this class of drift was invisible.
- `workers/internal/discovery/samples_test.go`: every record type is covered by a sample, a
  normalized record contains no `null`, and no payload is left nested.
- `workers/internal/discovery/rdap_test.go`: prefix extraction (families, bounds, malformed
  entries), `Retry-After` parsing (delay-seconds, HTTP-date, bounds), and an end-to-end lookup
  against a throttling RDAP server.

## [0.11.0] — Usability improvements

### Added

- **`reconnexus init`** — scaffolds `reconnexus.config.json` and a starter scope policy
  (`policies/<domain>.json`). Non-interactive via flags (`--domain`, `--authorized-by`,
  `--reference`, `--out`, `--force`); prompts on a TTY when flags are omitted. Never overwrites
  existing files unless `--force`.
- **`scan start <url> --run`** — authorize and run in a single command.
- **`scan list`** — list recent scans with status and target.
- **Policy auto-discovery** — `--policy` is optional when `defaultPolicyFile` is set or exactly one
  policy exists under `policies/`; multiple candidates produce an actionable error.
- **Live progress** during `scan run`/`resume` in human mode (stage start/end to stderr); fully
  suppressed in `--json` mode.
- **Colorized output** with `--color auto|always|never` and `NO_COLOR` support (auto-disabled when
  not a TTY); scan/job status labels are colour-coded.

### Changed

- Running `reconnexus` with no arguments now prints help and exits `0` (previously a usage error),
  and the help text includes a "Getting started" block with copy-pasteable commands.
- `scope check`/`scan start` errors for a missing policy now suggest `reconnexus init ...`.

### Tests

- `test/unit/init.test.ts`: policy/config scaffolding, discovery, non-clobbering, and multi-policy
  ambiguity (143 TS tests across 35 files).

## [0.10.0] — Phase 8: Release hardening & security assurance

### Fixed

- **TS/Go URL-canonicalization parity (High).** The TypeScript engine (WHATWG URL) resolves
  percent-encoded dot-segments (`%2e`, `%2E`) during normalization, while the Go engine did not.
  `http://h/%2e%2e/x` canonicalized to `/x` in TypeScript but `/%2e%2e/x` in Go, a divergence that
  also affected **path-exclusion scope checks** (a request to an encoded `/logout` could slip past a
  Go exclusion). Go now implements WHATWG dot-segment rules; the Go **scope engine** normalizes URL
  paths with the same resolver. Locked by new canonicalization and scope-exclusion conformance
  fixtures.
- **AWS-secret rule** tightened to a realistic form (`aws_secret_access_key = '...'`).

### Hardened

- **Persisted provider diagnostics are re-redacted** at the ingestion boundary (`stderr_excerpt`),
  so a parser error that echoes content can never persist a raw value.
- **CSV exports neutralise spreadsheet formula injection** (`=`, `+`, `-`, `@`, tab, CR are prefixed)
  in addition to RFC-4180 quoting.
- **`providers matrix`** emits a machine-readable provider compatibility matrix.

### Added (tests, benchmarks, evaluation)

- Expanded the shared conformance corpus with adversarial encoded-path canonicalization and
  scope-exclusion cases.
- Failure-injection suite (`test/security/failure-injection.test.ts`): database unreachable,
  transaction rollback (deterministic marker), and cancellation.
- CSV escaping/injection unit tests.
- Go benchmark (`BenchmarkCanonicalURL`, `BenchmarkNormalizePath`) and a TypeScript benchmark
  harness (`test/benchmark/run.ts`); baselines recorded in `docs/testing/benchmarks.md`.
- Labeled synthetic secret-detection evaluation corpus (`test/fixtures/eval/secrets.json`, 24 cases)
  with a precision/recall/F1 test reported in `docs/testing/evaluation-corpus.md`.

### Docs

- New: `docs/operations/provider-compatibility.md`, `docs/testing/benchmarks.md`,
  `docs/testing/evaluation-corpus.md`, `docs/testing/failure-injection.md`.

### Known limitations / residual risk

- No labelled real-world corpus ⇒ no production precision/recall claim.
- `katana` is opt-in and not connection-bound (documented).
- External archive providers (`gau`, `waybackurls`) are inherently unreliable.
- No minimum-version enforcement for external binaries.
- The Phase 7 same-line residual is re-redacted where patterns match but not claimed fully solved.

## [0.9.0] — Stage 12: Evidence-based reporting

### Added

- **Stage `12-reporting`** — the final DAG stage; a deterministic, control-plane report generator
  over persisted state (no network requests).
- **Typed contract** `ReportSchema`: scan identity/context, `scanStatus`, `reportStatus`, per-stage
  job + coverage status, coverage gaps, asset/observation counts, redacted secret findings,
  correlations, limitations, and a summary.
- **Report-status derivation** (six states) from authoritative records: `COMPLETE_WITH_FINDINGS`,
  `COMPLETE_NO_FINDINGS`, `PARTIAL`, `FAILED`, `REPORTING_NOT_RUN`, `REPORTING_FAILED`. The analysis
  status is reconciled from the **non-reporting** stages, so reporting success never upgrades an
  incomplete scan to "complete", and a skipped stage is never presented as "found nothing".
- **Report-boundary redaction, fail-closed**: a structure-preserving redactor applies the centralized
  string redactor to every string value and re-validates; on any failure it throws and never emits an
  unredacted report. No raw secrets, fingerprints, or artifact bodies are emitted.
- **Persistence** as a single `report` observation (kind `report`) on the root domain asset,
  delete+insert (idempotent, no duplication). Report generation is also available on demand.
- **CLI**: `report <scanId> --format human|json|jsonl|csv`; distinguishes missing scan, not-run,
  empty, partial, and failure with stable exit codes.
- **No schema migration** — the existing model represents the report lifecycle.

### Tests

- TypeScript: report contract; status derivation for all six states; boundary redaction fail-closed;
  Stage 12 persistence + determinism/idempotency + DB redaction regression; CLI formats + exit codes
  (135 tests across 33 files).

### Verified end-to-end

- The built CLI generated a report: `REPORTING_NOT_RUN` before the stage ran, `PARTIAL` after a
  simulated completed scan, with working `--format json`.

### Known limitations

- Reports are CLI-only: `human`/`json`/`jsonl`/`csv` are implemented; **static HTML is not**.
- The Phase 7 residual (a non-rule-matching secret on the same line as a detected match) is
  re-redacted at the report boundary where patterns match, but is not claimed to be fully solved.
- No historical/cross-scan diffing yet.
- Full pipeline stages are implemented, but the product is **not** declared production-ready here;
  see the final report for release-readiness caveats (no labelled corpus for precision/recall, etc.).

## [0.8.0] — Stage 11: Deterministic evidence correlation

### Added

- **Stage `11-correlation`** — a deterministic, control-plane correlation pass over persisted
  records (no network requests, no new provider).
- **Shared secret-fingerprint equivalence**: artifacts sharing the same `(ruleId, non-empty HMAC
  fingerprint)` — where both artifacts' `secret-scan-artifact` records report `hmacKeyed` — produce
  a `shares_secret_fingerprint` asset relationship plus a correlation observation. Empty
  fingerprints, unkeyed artifacts, and differing rules never correlate.
- **Multi-source corroboration**: an asset observed by ≥2 distinct sources produces a
  `MULTI_SOURCE_CORROBORATION` correlation observation (cross-provider duplicate detection).
- **Coverage-gap summary**: upstream stages whose coverage is not `COLLECTED` are recorded in the
  Stage 11 coverage `details`.
- **Typed contract** `CorrelationRecordSchema` (`relation`, `status`, `subject`, `related`, `ruleId`,
  `hmacKeyed`, opaque `correlationGroup`, `sourceRecordIds`, `sourceStage`, redacted `evidence`,
  `confidence`). No `VALIDATED`/`CONFIRMED`/`ACTIVE`.
- **CLI**: `correlations <scanId>` (`--relation`/`--subject`/`--limit`) with redacted output and
  distinct not-run / partial / failed / complete-empty / populated states.
- **No schema migration** — edges reuse `asset_relationships`; correlation records reuse
  `observations` (kind `correlation`).

### Tests

- TypeScript: correlation contract; Stage 11 correctness (shared fingerprint correlates; unrelated,
  empty-fingerprint, and unkeyed cases do not; multi-source corroboration; edge endpoints),
  idempotency, coverage, and security regressions (no raw value, no fingerprint, no
  VALIDATED/CONFIRMED persisted); CLI state machine + JSON (119 TS tests across 29 files).

### Known limitations

- Correlation is a deterministic join over persisted evidence: **two records sharing a keyed
  fingerprint is not proof the credential is valid, active, or exploitable**, and multi-source
  corroboration is not proof of causation.
- Fingerprints produced with different HMAC keys are not comparable; the stage relies on HMAC
  producing no collisions and the operator keeping `RECONNEXUS_HMAC_KEY` stable.
- The Phase 7 residual (a non-rule-matching secret on the same line as a detected match) is
  unchanged by Stage 11.
- Stage 12 (reporting) remains unimplemented; scans report `PARTIAL`.

## [0.7.0] — Phase 7: Secret detection & sensitive artifact analysis

### Added

- **Stage `09-secret-detection`** — `builtin-secret-scan` provider (capability `SECRET_SCAN`).
  Selects the persisted JS artifacts and API specifications from stages 07/08 and re-collects their
  content in-memory through the connection-bound transport (raw bodies are deliberately **not**
  persisted), then scans it.
- **Detection rules** (maintained, high-signal): AWS key id + secret, Google, Slack, GitHub, Stripe,
  Twilio, SendGrid, npm, Azure account key, private-key markers, database connection strings, OAuth
  client secrets, webhook signing secrets, JWTs, bearer tokens, embedded credentials, password
  assignments, plus a single entropy heuristic for generic key/token assignments.
- **Confidence & context**: rule id, category, confidence, rationale; high-confidence vs candidate;
  entropy threshold; overlapping generic matches suppressed by more specific matches;
  placeholder/example suppression; rule-specific suppression via configuration.
- **Secret-safe evidence (release-blocking)**: only a **line-scoped** redacted snippet (raw value
  replaced, every rule match in the snippet re-redacted, global redactor last), a keyed HMAC
  fingerprint, and the source location are persisted. Private keys and over-long (minified) lines
  store a context-free marker. Raw values never reach findings, logs, errors, or the database.
- **Lifecycle**: `CANDIDATE`, `HIGH_CONFIDENCE`, `SUPPRESSED`, `ANALYSIS_FAILED`. No
  `VALIDATED`/`ACTIVE` state exists — no credential verification is performed, and no values are
  sent to external services.
- **Persistence**: `secret-finding` and `secret-scan-artifact` observations on the artifact `URL`
  asset (no schema migration).
- **CLI**: `secrets <scanId>` (filters by rule/category/status/confidence/artifact/host), redacted
  output only; `--secret-providers` on `scan run`/`resume`.

### Tests

- Go: rule detection, entropy, suppression, dedup with occurrence counts, oversized, malformed /
  Unicode bytes, analysis failure, out-of-scope skip, cancellation, capability blocking, HMAC
  keyed/unkeyed, and a release-gate test that asserts no raw fixture value (including a private-key
  body) appears in the worker output.
- TypeScript: secret-scan contract, Stage 09 orchestration + DB-wide redaction regression +
  idempotency, CLI filters + JSON (112 TS tests across 26 files).

### Verified end-to-end

- Compiled worker detected AWS key/private-key/DB-URL/password candidates in a served artifact; the
  redacted snippets contained no raw value and the private-key body was absent.

### Known limitations

- Detection favours a maintained high-signal rule set; generic/entropy matching is a low-confidence
  candidate and is not a claim of validity or exploitability. Pattern matches are **not** proof a
  credential is valid, active, or exploitable.
- A non-rule-matching secret appearing on the *same line* as a detected match is not redacted from
  that finding's snippet (the line is otherwise fully rule-redacted); this is a documented residual
  limitation.
- Stages 11–12 (correlation, reporting) remain unimplemented; scans report `PARTIAL`.

## [0.6.0] — Phase 6: Security metadata & exposure intelligence

### Added

- **Stage `06-url-categorization` resolved** — previously `SKIPPED`; now a real, network-free stage
  that materializes categorization coverage from Stage 05 URL observations (no duplicate data).
- **Stage `10-security-checks`** — `builtin-security-meta` provider (capability `SECURITY_CHECKS`)
  issues one bounded, connection-bound GET per in-scope service and records, with evidence:
  - **TLS** certificate metadata: subject/issuer/notBefore/notAfter/sha256/protocol/selfSigned/
    hostnameMatch/daysToExpiry/validNow;
  - **HSTS** parsed (max-age/includeSubDomains/preload);
  - **security headers** (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
    Permissions-Policy, Cross-Origin-*), each `OBSERVED` or `NOT_OBSERVED`;
  - **cookie attributes** (Secure/HttpOnly/SameSite/Domain/Path/Max-Age) with **values never stored**;
  - **CORS** policy (origin/credentials/methods/headers, wildcard) with wildcard+credentials flagged
    `INCONSISTENT`;
  - **content-type** declared vs observed-body consistency.
- **Status model** for metadata: `OBSERVED`, `INFERRED`, `INCONSISTENT`, `NOT_OBSERVED`, `UNKNOWN`,
  `COLLECTION_FAILED`; a missing header is never presented as "control absent".
- **Persistence**: `security-metadata` observations on `SERVICE` assets; TLS metadata correlated to a
  `CERTIFICATE` asset (`presents_certificate`); redacted evidence linked to observations.
- **CLI**: `security <scanId>` (filters by category/status/host), `--security-providers` on
  `scan run`/`resume`.
- **No schema migration** — the existing asset/observation/evidence/relationship/coverage models
  cover the data.

### Tests

- Go: header extraction (present/absent), HSTS parsing, cookie attributes without value leakage,
  CORS wildcard+credentials inconsistency, content-type mismatch, TLS via a trusted test CA,
  certificate validity boundaries (valid/expired/not-yet-valid), collection failure, out-of-scope
  skip, cancellation, capability blocking.
- TypeScript: security-metadata contract, stages 06+10 orchestration + idempotency + certificate
  correlation, CLI filters + JSON envelope (105 TS tests across 23 files).

### Verified end-to-end

- Compiled worker against a local mock server: HSTS `OBSERVED`, `X-Content-Type-Options` `OBSERVED`,
  other headers `NOT_OBSERVED` with limitations, CORS `INCONSISTENT` (wildcard + credentials), cookie
  attributes captured with the value confirmed absent, content-type consistent, TLS `NOT_OBSERVED`
  over plaintext.

### Known limitations

- CORS is observed from a normal GET (no crafted `Origin`); reflective CORS is not tested, stated per
  observation. No vulnerability/exploitability claims are made.
- `NOT_OBSERVED` reflects one response at one time, not the absence of a control.
- Stage 09 (secret detection) and 11–12 (correlation, reporting) remain unimplemented; scans report
  `PARTIAL`.

## [0.5.0] — Phase 5: JavaScript & API intelligence

### Added

- **Stage `07-js-intelligence`** — `builtin-js` provider: retrieves JavaScript artifacts with
  connection-bound scope enforcement (bounded concurrency/size/timeout/cancellation), records URL,
  canonical URL, SHA-256 content hash, MIME type, size, source URL, discovery method, status and
  provenance; honest outcomes (`RETRIEVED`/`NOT_FOUND`/`ERROR`/`OVERSIZED`/`MISMATCHED_MIME`).
- **Bounded static JS analysis** (RE2 lexical scan; no JS execution, no browser, no package
  install): `fetch()`, `axios.<method>()`, `XMLHttpRequest.open()`, `WebSocket`, absolute/relative
  URL and path literals; dynamic template literals are retained as **unresolved candidates**.
  Evidence is minimal and secret-redacted.
- **Source-map analysis** — `sourceMappingURL` discovery, safe JSON parsing, size/recursion/cycle
  limits, configurable via `fetchSourceMaps`, scope-checked, and it never fetches the listed sources.
- **Stage `08-api-discovery`** — `builtin-api` provider: OpenAPI/Swagger **JSON and YAML** parsing
  (version, title, servers, paths, methods, operationIds, tags, parameters, request bodies,
  responses/content types, auth schemes); local `$ref` resolution with depth/cycle limits (remote
  `$ref` never fetched); GraphQL paths surfaced without live introspection.
- **Method-aware endpoint identity** (`METHOD origin path`) distinguishing JS-extracted vs
  SPEC-documented vs HTTP-observed endpoints, with unresolved dynamic candidates flagged.
- **Persistence** of `JS_ARTIFACT`/`API_ENDPOINT` assets, `js-artifact`/`source-map`/`api-spec`/
  `api-endpoint` observations, and `references`/`has_source_map`/`exposes`/`documents` relationships.
- **CLI**: `js <scanId>`, `apis <scanId>` (filters by host/method/via/documented/unresolved),
  `specs <scanId>`, `--js-providers` / `--api-providers`; `params` now includes endpoint parameters.
- **Conformance**: JS/API now sourced from the existing stages rather than a new Stage 06; no
  duplicate stage IDs; no schema migration required.

### Tests

- Go: JS extraction (including dynamic templates, adversarial/oversized input, secret redaction),
  source-map parse/disabled, honest failures, OpenAPI 3 JSON, Swagger 2 YAML, `$ref` resolution and
  unresolved remote refs, out-of-scope origin dropping, capability blocking.
- TypeScript: JS/API result contract, stages 07/08 orchestration + idempotency + multi-source
  provenance, CLI commands + JSON envelope (99 TS tests across 20 files).

### Verified end-to-end

- Compiled worker retrieved and hashed a served JS artifact, extracted `GET`/`POST`
  `/api/v1/users` and a `WebSocket` endpoint, parsed a source map (2 sources), and confirmed a
  `token=`-shaped value was redacted.
- Compiled worker parsed a live OpenAPI 3 JSON document into a documented `GET /api/users` endpoint
  with its `query` parameter.

### Known limitations

- Static analysis is regex/lexical, not a full parser: it favours recall on literal strings and may
  miss concatenated/dynamic constructions (retained as unresolved candidates) or report path-like
  strings that are not endpoints. This is documented and intentional.
- Source-map and spec payloads are size-capped; very large artifacts are truncated and flagged.
- Only local `$ref` targets are resolved; remote `$ref` targets are counted as unresolved.
- Stages 06 and 09–12 remain unimplemented; scans report `PARTIAL`.

## [0.4.0] — Phase 4: URL intelligence

### Added

- **URL canonicalization** (`workers/internal/matching/url.go` + TS `parseUrl().canonical`): scheme
  and host lowercasing, IDN→punycode, default-port removal, RFC 3986 dot-segment removal, fragment
  removal. Deliberately **not** applied: query sorting, parameter removal/collapsing, trailing-slash
  stripping, percent-decoding. Verified by shared conformance fixtures (`test/fixtures/conformance/urls.json`).
- **Active collection — `builtin-crawler`**: BFS crawl using the Phase 3A connection-bound transport
  (DialContext scope enforcement + per-hop redirect reauthorization), with depth, request-budget,
  concurrency, timeout and response-size limits and cancellation.
- **Opt-in `katana` adapter**: runs `katana -dr -jsonl` with a scope regex and post-filters all
  output. Documented as **not** connection-bound (katana resolves/follows internally), so it is not
  a default provider.
- **Passive collection — `gau` and `waybackurls`**: scope-filtered URL extraction with honest
  timeout/unavailable/malformed handling. No fabricated URLs; empty output is never "success by
  assumption".
- **Static discovery — `builtin-static`**: robots.txt and sitemap XML parsing (`<urlset>` and
  bounded `<sitemapindex>` recursion, sitemap/URL caps). robots `Disallow`/`Allow` paths are
  recorded as **candidates only**, never as authorization.
- **Classification** (`workers/internal/discovery/urlclassify.go`): URL categories (HTML, API,
  GraphQL, JS, static, auth/registration/password/session, search/filter/pagination/export,
  upload/download, docs/API-spec/developer, admin, redirect) and query-parameter roles
  (pagination, search, filter, identifier, redirect, file/path, auth token). Each carries a
  confidence and an evidence string; competing hypotheses are allowed and low-confidence route-only
  guesses are never treated as fact.
- **Persistence**: `URL` assets, `url` observations with per-provider provenance, `contains_url`
  relationships; canonical dedup that preserves every provider's observation; idempotent.
- **Orchestration**: Stage `05-url-collection` seeded from HTTP observations (fallback: resolved
  hosts), per-provider coverage, resume/cancel, distinct reporting of empty/partial/failed.
- **CLI**: `urls <scanId>` (filter by host/provider/category/param/method/status; `--stats`),
  `params <scanId>`, and `--url-providers` on `scan run`/`resume`.

### Tests

- Go: crawler (link discovery, depth limiting, dedup, out-of-scope drop, redirect-to-private denial,
  DNS rebinding, cancellation), static (robots, sitemap, sitemap index, malformed XML),
  passive (parsing, fake binary, unavailable), URL normalization edge cases, and classification with
  a labeled fixture confusion matrix (24/24 on the curated set).
- TypeScript: URL observation contract, Stage 05 orchestration + idempotency + multi-provider
  provenance, and CLI command/JSON/exit-code tests (92 TS tests across 17 files).

### Verified end-to-end

- Compiled worker crawled a local mock server: 4 unique canonical URLs, correct classifications
  (`ADMIN`, `JAVASCRIPT`, `PAGINATION`) and parameter extraction, with the out-of-scope link
  rejected and counted.
- Live passive `waybackurls` returned 18 scope-filtered, classified URLs for a documentation domain
  (no traffic sent to the target).
- Live `gau` timed out at 45s and was reported `FAILED` (not an empty success), demonstrating
  truthful provider-failure handling.

### Known limitations

- `gau` may be slow or rate-limited by public archives; it is a default provider but failures are
  reported honestly, and operators can restrict providers with `--url-providers`.
- `katana` is opt-in and not connection-bound; it is documented as such and is not a default.
- Classification precision/recall is measured only against a small hand-labeled fixture (24 cases);
  this is a regression guard, not a real-world benchmark.
- Stages 06–12 remain unimplemented; scans report `PARTIAL`.

## [0.3.0] — Phase 3A: HTTP probing & fingerprinting

### Added

- **`builtin-http` provider** (`workers/internal/discovery/http.go`) — HTTP/HTTPS probing with
  bounded concurrency, connection/request timeouts, response-size and redirect limits, and
  cancellation. Emits `HTTP_OBSERVATION` records (status, final URL, redirect chain, content type,
  title, selected headers, TLS subject/issuer/validity/SHA-256/protocol/SANs, outcome/reason).
  Cookies, `Authorization`, and other sensitive headers are never persisted.
- **Mandatory SSRF/redirect protection** — normalize → hostname scope check → resolve → address
  check → **bind the validated address to the actual connection** (custom `DialContext`) →
  reauthorize **every redirect hop** → enforce redirect count → block loopback/private/link-local/
  metadata addresses (incl. IPv4-mapped IPv6). TLS verification is never globally disabled.
- **Evidence-backed fingerprinting** (`workers/internal/discovery/fingerprint.go`) — deterministic,
  specific signatures for web servers, frameworks, CMS, frontend frameworks, CDN/WAF, API
  gateways, and login/documentation/dev-service hints. Each hit carries category, evidence type,
  evidence string and confidence; generic strings never assert a technology and competing
  hypotheses are allowed.
- **Ingestion** — `SERVICE`, `TECHNOLOGY` and `CERTIFICATE` assets; `http`/`technology`/`tls`
  observations with provenance; `serves`/`runs`/`presents_certificate` relationships; worker output
  stored as content-addressed evidence and linked to observations.
- **Orchestration** — HTTP stage `04-http-probe` consumes resolved in-scope hosts, reauthorizes each
  inside the worker, bounds the number of targets, and reports per-provider coverage truthfully.
- **CLI** — `http <scanId>`, `technologies <scanId>`, and `--http-providers` on `scan run`/`resume`.

### Design decision

The provider is a built-in Go HTTP client rather than ProjectDiscovery `httpx`. httpx resolves and
follows redirects internally, so it cannot reauthorize each redirect hop or bind a validated IP
decision to the socket — both mandatory. This is documented in
`docs/architecture/provider-contracts.md` and `docs/architecture/discovery.md`.

### Tests

- Go (`workers/internal/discovery/http_test.go`, `fingerprint_test.go`) — local `httptest` servers
  and an injectable resolver cover: basic probe, redirect chain, redirect to excluded host,
  out-of-scope domain, loopback/private/metadata/IPv4-mapped destinations, DNS rebinding at the
  connection boundary, trusted vs untrusted TLS (no global bypass), timeout, oversized bodies,
  cancellation, out-of-scope skip, and fingerprint false positives.
- TypeScript — `test/unit/http-contract.test.ts` and `test/integration/http-stage.test.ts` (85 TS
  tests across 14 files total).

### Verified end-to-end

The compiled worker probed a local mock server: `200 OK` with title and `Server` header, four
evidence-backed fingerprints (nginx, PHP, WordPress, React), and `REDIRECT_DENIED` for a redirect to
`http://10.0.0.1/` with the pre-redirect `302` metadata preserved.

### Known limitations

- HTTPX is not used (see design decision).
- Stage 04 follows at most `network.maxRedirects` hops; deeper chains are recorded as
  `TOO_MANY_REDIRECTS`.
- Fingerprints are heuristic evidence, not proof of version or vulnerability.

## [0.2.0] — Phase 2: orchestration + asset discovery

### Added

- **Shared conformance suite** — `test/fixtures/conformance/` (domains, IPs, scope decisions) is
  evaluated by both the TypeScript and Go engines; the TypeScript test runs the Go
  `cmd/conformance` binary and asserts identical output. `make conformance`.
- **Go PSL parity** — `workers/internal/matching` uses `golang.org/x/net/publicsuffix` for
  registrable-domain extraction, adds label-boundary matching, and a classification model that
  matches `packages/normalization`. The worker scope engine now also applies registrable-domain
  inference, matching TypeScript exactly.
- **Discovery worker** (`workers/cmd/reconnexus-worker`) — executes a job and emits a
  schema-validated `DiscoveryResult`. Providers: `subfinder`, `assetfinder`, `amass` (passive),
  `dnsx`, `builtin-dns` (concurrent Go resolver), `rdap`, `offline-ipmeta`, and `mock`.
- **Provider execution lifecycle** — capability validation, executable + version checks, structured
  argv, timeouts, bounded output, cancellation, exit-code interpretation, retry classification,
  structured execution records, truthful failure states.
- **Orchestrator** (`apps/control-plane/src/orchestration`) — job claiming with leases, dependency
  gating, bounded retries with backoff + jitter, cancellation, resume, per-stage coverage,
  per-provider outcomes, and scan-status reconciliation from actual outcomes.
- **Idempotent ingestion** — canonical assets dedupe by unique key; observations append with
  provenance; relationships dedupe; worker output preserved as a content-addressed evidence
  artifact.
- **Worker client** (`GoWorkerRunner`) — spawns the worker (argv array, no shell), validates JSON
  with zod, and reports timeouts/malformed output/cancellation truthfully.
- **Database migration `0003_discovery`** — execution metrics on `provider_executions`, coverage
  `details`, and `job_provider_outcomes`.
- **CLI**: `scan run`, `scan resume`, `scan status` (jobs + coverage + providers), `coverage`,
  `assets list`; `--providers` / `--dns-providers` / `--ip-providers` selection.
- **Tests** — Go discovery/scope/matching/conformance suites; TS worker-client, discovery-contract
  and orchestration integration suites (80 TS tests across 12 files). All deterministic; no public
  Internet required.

### Verified end-to-end

- `subfinder` (real, passive) produced 22,249 normalized observations persisted as assets.
- `builtin-dns` (real) persisted A/AAAA observations with provenance; `rdap` correlated a CIDR
  (`2606:4700::/48`) and reported `PARTIAL` where responses were not parseable — no fabricated ASN.

### Known limitations

- Stages 04–12 (HTTP probing, URL/JS/API analysis, secrets, reporting) remain unimplemented and are
  recorded as `SKIPPED`; the scan status is therefore `PARTIAL`.
- ASN is only recorded when present in the RDAP response (RDAP IP responses usually omit it);
  this is stated per record rather than inferred.
- The full DNS stage over a domain with tens of thousands of passive results is bounded by
  `limits.maxRuntimeSeconds`; the worker returns partial results on that deadline rather than being
  killed with nothing saved.

## [0.1.0] — Phase 0 + Phase 1

### Added

- **Phase 0** repository audit and phased implementation plan (`docs/`).
- **Monorepo** (npm workspaces + `go.work`): `apps/cli`, `apps/control-plane`, `packages/*`,
  `workers/`, `db/migrations`, `test/`, `docs/`, `policies/`.
- **`packages/contracts`** — zod schemas and types: exit codes, capabilities, job/finding/coverage
  statuses, scope policy, scan manifest, provider descriptor, observation/evidence/finding/coverage
  records, CLI envelope.
- **`packages/normalization`** — IPv4/IPv6 parsing & canonicalization (incl. IPv4-mapped unwrap),
  special-range classification, CIDR matching, PSL-aware registrable-domain parsing (`tldts`),
  URL normalization.
- **`packages/scope-policy`** — enforcement engine implementing authorization validity, capability
  gating, exclusions (with precedence), positive-match requirement, address-space validation, and
  audit emission; `resolveAndCheck` with DNS-rebinding guard and injectable resolver.
- **`packages/configuration`** — layered (defaults → file → env → overrides), versioned, validated
  configuration with absolute-path resolution.
- **`packages/logging`** — structured JSON logging with centralized secret redaction.
- **`packages/evidence-contracts`** — `ArtifactStore` abstraction + content-addressed local
  filesystem implementation with size limits and path-traversal protection.
- **`apps/control-plane`** — Postgres pool + transactions, dependency-aware repository, idempotent
  advisory-locked migration runner, provider catalog, dependency diagnostics, and `ScanService`
  (Stage 00: validate URL, enforce scope, persist manifest + 13-stage job DAG, audit decision).
- **`db/migrations`** — full data model: workspaces, users/memberships, projects,
  authorization_records, scope_policies, scan_runs, jobs, provider_executions, assets,
  asset_relationships, observations, evidence_artifacts, findings, finding_evidence, evidence_links,
  coverage_records, audit_events.
- **`apps/cli`** — command hierarchy (`scan`, `scope`, `assets`, `urls`, `apis`, `secrets`,
  `findings`, `coverage`, `report`, `providers`, `config`, `doctor`), `--json` output envelopes,
  stable exit codes, non-interactive operation.
- **`workers` (Go)** — independent scope-enforcement engine, structured process adapters (argv,
  timeouts, output limits, cooperative cancellation), telemetry with redaction, `provider-check` and
  a worker skeleton.
- **Tests** — 63 TypeScript tests (unit/integration/security) and Go tests; security release gate
  asserting zero out-of-scope decisions; synthetic fixture corpus.
- **Docs** — audit, plan, architecture (overview, data model, provider contracts), scope threat
  model, operations (installation, configuration, troubleshooting), testing methodology.

### Known limitations

- Scan pipeline stages 01–12 are **not implemented**; only Stage 00 executes.
- Worker job execution/claiming is not implemented (skeleton only).
- `assets`, `urls`, `apis`, `secrets`, `findings`, `coverage`, `report`, and `scan resume` return
  `NOT_IMPLEMENTED` (exit 3).
- The Go worker's domain matching does not yet consult the Public Suffix List.
