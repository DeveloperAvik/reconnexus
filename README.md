# ReconNexus

CLI reconnaissance and web/API attack-surface intelligence platform.

> **Build status: Stages 00–12 complete** — the full pipeline executes end to end: input/
> authorization, target intelligence, subdomain discovery, DNS/infrastructure correlation, HTTP
> probing + fingerprinting, URL collection/categorization, JavaScript analysis, API
> (OpenAPI/Swagger) intelligence, secret detection (redacted), security-metadata enrichment,
> deterministic evidence correlation, and redacted evidence-based reporting. A scan that skipped or
> failed stages is reported `PARTIAL`/`FAILED`, never "complete". Raw secret values are never
> persisted or printed; reports are regenerated deterministically and redaction fails closed. This is
> **not a claim of production readiness** — see [docs/implementation-plan.md](docs/implementation-plan.md).

ReconNexus is a CLI-only platform: there is no web dashboard and no frontend. It is designed to
collect, normalize, correlate, and report reconnaissance data for **explicitly authorized**
assessments, with scope enforcement, evidence preservation, and honest coverage reporting at its
core.

## What works today

| Area | Status |
| --- | --- |
| CLI command hierarchy (`scan`, `scope`, `assets`, `urls`, `apis`, `secrets`, `findings`, `coverage`, `report`, `providers`, `config`, `doctor`) | ✅ registered; implemented commands work, others return `NOT_IMPLEMENTED` |
| Structured JSON output (`--json`) and human output | ✅ |
| Layered, versioned configuration + validation | ✅ |
| Scope-policy engine (10 enforcement checks, TS + independent Go mirror) | ✅ |
| DNS/redirect/rebinding-safe destination validation | ✅ |
| PostgreSQL schema + idempotent migration runner | ✅ |
| Stage 00 scan creation (validate URL, authorize, persist manifest + job DAG) | ✅ |
| Scan orchestration: job DAG, leases, retries/backoff, cancellation, resume, coverage | ✅ |
| Subdomain discovery (subfinder/assetfinder/amass + mock) | ✅ |
| DNS intelligence (builtin-dns + dnsx): A/AAAA/CNAME/MX/NS/TXT/PTR, wildcard, statuses | ✅ |
| Infrastructure correlation (RDAP + offline fixture): IP→CIDR→ASN with limitations | ✅ |
| HTTP probing (`builtin-http`): status, redirects, title, headers, TLS, with per-hop redirect reauthorization | ✅ |
| Evidence-backed technology fingerprinting (servers, frameworks, CMS, CDN/WAF, …) | ✅ |
| URL collection: crawler, gau, waybackurls, robots/sitemaps; canonicalization + classification | ✅ |
| JavaScript intelligence: artifact hashing, bounded static analysis, source maps | ✅ |
| API intelligence: OpenAPI/Swagger (JSON+YAML), method-aware endpoints, parameters, `$ref` | ✅ |
| API specification discovery: well-known paths probed on origins with evidence of an API (budgeted, deterministic) | ✅ |
| Queryable assets/HTTP/technologies/URLs/params/JS/endpoints/specs (`js`, `apis`, `specs`) | ✅ |
| Security metadata: TLS/HSTS/headers/cookies(attrs)/CORS/content-type with status + evidence | ✅ |
| Secret detection: rules + entropy, redacted-only findings, keyed fingerprints | ✅ |
| Subdomain-takeover detection: CNAME fingerprints + unclaimed-marker confirmation (candidate-only) | ✅ |
| Evidence correlation: shared secret fingerprints, multi-source corroboration, coverage gaps | ✅ |
| Reporting: redacted human/json/jsonl/csv with truthful scan-status derivation | ✅ |
| Structured logging with secret redaction | ✅ |
| Provider health checks (`doctor`, `providers`, Go `provider-check`) | ✅ |
| Static HTML report export | ❌ not implemented (CLI-only product) |

## Hardening (Phase 8)

A repository-wide security/reliability audit fixed a **High** TS/Go scope-parity defect
(percent-encoded dot-segment handling in URL path normalization now matches WHATWG in both engines),
re-redacts persisted provider diagnostics, guards CSV exports against formula injection, and adds a
failure-injection suite, a provider compatibility matrix (`reconnexus providers matrix`), benchmarks,
and a labeled secret-detection evaluation corpus. See
[docs/testing/failure-injection.md](docs/testing/failure-injection.md) for the injected-failure
matrix and [CHANGELOG.md](CHANGELOG.md) for details.

## Requirements

- macOS on Apple Silicon (`darwin/arm64`) for development.
- Node.js ≥ 20 (developed against v26) and npm.
- Go ≥ 1.23 (developed against 1.27).
- PostgreSQL 16 (authoritative store).
- Optional: Redis (not required; the Postgres queue is authoritative).
- External providers on `PATH` for the stages that use them.

## Quick start

Running from source uses `npm run rn -- <args>`; after `npm run build` you can use the compiled
`reconnexus` binary (`node apps/cli/bin/reconnexus.mjs <args>`). Running `reconnexus` with no
arguments prints help.

To make the bare `reconnexus` command available on your `PATH` (one-time, after `npm run build`):

```bash
chmod +x apps/cli/bin/reconnexus.mjs
npm link          # links the bin into the global prefix (e.g. /opt/homebrew/bin)
reconnexus --help # verify
```

Undo with `npm unlink -g reconnexus`.

```bash
# 1. Services + dependencies
brew services start postgresql@16 redis
npm install

# 2. Scaffold config + a scope policy for a domain you are authorized to test
#    (interactive if you omit --domain/--authorized-by)
npm run rn -- init --domain example.com --authorized-by "Your Name" --reference AUTH-123

# 3. Database + environment check
createdb reconnexus
npm run rn -- config migrate
npm run rn -- doctor

# 4. Build the Go discovery worker used by scans
make worker-build

# 5. Authorize and run a scan in one step (policy is auto-discovered from policies/)
npm run rn -- scan start https://example.com/ --run

# 6. Inspect results (the scan id is printed by scan start / scan list)
npm run rn -- scan list
npm run rn -- scan status "$SCAN"
npm run rn -- coverage "$SCAN"
npm run rn -- urls "$SCAN" --stats
npm run rn -- secrets "$SCAN"
npm run rn -- takeover "$SCAN"
npm run rn -- correlations "$SCAN"
npm run rn -- report "$SCAN"                 # or --format json|jsonl|csv
```

Notes:

- `--policy` is optional once a policy is configured (`defaultPolicyFile`) or when exactly one file
  exists under `policies/`.
- `scan start --run` chains creation and execution; `scan run <id>` and `scan resume <id>` run
  explicitly. `scan list` shows recent scans.
- Human output is colorized when attached to a terminal; use `--color never` (or `NO_COLOR=1`) to
  disable, `--json` for machine-readable output.
- A running scan prints one line per stage as it finishes — status, elapsed time, and each
  provider's record count — followed by a closing block naming anything that did not fully
  succeed. Per-provider log lines are suppressed while that progress is on screen; `--log-level
  debug` keeps them, and `--log-level error` turns progress off and prints the full stage table in
  the summary instead.
- Only scan targets you are explicitly authorized to assess — a scan refuses anything outside its
  scope policy.

Set `RECONNEXUS_HMAC_KEY` to enable keyed secret fingerprints (cross-record correlation); set
`RECONNEXUS_SECRET_SUPPRESS_RULES=rule-a,rule-b` to suppress specific rules. `secrets` never prints
raw values and has no flag to reveal them.

The compiled CLI is available at `node apps/cli/bin/reconnexus.mjs` after `npm run build`, or run
from source with `npm run rn -- <args>`.

## Testing

```bash
npm test          # TypeScript unit/integration/security suite (vitest)
make test-go      # Go unit tests
make test-all     # both
```

The security suite includes a mandatory release gate asserting that **no out-of-scope target is
ever allowed**.

## Repository layout

```
apps/cli              CLI (TypeScript, commander)
apps/control-plane    orchestration, repositories, migrations, diagnostics
packages/contracts    zod schemas + shared types
packages/normalization URL/domain/IP canonicalization
packages/scope-policy scope enforcement engine + DNS reauthorization
packages/configuration layered versioned config
packages/logging      structured logging + redaction
packages/evidence-contracts content-addressed artifact storage abstraction
workers/              Go workers, provider adapters, independent scope enforcement
db/migrations         PostgreSQL migrations
docs/                 architecture, operations, threat model, testing
policies/             example scope policies
test/                 unit, integration, security, fixtures
```

## Documentation

- [Repository audit](docs/implementation-audit.md)
- [Implementation plan](docs/implementation-plan.md)
- [Architecture overview](docs/architecture/overview.md)
- [Data model](docs/architecture/data-model.md)
- [Provider contracts](docs/architecture/provider-contracts.md)
- [Subdomain-takeover detection](docs/architecture/subdomain-takeover.md)
- [Scope enforcement threat model](docs/threat-model/scope-enforcement.md)
- [Installation](docs/operations/installation.md) · [Configuration](docs/operations/configuration.md) · [Troubleshooting](docs/operations/troubleshooting.md)
- [Provider compatibility matrix](docs/operations/provider-compatibility.md)
- [Benchmarks](docs/testing/benchmarks.md) · [Evaluation corpus](docs/testing/evaluation-corpus.md) · [Failure injection](docs/testing/failure-injection.md)
- [Benchmark methodology](docs/testing/benchmark-methodology.md)
- [Changelog](CHANGELOG.md)

## Legal and ethical use

ReconNexus is intended for authorized security testing only. Scope enforcement is a safety rail,
not a legal authorization. You are responsible for ensuring you have explicit permission to test
every target. Discovered infrastructure is **not** automatically authorized infrastructure.
