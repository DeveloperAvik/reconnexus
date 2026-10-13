# Provider Contracts

Every external tool is wrapped as a **provider adapter** with a declared contract
(`ProviderDescriptorSchema` in `packages/contracts`). A missing or incompatible tool must produce
an explicit dependency error — never an empty "successful" result.

## Descriptor fields

| Field | Meaning |
| --- | --- |
| `name`, `displayName` | Stable identifier and human label. |
| `source` | `external_binary`, `builtin`, or `http_api`. |
| `capabilities` | Operation classes the provider serves (subset of the canonical capability set). |
| `networkBehavior` | `NONE`, `PASSIVE`, `ACTIVE`, or `ACTIVE_TEMPLATE` — drives which policy capability is required. |
| `requiredCredentials` / `requiresCredentials` | Credential/env requirements, checked by the doctor. |
| `binaryPath` | Fixed absolute path; operators may configure it but cannot inject arbitrary argv. |
| `healthCheck` | `{ argv, expectExitCode, timeoutMs }` — a structured version probe. |
| `timeoutMs`, `retryable`, `supportsCancellation`, `maxOutputBytes` | Resource and lifecycle behavior. |
| `exitCodes` | Mapping of non-zero exit codes to meaning; unknown codes are failures. |

## Invocation rules

1. Providers are invoked with **argv arrays** through `execCapture` (TS) / `adapters.Run` (Go).
   A shell is never used, so untrusted values can never be interpreted as shell syntax.
2. Output exceeding `maxOutputBytes` is truncated and flagged (`truncated: true`).
3. Timeouts send `SIGTERM`, then `SIGKILL` after a bounded grace period.
4. Every execution is recorded in `provider_executions` (argv, exit code, byte counts, status).

## Registered providers (health-checked in Phase 1)

| Provider | Capabilities | Network | Version probe |
| --- | --- | --- | --- |
| subfinder | PASSIVE | PASSIVE | `-version` |
| amass | PASSIVE, DNS | PASSIVE | `-version` |
| assetfinder | PASSIVE | PASSIVE | none |
| dnsx | DNS | ACTIVE | `-version` |
| httpx | ACTIVE_HTTP | ACTIVE | `-version` |
| katana | CRAWL | ACTIVE | `-version` |
| gau | PASSIVE | PASSIVE | `--version` |
| waybackurls | PASSIVE | PASSIVE | none |
| mapcidr | PASSIVE | NONE | `-version` |
| nuclei | SECURITY_CHECKS, ACTIVE_TEMPLATE_CHECK | ACTIVE_TEMPLATE | `-version` |

> Availability of a binary does **not** imply credentials are configured (e.g. Subfinder passive
> sources). The doctor distinguishes `MISSING`, `FAILED_HEALTHCHECK`, and `MISSING_CREDENTIALS`.

## Adding a provider

1. Add a descriptor to `apps/control-plane/src/providers/catalog.ts` and
   `workers/internal/adapters/catalog.go`.
2. Declare the capability and network behavior so the scope engine can gate it.
3. Implement the adapter with strict output parsing and validation before persistence.
4. Add a health check and a test using recorded/synthetic output — never live credentials.

> **Stage 11 (`11-correlation`) has no provider** — it is a deterministic control-plane pass over
> persisted records (see [correlation.md](correlation.md)). Providers below cover the
> network-executing stages.

## Discovery providers (Phase 2)

Discovery providers run inside the Go worker and return a normalized `DiscoveryResult`
(`packages/contracts/src/discovery.ts`). Each provider declares a **kind**
(`SUBDOMAINS` / `DNS` / `IP_METADATA`), a required **capability**, and a **network behavior**;
the worker refuses a job whose capability is not authorized or whose kind the provider does not
serve.

| Provider | Kind | Capability | Network | Notes |
| --- | --- | --- | --- | --- |
| `subfinder` | SUBDOMAINS | PASSIVE | PASSIVE | `-d <domain> -silent`; one host per line. |
| `assetfinder` | SUBDOMAINS | PASSIVE | PASSIVE | `--subs-only <domain>`. |
| `amass` | SUBDOMAINS | PASSIVE | PASSIVE | `enum -passive -d <domain> -silent`. |
| `dnsx` | DNS | DNS | ACTIVE | `-json -a -aaaa -cname -mx -ns -txt -silent`, names on stdin. |
| `builtin-dns` | DNS | DNS | ACTIVE | Go resolver (concurrent); A/AAAA/CNAME/PTR, wildcard detection, custom resolver. |
| `rdap` | IP_METADATA | PASSIVE | PASSIVE | `GET {base}/ip/{ip}`; prefix/name/country; ASN only if present. |
| `offline-ipmeta` | IP_METADATA | PASSIVE | PASSIVE | Fixture-driven, deterministic (tests). |
| `mock` | any | — | NONE | Fixture-driven, all kinds (tests). |
| `builtin-http` | HTTP_PROBE | ACTIVE_HTTP | ACTIVE | In-process Go HTTP client: status, redirects (reauthorized per hop), title, selected headers, TLS metadata, fingerprints. |
| `builtin-crawler` | URL_COLLECTION | CRAWL | ACTIVE | Connection-bound BFS crawler (depth/budget/concurrency limits). |
| `builtin-static` | URL_COLLECTION | ACTIVE_HTTP | ACTIVE | robots.txt + sitemap XML discovery. |
| `gau` | URL_COLLECTION | PASSIVE | PASSIVE | Public archive URLs (may be slow/rate-limited). |
| `waybackurls` | URL_COLLECTION | PASSIVE | PASSIVE | Wayback CDX URLs. |
| `katana` (opt-in) | URL_COLLECTION | CRAWL | ACTIVE | `-dr -jsonl` + scope regex + post-filter; not connection-bound. |
| `mock-url` | URL_COLLECTION | — | NONE | Fixture-driven (tests). |
| `builtin-js` | JS_ANALYSIS | JS_ANALYSIS | ACTIVE | Retrieves + hashes JS, bounded static analysis, source maps. |
| `builtin-api` | API_SPEC | API_DISCOVERY | ACTIVE | OpenAPI/Swagger JSON+YAML parsing, local `$ref`, GraphQL refs. |
| `builtin-security-meta` | SECURITY_META | SECURITY_CHECKS | ACTIVE | One bounded GET per service: TLS/HSTS/security headers/cookie attributes/CORS/content-type metadata. |
| `builtin-secret-scan` | SECRET_SCAN | SECRET_SCAN | ACTIVE | Re-collects eligible artifacts in-memory; detects potential secrets; persists redacted findings + keyed fingerprints only. |

### katana / httpx limitation

`katana` (like `httpx`) resolves DNS and follows redirects internally, so it cannot bind a validated
IP decision to the socket or reauthorize each redirect hop. It is therefore **not a default
provider**; when explicitly selected it runs with `-dr` (redirects disabled) and every returned URL
is re-checked against the scope policy before persistence.

### Why not httpx for probing?

`httpx` is installed and healthy, but it resolves DNS and follows redirects **internally**, so it
cannot (a) reauthorize each redirect hop against the scope policy or (b) bind a validated IP
decision to the actual connection. Both are mandatory SSRF controls, so HTTP probing uses an
in-process Go client whose `http.Transport.DialContext` enforces the scope decision on the addresses
it actually dials, and whose `CheckRedirect` reauthorizes every hop. A `httpx` adapter would need an
external redirect-reauthorization strategy and is deferred.

### Job / result contract

`DiscoveryJob`: `{ schemaVersion, scanId, projectId, stage, jobKey, kind, provider, policy, inputs,
limits, allowRestrictedAddresses, binaryPath?, resolverAddress?, rdapBaseUrl?, timeoutMs?,
maxOutputBytes?, fixturePath? }`.

`DiscoveryResult`: `{ schemaVersion, status, provider, providerVersion, execution, coverage,
records[], diagnostics[] }` where a record is a discriminated union of `HOST_OBSERVATION`,
`DNS_RECORD`, or `IP_METADATA`. The worker always emits `argv` as an array (never null) and every
`HOST_OBSERVATION` carries its `provider`; the control plane validates all of this before persist.

`binaryPath` is operator configuration only — it is never derived from user scan input.
