# Provider Compatibility Matrix

ReconNexus has two kinds of provider: **external binaries** (invoked with a structured argv array,
never a shell) and **built-in in-process providers** (Go). The machine-readable external matrix is
emitted by `reconnexus providers matrix` (`--json` for scripting).

## External binaries

| Provider | Source | Capabilities | Network | Timeout | Binary |
| --- | --- | --- | --- | --- | --- |
| `subfinder` | external_binary | PASSIVE | PASSIVE | 600s | `subfinder` |
| `amass` | external_binary | PASSIVE, DNS | PASSIVE | 900s | `amass` |
| `assetfinder` | external_binary | PASSIVE | PASSIVE | 300s | `assetfinder` |
| `dnsx` | external_binary | DNS | ACTIVE | 300s | `dnsx` |
| `httpx` | external_binary | ACTIVE_HTTP | ACTIVE | 600s | `httpx` |
| `katana` | external_binary | CRAWL | ACTIVE | 900s | `katana` (opt-in; not a default) |
| `gau` | external_binary | PASSIVE | PASSIVE | 600s | `gau` |
| `waybackurls` | external_binary | PASSIVE | PASSIVE | 600s | `waybackurls` |
| `mapcidr` | external_binary | PASSIVE | NONE | 60s | `mapcidr` |
| `nuclei` | external_binary | SECURITY_CHECKS, ACTIVE_TEMPLATE_CHECK | ACTIVE_TEMPLATE | 900s | `nuclei` |

- **Health checks** (`providers check <name>` / `doctor`) run the binary's version probe; a binary
  that merely exists but fails its probe is reported `FAILED_HEALTHCHECK`, never `OK`.
- **Missing binary** ⇒ stage `SOURCE_UNAVAILABLE` (never an empty success).
- **Version detection:** a 3-part semver is extracted from the version probe; below-minimum versions
  are not currently enforced (documented limitation).
- **Architecture:** the dev host is macOS `arm64`; all listed tools are `arm64` native. Linux workers
  are the documented production target.

## Built-in in-process providers

| Provider | Stage | Capability | Network | Notes |
| --- | --- | --- | --- | --- |
| `builtin-crawler` | 05 | CRAWL | ACTIVE | Connection-bound DialContext + per-hop redirect reauthorization. |
| `builtin-static` | 05 | ACTIVE_HTTP | ACTIVE | robots.txt + sitemaps. |
| `builtin-http` | 04 | ACTIVE_HTTP | ACTIVE | Connection-bound probing + fingerprints. |
| `builtin-dns` | 03 | DNS | ACTIVE | Go resolver; wildcard detection. |
| `builtin-js` | 07 | JS_ANALYSIS | ACTIVE | Artifact retrieval/hash + bounded static analysis + source maps. |
| `builtin-api` | 08 | API_DISCOVERY | ACTIVE | OpenAPI/Swagger JSON+YAML. |
| `builtin-secret-scan` | 09 | SECRET_SCAN | ACTIVE | Re-collects eligible artifacts in-memory; redacted findings only. |
| `builtin-security-meta` | 10 | SECURITY_CHECKS | ACTIVE | TLS/HSTS/headers/cookie attributes/CORS/content-type. |
| `builtin-takeover` | 13 | TAKEOVER_CHECK | ACTIVE | CNAME fingerprints + one bounded GET per host; candidate-only. |
| `builtin-content` | 17 | CONTENT_DISCOVERY | ACTIVE | ~90 fixed sensitive paths per origin, soft-404 calibrated; bodies never stored. |
| `builtin-cloud-storage` | 18 | CLOUD_STORAGE_CHECK | ACTIVE | One GET per CNAME-derived candidate, always to the in-scope host itself. |
| `builtin-cors-redirect` | 19 | CORS_REDIRECT_CHECK | ACTIVE | One GET per CORS target (crafted Origin header) and per open-redirect candidate (one query parameter overwritten with a reserved canary URL). |
| `builtin-login-finder` | 14 | ACTIVE_HTTP | ACTIVE | Fixed admin-login and cPanel/WHM/webmail path/port probes; read-only. |
| `offline-ipmeta`, `mock`, `mock-url` | — | — | NONE | Deterministic test fixtures. |

Built-in providers are **always available** (no external dependency) and are the trusted default
because they enforce scope at the connection boundary.

## Archive-dependent providers (`gau`, `waybackurls`)

These query third-party archives and are inherently unreliable. The suite distinguishes:

| Condition | Result |
| --- | --- |
| Provider returns URLs | `SUCCEEDED` with records |
| Provider returns no URLs | `SUCCEEDED` with zero records (an empty result is a real, reported outcome) |
| Provider times out | `FAILED` (diagnostic "provider timed out") |
| Provider binary missing | `SOURCE_UNAVAILABLE` |
| Provider exits non-zero | `FAILED` with the exit code recorded |

An empty result is never substituted for a failure, and a failure is never reported as empty success.

## Tested failure behaviour

Covered by deterministic tests: missing executable, non-zero exit, timeout, output truncation,
malformed output, cancellation, and (for archive providers) empty results and unavailability.
