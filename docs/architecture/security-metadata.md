# Security Metadata & Exposure Intelligence (Phase 6, stage 10)

Phase 6 is implemented as **Stage `10-security-checks`** (capability `SECURITY_CHECKS`). It enriches
existing assets with security-relevant metadata observed from in-scope services. It is read-only:
one bounded GET per service, no payloads, no crawling, no exploitation.

## Collection

Seed services come from Stage 04 HTTP observations (origins that returned a response). Each request
goes through the Phase 3A connection-bound transport (DialContext scope enforcement + per-hop
redirect reauthorization), with bounded concurrency, request timeout, response-size limit and
cancellation.

## Categories and observations

| Category | What is recorded |
| --- | --- |
| `TLS` | subject, issuer, notBefore, notAfter, `sha256` fingerprint, protocol, `selfSigned`, `hostnameMatch`, `daysToExpiry`, `validNow` |
| `HSTS` | presence and parsed `max-age`, `includeSubDomains`, `preload` |
| `HEADER` | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-Opener/Resource/Embedder-Policy (each `OBSERVED`/`NOT_OBSERVED`) |
| `COOKIE` | name + `Secure`/`HttpOnly`/`SameSite`/`Domain`/`Path`/`Max-Age` — **value never stored** |
| `CORS` | `allowOrigin`/`allowCredentials`/`allowMethods`/`allowHeaders`, `wildcard` |
| `CONTENT_TYPE` | declared `Content-Type` vs sniffed body type and `consistent` |

## Status model

`OBSERVED`, `INFERRED`, `INCONSISTENT`, `NOT_OBSERVED`, `UNKNOWN`, `COLLECTION_FAILED`.

- A missing header is `NOT_OBSERVED` with an explicit limitation — **never** a statement that the
  control is absent.
- A wildcard CORS origin combined with `Access-Control-Allow-Credentials: true` is `INCONSISTENT`.
- A declared content type that disagrees with the observed body type is `INCONSISTENT`.
- A failed request is `COLLECTION_FAILED`, distinct from a successful response with a missing header.

## Evidence and correlation

Every observation records its source, a short evidence string and an evidence type, and is linked to
the stored (redacted) evidence artifact. TLS metadata is correlated to a `CERTIFICATE` asset (keyed
by certificate SHA-256) through a `presents_certificate` relationship on the `SERVICE` asset. Direct
observations and (future) inferred relationships are kept distinct.

## Scope and safety

- Connection-bound transport; redirects reauthorized per hop; restricted addresses blocked.
- The authorized target set is **never** expanded (certificates, DNS, specs and CORS headers do not
  add targets).
- No cookie values, secrets, or authorization headers are persisted; evidence is redacted.
- TLS verification is never disabled.

## CLI

`reconnexus security <scanId> [--category C] [--status S] [--host H] [--limit N]` lists metadata
with status/category summaries. JSON output uses the standard envelope.

## Findings (conservative)

Security metadata is **inventory by default**. A single response is not proof that a control is
universally missing, so an absent header, an `INCONSISTENT` CORS combination or a collection failure
is never turned into a finding.

Exactly one finding rule is derived (`apps/control-plane/src/reporting/findings.ts`,
`insecureCookieFindings`): a cookie set over HTTPS (`Secure` absent) yields a **LOW**, `SUSPECTED`
candidate scoped to the endpoint, with the Set-Cookie attributes as evidence. It is explicitly not a
claim of exposure — that needs HTTP reachability and the cookie's purpose. The rule deduplicates by
service+cookie name and never fires for `NOT_OBSERVED` controls, plaintext-HTTP responses, `Secure`
cookies, or other categories.

## Limitations

- CORS is observed from a normal GET (no synthetic `Origin`); reflective-CORS behaviour is not
  tested and is stated as a limitation on the observation.
- `NOT_OBSERVED` describes one response at one point in time.
- The insecure-cookie finding is a candidate misconfiguration observation, not a demonstrated
  vulnerability; validation is manual.
