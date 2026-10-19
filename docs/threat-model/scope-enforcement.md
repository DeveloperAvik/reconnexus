# Scope Enforcement Threat Model

Scope enforcement exists to guarantee that ReconNexus never sends traffic outside an explicitly
authorized assessment. It is a safety rail, not a legal authorization.

## Assets

- Target availability and integrity.
- Operator safety: avoiding accidental access to internal networks, cloud metadata, or third
  parties discovered during reconnaissance.
- Assessment integrity: scope decisions must be reproducible and auditable.

## Enforcement points

| # | Check | Where |
| --- | --- | --- |
| 1 | Reject expired/revoked authorization | TS `ScopeEngine`, Go `scope.Engine` |
| 2 | Reject not-yet-valid authorization | same |
| 3 | Require the capability to be granted | same |
| 4 | Reject excluded hosts/domains/IPs/CIDRs/paths (precedence over inclusion) | same |
| 5 | Require a **positive** scope match | same |
| 6 | Validate destination addresses at connection time | `resolvedAddresses` |
| 7 | Restricted-address denial (loopback, link-local, private, CGNAT, metadata, reserved) | same |
| 8 | Reauthorize redirect destinations | `isRedirect` request flag (Phase 4 wiring) |
| 9 | DNS-rebinding guard: judge on the resolved answer, not the name | `resolveAndCheck` |
| 10 | Record every allow/deny in the audit trail | `auditSink` + `audit_events` |

The engine is implemented **twice** — once in TypeScript (control plane) and once in Go (worker).
The worker re-checks independently so a compromised or misconfigured control plane cannot cause an
out-of-scope connection.

## Threats and mitigations

| Threat | Mitigation |
| --- | --- |
| **DNS rebinding** — public name later resolves to `127.0.0.1`/`10.0.0.1` | Destination is validated on the *resolved* addresses at connection time; failure to resolve is a denial. Re-resolve on each hop. |
| **Redirect pivot** — in-scope URL redirects to an attacker host | Every redirect hop is reauthorized with `isRedirect: true`. |
| **Alternate IP encodings** — `0177.0.0.1`, decimal, IPv6 forms | Strict parsers reject ambiguous forms (e.g. leading-zero octets) and canonicalize before classification. |
| **IPv4-mapped IPv6** — `::ffff:127.0.0.1` bypassing an IPv4-only blocklist | Addresses are unwrapped (`Unmap`) before classification. |
| **Cloud metadata** — `169.254.169.254`, `fd00:ec2::254` | Explicitly classified as `isMetadata` and denied. |
| **Discovery ≠ authorization** — a discovered IP or CIDR is treated as in scope | Discovered infrastructure is only *candidate*; inclusion requires an explicit scope entry. |
| **CIDR over-reach** — scanning a whole range because one IP matched | CIDR expansion is candidate discovery only; workers never auto-scan a range. |
| **Policy drift** — reused version with different content | `scope_policies` is unique per `(project_id, version)`; a mismatched `policyId` is rejected. |
| **Credential leakage in logs** | Central redaction for sensitive keys and secret-shaped values (TS + Go). |

## Restricted address space (P2-1)

Restricted classes: loopback, private/unique-local, link-local, CGNAT, cloud metadata, multicast,
unspecified, broadcast and reserved ranges. The address check runs on every literal IP target and on
every DNS-resolved answer (initial request, each redirect hop, and at dial time), before the
positive scope match. Both engines (`packages/scope-policy/src/engine.ts`,
`workers/internal/scope/scope.go`) implement the same rule:

| Address | Allowed when |
| --- | --- |
| Public / routable | Normal scope rules apply. |
| Documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) | Explicitly listed in `inScope.ips`/`cidrs`. These are never routable, so no override is needed. |
| Any other restricted class | **All three**: listed in `inScope.ips`/`cidrs`, **and** the policy grants `INTERNAL_NETWORK`, **and** the operator override is set (`network.allowRestrictedAddresses` / `--allow-restricted`; worker: `allowRestrictedAddresses`). |

Consequences:

- An explicit IP/CIDR entry alone never reaches loopback, private, link-local or metadata space.
  (Before P2-1 the engines let an explicit entry bypass the capability and override; the docs already
  required all three, so the code was brought in line.)
- The override never opens unlisted restricted space. A name that rebinds to an unlisted
  private/loopback/metadata address is denied even with `INTERNAL_NETWORK` and the override on.
- A DNS answer that falls inside an explicitly listed restricted CIDR is treated like a literal
  entry: it additionally needs the capability and override.
- Exclusions still win over inclusions, and IPv4-mapped IPv6 forms are unwrapped before all checks.
- Residual: with the full triple present, an in-scope hostname resolving to a *listed* restricted
  address is permitted. That is the explicit operator authorization.

## Test gates

The security suite (`test/security/scope-security.test.ts`) is a **release gate**: it fails if any
out-of-scope target is allowed. It covers the out-of-scope URL corpus, all restricted address
classes (including IPv4-mapped IPv6), redirect reauthorization, DNS-failure-as-denial, and an
injected rebinding answer.

The Go suite (`workers/internal/scope/scope_test.go`) mirrors these properties for worker-side
enforcement.

## Residual risks

- This document was written while only stages 00–03 were implemented, so its examples focus on
  Stage 00 and the Phase 2 discovery stages (01–03); the scope engine gates every active stage
  through 14 the same way, wired into live provider execution by the worker.
- Registrable-domain parsing uses the Public Suffix List in **both** engines: `tldts` in
  TypeScript and `golang.org/x/net/publicsuffix` in Go. Agreement is enforced by the shared
  conformance fixtures and the cross-language conformance test.

## HTTP probing: redirect and SSRF controls (Phase 3A)

The HTTP provider treats every request as untrusted. For each request it:

1. normalizes the URL and authorizes the hostname against the scope policy;
2. resolves the destination (injectable resolver; a failed resolution is never an allow);
3. validates every resolved address against the restricted-address policy;
4. **binds the validated decision to the connection** — the transport's `DialContext` re-resolves
   and re-checks the addresses it is about to dial, so a name that rebinds to a private/loopback/
   metadata address is blocked at connect time;
5. reauthorizes **every redirect hop** independently (never assuming the initial host authorizes the
   destination), including excluded hosts, out-of-scope domains, and restricted addresses;
6. enforces the configured redirect count (`TOO_MANY_REDIRECTS` beyond it).

A denied redirect does not discard data: the permitted pre-redirect response metadata is preserved
and the observation is recorded as `REDIRECT_DENIED`. TLS verification is never disabled globally
(an explicit CA bundle may be configured for tests, but verification always runs). Cookies,
`Authorization`, and other sensitive headers are never persisted.

## URL collection (Phase 4)

- **Discovered URLs are untrusted input.** Every URL from a crawler, archive, robots.txt or sitemap
  is re-checked against the scope policy before it is persisted or crawled; out-of-scope candidates
  are counted as skipped and never become assets or crawl seeds.
- The built-in crawler uses the Phase 3A connection-bound transport: each dial re-resolves and
  re-validates the address it is about to use, and every redirect hop is reauthorized. DNS rebinding
  during a crawl is therefore blocked at connect time.
- `katana` is opt-in and documented as **not** connection-bound; it runs with redirects disabled and
  all output is post-filtered.
- Passive providers (gau/waybackurls) query third-party archives and never send traffic to the
  target; URLs outside the authorized scope are rejected, not treated as eligible targets.
- robots.txt `Disallow`/`Allow` paths are recorded as **candidates only** — robots rules are not
  treated as authorization to access resources.
- Crawl depth, request budget, concurrency, timeout and response-size limits bound resource use;
  cancellation is honored. Credentials, cookies and authorization headers are never collected as URL
  metadata.

## JavaScript & API intelligence (Phase 5)

- **Artifacts and specs are fetched through the connection-bound transport** (Phase 3A): each dial
  re-resolves and re-validates the address, and redirects are reauthorized per hop. Source-map
  fetches are additionally pre-checked against scope.
- **Extracted endpoints are scope-checked by origin.** A JavaScript file or API specification may
  reference other hosts; any endpoint whose origin is not authorized is dropped and counted, so an
  artifact cannot expand the target set. Endpoints are recorded as candidates only and are never
  fetched in this phase.
- **No code execution**: no JavaScript is executed, no browser is used, no downloaded packages are
  installed, and no `eval`/expression evaluation occurs. Source-map `sourcesContent` bodies are not
  persisted; only source paths and counts are retained.
- **Secret hygiene**: extracted evidence strings are passed through centralized redaction; the
  scanner persists only minimal evidence and never stores authorization headers, cookies, tokens,
  or credentials from artifacts.
- **Input bounds**: artifacts and specs are size-capped, candidate counts are capped, and Go's RE2
  engine is linear-time (immune to catastrophic backtracking), so adversarial input cannot cause
  runaway analysis.
- **Remote `$ref` is never fetched automatically**, and no live GraphQL introspection is performed.

## Security metadata (Phase 6)

- Metadata collection uses the connection-bound transport (Phase 3A): connect-time address
  validation and per-hop redirect reauthorization; the service set is seeded only from services
  already observed in scope. Certificates, CORS headers, DNS records or API specs **never** expand
  the authorized target set.
- Only one bounded GET per service is issued; no payloads, no crawling, no exploitation.
- **Cookie values, secrets, session tokens and authorization headers are never persisted** — only
  cookie attributes (Secure/HttpOnly/SameSite/Domain/Path/Max-Age).
- TLS verification is never disabled. Evidence strings pass through redaction.
- A missing header is recorded `NOT_OBSERVED` with a limitation and is explicitly not a claim that
  the control is absent; a failed request is `COLLECTION_FAILED`.

## Secret detection (Phase 7)

- Stage 09 re-collects eligible artifacts through the connection-bound transport; the authorized
  target set is never expanded and references found inside artifacts are never followed.
- **Raw detected values are never persisted or printed.** Only a redacted snippet, rule/category,
  confidence, location, artifact reference, and a keyed HMAC fingerprint are stored. Findings pass
  through the global redactor; private keys and minified lines store a context-free marker.
- Credentials are never used, no login/authorization tests are performed, and no values are sent to
  external services or secret scanners.
- A pattern match is never treated as a valid, active, or exploitable credential.
- Raw artifacts are not retained, minimizing the blast radius of any artifact store.

## Evidence correlation (Stage 11)

- Correlation is a deterministic join over **already-persisted** records: it makes no network
  requests and cannot expand the target set or bypass scope.
- It stores only an opaque `correlationGroup = sha256(rule|fingerprint)[:16]` — never the HMAC
  fingerprint and never a raw secret value — in correlation records, coverage details, logs, or CLI
  output.
- It never promotes a candidate secret into a validated/active finding, never compares empty
  fingerprints, never treats shared fingerprints as proof of validity/exploitability, and never
  authenticates with or transmits discovered values.
- Ambiguous or unsupported relationships fail closed (no relationship is produced).

## Reporting (Stage 12)

- Report generation performs no network requests and cannot expand the target set or bypass scope.
- A structure-preserving redactor is re-applied at the report boundary and the result is re-validated;
  it **fails closed** — on any error nothing is emitted or persisted. No raw secret values, HMAC
  fingerprints, or artifact bodies appear in reports, JSON/CSV/JSONL output, logs, filenames, or
  error messages.
- Reports never promote candidates to confirmed credentials and never assert exploitability; the
  fixed limitations list states this.
- Report generation does not change upstream coverage or promote an incomplete scan to complete.

## TS/Go parity (Phase 8)

Scope enforcement runs in two independent engines; a divergence between them is a scope defect. A
Phase 8 audit found that URL path canonicalization differed on percent-encoded dot-segments: the
TypeScript engine (WHATWG URL) resolves `%2e`/`%2E`, so `http://h/%2e%2e/logout` normalizes to
`/logout` and matches a path exclusion, whereas the Go engine previously kept `/%2e%2e/logout` and
would **not** match the exclusion. This was fixed by implementing WHATWG dot-segment rules in Go and
using the same normalization in the Go scope engine. Both engines are now asserted, by shared
conformance fixtures, to agree on adversarial encoded paths and scope decisions.

## Subdomain-takeover detection (Stage 13)

- **Non-destructive and candidate-only**: it reads the CNAME (DNS) and issues one bounded GET to the
  authorized host; it never claims, registers, or interacts with the third-party service, and it
  never reports a confirmed takeover.
- **Scope-enforced**: every host is reauthorized (`TAKEOVER_CHECK`) and the request uses the
  connection-bound transport (address validation + per-hop redirect reauthorization). The CNAME
  target is never contacted directly.
- **No over-claiming**: results carry `SUSPECTED`/`CANDIDATE`/`NOT_VULNERABLE`/`INCONCLUSIVE` status
  and confidence; absence of a candidate is not proof no takeover exists. Evidence is redacted.

## Worker-side discovery enforcement

The Go worker is the boundary that actually contacts the network. Before any provider runs it
re-checks the policy independently:

- the subdomain root domain must be authorized for the provider's capability;
- every DNS name to resolve must pass a `DNS` check, and out-of-scope names are skipped (counted);
- an IP is only correlated when the in-scope host it was discovered through passes a `PASSIVE`
  check.

Discovered hosts and IPs are recorded as *discovered* assets, never promoted to authorized active
targets. A compromised or misconfigured control plane therefore cannot make the worker resolve or
contact an out-of-scope name.
