# Subdomain-Takeover Detection (Stage 13)

`13-subdomain-takeover` is a **non-destructive, candidate-only** detector. It reports that a
subdomain points (via CNAME) at a takeover-prone service and shows the service's response. It is
**not** a claim that the subdomain is takeoverable, and it never attempts to claim, register, or
otherwise interact with the third-party service.

## Pipeline placement

`OrderedStages` runs it after correlation and **before reporting** so reports include its findings:

```
… 10-security-checks → 11-correlation → 13-subdomain-takeover → 14-login-finder → 12-reporting
```

Numeric labels are stable identifiers; execution order is the `OrderedStages` array. The orchestrator
iterates jobs in that declared order (not lexicographic `job_key` order).

- Capability: `TAKEOVER_CHECK` (must be present in the scope policy).
- Provider: `builtin-takeover` (in-process Go).
- Input: `https://<host>/` URLs built from the scan's in-scope `SUBDOMAIN`/`HOST` assets.

## Detection

For each in-scope host:

1. Resolve the **CNAME** (read-only DNS). If there is no CNAME, or the target is not a
   fingerprintable service, nothing is emitted.
2. Match the CNAME against a maintained set of takeover-prone services (exact or label-suffix),
   including GitHub Pages, Heroku, Amazon S3/CloudFront, Azure App Service/Traffic Manager/Blob,
   Fastly, Netlify, Vercel, Surge, Pantheon, Read the Docs, Shopify, Tumblr, Zendesk, Ghost,
   UserVoice, Statuspage, WordPress.com.
3. Issue **one bounded HTTP GET** to the host (connection-bound transport, size/timeout limited) and
   look for that service's "unclaimed" marker.

Statuses:

| Status | Meaning |
| --- | --- |
| `SUSPECTED` | CNAME to the service **and** an unclaimed marker matched (highest signal). |
| `CANDIDATE` | Reserved for a service-specific signal that is weaker than a marker; not currently emitted. |
| `NOT_VULNERABLE` | CNAME to the service but the resource appears claimed (no marker). |
| `INCONCLUSIVE` | CNAME matched with an unclaimed-style status but no service-specific marker, or the HTTP request failed/timed out. |

Each record stores the host, CNAME, service, status, confidence, HTTP status, and redacted evidence.

**False-positive control.** Only `SUSPECTED` (a service-specific unclaimed marker matched) is treated
as an actionable finding; `CANDIDATE` also counts when emitted. `NOT_VULNERABLE` and `INCONCLUSIVE`
remain in the `takeoverCandidates` inventory but are **not** turned into report findings. A matching
HTTP status *alone* (e.g. a plain 404) is reported `INCONCLUSIVE` with `evidenceType: STATUS_ONLY` —
it is never a candidate, because ordinary error pages on claimed resources return the same status.
Generic marker strings were removed from the fingerprint set for the same reason; only
service-specific markers (e.g. GitHub Pages' "there isn't a github pages site here") raise a
candidate.

## Safety

- **Non-destructive:** DNS read + a single GET. No claiming, registration, payloads, or
  authentication.
- **Scope:** every host is reauthorized against the policy (`TAKEOVER_CHECK`); the HTTP request uses
  the connection-bound transport (address validation + per-hop redirect reauthorization).
- **No expansion:** only the in-scope subdomains are checked; the CNAME target (third party) is never
  contacted directly — the request goes to the authorized host.
- **No false certainty:** results are candidates with confidence, not confirmed takeovers; absence of
  a candidate is not proof that no takeover exists.
- Evidence is passed through redaction.

## CLI

`reconnexus takeover <scanId> [--status S] [--service name] [--host substr] [--limit N]` lists
candidates, their service, HTTP status and CNAME, and a reminder that candidates are not confirmed
takeovers. Reports include a `takeoverCandidates` section.

## Limitations

- Fingerprint set is curated and finite; a dangling CNAME to an unlisted service is not reported.
- A service may change its "unclaimed" response at any time; `NOT_VULNERABLE` reflects one response.
- CNAME-only dangling detection; A-record/NXDOMAIN-style takeovers and non-CNAME services are not
  covered.
