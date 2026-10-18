# Admin Login & cPanel Finder (Stage 14)

`14-login-finder` is a read-only interface-discovery stage. It requests a small, fixed set of
well-known administrative paths and hosting-control-panel ports on origins already observed during
HTTP probing, and records the interfaces it can verify from the response. It never submits
credentials and never attempts authentication.

## Pipeline placement

```
… 11-correlation → 13-subdomain-takeover → 14-login-finder → 12-reporting
```

Numeric labels are stable identifiers; execution order is the `OrderedStages` array. The stage runs
after HTTP probing has established which origins are live and before reporting so its coverage is
included in the assessment.

- Capability: `ACTIVE_HTTP` (the same capability used for the initial HTTP probe).
- Provider: `builtin-login-finder` (in-process Go).
- Input: origins (`scheme://host[:port]`) from successful/redirect-denied HTTP observations,
  capped at 25 origins per scan.

## Probes

| Kind | Candidates |
| --- | --- |
| `ADMIN` | `/admin`, `/admin/login`, `/administrator`, `/login`, `/signin`, `/wp-admin/`, `/wp-login.php`, `/phpmyadmin/`, `/manager/html`, `/admin/index.php` |
| `CPANEL` | `/cpanel`, `/whm`, `/webmail`; ports `2083` (https), `2082` (http), `2087` (https), `2086` (http), `2096` (https), `2095` (http) |

The candidate set is fixed and bounded (at most 800 candidate URLs per run). Candidate URLs are
individually reauthorized against the scope policy, so path exclusions still apply.

## Detection and status

| Status | Meaning |
| --- | --- |
| `DETECTED` | A concrete marker was observed: a password form, a service-specific header/cookie (e.g. `cpsrvd`), a control-panel title, or an administrative login page. |
| `POSSIBLE` | Weaker evidence only: an authentication-required/forbidden status on a known administrative path, a login/admin title, or a control-panel port responding without a marker. |

Records include `kind` (`ADMIN`/`CPANEL`), `status`, `confidence`, HTTP status, final URL, page
title, and redacted evidence. A generic `200` page with no login or control-panel marker is never
reported. These are reconnaissance observations, not vulnerability findings.

## Safety

- **Read-only:** only unauthenticated `GET` requests; no credentials, payloads, or authentication
  attempts.
- **Scope-enforced:** every candidate URL is checked with `ACTIVE_HTTP`; the HTTP client is
  connection-bound and reauthorizes every redirect hop.
- **Rate-limited:** requests go through the shared policy `requestsPerSecond` limiter.
- **Bounded:** fixed path/port set, bounded body size, per-request timeout, and a maximum candidate
  count.
- **Honest coverage:** speculative control-panel ports that refuse connections are recorded as
  skipped, not as findings or hard failures.

## CLI

```bash
reconnexus admin <scanId>  [--status DETECTED|POSSIBLE] [--host substr] [--confidence 0.7] [--limit N]
reconnexus cpanel <scanId> [--status DETECTED|POSSIBLE] [--host substr] [--confidence 0.7] [--limit N]
```

## Limitations

- Only the fixed candidate list is checked; a custom admin path is not discovered by this stage.
- Interface presence does not imply weak authentication or authorization. No login attempt is made.
- A host on a non-standard control-panel port not in the list is not reported.
