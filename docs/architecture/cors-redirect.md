# CORS misconfiguration and open-redirect probes (stage 19)

Two independent, read-only probes against targets already observed during earlier stages:
reflective CORS misconfiguration, and open redirect via a query parameter.

## CORS reflection

For each origin already observed during HTTP probing, one GET request is sent with an `Origin`
header set to a reserved, non-resolvable domain (`https://cors-probe.reconnexus.invalid`, RFC 2606
`.invalid`). The response's `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`
headers are then classified:

- **`REFLECTS_ARBITRARY_ORIGIN_WITH_CREDENTIALS`**: the arbitrary Origin was reflected back
  verbatim, and `Access-Control-Allow-Credentials: true` was also present. This is the serious
  case: any origin can read authenticated responses from a logged-in victim's browser.
- **`REFLECTS_ARBITRARY_ORIGIN`**: the arbitrary Origin was reflected back, without credentials.
  Weaker, but still an indication the server isn't checking Origin against an allowlist.
- **`NOT_VULNERABLE`**: the response did not reflect the probe's Origin. Recorded, not omitted, so
  the check's coverage is auditable.

This is a gap the existing `10-security-checks` stage explicitly calls out: it observes CORS
headers passively, without ever sending an `Origin` header, and says so in its own evidence
(`"observed without an Origin header; reflective CORS is not tested"`). This stage is what tests it.

Only reflection is tested here — not a wildcard (`*`) `Access-Control-Allow-Origin`, which the
security-checks stage already flags as inconsistent when combined with credentials, and not a
`null`-Origin variant, which is not implemented in this iteration.

## Open redirect

Candidates come from URLs already collected (crawling, sitemaps, etc.) whose query string carries
a parameter matching a known redirect-shaped name (`next`, `redirect`, `return_url`, `continue`,
`dest`, and similar — see `REDIRECT_PARAMETER_NAMES` in `stage-config.ts`) with a non-empty value.
For each candidate, that one parameter is overwritten with a reserved, non-resolvable canary URL
(`https://redirect-canary.reconnexus.invalid/`) and the request is sent with redirects not
followed. The response is classified:

- **`CONFIRMED`**: the response was a 3xx with a `Location` header that resolves to the injected
  canary URL — proof the parameter controls the redirect target.
- **`NOT_VULNERABLE`**: no redirect occurred, or it redirected somewhere other than the injected
  value. Recorded, not omitted, so the check's coverage is auditable.

No real browser is ever sent anywhere: the target of every request is always the in-scope URL
itself, and the only externally-named value involved is the reserved `.invalid` canary, which by
design cannot resolve.

## Output

`CORS_MISCONFIGURATION` and `OPEN_REDIRECT` records become `cors` and `open-redirect` observations
on the tested `URL` asset. Only `REFLECTS_ARBITRARY_ORIGIN*` and `CONFIRMED` become findings
(`CORS_MISCONFIGURATION` HIGH/MEDIUM depending on credentials, `OPEN_REDIRECT` MEDIUM);
`NOT_VULNERABLE` stays inventory.

CLI: `reconnexus cors <scanId> [--host --status --limit]`, `reconnexus redirects <scanId> [--host
--status --limit]`, `scan run --cors-redirect-providers`.

Opt-in via the `CORS_REDIRECT_CHECK` capability (migration 0009); excluded from the `quick` and
`stealth` scan profiles along with the other active-check stages.
