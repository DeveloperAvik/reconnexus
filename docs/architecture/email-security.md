# Email security posture (stage 20)

Checks the scan's root domain for SPF, DMARC, and a fixed list of common DKIM selectors. All of
it is read-only DNS TXT/MX lookups against the domain itself — never a connection to a mail
server, and never an attempt to send mail.

## Why this always runs (not opt-in)

Every other active-check stage added so far (content discovery, cloud storage, CORS/redirect,
port scan, template checks) gates on its own capability because it sends packets to the target's
web or network infrastructure. This stage only ever queries public DNS records for a domain
already in scope, under the same `DNS` capability every scan already requires to do anything at
all — the same basis the core `03-dns-infra` stage runs on. So it is in `IMPLEMENTED_STAGES` but
deliberately **not** in `OPT_IN_STAGES`: it always runs, and it is not excluded from the `quick`
or `stealth` profiles either, since it adds no additional footprint against the target beyond
ordinary DNS resolution.

## SPF

One TXT lookup for the root domain, looking for a record starting `v=spf1`.

- **`ABSENT`**: no SPF record found.
- **`MISCONFIGURED`**: more than one SPF record (RFC 7208 requires exactly one; behavior with
  multiple is undefined), or a record ending in `+all` (explicitly permits any sender to pass).
- **`STRONG`**: the record ends in `-all` (hard fail for unlisted senders).
- **`WEAK`**: the record ends in `~all` (softfail) or `?all` (neutral), or has no `all`
  mechanism at all (evaluation falls through with no explicit terminal policy).

## DMARC

One TXT lookup at `_dmarc.<domain>`, looking for a record starting `v=DMARC1`.

- **`ABSENT`**: no DMARC record found.
- **`MISCONFIGURED`**: more than one DMARC record, a record missing the required `p=` policy
  tag, or an unrecognized policy value.
- **`STRONG`**: `p=quarantine` or `p=reject` (enforced).
- **`WEAK`**: `p=none` (monitoring only — failing mail is not rejected or quarantined).

## DKIM

TXT lookups at `<selector>._domainkey.<domain>` for a fixed list of selectors used by common mail
providers (Google Workspace, Microsoft 365, and a handful of others — see
`commonDKIMSelectors` in `emailsecurity.go`).

- **`DETECTED`**: a key record was found at one of the probed selectors.
- **`NOT_DETECTED`**: none were. **This is never proof DKIM is absent** — only that the domain
  doesn't use one of the selectors this stage knows to check. It is recorded at low confidence
  (0.3) and never becomes a finding, for exactly that reason.

## Output and findings

`EMAIL_SECURITY` records become `email-security` observations on the checked domain's `HOST`/
`SUBDOMAIN` asset. Only SPF/DMARC `ABSENT`, `WEAK` and `MISCONFIGURED` become findings
(`EMAIL_SECURITY_WEAKNESS`, `MEDIUM` for DMARC and any `MISCONFIGURED`, `LOW` for SPF
`ABSENT`/`WEAK`). DKIM never becomes a finding, for the reason above. `STRONG` and `DETECTED`
stay inventory — good posture, not an issue to report.

CLI: `reconnexus email <scanId> [--category --status]`, `scan run --email-providers`.
