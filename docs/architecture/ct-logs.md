# Certificate Transparency log pivots

A new `builtin-ctlogs` provider inside the existing stage `02-subdomain-discovery`, alongside
`subfinder`/`assetfinder`/`amass`. It queries crt.sh's JSON API for the root domain and extracts
hostnames from the `common_name` and `name_value` fields of every matching certificate.

## Why this needs no new capability

Like `rdapProvider` (IP metadata) and the other third-party research lookups added alongside it
(`builtin-github-leaks`, `builtin-wayback-diff`), the request target is a shared public research
service (crt.sh), never the authorized target — so it runs under the existing `PASSIVE`
capability with a plain HTTP client and no scope check on the request itself. Discovered
hostnames are candidates only: like any other passive-discovery tool's output, they are
revalidated against scope the first time anything would actually act on them (DNS resolution,
HTTP probing).

## Filtering

A certificate's SAN list can include unrelated domains (a shared hosting cert, a multi-tenant
SaaS wildcard). Discovered names are kept only when they equal the queried root domain or are a
subdomain of it; a leading `*.` wildcard marker is stripped first.

## Availability

Not included in the default `SUBDOMAINS` provider list (same caution as `amass`, which is also
available but not default) — opt in with `--providers subfinder,assetfinder,builtin-ctlogs`.
Unlike the external-binary tools, it has no installation dependency: it's Go-native and always
available.

An operator can point it at a self-hosted or alternate crt.sh-compatible mirror via the
`RECONNEXUS_CTLOG_BASE` environment variable (default `https://crt.sh`).
