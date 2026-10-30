# Wayback diffing (stage 24)

Compares the Wayback Machine's CDX index for the scan's root domain against every URL this scan
has already observed, to surface paths that were archived returning a successful response at
some point but aren't reachable through anything this scan's own crawl found — candidates for a
forgotten-but-possibly-still-live endpoint (an old admin panel, a retired API version, a debug
page nothing links to anymore).

This is distinct from the existing `waybackurls`/`gau` passive URL-collection providers (stage
`05-url-collection`), which feed historical URLs in as crawl *seeds* to visit. This stage instead
*diffs* the archive against what was actually found, which is the part those providers don't do.

## Scope

The request target is `web.archive.org`'s CDX API, never the authorized target — like
`builtin-ctlogs`/`builtin-github-leaks`, a plain HTTP client with no scope check. **This is never
a live check**: a diffed path is not requested again here, only compared against what this scan
already observed. Confidence is capped at 0.5 for that reason — a page in the archive may well no
longer exist, may have moved, or may require different handling now.

## The query

One CDX request: `url=<domain>/*&output=json&fl=timestamp,original,statuscode,mimetype&
collapse=urlkey&limit=5000`. Only rows with `statuscode == "200"` are considered (a historical
404 isn't interesting). Each result's host+path (ignoring scheme, query string and a trailing
slash) is compared against the same reduction of every URL this scan collected; a match means
the archived path is accounted for and is skipped. Capped at 100 diffed records per scan.

An operator can point it at an alternate CDX-compatible endpoint via
`RECONNEXUS_WAYBACK_BASE` (default `https://web.archive.org`).

## Output

`WAYBACK_DIFF` records stay inventory — this is a recon lead for manual follow-up, not a
verified finding, so it never produces an automatic report finding.

Opt-in via the `WAYBACK_DIFF` capability (migration `0011`); excluded from the `quick` and
`stealth` profiles.

CLI: `reconnexus wayback <scanId> [--host --limit]`, `scan run --wayback-providers`.
