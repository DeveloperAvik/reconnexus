# Parameter discovery (stage 22)

Looks for undocumented query parameters on already-crawled URLs by injecting a fixed, short
wordlist of common parameter names, each with a unique random probe value, and comparing the
response to a calibration baseline.

## Why calibration comes first

A page that embeds a timestamp, a CSRF token, or any other per-request-varying content would
otherwise look "different" on every single probe, producing false positives for every parameter
tried. Before testing anything, two unmodified requests are made to the candidate URL itself (no
injected parameter) to measure how much the response naturally varies between two identical
requests. If the two baselines already differ in status code, or differ in length by more than
four times the detection margin, the candidate is treated as unstable and skipped entirely — no
wordlist parameter is ever tested against an unreliable baseline.

## Candidates

URLs already collected (crawling, sitemaps, etc.) that already carry a query string — the
clearest available signal that the endpoint is parameter-driven. Capped at 15 candidates per scan
(`MAX_PARAM_DISCOVERY_CANDIDATES`).

## The wordlist

A short, high-signal list of ~40 common application/debug/pagination parameter names (`id`,
`debug`, `admin`, `format`, `callback`, `page`, `limit`, `sort`, `filter`, `search`, `api_key`,
`token`, `session`, and similar — see `paramWordlist` in `paramdiscovery.go`). This is
deliberately not an exhaustive fuzzing list: a name absent from it is simply never tested, and its
absence from a result is never evidence the parameter doesn't exist.

## Classification

For each wordlist name, one request is made with that parameter added (set to a unique random
probe value) and compared against the baseline:

1. **`REFLECTED_VALUE`** (confidence 0.85): the exact probe value appears in the response body —
   the strongest possible signal, since a random value can only appear because the server
   echoed back what was sent.
2. **`STATUS_CODE_CHANGE`** (confidence 0.7): the response status code differs from the
   baseline's.
3. **`LENGTH_DELTA`** (confidence 0.5): the response length differs from the baseline by more
   than the candidate's own calibrated natural-variance margin.

If none of these apply, **nothing is recorded** — consistent with how the port scanner never
records a closed port. Only a positive discovery is ever persisted.

## Output

Every `PARAMETER_DISCOVERY` record is already a positive discovery, so every one becomes a
finding (`UNDOCUMENTED_PARAMETER`, `LOW`, `SUSPECTED`), carrying through the signal's confidence.

Opt-in via the `PARAMETER_DISCOVERY` capability (migration `0010`); excluded from the `quick` and
`stealth` profiles.

CLI: `reconnexus discovered-params <scanId> [--host --parameter --limit]`, `scan run
--param-discovery-providers`.
