# Content discovery (stage 17)

Probes a short, fixed list of well-known sensitive paths on the HTTP origins observed during probing.

## Authorization and safety
- Requires `CONTENT_DISCOVERY` (add it to the policy's capabilities). Without it the stage is not planned,
  and a worker job is `BLOCKED`. The `quick` and `stealth` profiles leave the stage out.
- Unauthenticated `GET` only; nothing is submitted. The path list is fixed in the worker (it is not user
  supplied), about 90 requests per origin, at most 25 origins per scan. Rate and concurrency follow the
  policy limits (concurrency capped at 16).
- Every candidate URL is reauthorized against scope (including path exclusions) and requests use the
  connection-bound transport. Redirects are inspected, not followed, and are never treated as hits.

## Avoiding false positives
- **Calibration:** three random missing paths are requested per origin first. A response with the same status
  and a near-identical size/hash (or the same redirect target) is the origin's "not found" and is discarded.
  If calibration cannot reach the origin, the origin is counted as failed rather than scanned blind.
- Paths whose real content is not HTML (`.env`, dumps, archives) are rejected when the response is HTML.
- `CONFIRMED` needs a content marker (for example `ref:` in `.git/HEAD`, `KEY=value` lines in `.env`, a SQL
  `CREATE TABLE`) or a web-server directory index. Otherwise the hit is `POSSIBLE` with low confidence.
- 401/403 means the path exists but is protected: recorded as `INFO`, never as a finding.

## Data handling
Response bodies are inspected in memory and discarded. Evidence records the marker's name, never any body
text, so an exposed `.env` or dump does not copy its secrets into the evidence store.

## Output
`CONTENT_DISCOVERY` records become `content-discovery` observations on the URL. `CONFIRMED` hits and
`POSSIBLE` hits rated MEDIUM or above become `SUSPECTED` `EXPOSED_CONTENT` findings with category-specific
remediation. INFO hits and weak LOW possibilities stay inventory. Severity is the impact if the exposure is
real; nothing is validated. The list is short and fixed, so no hit is not proof of absence.

CLI: `reconnexus content <scanId> [--host --category --status --limit]`, `scan run --content-providers`.
