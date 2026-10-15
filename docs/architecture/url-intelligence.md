# URL Intelligence (Phase 4, stage 05)

Stage 05 discovers URLs, canonicalizes them, classifies them, and persists them with provenance.
It runs after HTTP probing and is seeded from HTTP observations (fallback: resolved in-scope hosts).

## Collection methods

| Provider | Method | Capability | Notes |
| --- | --- | --- | --- |
| `builtin-crawler` | Active BFS crawl | `CRAWL` | Connection-bound transport (Phase 3A), per-hop redirect reauthorization, depth/budget/concurrency/timeout/response limits. |
| `builtin-static` | robots.txt + sitemaps | `ACTIVE_HTTP` | `<urlset>` and bounded `<sitemapindex>` recursion. |
| `gau` | Passive | `PASSIVE` | Public archives; may be slow/rate-limited (reported honestly). |
| `waybackurls` | Passive | `PASSIVE` | Wayback CDX. |
| `katana` (opt-in) | Active crawl | `CRAWL` | `-dr -jsonl` + scope regex + post-filter; **not** connection-bound. |
| `mock-url` | Fixture | — | Deterministic tests. |

Passive providers only query third-party archives; they never send traffic to the target. Every URL
they return is re-checked against the scope policy before persistence, and out-of-scope candidates
are counted as skipped and neither persisted nor crawled.

## Script-reference discovery (`<script src>`)

The active crawler additionally parses the `src` attribute of `<script>` tags in in-scope HTML
documents. For each reference it:

- resolves the URL against the **effective** document URL (after redirects), so relative,
  root-relative, protocol-relative and query-bearing references all resolve correctly;
- authorizes and canonicalizes it, deduplicating by canonical identity;
- marks the URL observation `scriptRef: true` with `parentUrl` set to the referencing document;
- adds a `JAVASCRIPT` classification (`evidenceType: SCRIPT_REF`) when the path has no script
  extension, so extensionless bundles reach Stage 07 (JS intelligence).

Inline script bodies are never parsed for URLs, and a reference to a clearly non-script asset
(image/font/CSS/download) is not relabelled as JavaScript. Script and static URLs are recorded in the
inventory but are **not** added to the crawl frontier, so they do not consume the request budget;
Stage 07 retrieves them once with content validation. Stage 07 selects URLs classified `JAVASCRIPT`,
referenced by a `<script src>` (`scriptRef`), or ending in `.js`/`.mjs`.

## Canonicalization (deduplication identity)

`canonicalUrl` is the dedup key. Applied transformations:

- scheme and host lowercased;
- internationalized host → punycode (IDNA);
- default ports (80/443) removed;
- RFC 3986 dot-segment (`.`/`..`) removal in the path;
- fragment removed (not part of HTTP request identity).

Deliberately **not** applied (these can change application behavior):

- query parameters are not sorted, removed, or collapsed; repeated parameters are preserved in order;
- the trailing slash is preserved (`/a` ≠ `/a/`);
- existing percent-encoding is preserved (no decoding; `%2F` stays `%2F`).

The original observed URL is stored alongside the canonical URL, so normalization never erases the
raw value. Canonicalization is implemented in Go (`matching.CanonicalURL`) and mirrored in
TypeScript (`parseUrl().canonical`); agreement is enforced by
`test/fixtures/conformance/urls.json`.

## Deduplication and provenance

- `URL` assets dedupe by `canonicalUrl` (unique `(project_id, type, canonical_key)`).
- Each provider's discovery is a separate `url` observation, so multi-provider discovery is retained.
- Within a single provider run, the crawler emits one observation per canonical URL (candidates are
  updated in place when later fetched); passive providers dedupe their own output.
- `contains_url` relationships link the host asset to the URL asset.

## Classification

`workers/internal/discovery/urlclassify.go` produces, per URL:

- **Categories** (with confidence + evidence): `HTML_PAGE`, `API_ENDPOINT`, `GRAPHQL`, `JAVASCRIPT`,
  `STATIC_ASSET`, `AUTHENTICATION`, `REGISTRATION`, `PASSWORD_RECOVERY`, `SESSION`, `SEARCH`,
  `FILTER`, `PAGINATION`, `EXPORT`, `UPLOAD`, `DOWNLOAD`, `DOCUMENTATION`, `API_SPEC`, `DEVELOPER`,
  `ADMIN`, `REDIRECT`, `UNKNOWN`.
- **Parameter roles** (per query parameter): `pagination`, `search`, `filter`, `identifier`,
  `redirect`, `file_path`, `auth_token`, `unknown`.

Design rules: evidence is always recorded; multiple hypotheses are allowed; route-only guesses are
low confidence; and these are **reconnaissance hints, not vulnerability findings**. A parameter
named `url`, `redirect`, `file`, or `id` is explicitly not treated as proof of a vulnerability.

## Measurement

`reconnexus urls <scanId> --stats` reports: per-provider record counts and outcomes, raw
observations, unique canonical URLs, duplicate rate, skipped-by-provider candidates, method/host
distribution, classification distribution, and parameter inventory.

Classification quality is measured against a small hand-labeled fixture in
`workers/internal/discovery/urlclassify_test.go`, which prints a confusion matrix. On the current
24-case curated set the top-1 accuracy is 1.00. This is a **regression guard, not a real-world
benchmark**; the fixture is too small to establish meaningful precision/recall, and no such claim is
made.
