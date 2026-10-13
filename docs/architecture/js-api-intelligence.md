# JavaScript & API Intelligence (Phase 5, stages 07 & 08)

Phase 5 is implemented as the existing DAG stages **`07-js-intelligence`** and
**`08-api-discovery`**. Stage `06-url-categorization` is satisfied during URL collection (stage 05)
and remains `SKIPPED` with that note; no new stage identifiers were introduced.

## Stage 07 — JavaScript intelligence (`builtin-js`)

Seeds: URLs from stage 05 classified `JAVASCRIPT`/`STATIC_ASSET` (or ending `.js`/`.mjs`).

1. **Retrieval** — each JS URL is fetched through the Phase 3A connection-bound transport
   (DialContext scope enforcement + per-hop redirect reauthorization), with bounded concurrency,
   per-request timeout, response-size limit and cancellation. The artifact records URL, canonical
   URL, SHA-256 content hash, MIME type, size, source URL, discovery method and status
   (`RETRIEVED`/`NOT_FOUND`/`ERROR`/`OVERSIZED`/`MISMATCHED_MIME`).
2. **Bounded static analysis** — an RE2 (linear-time) lexical scan extracts:
   - `fetch("...")`, `axios.<method>("...")`, `XMLHttpRequest.open("METHOD","...")`, `new WebSocket("...")`;
   - absolute (`http(s)://`, `ws(s)://`) and relative (`/...`) URL/path string literals;
   - GraphQL / API-document references (path literals such as `/graphql`, `/api/...`, version prefixes);
   - **dynamic template literals** (`fetch(\`/api/users/${id}\`)`) are retained as **unresolved
     candidates** (`resolved=false`) using only the static prefix — no endpoint is fabricated.

   No JavaScript is executed, no browser is used, and no packages are installed. Bounded by the
   response-size limit and a per-artifact candidate cap; RE2 cannot suffer catastrophic backtracking.
3. **Source maps** — `sourceMappingURL` comments are resolved against the artifact URL and, when
   `fetchSourceMaps` is enabled and the target is in scope, parsed as bounded JSON
   (`version`, `sourceRoot`, `sources`, `sourcesContent` presence). Listing sources does not fetch
   them; malformed maps and missing/failed fetches are reported honestly. When disabled the map is
   recorded with status `DISABLED`.

Discovered endpoint **origins are themselves scope-checked**; out-of-scope origins are dropped and
counted. Evidence strings are minimal and passed through secret redaction.

## Stage 08 — API specification intelligence (`builtin-api`)

Seeds: URLs from stage 05 classified `API_SPEC`/`DOCUMENTATION` (or matching `openapi`/`swagger`).

- Retrieval uses the same connection-bound transport. JSON and YAML are both supported (JSON first
  when the body/content-type looks like JSON, YAML otherwise).
- Extracted: spec version (`openapi:x` / `swagger:x`), `info.title`, servers (OpenAPI `servers[]`
  or Swagger `host`+`basePath`+`schemes`), paths, HTTP methods, `operationId`, `tags`, parameters
  (query/path/header/cookie, with `required` and `type`), request-body properties (as `body`
  parameters), response/content types, and declared `securitySchemes` names (**no credentials**).
- **`$ref` handling**: local `#/...` pointers are resolved with depth and cycle limits; remote
  `$ref` targets are never fetched and are counted as `unresolvedRefs`.
- Server base paths are prefixed onto operation paths, so a server `https://host/api` with path
  `/users` yields `/api/users`.
- Endpoint origins are scope-checked exactly as in stage 07.

GraphQL endpoints are surfaced as ordinary endpoints (from JS string literals or spec paths); no
live introspection is performed.

## Endpoint identity and provenance

Endpoint assets are keyed by **`METHOD origin path`**, so the same path under different origins or
methods is never merged. Each endpoint records `discoveredVia` (`JS`/`SPEC`/`HTTP`), `documented`,
`resolved`, parameters, content types, auth-scheme names where declared, the source artifact/spec
URL, and a short evidence string + evidence type. Observations from multiple sources are retained.
Parameter names are reconnaissance hints only and are never treated as proof of a vulnerability.

## CLI

- `js <scanId>` — artifacts (status, size, hash prefix) and source maps.
- `apis <scanId>` — endpoints; filter by `--host`, `--method`, `--via`, `--documented`, `--unresolved`.
- `specs <scanId>` — specifications with parse status, version and path/operation counts.
- `params <scanId>` — parameter inventory aggregated across URLs **and** API endpoints.

## Limitations

- Static analysis is lexical/regex-based, not a full JavaScript parser: it favours recall on string
  literals and may miss dynamically constructed endpoints (kept as unresolved candidates) or flag
  path-like strings that are not real endpoints.
- Remote `$ref` resolution and full GraphQL/Postman ingestion are out of scope for this phase.
