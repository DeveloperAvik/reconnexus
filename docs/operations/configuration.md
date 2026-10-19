# Configuration

Configuration is layered and validated. Precedence (lowest to highest):

1. Built-in defaults
2. Config file
3. Environment variables
4. Explicit CLI overrides

## Config file

Placed at the repository root as `reconnexus.config.json` (also `.reconnexusrc.json` or
`reconnexus.json`), or passed with `--config <path>`. All fields are optional and merged over
defaults.

```json
{
  "schemaVersion": 1,
  "database": { "url": "postgres://localhost:5432/reconnexus", "poolSize": 10 },
  "redis": { "enabled": false, "url": "redis://127.0.0.1:6379" },
  "artifacts": { "root": "./.reconnexus/artifacts", "maxBytes": 8388608 },
  "logging": { "level": "info", "format": "json" },
  "network": { "allowRestrictedAddresses": false, "requestTimeoutMs": 15000, "maxRedirects": 5 },
  "providers": {
    "subfinder": { "enabled": true, "binaryPath": "/Users/me/go/bin/subfinder" }
  },
  "defaultPolicyFile": "./policies/example-scope-policy.json"
}
```

`schemaVersion` must be `1`; an unsupported version is rejected with a clear error.

## Environment variables

| Variable | Effect |
| --- | --- |
| `RECONNEXUS_DATABASE_URL` / `DATABASE_URL` | Postgres connection string. |
| `RECONNEXUS_DB_POOL_SIZE` | Connection pool size. |
| `RECONNEXUS_REDIS_URL` | Enables Redis and sets its URL. |
| `RECONNEXUS_ARTIFACTS_DIR` | Artifact storage root. |
| `RECONNEXUS_LOG_LEVEL` | `debug` \| `info` \| `warn` \| `error`. |
| `RECONNEXUS_LOG_FORMAT` | `json` \| `pretty`. |
| `RECONNEXUS_ALLOW_RESTRICTED` | `true` to permit restricted address space (still requires the `INTERNAL_NETWORK` capability). |

See [`.env.example`](../../.env.example).

## Scope policy

Scope policies are JSON documents validated by `ScopePolicySchema`. See
[`policies/example-scope-policy.json`](../../policies/example-scope-policy.json). Key fields:

- `authorization` — reference, authorizer, validity window, and granted `capabilities`.
- `inScope` — `domains` (`{ value, includeSubdomains }`), `hosts`, `ips`, `cidrs`.
- `exclusions` — same shape plus `paths`; exclusions take precedence over inclusions.
- `limits` — concurrency, request rate, crawl depth, runtime, artifact size.
- `policyVersion` — unique per project; reuse with different content is rejected.

Validate and inspect:

```bash
reconnexus scope validate policies/example-scope-policy.json
reconnexus scope show policies/example-scope-policy.json
```

## Worker

The discovery worker is a Go binary spawned with a fixed argv array (never a shell):

```json
{
  "worker": {
    "binaryPath": "./bin/reconnexus-worker",
    "workDir": ".",
    "goRunCommand": ["go", "run", "./cmd/reconnexus-worker"]
  }
}
```

Resolution order: configured `binaryPath` → `RECONNEXUS_WORKER_BIN` env → `<repoRoot>/bin/reconnexus-worker`
→ `goRunCommand` → `go run ./cmd/reconnexus-worker` (from `workers/`). Build it with
`make worker-build`.

Per-scan provider selection (CLI flags on `scan run` / `scan resume`):

```bash
reconnexus scan run <scanId> \
  --providers subfinder,assetfinder \
  --dns-providers builtin-dns \
  --ip-providers rdap \
  --http-providers builtin-http \
  --url-providers builtin-crawler,builtin-static,gau,waybackurls \
  --js-providers builtin-js \
  --api-providers builtin-api \
  --security-providers builtin-security-meta \
  --secret-providers builtin-secret-scan
```

Stage 09 (`builtin-secret-scan`) requires the `SECRET_SCAN` capability. Two environment variables
control it:

- `RECONNEXUS_HMAC_KEY` — enables keyed HMAC fingerprints for cross-record correlation (without it,
  fingerprints are empty).
- `RECONNEXUS_SECRET_SUPPRESS_RULES` — comma-separated rule ids to suppress.

An artifact whose upstream JS/spec stage was skipped yields no stage-09 work; a failed re-collection
is reported as `ANALYSIS_FAILED`, distinct from a clean scan with no findings.

Stage 10 (`builtin-security-meta`) requires the `SECURITY_CHECKS` capability in the policy. It issues
one bounded GET per in-scope service (bounded by `limits.maxConcurrency`, `limits.maxArtifactBytes`
and `network.requestTimeoutMs`) and records TLS/HSTS/header/cookie-attribute/CORS/content-type
metadata.

Stage 07 (`builtin-js`) retrieves and analyses JavaScript discovered by URL collection, and stage
08 (`builtin-api`) parses OpenAPI/Swagger specifications. Source-map retrieval is enabled by the
orchestrator (`fetchSourceMaps: true`) and always subject to the scope policy. Artifact and spec
sizes are bounded by `limits.maxArtifactBytes`.

URL collection is bounded by the policy's `limits.crawlDepth` (default 2) and an internal request
budget (800 requests/scan). `katana` is available via `--url-providers katana` but is **not** a
default because it is not connection-bound (see
[provider-contracts.md](../architecture/provider-contracts.md)).

A provider is disabled by setting `providers.<name>.enabled` to `false`.

HTTP probing limits come from `network` config and the policy:

```json
{ "network": { "maxRedirects": 5, "requestTimeoutMs": 15000 } }
```

`maxRedirects` bounds redirect following (default 5); `requestTimeoutMs` is the per-request timeout.
Response size is bounded by the policy's `limits.maxArtifactBytes`. A request/response failure is
recorded per observation (`TIMEOUT`, `CONNECTION_ERROR`, `TLS_ERROR`, `REDIRECT_DENIED`,
`TOO_MANY_REDIRECTS`, `OVERSIZED`, `BLOCKED_ADDRESS`, `ERROR`) — never silently swallowed.

## Safety defaults

- Restricted address space (`loopback`, `private`, `link-local`, `CGNAT`, `metadata`, `reserved`)
  is **denied by default**, with or without the `INTERNAL_NETWORK` capability.
- To reach explicitly authorized restricted destinations, **all three** are required: an in-scope
  IP/CIDR entry, the `INTERNAL_NETWORK` capability, **and** `network.allowRestrictedAddresses` (or
  `--allow-restricted`). The override never opens unlisted restricted space. The only exception is
  documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`), where
  the explicit entry alone suffices.
