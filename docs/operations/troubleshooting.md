# Troubleshooting

Start with `reconnexus doctor` (add `--json` for machine-readable output). It reports runtime,
Postgres/Redis connectivity, artifact/migration paths, and every provider's health.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | general error |
| 2 | usage error |
| 3 | not implemented (the requested stage is not in this build) |
| 4 | scope denied |
| 5 | authorization invalid or expired |
| 6 | required dependency missing |
| 7 | configuration invalid |
| 8 | scan completed partially |
| 130 | cancelled |

## Common problems

### `postgres … connect ECONNREFUSED`

Postgres is not running or unreachable.

```bash
brew services start postgresql@16
createdb reconnexus
```

Check `RECONNEXUS_DATABASE_URL`. The default is `postgres://$USER@127.0.0.1:5432/reconnexus`.

### `config file failed schema validation`

A field has the wrong type or an unsupported `schemaVersion`. Run `reconnexus config validate`
and compare against [configuration.md](configuration.md).

### A provider shows `MISSING`

The binary is not on `PATH`. Install it (see [installation.md](installation.md)) or set
`providers.<name>.binaryPath` in config. ReconNexus never treats a missing tool as an empty success.

### `scope check` returns `DENY NOT_IN_SCOPE`

The host is not covered by `inScope`. Add a `domains` entry (with `includeSubdomains` for
subdomains), a `hosts` entry, or an `ips`/`cidrs` entry as appropriate. Remember that a starting
URL is **not** authorization to scan every discovered host.

### `scope check` returns `DENY RESTRICTED_ADDRESS_SPACE`

The destination is special/restricted. To intentionally reach an explicitly authorized restricted
destination, add it to `inScope.ips`/`cidrs` **and** grant `INTERNAL_NETWORK` **and** set
`network.allowRestrictedAddresses` (or pass `--allow-restricted`). All three are required; an
unlisted restricted address stays denied even with the capability and override. Documentation
ranges need only the explicit entry. Do this only for authorized lab targets.

### `secret-fingerprint correlation disabled` / `doctor` warns about `RECONNEXUS_HMAC_KEY`

`RECONNEXUS_HMAC_KEY` is not set (or is empty). Secret detection works normally; only correlation
of the same secret across artifacts and scans is off. Generate a key with `openssl rand -hex 32`,
export it (ReconNexus does not load `.env` by itself) and re-run the scan; see
[`RECONNEXUS_HMAC_KEY`](configuration.md#reconnexus_hmac_key).

### `EXCLUDED` / `EXCLUDED_PATH`

An exclusion matched (exclusions take precedence). Adjust `exclusions` if the policy is wrong.

### `AUTHORIZATION_EXPIRED`

`authorization.validUntil` is in the past. Update the authorization record and bump
`policyVersion`.

### `policy version N already exists … with a different policyId`

Policy versions are immutable per project. Bump `policyVersion` when changing a policy.

### `command '…' is not implemented in this build` (exit 3)

Expected in Phase 1 for `assets`, `urls`, `apis`, `secrets`, `findings`, `coverage`, `report`, and
`scan resume`. See [implementation-plan.md](../implementation-plan.md).

## Logs

Logging goes to **stderr** as JSON by default, so `--json` stdout stays machine-parseable. Use
`--log-format pretty` for humans, or `--log-level debug` for detail. Secrets are redacted
automatically; if you find a leak, treat it as a bug.
