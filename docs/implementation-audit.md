# ReconNexus — Repository Audit (Phase 0)

- **Date:** 2026-10-13
- **Host:** macOS 27.0.1 (build 26A434), Apple Silicon `arm64` (Darwin kernel 27.0.0)
- **Repository:** `/Users/dreadspecter/bug-hunting-tools`
- **Audit outcome:** Greenfield. The working directory was **empty** at the start of this audit and was **not** a git repository.

## 1. Pre-existing state

| Item | Finding |
| --- | --- |
| Existing source files | None |
| Existing docs | None |
| Dependency manifests | None (`package.json`, `go.mod`, `go.work` all absent) |
| Database migrations | None |
| Tests | None |
| Git repository | Not initialized |
| Unrelated user changes | None to preserve (directory was empty) |

Because there is no prior implementation, **nothing is being replaced or deleted**. All structure below is newly created. This satisfies the constraint to extend rather than blindly replace existing work (there was none).

## 2. Host toolchain

| Tool | Version / Path | Status |
| --- | --- | --- |
| Go | `go1.27.2 darwin/arm64` | ✅ Present |
| Node.js | `v26.11.1` | ✅ Present |
| npm | `11.20.0` | ✅ Present |
| pnpm | — | ❌ Not installed (using npm workspaces instead) |
| tsx | — | ❌ Not installed (installed as a dev dependency) |
| PostgreSQL | — | ❌ Not installed → installing `postgresql@16` via Homebrew (operator-approved) |
| Redis | — | ❌ Not installed → installing `redis` via Homebrew (operator-approved) |
| Docker | — | ❌ Not installed (not required; native local services used) |
| git | `2.56.0` | ✅ Present (repo intentionally **not** initialized per operator decision) |

## 3. External reconnaissance providers

All ProjectDiscovery and related tools are present under `~/go/bin` or `/opt/homebrew/bin` and are `darwin/arm64` native binaries:

| Provider | Path | Phase used |
| --- | --- | --- |
| subfinder v2.16.0 | `~/go/bin/subfinder` | Phase 3 (subdomain discovery) |
| amass v5.1.1 | `/opt/homebrew/bin/amass` | Phase 3 |
| assetfinder | `~/go/bin/assetfinder` | Phase 3 |
| httpx | `~/go/bin/httpx` | Phase 3 (HTTP probing) |
| dnsx | `~/go/bin/dnsx` | Phase 3 (DNS) |
| katana | `~/go/bin/katana` | Phase 4 (crawling) |
| gau v2.2.4 | `~/go/bin/gau` | Phase 4 (historical URLs) |
| waybackurls | `~/go/bin/waybackurls` | Phase 4 |
| mapcidr | `~/go/bin/mapcidr` | Phase 3 (CIDR) |
| nuclei | `~/go/bin/nuclei` | Phase 6 (authorized checks) |

**Important:** availability of a provider binary does **not** imply provider credentials are configured (e.g. subfinder passive API keys). The `providers`/`doctor` commands must report capability and credential status honestly and must **not** report a missing tool as an empty successful result.

## 4. Platform-specific considerations (macOS ARM64)

- All Go builds target `darwin/arm64` natively; no cross-compilation or VM required.
- External provider binaries are already `arm64` native — no Rosetta needed.
- PostgreSQL/Redis run as native Homebrew services with launchd; development needs **no** Docker.
- Local test servers bind to `127.0.0.1` on ephemeral ports for deterministic, network-free integration tests.
- Production deployment is documented separately (isolated Linux workers + controlled egress) but is **out of scope** for the local Phase 1 deliverable.

## 5. Architectural deviations from the prompt's reference layout

The prompt's reference structure is used almost verbatim. Deviations:

1. **No `pnpm-workspace.yaml`** — pnpm is not installed. npm workspaces (`package.json` `workspaces`) are used instead. The `go.work` workspace is used as specified.
2. **`workers/internal/scope`** added — a Go-side, independent scope enforcement implementation to satisfy "worker-side enforcement" (§8) mirroring the TypeScript policy service.
3. **`packages/logging`** added — shared structured logging used by all TS packages and mirrored in Go `internal/telemetry`.

These deviations are documented here as required by §5.

## 6. Risk register

| Risk | Mitigation |
| --- | --- |
| Provider tools absent on another machine | `doctor` reports explicit dependency errors; no fabricated empty success |
| Postgres/Redis not running | `doctor` performs a live connectivity check; migration runner exits non-zero with a clear message |
| Scope bypass via redirect / DNS rebinding | Connection-time destination validation + independent worker-side policy (Phase 1 core, tested) |
| Secret leakage in logs/reports | Central redaction in logging + report layers; synthetic fixtures only |
| Non-deterministic tests | Local fixtures; no live network in unit tests; test servers on loopback |
| Overstating completion | Every doc distinguishes implemented vs planned; no placeholder features are labelled complete |

## 7. Conclusion

The repository is greenfield with a complete, native `arm64` reconnaissance toolchain already available. There is no legacy code to preserve. Phase 1 can proceed on a clean foundation. The only provisioning gap is the database and queue, which is being resolved via Homebrew per operator approval.
