# Benchmarks and Measured Baselines

Micro-benchmarks are kept **separate** from the deterministic unit-test suite. No performance target
is claimed; the numbers below are single-run observations on the development host (macOS `arm64`,
Apple Silicon) and will vary by machine and load.

## How to run

```bash
# Go
cd workers && go test -bench='.' -benchmem -run '^$' ./internal/matching/

# TypeScript
npx tsx test/benchmark/run.ts
```

## Measured baselines (2026)

Host: macOS `arm64` (Apple Silicon), Go 1.27, Node 26.

| Benchmark | Result |
| --- | --- |
| `matching.CanonicalURL` | ~508 ns/op, 460 B/op, 9 allocs/op |
| `matching.NormalizePath` | ~109 ns/op, 144 B/op, 3 allocs/op |
| TS `parseUrl` canonicalization | ~775 ns/op (~1.29M ops/sec) |
| Report `human` format (50 findings, 20 correlations) | ~12 µs/op (~83k ops/sec) |
| Report `json` format | ~23 µs/op (~43k ops/sec) |
| Report `csv` format | ~21 µs/op (~49k ops/sec) |
| Report `jsonl` format | ~38 µs/op (~26k ops/sec) |

## Resource-exhaustion protections (verified by tests, not benchmarks)

- Artifacts/specs are size-capped by `limits.maxArtifactBytes`; oversized bodies are truncated and
  flagged (`OVERSIZED`).
- Secret scanning caps matches per rule and uses RE2 (linear-time) — immune to catastrophic
  backtracking.
- Source maps cap bytes and listed sources; API specs cap bytes and endpoints.
- Crawler bounds depth, request budget, concurrency, timeout and response size.
- Report redaction enforces a depth bound and fails closed.

## Thresholds

No hard thresholds are asserted in CI. Proposed starting gates (to be revisited against recorded
baselines) are ~2× the measured per-op cost on comparable hardware; they are **not** enforced because
no stable CI hardware baseline exists yet.
