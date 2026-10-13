# Failure-Injection Suite

Deterministic, local-only tests that inject failures at major boundaries and assert the resulting
state, coverage, retry safety, resumability, data protection, and CLI status. No external targets.

| Boundary | Injected failure | Test | Asserted outcome |
| --- | --- | --- | --- |
| Database | Unreachable Postgres | `test/security/failure-injection.test.ts` | `runScan` rejects; no false success |
| Database | FK violation mid-ingest | same | transaction rolls back; no partial assets/observations (unique marker absent) |
| Orchestration | Abort signal before run | same | zero provider calls; no `SUCCEEDED` job beyond the pre-existing Stage 00 |
| Provider process | Missing binary | `workers/internal/discovery/*_test.go` | `SOURCE_UNAVAILABLE` (not empty success) |
| Provider process | Non-zero exit | `discovery_test.go`, `http_test.go` | `FAILED` with exit code recorded |
| Provider process | Timeout | `discovery_test.go`, `secretscan_test.go` | `FAILED`, `timedOut=true` |
| Provider process | Cancellation | `discovery_test.go` | `CANCELLED` |
| Provider output | Malformed JSON / protocol | `test/unit/worker-client.test.ts` | `FAILED` with diagnostic; never success |
| Provider output | Oversized | `discovery_test.go`, `jsanalysis_test.go` | truncated + `OVERSIZED` |
| Redaction | Throwing redactor | `test/integration/report-stage.test.ts` | fails closed: no report persisted; `REPORTING_FAILED` |
| Report | Determinism / idempotency | `report-stage.test.ts` | byte-identical for frozen clock; single record |
| Secret scan | Malformed/Unicode bytes | `secretscan_test.go` | no crash; detection still works |
| Archive sources | Empty result vs timeout vs unavailable | `urlcollect_test.go`, `providers` docs | distinguished honestly |

## Properties asserted

For each injected failure the suite checks, where applicable:

1. **State/coverage** — a failed stage is `FAILED`/`MISSING`, not `SUCCEEDED`/`COLLECTED`.
2. **Partial retention** — successful providers keep their observations; failures don't erase them.
3. **Retry safety** — retries are bounded; policy denials and control-plane failures are not retried;
   re-execution is idempotent (no duplicate assets/observations/edges/report rows).
4. **Resumability** — resuming re-runs only non-terminal/failed work with attempts remaining.
5. **Secret protection** — no raw secret markers in persisted rows or emitted output.
6. **CLI status** — missing scan ⇒ exit 2; scope denial ⇒ exit 4; dependency missing ⇒ exit 6;
   partial scan ⇒ exit 8; not-implemented ⇒ exit 3.

## Not covered (documented gaps)

- Process-kill during a committed transaction is not simulated in-process (Postgres provides the
  atomicity guarantee; a killed worker leaves a leased `RUNNING` job that resume reclaims).
- Network-level faults (packet loss, partial streams) are approximated by timeouts/truncation.
