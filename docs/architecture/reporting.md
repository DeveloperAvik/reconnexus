# Evidence-Based Reporting (Stage 12)

`12-reporting` is the final stage of the DAG. It is a deterministic, control-plane stage that
produces a redacted, evidence-backed report from **persisted** state. It makes no network requests,
changes no upstream coverage, and never upgrades a scan's status.

## What it reports

- Scan identity and target context (`scanId`, `projectId`, `rootDomain`, `startUrl`) — **without
  expanding scope**.
- `scanStatus` (reconciled analysis status) and `reportStatus` (overall interpretation).
- Per-stage execution status and coverage (job status, coverage status, expected/collected, notes).
- Coverage gaps (stages not `COLLECTED`).
- Asset counts (project-level) and observation counts (by kind / source).
- Redacted secret findings (rule, category, status, confidence, artifact, location, redacted snippet).
- Correlations (relation, status, subject, related, ruleId, `hmacKeyed`, opaque group, evidence,
  confidence).
- A fixed list of interpretation limitations and a plain-language summary.

## Report-status derivation

Derived deterministically from authoritative records, **excluding the reporting job itself** (so the
report is correct while Stage 12 is still running):

| Condition | `reportStatus` |
| --- | --- |
| Reporting job `FAILED`/`SOURCE_UNAVAILABLE`/`BLOCKED` | `REPORTING_FAILED` |
| Reporting job never started (`QUEUED`/absent) | `REPORTING_NOT_RUN` |
| Analysis reconciled `FAILED` | `FAILED` |
| Analysis reconciled `PARTIAL` (skipped/failed stages) | `PARTIAL` |
| Analysis reconciled `SUCCEEDED`, findings > 0 | `COMPLETE_WITH_FINDINGS` |
| Analysis reconciled `SUCCEEDED`, findings = 0 | `COMPLETE_NO_FINDINGS` |

`COMPLETE_*` requires every non-reporting stage to be `SUCCEEDED`. A skipped stage did not "find
nothing" — it was not run — so it forces `PARTIAL`.

## Redaction and data minimization

- A **structure-preserving** boundary redactor applies the centralized string redactor to every
  string value (leaving keys and numeric/boolean structure intact) and then re-validates the report.
- It **fails closed**: any error throws `ReportRedactionError` and no report is emitted or persisted
  (Stage 12 records `MISSING` coverage and fails; the CLI exits non-zero and prints nothing).
- No raw secret values, HMAC fingerprints, or artifact bodies are included. Correlation groups remain
  opaque (`sha256(rule|fingerprint)[:16]`).

## Persistence and idempotency

- Stored as a single `report` observation (kind `report`) on the root domain asset; the stage deletes
  any prior `report` observation for the scan and inserts one, so regeneration never duplicates.
- Reports are also produced on demand by the CLI from current persisted state.
- No migration: scan/job/coverage/observation/asset models fully represent the lifecycle.

## Determinism

Sections and records are sorted (stages by stage id, secret findings by rule/artifact/location,
correlations by relation/subject, count maps by key). The clock is injectable so identical persisted
state yields byte-identical reports.

## CLI

`reconnexus report <scanId> [--format human|json|jsonl|csv]` (default `human`). Exit codes:
`0` success (including `PARTIAL`/`FAILED` analysis — the report was produced), `2` scan not found,
`1` report generation failed (e.g. redaction fail-closed). The output always states `reportStatus`,
so an operator can distinguish a missing scan, a not-run report, a successful empty report, a partial
report, and a reporting failure.

## Limitations

- CLI-only: `human`, `json`, `jsonl`, `csv` are implemented; static HTML is not.
- A secret candidate is not a confirmed credential; a correlation is not proof of exploitability or
  causation. The report states this in its limitations.
- The Phase 7 residual (a non-rule-matching secret on the same line as a detected match) is
  re-redacted where patterns match but is not claimed to be fully solved.
- No historical/cross-scan diffing.
