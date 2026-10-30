# SARIF export (`report --format sarif`)

A SARIF 2.1.0 exporter for the canonical report model (`apps/control-plane/src/reporting/sarif.ts`),
so findings can flow into tools that already consume SARIF — GitHub code scanning, most CI
security dashboards — without a bespoke importer. It follows the same pattern as every other
format in `apps/control-plane/src/reporting/format.ts`: a pure function `(report: Report) =>
string`, operating only on the already-redacted canonical model handed to `formatReport()`. It
adds no data source of its own and performs no new query.

## What's represented

Only `report.findings` has a SARIF equivalent. The rest of the report — coverage, inventory,
secret/takeover candidates that were never promoted to a finding — is intentionally left out;
SARIF is a results format, not a general report format, so `sarif` sits alongside `human`/`json`/
`jsonl`/`csv`/`html` as one more view of the same model rather than a replacement for any of
them.

## Mapping

- One SARIF `result` per finding. `ruleId` is the finding's `category`; `message.text` is the
  title plus evidence; `level` is derived from `severity` (`CRITICAL`/`HIGH` → `error`, `MEDIUM`
  → `warning`, `LOW`/`INFO` → `note`).
- `locations` uses a `logicalLocations` entry (`kind: "resource"`) naming the finding's
  `subject` (a host or URL) — not a `physicalLocation`/`artifactLocation`, since a recon finding's
  subject is a live network resource, not a file in a repository.
- `partialFingerprints.reconnexusFindingId` carries the finding's own stable id, so a diff
  between two exports (or a SARIF-consuming tool's own deduplication) can recognize "the same
  finding" across report generations.
- `properties` carries everything SARIF has no first-class field for: `confidence`,
  `validation`, `sourceStage`, `sourceKind`, `remediation`, `references`, `evidenceRefs`.
- One SARIF `rule` is declared per distinct category, with a `defaultConfiguration.level` taken
  from the first finding of that category encountered (a rule's own level is only ever a
  fallback — a result's own `level` always wins in a SARIF viewer, since the same category can
  carry different severities, e.g. a CORS misconfiguration is `HIGH` with credentials and
  `MEDIUM` without).

Since the output is JSON, there is no markup-escaping step the way the HTML exporter needs —
`JSON.stringify` handles every metacharacter, verified by a unit test that round-trips a finding
whose title contains quotes and a newline.

## Usage

```
reconnexus report <scanId> --format sarif --out report.sarif.json
```
