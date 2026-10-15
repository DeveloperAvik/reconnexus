# Scan-to-Scan Change Intelligence (`changes`)

`reconnexus changes <baselineScanId> <currentScanId>` compares what two scans of the same project
actually recorded. It is **read-only**: it makes no network request, writes nothing, and never infers
a change it cannot support from persisted evidence.

## Model

The engine (`apps/control-plane/src/comparison/engine.ts`) works on a read-only subset of the
repository:

- `listScanAssets(scanId, types?)` — assets observed in a scan (assets are project-scoped, so "seen
  in a scan" means the subject of an `observations` row with that `scan_id`).
- `listScanObservations(scanId, { kinds?, kindPrefix? })` — the observations of a scan, filtered to
  the kinds a category needs.
- `listCoverage(scanId)` — per-stage coverage status.

No migration is required: `observations` (with `scan_id`, `kind`, `data jsonb`) and
`coverage_records` already carry everything the comparison needs.

## Categories

| Category | Source | Identity | Compared fields |
| --- | --- | --- | --- |
| `assets` | asset table | type + canonical key | presence only |
| `dns` | `dns:*` observations | name + record type | value, status |
| `http` | `http` observations | service origin | status, title, server, content type, final URL, probe status |
| `tls` | `tls` observations | certificate hash | subject, issuer, protocol, validity, SAN count |
| `technology` | `technology` observations | host + name | category |
| `api` | `api-endpoint`, `api-spec` | method+origin+path / spec URL | documented, resolved, params, content types, counts |
| `js` | `js-artifact`, `source-map` | URL | content hash, size, status |
| `findings` | `secret-finding`, `takeover-candidate` | rule/artifact/location/fingerprint, host+CNAME | status, confidence |

Each category declares the stage(s) that produce it, which drives the coverage decision.

## Outcomes and the coverage rule

Every key yields one of `ADDED | REMOVED | CHANGED | UNCHANGED | UNKNOWN`.

- `ADDED`: present only in the current scan. Always supported (presence is observed directly).
- `REMOVED`: present only in the baseline scan — reported only when the producing stage was fully
  `COLLECTED` in **both** scans; otherwise `UNKNOWN`.
- `CHANGED`: present in both with different projected fields — only when the stage was `COLLECTED` in
  both scans; otherwise `UNKNOWN` (a difference was observed, but one side is incomplete).
- `UNCHANGED`: present in both with equal projections (presence in both is a fact).
- `UNKNOWN`: cannot be established; carries a reason. When any stage for a category is not fully
  collected, the category emits a `COVERAGE_GAP` limitation.

A stage that is skipped, failed, partial, blocked or not attempted establishes **no absence** — it is
a coverage gap, not evidence that an asset or record disappeared.

## Determinism and bounds

- Duplicate observations of the same identity collapse to the latest `observed_at` (then a stable
  tie-break), so repeated runs are byte-identical.
- Categories render in registry order; change rows are ordered by outcome group then key.
- `--limit` bounds rows per category; totals remain exact (`truncated` flags the cut).
- `--category` and `--status` filter what is returned, never what is counted.

## CLI

```bash
reconnexus changes <baseline> <current> [--category a,b] [--status ADDED,CHANGED] [--limit n] [--format human|json|html]
```

`human` prints per-category counts and the change rows; `json` returns the full model including
coverage and limitations; `html` is a single self-contained, escaped report. Unknown categories or
statuses, missing scans, and cross-project comparisons are usage errors.

## Relationship to `assets diff`

`assets diff` is the asset-only shortcut (identity = type + canonical key) with a fixed, minimal
output. `changes` is the general engine; the `assets` category reproduces `assets diff`'s verdicts
with the same coverage rule.

## Limitations

- Only persisted observations are compared; a category with no recorded evidence compares as empty,
  which the per-stage coverage discloses.
- A finding moving to "not observed" means *not observed this scan*, not *resolved on the target*;
  a candidate is never promoted to confirmed.
- Findings are derived from their stage records (secret findings, takeover candidates); there is no
  separate persisted finding entity to compare beyond those records.
