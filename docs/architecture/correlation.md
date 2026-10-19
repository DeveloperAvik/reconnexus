# Evidence Correlation (Stage 11)

Stage `11-correlation` is a deterministic, control-plane pass over **persisted** records. It performs
**no network requests**, uses no provider, and never uses or validates credentials. Results are
derived purely from stored observations/assets/coverage, so runs are reproducible and idempotent.

## What already exists (and is NOT recreated)

The asset graph is built inline during ingestion (Stages 01–10): `resolves_to`, `serves`, `runs`,
`presents_certificate`, `references`, `has_source_map`, `exposes`, `documents`, `contains_url`,
`cname_to`, `mx_to`, `ns_to`, `ptr`, `in_prefix`, `announced_by`. Stage 11 does not duplicate these.

## What Stage 11 correlates

1. **Shared secret fingerprint** (`SHARES_SECRET_FINGERPRINT`)
   Two artifacts whose secret findings share the same `(ruleId, fingerprint)` correlate, **only**
   when both artifacts' `secret-scan-artifact` records report `hmacKeyed: true`. The result is a
   `shares_secret_fingerprint` edge in `asset_relationships` plus a correlation observation.
   - Empty fingerprints never correlate (they are not evidence of equality).
   - Unkeyed fingerprints never correlate (provenance is not comparable).
   - Fingerprints from different `ruleId`s never correlate.
   - When no finding can correlate because no key was configured, stage 11 records
     `secretFingerprintCorrelation=DISABLED_NO_HMAC_KEY` (or `PARTIAL_UNKEYED`) in its coverage
     notes/details and the report; the stage still succeeds.
   - Fingerprints produced with different HMAC keys are not comparable; the stage relies on HMAC
     (not a plain hash) and on `RECONNEXUS_HMAC_KEY` being stable.

2. **Multi-source corroboration** (`MULTI_SOURCE_CORROBORATION`)
   An asset observed by ≥2 distinct sources produces a correlation observation listing the sources.
   This is cross-provider duplicate detection — corroboration of presence, not of causation.

3. **Coverage-gap summary**
   Upstream stages whose coverage is not `COLLECTED` are recorded in the Stage 11 coverage `details`,
   so incomplete work cannot be mistaken for completeness.

## Contract

`CorrelationRecordSchema` (`packages/contracts/src/discovery.ts`): `relation`, `status`
(`OBSERVED`/`PARTIAL`/`FAILED`), `subject`, `related[]`, `ruleId`, `hmacKeyed`, `correlationGroup`
(opaque), `sourceRecordIds[]`, `sourceStage`, redacted `evidence`, `confidence`.

- **No** `VALIDATED`/`CONFIRMED`/`ACTIVE` states exist.
- `confidence` measures the strength of the stated relationship only (fingerprint equality = 0.9;
  corroboration = 0.6) — never credential validity or exploitability.

## Persistence and idempotency

- Edges reuse `asset_relationships` (arbitrary `relation` + `confidence` + `source =
  'stage-11-correlation'`, unique on `(project, from, to, relation)`), inserted with
  `ON CONFLICT DO NOTHING`.
- Correlation observations reuse `observations` (kind `correlation`). Because they are fully
  derived, the stage **deletes** prior `correlation` observations for the scan and re-inserts them
  inside one transaction — repeated runs yield identical results.
- No schema migration.

## Secret safety

- Only an opaque `correlationGroup = sha256(ruleId | fingerprint).slice(0,16)` is stored — the
  fingerprint and any raw secret value are never persisted in correlation records, logs, or CLI
  output.
- Correlation never promotes a candidate secret into a validated/active finding, never compares
  empty fingerprints, and never authenticates with or transmits discovered values.

## Failure and coverage semantics

- No eligible persisted records ⇒ stage `SKIPPED` (coverage `NOT_ATTEMPTED`).
- Normal completion ⇒ coverage `COLLECTED` (0 correlations is a valid, distinguishable result).
- Truncation (very large fingerprint groups / edge cap) ⇒ `PARTIAL`.
- Upstream failures propagate: dependency gating means Stage 11 only runs once its prerequisite is
  terminal, and the coverage-gap summary records non-`COLLECTED` stages.

## CLI

`reconnexus correlations <scanId> [--relation R] [--subject S] [--limit N]` — redacted output; the
command distinguishes **not run**, **failed**, **partial**, **complete with no correlations**, and
**populated**.

## Limitations

- A shared keyed fingerprint is evidence that the same value recurs; it is **not** proof the
  credential is valid, active, or exploitable.
- Multi-source corroboration is not proof of causation.
- The Phase 7 residual (a non-rule-matching secret on the same line as a detected match) is
  unchanged here.
- Only relationships directly supported by persisted evidence are produced; ambiguous cases fail
  closed (no relationship).
