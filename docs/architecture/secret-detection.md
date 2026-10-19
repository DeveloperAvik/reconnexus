# Secret Detection (Phase 7, stage 09)

Stage `09-secret-detection` (capability `SECRET_SCAN`) analyses eligible artifacts for potential
secrets. It depends on Stage 08 and feeds Stage 10.

## Inputs and architecture

Raw artifact bodies are **deliberately not persisted** — they may contain credentials, so storing
them would violate the secret-safety requirement. Instead Stage 09 selects the **persisted JS
artifacts and API specifications** from stages 07/08 (as asset/observation references) and
re-collects their content **in-memory** through the Phase 3A connection-bound transport (connect-time
address validation + per-hop redirect reauthorization). Scope is enforced for `SECRET_SCAN`, sizes
and concurrency are bounded, and cancellation is honoured.

Detected references are **never followed**; credentials are **never used**; no values are sent to
external services or verified in any way.

## Detection engine

`workers/internal/discovery/secretscan.go` applies a maintained, high-signal rule table plus a single
entropy heuristic. Categories: `CLOUD_CREDENTIAL`, `API_KEY`, `PRIVATE_KEY`, `DATABASE_URL`,
`OAUTH_SECRET`, `BEARER_TOKEN`, `WEBHOOK_SECRET`, `PASSWORD`, `GENERIC_HIGH_ENTROPY`, `OTHER`.

Rules include AWS key id/secret, Google, Slack, GitHub, Stripe, Twilio, SendGrid, npm, Azure account
key, private-key markers, database connection strings, OAuth client secrets, webhook signing
secrets, JWTs, bearer tokens, embedded credentials, and password assignments.

- **Confidence:** high-confidence rules ⇒ `HIGH_CONFIDENCE`; heuristic/ambiguous rules ⇒ `CANDIDATE`.
- **Overlap:** a generic/entropy match that overlaps a more specific match is dropped.
- **Entropy:** the generic key/token rule and the weak *assignment* rules (password, bearer, OAuth
  client secret, webhook signing secret, JWT) require Shannon entropy ≥ 3.5. This drops ordinary
  configuration/UI values (`password = 'required'`, repeated characters) that otherwise caused false
  positives in minified JavaScript.
- **Context for ambiguous formats:** the Twilio rule (`SK` + 32 hex) requires a nearby
  `twilio`/`account_sid`/`auth_token`/`api_key` token, because a bare `SK`+hex string matches hashes
  and generated ids.
- **Placeholders** (`example`, `changeme`, `your_`, `required`, `invalid`, `{{`, …) ⇒ `SUPPRESSED`.
  Placeholders are checked before the entropy gate, so the suppression is still recorded.
- **Configured suppression:** `RECONNEXUS_SECRET_SUPPRESS_RULES` lists rule ids to suppress.
- **Deduplication:** identical rule+value matches collapse into one finding with an `occurrences`
  count; findings remain per-artifact for provenance.
- A pattern match is **never** a claim that a credential is valid, active, or exploitable.

## Secret-safe evidence (release-blocking)

- Raw values are **never** written to findings, logs, error messages, metrics, or the database.
- The only stored context is a **line-scoped** redacted snippet: the matched value is replaced, every
  rule match remaining in the snippet is re-replaced, and the global redactor runs last. Private
  keys and over-long (minified) lines store a context-free `[REDACTED:<rule>]` marker so no part of a
  key body or a neighbouring secret can leak.
- Cross-record correlation uses a **keyed HMAC-SHA256** of `rule|value` (key from
  `RECONNEXUS_HMAC_KEY`); without a key the fingerprint is empty (`hmacKeyed=false`). A plain hash is
  never used. See [`RECONNEXUS_HMAC_KEY`](../operations/configuration.md#reconnexus_hmac_key) for
  setup. A missing key disables correlation only; detection and redaction are unchanged, and the
  state is reported by `doctor`, the stage-09 diagnostic and stage 11 coverage.

Lifecycle states: `CANDIDATE`, `HIGH_CONFIDENCE`, `SUPPRESSED`, `ANALYSIS_FAILED`. There is no
`VALIDATED`/`ACTIVE` state.

## Persistence

Findings are stored as `secret-finding` observations and per-artifact outcomes as
`secret-scan-artifact` observations on the artifact `URL` asset (existing model — no migration).
Ingestion is idempotent; findings from different artifacts are preserved.

## CLI

`reconnexus secrets <scanId> [--rule R] [--category C] [--status S] [--confidence N]
[--artifact A] [--host H] [--limit N]` prints redacted snippets only. There is no flag that reveals
raw values.

## Limitations

- Detection is a heuristic over a maintained rule set; novel formats may be missed (false negatives)
  and generic rules can over-match (false positives), which is why heuristic matches are low
  confidence and labelled candidates.
- A non-rule-matching secret appearing on the **same line** as a detected match is not redacted from
  that finding's snippet (the rest of the line is fully rule-redacted). This is a documented residual
  limitation.
- Production precision/recall is not established (no labelled corpus beyond the functional fixtures).
