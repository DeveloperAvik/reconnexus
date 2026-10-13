# Evaluation Corpus and Measurement Quality

## Purpose

The evaluation corpus is a small, hand-labeled, **synthetic** fixture set used as a *regression
guard*. It is **not** an estimate of real-world detection quality, and no production precision,
recall, or F1 is claimed.

## Corpora

| Corpus | Location | Size | Consumer |
| --- | --- | --- | --- |
| URL classification | `workers/internal/discovery/urlclassify_test.go` (`labeled`) | 24 cases | `ClassifyURL` |
| Secret detection | `test/fixtures/eval/secrets.json` | 24 cases (14 positive, 10 negative) | `scanText` |
| Scope/URL/IP conformance | `test/fixtures/conformance/*.json` | domains, IPs, scope decisions, URL canonicalization | TS + Go engines |
| Normalization/scope security | `test/security/scope-security.test.ts` | out-of-scope URL corpus, restricted-address classes | `ScopeEngine` |

Corpora contain **synthetic, non-functional** values only. No real credentials, private artifacts,
or production data are used.

## Metrics (curated fixture set)

- **URL classification:** top-1 accuracy 1.00 on the 24-case curated set (confusion matrix printed
  by `TestClassifyURLFixturesAndConfusionMatrix`).
- **Secret detection:** TP=14, FP=0, FN=0 → precision=1.000, recall=1.000, F1=1.000 on the 24-case
  curated set (`TestSecretDetectionEvaluation`).

These figures describe behaviour on the fixtures that were written to match the rules; they do not
predict field performance. Negatives include placeholders, configuration-like strings, SQL, semver,
emails, URLs, hex colors and numeric ids.

## Guidance for expansion

- Keep positive/negative and ambiguous cases distinct; add adversarial/Unicode edge cases.
- Keep tuning examples separate from held-out examples where feasible.
- Report confusion matrices and per-rule metrics; never fabricate counts.
- A real-world estimate would require an externally-labeled, consented corpus — out of scope here.
