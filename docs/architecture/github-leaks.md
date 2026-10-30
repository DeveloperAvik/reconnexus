# GitHub leak search (stage 23)

Searches GitHub's public code search API for mentions of the scan's root domain in public
repositories.

## Scope and authentication

The request target is GitHub's API, never the authorized target, so — like `builtin-ctlogs` and
`rdapProvider` — it uses a plain HTTP client with no scope check.

GitHub's code search API requires an authenticated token. Set `RECONNEXUS_GITHUB_TOKEN` (a
classic personal access token is sufficient; no special scopes are needed for public code
search). Without it, the stage reports `SOURCE_UNAVAILABLE` rather than failing, the same way
`nmap`/`nuclei` report an unavailable binary. The token is read directly from the worker's
environment — it is never passed through the job payload or persisted policy.

An operator can point it at a GitHub Enterprise Server instance via `RECONNEXUS_GITHUB_API_BASE`.

## What it does

One query, `"<domain>"`, against `/search/code`, requesting text-match fragments
(`Accept: application/vnd.github.text-match+json`) so each hit comes with the surrounding
snippet. Up to 20 results per scan.

For every hit:

- A `GITHUB_CODE_MATCH` record is always recorded (repository, path, GitHub URL, relevance
  score), with the snippet passed through the same redaction the secret scanner uses
  (`redactAllRuleMatches`) before being stored — arbitrary public code might contain a real
  credential right next to the domain mention.
- The snippet is **also** run through the existing secret-detection rule set (`scanText`, the
  same function the target's own JavaScript artifacts are scanned with). A fragment that matches
  a secret pattern produces its own `SECRET_CANDIDATE` record and flows through the existing
  secret-finding report pipeline automatically — no separate finding logic was needed for this.

## Findings

A plain code mention is not itself a vulnerability claim — most matches will be benign (a
README, a test fixture, a CI config) — so `GITHUB_CODE_MATCH` stays inventory. Only an actual
secret-shaped match (via the reused secret scanner) becomes a finding, through the existing
secret-detection pipeline.

Opt-in via the `GITHUB_LEAK_SEARCH` capability (migration `0011`); excluded from the `quick` and
`stealth` profiles.

CLI: `reconnexus github <scanId> [--repository --limit]`, `scan run --github-providers`.
