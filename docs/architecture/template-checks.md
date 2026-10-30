# Template checks (stage 16)

Runs nuclei over the HTTP origins observed during probing, restricted to detection-oriented templates.

## Authorization and safety
- Requires `ACTIVE_TEMPLATE_CHECK`. Without it the stage is not planned, and a worker job is `BLOCKED`.
- Default tags: `exposure,misconfig,tech,panel`. `--template-tags` replaces the include list (lowercase
  letters, digits, `_`, `-`; a tag can never become a flag).
- Always excluded, whatever the job says: `dos,fuzz,intrusive,bruteforce,brute-force,default-login,oast,rce,
  sqli,xss,ssrf,lfi,kev`. Template updates (`-duc`) and the out-of-band service (`-ni`) are off. Rate and
  concurrency follow the policy limits (concurrency capped at 10).
- Targets are re-checked against scope in the worker, and a match whose URL is out of scope is discarded.
- nuclei emits the full request and response; the parser never reads them. Extracted values are redacted
  and truncated (5 values, 200 characters).
- Templates must already be installed (`nuclei -update-templates`); the stage does not download them.

## Output
`TEMPLATE_FINDING` records become `template-finding` observations on the matched URL. Non-INFO matches are
findings (`TEMPLATE_MATCH`, `SUSPECTED`, CRITICAL capped at HIGH): a signature match is not a verified
vulnerability and can be a false positive. INFO matches (technology detection) stay inventory. No match is
not proof the issue is absent.
