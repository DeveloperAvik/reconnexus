# Risk ranking and scan profiles

## Risk ranking (`rn risk <scanId>`)
Ranks hosts by how much attention they deserve. Inputs are the scan's findings, open non-web ports and
login interfaces; nothing is exploited or validated, so this is a prioritization aid, not a likelihood of
compromise.

- Finding points = severity (CRITICAL 40, HIGH 25, MEDIUM 12, LOW 4, INFO 1) x validation weight
  (VALIDATED 1, SUSPECTED 0.8, OBSERVED 0.7, INDETERMINATE 0.3, REJECTED 0) x (0.5 + 0.5 x confidence).
- Each severity tier adds at most 2x a single finding's points per host, so many LOW findings never equal a HIGH one.
- Non-web open ports: 2 points each, capped at 10. Login interfaces: admin 8/3, control panel 10/4
  (detected/possible), once per host, kind and status.
- Raw points are squashed to 0-100 (`100 x (1 - e^(-raw/50))`). Levels: >=70 CRITICAL, >=45 HIGH, >=20 MEDIUM,
  >0 LOW, 0 MINIMAL. `--explain` lists the factors behind each score.
- Not yet included: CVE/KEV applicability from `vulns`, and change recency from `changes`.

## Scan profiles (`scan start --profile <name>`)
Chosen when the scan is planned and recorded in its config snapshot. A profile never raises a rate,
concurrency or depth above the policy, and never adds a capability.

| Profile | Left out | Limits | Other |
| --- | --- | --- | --- |
| `quick` | port scan, template checks, login finder | crawl depth <= 1 | crawl budget 200 |
| `standard` | nothing | policy's own | crawl budget 800 |
| `deep` | nothing | policy's own | crawl budget 2000, ports 1-1000 + common high ports, tags + `cve` |
| `stealth` | port scan, template checks, login finder | <= 2 req/s, <= 2 connections, depth <= 1 | crawl budget 100 |

Left-out stages are not planned at all (like opt-in stages the policy does not grant), so the scan is not
reported `PARTIAL` for work it was never meant to do. An explicit `--ports` or `--template-tags` wins over a
profile default.
