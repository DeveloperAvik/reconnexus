# GraphQL intelligence (stage 21)

Sends a read-only GraphQL introspection query to a bounded list of candidate endpoints and
reports whether introspection is enabled. No mutation is ever sent, and the only queries used are
the standard `__schema` introspection query plus, when that succeeds, one follow-up query per
discovered root type to count its top-level fields — never an attempt to read or modify
application data.

## Candidates

- Every URL already classified `GRAPHQL` during crawling (the URL categorizer already recognizes
  `graphql`/`graphiql` path segments — see `ClassifyURL` in `urlclassify.go` — this stage is what
  acts on that classification).
- A fixed list of well-known GraphQL paths (`/graphql`, `/api/graphql`, `/graphql/console`,
  `/v1/graphql`, `/query`, `/graphiql`) appended to every origin already observed during HTTP
  probing.

Capped at 30 candidates per scan (`MAX_GRAPHQL_CANDIDATES`).

## The check

One POST with `{"query": "{ __schema { queryType { name } mutationType { name }
subscriptionType { name } types { name kind } } } "}`.

- **`INTROSPECTION_ENABLED`**: the response's `data.__schema` is a non-null object. The root
  query/mutation/subscription type names and total type count are recorded. If introspection
  succeeded, one follow-up query per discovered root type (`__type(name: "...") { fields { name
  } } }`) counts its top-level fields, so the finding can say how large the exposed surface is.
- **`INTROSPECTION_DISABLED`**: the response has a GraphQL `errors` array (introspection was
  rejected) — a good outcome, never a finding.
- **`NOT_GRAPHQL`**: the response isn't valid JSON, or is valid JSON with neither a `data` nor an
  `errors` key — this candidate doesn't look like a GraphQL endpoint at all.

## Output

Only `INTROSPECTION_ENABLED` becomes a finding (`GRAPHQL_INTROSPECTION_ENABLED`, `MEDIUM`,
`SUSPECTED`), naming the disclosed root types and field counts. `INTROSPECTION_DISABLED` and
`NOT_GRAPHQL` stay inventory.

Opt-in via the `GRAPHQL_INTROSPECTION` capability (migration `0010`); excluded from the `quick`
and `stealth` profiles.

CLI: `reconnexus graphql <scanId> [--host --status --limit]`, `scan run --graphql-providers`.
