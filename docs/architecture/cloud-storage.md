# Cloud storage exposure (stage 18)

Checks whether a cloud storage bucket fronted by a CNAME on an in-scope host is publicly listable.

## Scope: why this never contacts a third-party bucket hostname directly

The worker's scope engine (`workers/internal/scope`) only ever authorizes a request whose target host is
literally present in the policy's `inScope` list. There is no capability that bypasses this, by design: it
is what lets an independent, worker-side check catch a compromised or misconfigured control plane. That
means a bucket referenced only by its own cloud-provider hostname (`mybucket.s3.amazonaws.com` found in a
JS bundle, say, but never added to the policy's `inScope`) **cannot** be checked by this stage — the request
would simply be dropped as out of scope, capability or not.

What this stage checks instead is a CNAME-fronted bucket: an in-scope host (`static.example.com`) whose
DNS CNAME points at a cloud storage endpoint. The request target is always `static.example.com` itself —
already authorized — and both S3 and GCS route that request to the bucket at the DNS layer. This is also
the only configuration where the finding is actionable without more evidence: the bucket is demonstrably
serving the target's own domain, not merely referenced by it.

**Not implemented:** checking a bucket by its own hostname when that hostname isn't in scope. If you know a
specific third-party bucket hostname belongs to the target and want it checked, add it to the policy's
`inScope.hosts` explicitly; after that it is just another in-scope host like any other.

## Candidate derivation

The control plane derives candidates from DNS CNAME records of in-scope hosts, already collected during the
DNS stage — no new request is made to find them. A CNAME target is matched against:

- **Amazon S3, REST-style endpoints only**: `*.amazonaws.com` ending in `s3.<region>.amazonaws.com`,
  `s3-<region>.amazonaws.com`, or the legacy per-bucket virtual-host form `<bucket>.s3.amazonaws.com`.
  `s3-website-*` is deliberately excluded: a website endpoint answers a plain GET with the site's own
  intended public content, never a listing, so it can never produce this stage's finding.
- **Google Cloud Storage**: a bare CNAME to `storage.googleapis.com` or `c.storage.googleapis.com`.

Bucket name: the legacy per-bucket vhost form carries the bucket name as its leading label (`mybucket.s3...`
→ `mybucket`). A bare CNAME to the shared endpoint requires the bucket name to equal the custom domain
itself — that's what makes DNS-layer routing work at all for that form — so the bucket name is the host.

At most 25 candidates per scan (`MAX_CLOUD_STORAGE_CANDIDATES`).

## The check

One GET to the in-scope host's own origin, HTTPS first then HTTP (a REST-style custom-domain CNAME is
typically served without a certificate that matches the custom domain, so the HTTP fallback is required for
this to work at all, not just a convenience). Redirects are inspected, not followed.

- **`LISTABLE`**: the response is HTTP 200 and the body contains an actual `<ListBucketResult>` element
  (S3's REST API and GCS's S3-interoperable XML API share this response shape). Confidence 0.9. The number
  of `<Key>` elements is counted (capped) and recorded, never the keys themselves.
- **`NOT_LISTABLE`**: the body is an `<Error>` with code `AccessDenied`/`Forbidden` — the bucket exists and
  listing is not public. This is a good outcome and is never a finding.
- **`INCONCLUSIVE`**: either the error code is `NoSuchBucket` (no bucket by that name exists — a
  dangling-CNAME/subdomain-takeover question, already covered by the `13-subdomain-takeover` stage, not an
  exposure here), or the response matched neither shape at all (for example an unrelated CDN or WAF page).
  A generic 200 is never read as a listing without the `<ListBucketResult>` element itself present.

No write request is ever made, and no bucket name beyond the one CNAME derivation produced is ever guessed
or brute-forced.

## Output

`CLOUD_STORAGE` records become `cloud-storage` observations on a `CLOUD_BUCKET` asset, related to the
fronting host (`fronts_bucket`). Only `LISTABLE` becomes a finding: `SUSPECTED`, `HIGH`,
`EXPOSED_CLOUD_STORAGE`, naming the provider, bucket and fronting host. `NOT_LISTABLE` and `INCONCLUSIVE`
stay inventory.

CLI: `reconnexus buckets <scanId> [--host --status --limit]`, `scan run --cloud-storage-providers`.
