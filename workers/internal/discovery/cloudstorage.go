package discovery

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/reconnexus/workers/internal/matching"
	"github.com/reconnexus/workers/internal/scope"
)

// builtinCloudStorage checks, for each candidate the control plane derived from a CNAME on an
// in-scope host, whether the cloud storage bucket that CNAME fronts is publicly listable. The
// request target is always the in-scope host itself (never the bucket's own cloud-provider
// hostname): the control plane resolves candidates from CNAME records of in-scope hosts, so this
// never asks the worker to reach a third-party domain the policy never authorized. One bounded
// GET per candidate; no writes, no bucket-name guessing beyond the CNAME the control plane saw.
type builtinCloudStorage struct{}

func (builtinCloudStorage) Name() string            { return "builtin-cloud-storage" }
func (builtinCloudStorage) Kind() string            { return "CLOUD_STORAGE" }
func (builtinCloudStorage) Capability() string      { return "CLOUD_STORAGE_CHECK" }
func (builtinCloudStorage) NetworkBehavior() string { return "ACTIVE" }

// Cloud storage providers.
const (
	CloudProviderS3  = "S3"
	CloudProviderGCS = "GCS"
)

// Cloud storage statuses. LISTABLE means the bucket answered with an object listing anyone can
// read; NOT_LISTABLE means it answered but declined to list (access denied, or no such bucket by
// that name, which is a dangling-CNAME/takeover question handled by the takeover stage, not this
// one); INCONCLUSIVE means the response did not look like either.
const (
	CloudStorageListable     = "LISTABLE"
	CloudStorageNotListable  = "NOT_LISTABLE"
	CloudStorageInconclusive = "INCONCLUSIVE"
)

const (
	maxCloudCandidates  = 25
	maxCloudBodyBytes   = 512 * 1024
	maxCloudObjectCount = 100000
)

// S3's XML REST API and GCS's S3-interoperable XML API share the same response shapes, so one
// parser covers both. <Key> elements inside <ListBucketResult> are one entry per listed object;
// counting them (capped) is the only thing read out of the body besides the error code.
var (
	listBucketResultRe = regexp.MustCompile(`(?i)<ListBucketResult[\s>]`)
	bucketKeyRe        = regexp.MustCompile(`(?i)<Key>`)
	errorCodeRe        = regexp.MustCompile(`(?is)<Error>.*?<Code>\s*([A-Za-z]+)\s*</Code>`)
)

func (builtinCloudStorage) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{Coverage: Coverage{}}
	candidates := job.Inputs.CloudCandidates
	if len(candidates) > maxCloudCandidates {
		candidates = candidates[:maxCloudCandidates]
	}
	if len(candidates) == 0 {
		res.StatusOverride = StatusSkipped
		res.Diagnostics = append(res.Diagnostics, "no CNAME-derived cloud storage candidates to check")
		return res, nil
	}

	concurrency := job.Limits.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 4
	}
	if concurrency > 8 {
		concurrency = 8
	}
	timeout := time.Duration(job.RequestTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = time.Duration(defaultCrawlTimeoutMs) * time.Millisecond
	}
	transport, err := pc.buildTransport(job)
	if err != nil {
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "cannot build transport: "+err.Error())
		return res, nil
	}

	var mu sync.Mutex
	var records []Record
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for _, cand := range candidates {
		cand := cand
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			client, _ := newGuardedClient(transport, pc.Engine, timeout, job.MaxRedirects)
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			rec, outcome := checkCloudStorage(ctx, client, pc, cand)
			mu.Lock()
			defer mu.Unlock()
			res.Coverage.Attempted++
			switch outcome {
			case interfaceHit, interfaceMiss:
				res.Coverage.Succeeded++
			case interfaceSkipped:
				res.Coverage.Skipped++
			default:
				res.Coverage.Failed++
			}
			if rec != nil {
				records = append(records, *rec)
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		res.StatusOverride = StatusCancelled
	}
	res.Records = records
	if len(records) == 0 {
		res.Diagnostics = append(res.Diagnostics, "no cloud storage candidate produced a classifiable response")
	}
	return res, nil
}

// checkCloudStorage requests the candidate's own in-scope host over HTTPS, then HTTP: a
// REST-style custom-domain CNAME is typically served without a matching TLS certificate, so the
// plain-HTTP fallback is required for this check to work at all, not just a convenience.
func checkCloudStorage(ctx context.Context, client *http.Client, pc ProviderContext, cand CloudStorageCandidate) (*Record, interfaceResult) {
	u, perr := url.Parse(strings.TrimSpace(cand.URL))
	if perr != nil || u.Host == "" {
		return nil, interfaceSkipped
	}
	netloc := u.Host // host[:port], so a non-default test port round-trips correctly
	host := u.Hostname()
	var status int
	var body string
	var usedURL string
	var ferr error
	for _, scheme := range []string{"https", "http"} {
		target := scheme + "://" + netloc + "/"
		canon, cerr := matching.CanonicalURL(target)
		if cerr != nil {
			continue
		}
		d := pc.Engine.Check(scope.Request{Kind: "URL", Value: canon, Capability: "CLOUD_STORAGE_CHECK"})
		if !d.Allowed {
			return nil, interfaceSkipped
		}
		req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, canon, nil)
		if rerr != nil {
			continue
		}
		req.Header.Set("User-Agent", "reconnexus/0.20 (+https://github.com/anomalyco/opencode)")
		req.Header.Set("Accept", "application/xml,text/plain,*/*")
		resp, derr := doRequest(ctx, client, pc.Limiter, req)
		if derr != nil || resp == nil {
			ferr = derr
			continue
		}
		b, _, _ := readBounded(resp.Body, maxCloudBodyBytes)
		resp.Body.Close()
		status, body, usedURL, ferr = resp.StatusCode, b, canon, nil
		break
	}
	if ferr != nil || status == 0 {
		return nil, interfaceFailed
	}

	info := classifyCloudStorage(cand, status, body)
	return &Record{
		Type:         TypeCloudStorage,
		URL:          usedURL,
		Host:         host,
		Provider:     "builtin-cloud-storage",
		Source:       "cloud-storage",
		CloudStorage: info,
	}, interfaceHit
}

// classifyCloudStorage never reports LISTABLE from a status alone: it requires the
// <ListBucketResult> element itself, since a generic 200 with unrelated XML (a CDN or WAF error
// page, for example) must not be read as a public bucket.
func classifyCloudStorage(cand CloudStorageCandidate, status int, body string) *CloudStorageInfo {
	info := &CloudStorageInfo{CloudProvider: cand.Provider, Bucket: cand.Bucket, Origin: "CUSTOM_DOMAIN", HTTPStatus: &status}
	switch {
	case status == http.StatusOK && listBucketResultRe.MatchString(body):
		count := len(bucketKeyRe.FindAllStringIndex(body, maxCloudObjectCount+1))
		if count > maxCloudObjectCount {
			count = maxCloudObjectCount
		}
		info.Status, info.Confidence, info.ObjectCount = CloudStorageListable, 0.9, count
		info.EvidenceType = "LIST_BUCKET_RESULT"
		info.Evidence = "HTTP 200 with a <ListBucketResult> object listing"
	case errorCodeRe.FindStringSubmatch(body) != nil:
		code := strings.ToLower(errorCodeRe.FindStringSubmatch(body)[1])
		info.Status, info.Confidence = CloudStorageNotListable, 0.8
		switch {
		case strings.Contains(code, "accessdenied") || strings.Contains(code, "forbidden"):
			info.EvidenceType, info.Evidence = "ACCESS_DENIED", "HTTP "+strconv.Itoa(status)+" with error code "+code+": listing is not public"
		case strings.Contains(code, "nosuchbucket"):
			info.EvidenceType, info.Evidence = "NO_SUCH_BUCKET", "HTTP "+strconv.Itoa(status)+" with error code "+code+": no bucket by this name exists (see subdomain-takeover findings, not an exposure)"
			info.Status, info.Confidence = CloudStorageInconclusive, 0.6
		default:
			info.EvidenceType, info.Evidence = "ERROR_RESPONSE", "HTTP "+strconv.Itoa(status)+" with error code "+code
		}
	default:
		info.Status, info.Confidence = CloudStorageInconclusive, 0.3
		info.EvidenceType, info.Evidence = "UNRECOGNIZED_RESPONSE", "HTTP "+strconv.Itoa(status)+" did not match a known bucket listing or error response"
	}
	return info
}
