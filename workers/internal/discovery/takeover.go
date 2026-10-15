package discovery

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/reconnexus/workers/internal/telemetry"
)

// builtinTakeover performs non-destructive subdomain-takeover detection. For each in-scope host it
// resolves the CNAME, matches it against a maintained set of takeover-prone services, and issues a
// single bounded HTTP request to the host to look for that service's "unclaimed" marker. It NEVER
// claims, registers, or probes the third-party service, and it never reports a confirmed takeover.
type builtinTakeover struct{}

func (builtinTakeover) Name() string            { return "builtin-takeover" }
func (builtinTakeover) Kind() string            { return "TAKEOVER" }
func (builtinTakeover) Capability() string      { return "TAKEOVER_CHECK" }
func (builtinTakeover) NetworkBehavior() string { return "ACTIVE" }

// takeoverFingerprint describes a service that is prone to subdomain takeover.
type takeoverFingerprint struct {
	service string
	/** CNAME suffixes that belong to the service (matched exactly or as a label suffix). */
	suffixes []string
	/** Body substrings (lowercased) that indicate an unclaimed/available resource. */
	markers []string
	/** HTTP status codes consistent with an unclaimed resource. */
	statusCodes []int
}

// Markers must be service-specific. Generic strings such as "not found", "bad request" or
// "doesn't exist" appear on ordinary error pages and were the main source of false positives, so
// they were removed: a service with only a generic string now needs the marker absent and yields
// INCONCLUSIVE from the status code, never a candidate.
var takeoverFingerprints = []takeoverFingerprint{
	{"GitHub Pages", []string{"github.io"}, []string{"there isn't a github pages site here"}, []int{404}},
	{"Heroku", []string{"herokuapp.com", "herokussl.com"}, []string{"no such app"}, []int{404}},
	{"Amazon S3", []string{"s3.amazonaws.com", "s3-website-us-east-1.amazonaws.com", "s3-website.eu-west-1.amazonaws.com", "s3-website-us-west-2.amazonaws.com"}, []string{"nosuchbucket", "the specified bucket does not exist"}, []int{404, 403}},
	{"Amazon CloudFront", []string{"cloudfront.net"}, []string{"the request could not be satisfied"}, []int{403, 404}},
	{"Azure App Service", []string{"azurewebsites.net"}, []string{"error 404 - web app not found", "web app not found"}, []int{404}},
	// Azure Traffic Manager has no reliable service-specific unclaimed marker, so it can only ever
	// be INCONCLUSIVE from a matching status, never a candidate.
	{"Azure Traffic Manager", []string{"trafficmanager.net"}, nil, []int{404}},
	{"Azure Blob Storage", []string{"blob.core.windows.net", "web.core.windows.net"}, []string{"the specified container does not exist", "blobnotfound"}, []int{404}},
	{"Fastly", []string{"fastly.net", "fastlylb.net", "global.ssl.fastly.net"}, []string{"fastly error: unknown domain"}, []int{404, 500, 503}},
	{"Netlify", []string{"netlify.app", "netlify.com"}, []string{"not found - request id"}, []int{404}},
	{"Vercel", []string{"vercel.app", "now.sh"}, []string{"the deployment could not be found", "deployment_not_found"}, []int{404}},
	{"Surge", []string{"surge.sh"}, []string{"project not found"}, []int{404}},
	{"Pantheon", []string{"pantheonsite.io", "gotpantheon.com"}, []string{"the site you were looking for couldn't be found"}, []int{404}},
	{"Read the Docs", []string{"readthedocs.io", "readthedocs.org", "rtfd.io"}, []string{"unknown domain"}, []int{404}},
	{"Shopify", []string{"myshopify.com"}, []string{"sorry, this shop is currently unavailable"}, []int{404}},
	{"Tumblr", []string{"tumblr.com"}, []string{"there's nothing here", "there isn’t a blog here"}, []int{404}},
	{"Zendesk", []string{"zendesk.com"}, []string{"help center closed"}, []int{404}},
	{"Ghost", []string{"ghost.io"}, []string{"domain not configured"}, []int{404}},
	{"UserVoice", []string{"uservoice.com"}, []string{"this uservoice subdomain is still available"}, []int{200, 404}},
	{"Statuspage", []string{"statuspage.io"}, nil, []int{404}},
	{"WordPress.com", []string{"wordpress.com"}, nil, []int{404}},
}

func matchTakeoverService(cname string) *takeoverFingerprint {
	c := strings.ToLower(strings.TrimSuffix(cname, "."))
	for i := range takeoverFingerprints {
		fp := &takeoverFingerprints[i]
		for _, s := range fp.suffixes {
			if c == s || strings.HasSuffix(c, "."+s) {
				return fp
			}
		}
	}
	return nil
}

func (builtinTakeover) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{Coverage: Coverage{}}
	urls := job.Inputs.URLs
	if len(urls) == 0 {
		res.StatusOverride = StatusSkipped
		res.Diagnostics = append(res.Diagnostics, "no candidate hosts to check for takeover")
		return res, nil
	}
	res.Coverage.Attempted = len(urls)

	concurrency := job.Limits.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 8
	}
	if concurrency > 32 {
		concurrency = 32
	}
	timeout := time.Duration(job.RequestTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = defaultCrawlTimeoutMs * time.Millisecond
	}
	maxBytes := job.Limits.MaxArtifactBytes
	if maxBytes <= 0 {
		maxBytes = 256 * 1024
	}
	resolver := resolverFactory(job)
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
	for _, raw := range urls {
		raw := raw
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			client, _ := newGuardedClient(transport, pc.Engine, timeout, job.MaxRedirects)
			rec, checked := checkTakeover(ctx, resolver, client, raw, maxBytes)
			mu.Lock()
			if rec != nil {
				records = append(records, *rec)
			}
			if checked {
				res.Coverage.Succeeded++
			} else {
				res.Coverage.Skipped++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		res.StatusOverride = StatusCancelled
	}
	res.Records = records
	return res, nil
}

func checkTakeover(ctx context.Context, resolver hostResolver, client *http.Client, rawURL string, maxBytes int) (*Record, bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return nil, false
	}
	host := strings.ToLower(u.Hostname())

	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	cname, err := resolver.LookupCNAME(cctx, host)
	cancel()
	if err != nil {
		return nil, false
	}
	cname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cname), "."))
	if cname == "" || cname == host {
		return nil, false // no CNAME → not a CNAME-based takeover candidate
	}
	fp := matchTakeoverService(cname)
	if fp == nil {
		return nil, false // points at a service we do not fingerprint; stay quiet
	}

	httpStatus, body, fetchErr := fetchForTakeover(ctx, client, rawURL, maxBytes)
	info := &TakeoverInfo{
		Host:       host,
		CNAME:      cname,
		Service:    fp.service,
		Confidence: 0.3,
		Evidence:   fmt.Sprintf("CNAME %s -> %s (%s)", host, cname, fp.service),
	}
	if fetchErr != nil {
		info.Status = TakeoverInconclusive
		info.Confidence = 0.3
		info.Evidence += "; HTTP fetch failed: " + truncate(telemetry.RedactString(fetchErr.Error()), 120)
	} else if sc := httpStatus; sc != nil {
		info.HTTPStatus = sc
		lower := strings.ToLower(body)
		marker := matchedMarker(lower, fp.markers)
		switch {
		case marker != "":
			info.Status = TakeoverSuspected
			info.Confidence = 0.8
			info.EvidenceType = "UNCLAIMED_MARKER"
			info.Evidence += fmt.Sprintf("; HTTP %d; unclaimed marker matched: %q", *sc, marker)
		case containsInt(fp.statusCodes, *sc):
			// A matching status with no service-specific unclaimed marker is not evidence of a
			// takeover: the same status is returned by ordinary error pages on claimed resources.
			// Report it as INCONCLUSIVE so it is never presented as a candidate.
			info.Status = TakeoverInconclusive
			info.Confidence = 0.25
			info.EvidenceType = "STATUS_ONLY"
			info.Evidence += fmt.Sprintf("; HTTP %d, but no unclaimed marker matched — status alone is not evidence of an unclaimed resource", *sc)
		default:
			info.Status = TakeoverNotVuln
			info.Confidence = 0.15
			info.EvidenceType = "RESPONSE"
			info.Evidence += fmt.Sprintf("; HTTP %d (no unclaimed marker; resource appears claimed)", *sc)
		}
	} else {
		info.Status = TakeoverInconclusive
		info.Confidence = 0.3
	}
	info.Evidence = telemetry.RedactString(info.Evidence)
	return &Record{
		Type:     TypeTakeoverCandidate,
		URL:      rawURL,
		Host:     host,
		Provider: "builtin-takeover",
		Source:   "takeover",
		Takeover: info,
	}, true
}

func fetchForTakeover(ctx context.Context, client *http.Client, rawURL string, maxBytes int) (*int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "reconnexus/0.12 (+https://github.com/anomalyco/opencode)")
	resp, derr := client.Do(req)
	if derr != nil || resp == nil {
		if derr == nil {
			derr = fmt.Errorf("no response")
		}
		return nil, "", derr
	}
	defer resp.Body.Close()
	body, _, _ := readBounded(resp.Body, maxBytes)
	sc := resp.StatusCode
	return &sc, body, nil
}

func matchedMarker(lowerBody string, markers []string) string {
	for _, m := range markers {
		if strings.Contains(lowerBody, strings.ToLower(m)) {
			return m
		}
	}
	return ""
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
