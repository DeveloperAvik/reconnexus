package discovery

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/reconnexus/workers/internal/matching"
	"github.com/reconnexus/workers/internal/scope"
)

// builtinCorsRedirect runs two independent, read-only probes against in-scope targets:
//
//   - CORS reflection: one GET to an already-observed origin with a crafted, arbitrary Origin
//     header, checking whether the response reflects it back in Access-Control-Allow-Origin.
//   - Open redirect: one GET to an already-observed URL with a single query parameter (already
//     identified by the control plane as redirect-shaped) overwritten with an externally-owned
//     canary value, checking whether the response redirects there.
//
// Both probes only ever target an in-scope host; the canary values are reserved, non-resolvable
// domains (RFC 2606 `.invalid`), never a real third party.
type builtinCorsRedirect struct{}

func (builtinCorsRedirect) Name() string            { return "builtin-cors-redirect" }
func (builtinCorsRedirect) Kind() string            { return "CORS_REDIRECT" }
func (builtinCorsRedirect) Capability() string      { return "CORS_REDIRECT_CHECK" }
func (builtinCorsRedirect) NetworkBehavior() string { return "ACTIVE" }

// CORS misconfiguration statuses. NOT_VULNERABLE is recorded, not omitted, so the probe's
// coverage is auditable.
const (
	CorsReflectsArbitraryOriginWithCredentials = "REFLECTS_ARBITRARY_ORIGIN_WITH_CREDENTIALS"
	CorsReflectsArbitraryOrigin                = "REFLECTS_ARBITRARY_ORIGIN"
	CorsNotVulnerable                          = "NOT_VULNERABLE"
)

// Open redirect statuses.
const (
	RedirectConfirmed     = "CONFIRMED"
	RedirectNotVulnerable = "NOT_VULNERABLE"
)

const (
	maxCorsTargets        = 50
	maxRedirectCandidates = 50

	// corsProbeOrigin is sent as the Origin header. It is a reserved, non-resolvable domain
	// (RFC 2606 .invalid): if a response reflects it back, that is proof the server reflects an
	// arbitrary caller-supplied origin rather than checking it against an allowlist.
	corsProbeOrigin = "https://cors-probe.reconnexus.invalid"
	// redirectCanaryURL replaces a candidate's redirect-shaped query parameter. It is a reserved,
	// non-resolvable domain: a response that redirects here proves the parameter controls the
	// redirect target, without ever sending a real browser anywhere.
	redirectCanaryURL = "https://redirect-canary.reconnexus.invalid/"
)

func (builtinCorsRedirect) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{Coverage: Coverage{}}
	corsTargets := job.Inputs.URLs
	if len(corsTargets) > maxCorsTargets {
		corsTargets = corsTargets[:maxCorsTargets]
	}
	redirectCandidates := job.Inputs.RedirectCandidates
	if len(redirectCandidates) > maxRedirectCandidates {
		redirectCandidates = redirectCandidates[:maxRedirectCandidates]
	}
	if len(corsTargets) == 0 && len(redirectCandidates) == 0 {
		res.StatusOverride = StatusSkipped
		res.Diagnostics = append(res.Diagnostics, "no CORS targets or open-redirect candidates to check")
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
	run := func(fn func() (*Record, interfaceResult)) {
		defer wg.Done()
		defer func() { <-sem }()
		rec, outcome := fn()
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
	}

	for _, target := range corsTargets {
		target := target
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			client, _ := newGuardedClient(transport, pc.Engine, timeout, job.MaxRedirects)
			run(func() (*Record, interfaceResult) { return checkCors(ctx, client, pc, target) })
		}()
	}
	for _, cand := range redirectCandidates {
		cand := cand
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			client, _ := newGuardedClient(transport, pc.Engine, timeout, job.MaxRedirects)
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			run(func() (*Record, interfaceResult) { return checkOpenRedirect(ctx, client, pc, cand) })
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		res.StatusOverride = StatusCancelled
	}
	res.Records = records
	if len(records) == 0 {
		res.Diagnostics = append(res.Diagnostics, "no target produced a classifiable response")
	}
	return res, nil
}

// checkCors requests the target origin with a crafted, arbitrary Origin header and classifies
// the response's Access-Control-Allow-Origin/Access-Control-Allow-Credentials headers.
func checkCors(ctx context.Context, client *http.Client, pc ProviderContext, target string) (*Record, interfaceResult) {
	canon, cerr := matching.CanonicalURL(strings.TrimSpace(target))
	if cerr != nil {
		return nil, interfaceSkipped
	}
	d := pc.Engine.Check(scope.Request{Kind: "URL", Value: canon, Capability: "CORS_REDIRECT_CHECK"})
	if !d.Allowed {
		return nil, interfaceSkipped
	}
	parsedTarget, perr := url.Parse(canon)
	if perr != nil || parsedTarget.Hostname() == "" {
		return nil, interfaceSkipped
	}
	host := parsedTarget.Hostname()
	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, canon, nil)
	if rerr != nil {
		return nil, interfaceFailed
	}
	req.Header.Set("User-Agent", "reconnexus/0.20 (+https://github.com/anomalyco/opencode)")
	req.Header.Set("Origin", corsProbeOrigin)
	resp, derr := doRequest(ctx, client, pc.Limiter, req)
	if derr != nil || resp == nil {
		return nil, interfaceFailed
	}
	defer resp.Body.Close()
	_, _, _ = readBounded(resp.Body, maxCloudBodyBytes)
	status := resp.StatusCode
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	info := classifyCors(acao, acac, status)
	return &Record{
		Type:     TypeCorsMisconfig,
		URL:      canon,
		Host:     host,
		Provider: "builtin-cors-redirect",
		Source:   "cors-redirect",
		Cors:     info,
	}, interfaceHit
}

func classifyCors(acao, acac string, status int) *CorsInfo {
	credentials := strings.EqualFold(strings.TrimSpace(acac), "true")
	info := &CorsInfo{AllowOrigin: acao, AllowCredentials: credentials, TestedOrigin: corsProbeOrigin, HTTPStatus: &status}
	reflects := acao == corsProbeOrigin
	switch {
	case reflects && credentials:
		info.Status, info.Confidence = CorsReflectsArbitraryOriginWithCredentials, 0.9
		info.EvidenceType = "REFLECTED_ORIGIN_WITH_CREDENTIALS"
		info.Evidence = "Access-Control-Allow-Origin reflected the arbitrary Origin sent, with Access-Control-Allow-Credentials: true"
	case reflects:
		info.Status, info.Confidence = CorsReflectsArbitraryOrigin, 0.7
		info.EvidenceType = "REFLECTED_ORIGIN"
		info.Evidence = "Access-Control-Allow-Origin reflected the arbitrary Origin sent"
	default:
		info.Status, info.Confidence = CorsNotVulnerable, 0.8
		info.EvidenceType = "NOT_REFLECTED"
		info.Evidence = "Access-Control-Allow-Origin did not reflect the arbitrary Origin sent"
	}
	return info
}

// checkOpenRedirect overwrites the candidate's identified query parameter with the canary URL
// and checks whether the response redirects there. Redirects are inspected, not followed.
func checkOpenRedirect(ctx context.Context, client *http.Client, pc ProviderContext, cand RedirectCandidate) (*Record, interfaceResult) {
	u, perr := url.Parse(strings.TrimSpace(cand.URL))
	if perr != nil || u.Host == "" {
		return nil, interfaceSkipped
	}
	q := u.Query()
	if _, ok := q[cand.Parameter]; !ok {
		return nil, interfaceSkipped
	}
	q.Set(cand.Parameter, redirectCanaryURL)
	u.RawQuery = q.Encode()
	testedURL := u.String()

	canon, cerr := matching.CanonicalURL(testedURL)
	if cerr != nil {
		return nil, interfaceSkipped
	}
	d := pc.Engine.Check(scope.Request{Kind: "URL", Value: canon, Capability: "CORS_REDIRECT_CHECK"})
	if !d.Allowed {
		return nil, interfaceSkipped
	}
	parsedTarget, perr := url.Parse(canon)
	if perr != nil || parsedTarget.Hostname() == "" {
		return nil, interfaceSkipped
	}
	host := parsedTarget.Hostname()
	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, canon, nil)
	if rerr != nil {
		return nil, interfaceFailed
	}
	req.Header.Set("User-Agent", "reconnexus/0.20 (+https://github.com/anomalyco/opencode)")
	resp, derr := doRequest(ctx, client, pc.Limiter, req)
	if derr != nil || resp == nil {
		return nil, interfaceFailed
	}
	defer resp.Body.Close()
	_, _, _ = readBounded(resp.Body, maxCloudBodyBytes)
	status := resp.StatusCode
	location := resp.Header.Get("Location")

	info := classifyOpenRedirect(canon, cand.Parameter, status, location)
	return &Record{
		Type:         TypeOpenRedirect,
		URL:          cand.URL,
		Host:         host,
		Provider:     "builtin-cors-redirect",
		Source:       "cors-redirect",
		OpenRedirect: info,
	}, interfaceHit
}

func classifyOpenRedirect(testedURL, parameter string, status int, location string) *OpenRedirectInfo {
	info := &OpenRedirectInfo{TestedURL: testedURL, Parameter: parameter, HTTPStatus: &status, Location: truncate(location, 300)}
	if status < 300 || status >= 400 || location == "" {
		info.Status, info.Confidence = RedirectNotVulnerable, 0.6
		info.EvidenceType, info.Evidence = "NO_REDIRECT", "no redirect occurred for the injected value"
		return info
	}
	base, berr := url.Parse(testedURL)
	resolved, lerr := url.Parse(location)
	if berr != nil || lerr != nil {
		info.Status, info.Confidence = RedirectNotVulnerable, 0.5
		info.EvidenceType, info.Evidence = "UNPARSEABLE_LOCATION", "redirected, but the Location header could not be parsed"
		return info
	}
	resolvedAbs := base.ResolveReference(resolved).String()
	if strings.HasPrefix(resolvedAbs, redirectCanaryURL) {
		info.Status, info.Confidence = RedirectConfirmed, 0.9
		info.EvidenceType, info.Evidence = "REDIRECTED_TO_CANARY", "redirected to the injected externally-controlled value"
		return info
	}
	info.Status, info.Confidence = RedirectNotVulnerable, 0.8
	info.EvidenceType, info.Evidence = "REDIRECTED_ELSEWHERE", "redirected, but not to the injected value"
	return info
}
