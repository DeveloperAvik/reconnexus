package discovery

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/reconnexus/workers/internal/matching"
	"github.com/reconnexus/workers/internal/scope"
)

// builtinParamDiscovery looks for undocumented query parameters on a candidate URL by injecting
// a fixed wordlist of common parameter names, each with a unique random probe value, and
// comparing the response to a calibration baseline. Two unmodified requests to the candidate are
// made first to measure the page's natural response variance; a candidate whose own baseline
// already varies more than the detection threshold is skipped, so a page that is simply dynamic
// (a timestamp, a CSRF token) is never reported as having a discovered parameter.
type builtinParamDiscovery struct{}

func (builtinParamDiscovery) Name() string            { return "builtin-param-discovery" }
func (builtinParamDiscovery) Kind() string            { return "PARAMETER_DISCOVERY" }
func (builtinParamDiscovery) Capability() string      { return "PARAMETER_DISCOVERY" }
func (builtinParamDiscovery) NetworkBehavior() string { return "ACTIVE" }

const (
	maxParamCandidates = 15
	maxParamBodyBytes  = 256 * 1024
	// lengthDeltaMargin is added on top of the candidate's own measured natural variance before a
	// length difference is treated as evidence, so ordinary per-request noise never qualifies.
	lengthDeltaMargin = 50
)

// paramWordlist is deliberately short and high-signal: common application/debug/pagination
// parameters, not an exhaustive fuzzing list. A name absent from this list is simply never
// tested — its absence from a result is not evidence the parameter doesn't exist.
var paramWordlist = []string{
	"id", "debug", "test", "admin", "format", "callback", "page", "limit", "offset", "sort",
	"filter", "search", "q", "lang", "locale", "api_key", "apikey", "key", "secret",
	"access_token", "token", "session", "sid", "ref", "source", "version", "v", "action", "cmd",
	"file", "path", "template", "view", "mode", "env", "config", "type", "output", "include", "fields",
}

func (builtinParamDiscovery) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{Coverage: Coverage{}}
	candidates := job.Inputs.URLs
	if len(candidates) > maxParamCandidates {
		candidates = candidates[:maxParamCandidates]
	}
	if len(candidates) == 0 {
		res.StatusOverride = StatusSkipped
		res.Diagnostics = append(res.Diagnostics, "no parameter-discovery candidates to check")
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
			local, outcome := checkParamDiscovery(ctx, client, pc, cand)
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
			records = append(records, local...)
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		res.StatusOverride = StatusCancelled
	}
	res.Records = records
	if len(records) == 0 {
		res.Diagnostics = append(res.Diagnostics, "no undocumented parameter discovered")
	}
	return res, nil
}

func checkParamDiscovery(ctx context.Context, client *http.Client, pc ProviderContext, candidate string) ([]Record, interfaceResult) {
	canon, cerr := matching.CanonicalURL(strings.TrimSpace(candidate))
	if cerr != nil {
		return nil, interfaceSkipped
	}
	d := pc.Engine.Check(scope.Request{Kind: "URL", Value: canon, Capability: "PARAMETER_DISCOVERY"})
	if !d.Allowed {
		return nil, interfaceSkipped
	}
	parsedURL, perr := url.Parse(canon)
	if perr != nil || parsedURL.Hostname() == "" {
		return nil, interfaceSkipped
	}
	host := parsedURL.Hostname()

	base1Status, base1Body, ok := getParam(ctx, client, pc, canon)
	if !ok {
		return nil, interfaceFailed
	}
	base2Status, base2Body, ok := getParam(ctx, client, pc, canon)
	if !ok {
		return nil, interfaceFailed
	}
	naturalDelta := absInt(len(base1Body) - len(base2Body))
	if base1Status != base2Status || naturalDelta > lengthDeltaMargin*4 {
		// The page's own baseline is already unstable (status flaps, or the body varies by a lot
		// between two unmodified requests); testing parameters against it would be unreliable.
		return nil, interfaceSkipped
	}
	threshold := naturalDelta + lengthDeltaMargin

	var out []Record
	for _, name := range paramWordlist {
		if ctx.Err() != nil {
			break
		}
		probe := randomLabel()
		testURL, terr := withQueryParam(canon, name, probe)
		if terr != nil {
			continue
		}
		testStatus, testBody, ok := getParam(ctx, client, pc, testURL)
		if !ok {
			continue
		}
		info := classifyParamDiscovery(name, probe, base1Status, len(base1Body), testStatus, testBody, threshold)
		if info == nil {
			continue
		}
		out = append(out, Record{Type: TypeParamDiscovery, URL: canon, Host: host, Provider: "builtin-param-discovery", Source: "param-discovery", ParamDiscovery: info})
	}
	if len(out) == 0 {
		return nil, interfaceMiss
	}
	return out, interfaceHit
}

func getParam(ctx context.Context, client *http.Client, pc ProviderContext, url string) (int, string, bool) {
	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if rerr != nil {
		return 0, "", false
	}
	req.Header.Set("User-Agent", "reconnexus/0.20 (+https://github.com/anomalyco/opencode)")
	resp, derr := doRequest(ctx, client, pc.Limiter, req)
	if derr != nil || resp == nil {
		return 0, "", false
	}
	defer resp.Body.Close()
	b, _, _ := readBounded(resp.Body, maxParamBodyBytes)
	return resp.StatusCode, b, true
}

func withQueryParam(raw, name, value string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// classifyParamDiscovery only ever returns a record for a positive signal: reflection of the
// unique probe value is the strongest evidence, a status-code change is next, and a length
// change beyond the candidate's own calibrated threshold is the weakest. Anything else returns
// nil, and nothing is recorded — consistent with a closed port never being recorded.
func classifyParamDiscovery(name, probe string, baseStatus, baseLen, testStatus int, testBody string, threshold int) *ParamDiscoveryInfo {
	bs := baseStatus
	switch {
	case strings.Contains(testBody, probe):
		return &ParamDiscoveryInfo{
			Parameter: name, Confidence: 0.85, HTTPStatus: &testStatus, BaselineStatus: &bs, BaselineLength: baseLen, TestLength: len(testBody),
			Evidence: "injected probe value for parameter \"" + name + "\" was reflected in the response", EvidenceType: "REFLECTED_VALUE",
		}
	case testStatus != baseStatus:
		return &ParamDiscoveryInfo{
			Parameter: name, Confidence: 0.7, HTTPStatus: &testStatus, BaselineStatus: &bs, BaselineLength: baseLen, TestLength: len(testBody),
			Evidence: "adding parameter \"" + name + "\" changed the response status from " + strconv.Itoa(baseStatus) + " to " + strconv.Itoa(testStatus), EvidenceType: "STATUS_CODE_CHANGE",
		}
	case absInt(len(testBody)-baseLen) > threshold:
		return &ParamDiscoveryInfo{
			Parameter: name, Confidence: 0.5, HTTPStatus: &testStatus, BaselineStatus: &bs, BaselineLength: baseLen, TestLength: len(testBody),
			Evidence: "adding parameter \"" + name + "\" changed the response length beyond the page's own calibrated variance", EvidenceType: "LENGTH_DELTA",
		}
	}
	return nil
}
