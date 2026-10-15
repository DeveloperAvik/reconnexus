package discovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/reconnexus/workers/internal/matching"
	"github.com/reconnexus/workers/internal/scope"
	"github.com/reconnexus/workers/internal/telemetry"
)

// builtinJSProvider retrieves JavaScript artifacts and statically analyses them. Analysis is a
// bounded lexical scan using RE2 (linear-time) regular expressions — no JavaScript is executed,
// no packages are installed, and no browser is used. Pathological input is bounded by the
// response-size limit and per-artifact candidate caps.
type builtinJSProvider struct{}

func (builtinJSProvider) Name() string            { return "builtin-js" }
func (builtinJSProvider) Kind() string            { return "JS_ANALYSIS" }
func (builtinJSProvider) Capability() string      { return "JS_ANALYSIS" }
func (builtinJSProvider) NetworkBehavior() string { return "ACTIVE" }

const (
	maxJSFindings      = 500
	maxSourceMapBytes  = 4 * 1024 * 1024
	maxSourceMapSource = 2000
)

func (builtinJSProvider) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{Coverage: Coverage{}}
	urls := job.Inputs.JSURLs
	if len(urls) == 0 {
		res.StatusOverride = StatusSkipped
		res.Diagnostics = append(res.Diagnostics, "no JavaScript URLs to analyse")
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
		maxBytes = 4 * 1024 * 1024
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
	var diagnostics []string
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
			recs, diag, ok, skipped := analyseOne(ctx, client, pc, raw, maxBytes, job.Inputs.FetchSourceMaps)
			mu.Lock()
			records = append(records, recs...)
			diagnostics = append(diagnostics, diag...)
			res.Coverage.Skipped += skipped
			if ok {
				res.Coverage.Succeeded++
			} else {
				res.Coverage.Failed++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if ctx.Err() != nil {
		res.StatusOverride = StatusCancelled
	}
	res.Records = records
	res.Diagnostics = append(res.Diagnostics, diagnostics...)
	return res, nil
}

func analyseOne(ctx context.Context, client *http.Client, pc ProviderContext, rawURL string, maxBytes int, fetchSourceMaps bool) ([]Record, []string, bool, int) {
	var out []Record
	var diag []string

	canon, err := matching.CanonicalURL(rawURL)
	if err != nil {
		return nil, []string{"invalid JS URL: " + truncate(rawURL, 80)}, false, 0
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, canon, nil)
	if err != nil {
		return nil, []string{"request build failed: " + err.Error()}, false, 0
	}
	req.Header.Set("User-Agent", "reconnexus/0.5 (+https://github.com/anomalyco/opencode)")
	req.Header.Set("Accept", "application/javascript, text/javascript, */*")
	resp, derr := doRequest(ctx, client, pc.Limiter, req)
	artifact := JsArtifactInfo{URL: rawURL, CanonicalURL: canon, DiscoveryMethod: "stage05"}
	if derr != nil {
		artifact.Status = ArtifactError
		artifact.Error = telemetry.RedactString(derr.Error())
		out = append(out, Record{Type: TypeJSArtifact, URL: rawURL, CanonicalURL: canon, Provider: "builtin-js", Source: "js", Artifact: &artifact})
		return out, []string{"js fetch failed " + truncate(canon, 100) + ": " + truncate(derr.Error(), 120)}, false, 0
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		artifact.Status = ArtifactNotFound
		out = append(out, Record{Type: TypeJSArtifact, URL: rawURL, CanonicalURL: canon, Provider: "builtin-js", Source: "js", Artifact: &artifact})
		return out, nil, false, 0
	}
	if resp.StatusCode >= 400 {
		artifact.Status = ArtifactError
		artifact.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		out = append(out, Record{Type: TypeJSArtifact, URL: rawURL, CanonicalURL: canon, Provider: "builtin-js", Source: "js", Artifact: &artifact})
		return out, nil, false, 0
	}

	body, truncated, _ := readBounded(resp.Body, maxBytes)
	sum := sha256.Sum256([]byte(body))
	artifact.ContentHash = hex.EncodeToString(sum[:])
	artifact.ContentType = resp.Header.Get("Content-Type")
	artifact.SizeBytes = len(body)
	artifact.Truncated = truncated
	artifact.Status = ArtifactRetrieved
	// Misleading MIME: served as JS but is actually HTML (common WAF/404 page).
	isHTML := strings.Contains(strings.ToLower(artifact.ContentType), "html") ||
		strings.HasPrefix(strings.TrimSpace(strings.ToLower(string(body))), "<!doctype html") ||
		strings.HasPrefix(strings.TrimSpace(strings.ToLower(string(body))), "<html")
	if isHTML {
		artifact.Status = ArtifactMismatchedMime
	}
	if truncated {
		artifact.Status = ArtifactOversized
	}
	if resp.Request != nil {
		if c, err := matching.CanonicalURL(resp.Request.URL.String()); err == nil {
			artifact.CanonicalURL = c
		}
	}

	// Content validation: an HTML error page or a non-script asset (image, font, video, PDF,
	// archive) is not JavaScript, whatever the URL extension said. Record the observation and its
	// classification rationale, but never run lexical JS analysis over HTML or binary content.
	if isHTML || truncated {
		out = append(out, Record{Type: TypeJSArtifact, URL: rawURL, CanonicalURL: artifact.CanonicalURL, Provider: "builtin-js", Source: "js", Artifact: &artifact})
		if isHTML {
			return out, []string{"skipped non-JavaScript artifact " + truncate(canon, 100) + ": served HTML (" + truncate(artifact.ContentType, 60) + ")"}, true, 0
		}
		return out, []string{"skipped oversized artifact " + truncate(canon, 100)}, true, 0
	}
	if reason, nonScript := nonScriptContent(artifact.ContentType, []byte(body)); nonScript {
		artifact.Status = ArtifactSkipped
		out = append(out, Record{Type: TypeJSArtifact, URL: rawURL, CanonicalURL: artifact.CanonicalURL, Provider: "builtin-js", Source: "js", Artifact: &artifact})
		return out, []string{"skipped non-JavaScript artifact " + truncate(canon, 100) + ": " + reason}, true, 1
	}
	out = append(out, Record{Type: TypeJSArtifact, URL: rawURL, CanonicalURL: artifact.CanonicalURL, Provider: "builtin-js", Source: "js", Artifact: &artifact})

	origin := originOfURL(artifact.CanonicalURL)
	endpoints, smRef := extractJSFindings(body, origin, maxJSFindings)
	for i := range endpoints {
		endpoints[i].Endpoint.SourceURL = artifact.CanonicalURL
	}
	kept, skipped := filterEndpointRecords(pc.Engine, endpoints, "JS_ANALYSIS")
	out = append(out, kept...)

	// Source maps: resolved against the artifact URL, configurable, scope-checked, and never
	// recursively fetched.
	var smURL string
	if smRef != "" {
		smURL = resolveAgainst(artifact.CanonicalURL, smRef)
	}
	if smURL != "" {
		sm := SourceMapInfo{JsURL: artifact.CanonicalURL, SourceMapURL: smURL}
		if !fetchSourceMaps {
			sm.Status = "DISABLED"
			out = append(out, Record{Type: TypeSourceMap, URL: smURL, Provider: "builtin-js", Source: "sourcemap", SourceMap: &sm})
		} else {
			resolveSourceMap(ctx, client, pc, smURL, &sm)
			out = append(out, Record{Type: TypeSourceMap, URL: smURL, Provider: "builtin-js", Source: "sourcemap", SourceMap: &sm})
		}
	}
	return out, diag, true, skipped
}

func resolveSourceMap(ctx context.Context, client *http.Client, pc ProviderContext, smURL string, sm *SourceMapInfo) {
	canon, err := matching.CanonicalURL(smURL)
	if err != nil {
		sm.Status = "ERROR"
		sm.Error = "invalid source map URL"
		return
	}
	if d := pc.Engine.Check(scope.Request{Kind: "URL", Value: canon, Capability: "JS_ANALYSIS"}); !d.Allowed {
		sm.Status = "SKIPPED"
		sm.Error = "source map not authorized: " + d.Code
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, canon, nil)
	if err != nil {
		sm.Status = "ERROR"
		return
	}
	resp, err := doRequest(ctx, client, pc.Limiter, req)
	if err != nil {
		sm.Status = "ERROR"
		sm.Error = telemetry.RedactString(err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		sm.Status = "NOT_FOUND"
		return
	}
	if resp.StatusCode >= 400 {
		sm.Status = "ERROR"
		sm.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return
	}
	body, _, _ := readBounded(resp.Body, maxSourceMapBytes)
	var doc struct {
		Version        int      `json:"version"`
		SourceRoot     string   `json:"sourceRoot"`
		Sources        []string `json:"sources"`
		SourcesContent []any    `json:"sourcesContent"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		sm.Status = "ERROR"
		sm.Error = "malformed source map JSON"
		return
	}
	sm.Status = "PARSED"
	sm.SourceRoot = doc.SourceRoot
	sm.HasContent = doc.SourcesContent != nil
	count := len(doc.Sources)
	if count > maxSourceMapSource {
		count = maxSourceMapSource
	}
	for _, s := range doc.Sources[:count] {
		sm.Sources = append(sm.Sources, telemetry.RedactString(s))
	}
	sm.SourcesCount = len(doc.Sources)
}

func originOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// nonScriptContent reports whether a fetched artifact is clearly not JavaScript, based on a
// magic-byte sniff of the body and then the declared content type. It deliberately does not skip
// on a missing or generic content type, so dynamically served text/JavaScript is still analysed;
// only strong evidence (a binary signature, or an asset/document MIME type) excludes an artifact.
func nonScriptContent(contentType string, body []byte) (string, bool) {
	switch {
	case bytes.HasPrefix(body, []byte{0xFF, 0xD8, 0xFF}):
		return "JPEG image signature", true
	case bytes.HasPrefix(body, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}):
		return "PNG image signature", true
	case bytes.HasPrefix(body, []byte("GIF87a")) || bytes.HasPrefix(body, []byte("GIF89a")):
		return "GIF image signature", true
	case bytes.HasPrefix(body, []byte("%PDF")):
		return "PDF signature", true
	case bytes.HasPrefix(body, []byte("PK\x03\x04")):
		return "ZIP/archive signature", true
	case bytes.HasPrefix(body, []byte{0x1F, 0x8B}):
		return "gzip signature", true
	case bytes.HasPrefix(body, []byte("wOFF")) || bytes.HasPrefix(body, []byte("wOF2")):
		return "WOFF font signature", true
	case bytes.HasPrefix(body, []byte{0x00, 0x01, 0x00, 0x00}) || bytes.HasPrefix(body, []byte("OTTO")):
		return "OpenType font signature", true
	}
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	switch {
	case ct == "":
		return "", false
	case strings.HasPrefix(ct, "image/"),
		strings.HasPrefix(ct, "font/"),
		strings.HasPrefix(ct, "video/"),
		strings.HasPrefix(ct, "audio/"),
		strings.HasPrefix(ct, "application/x-font"),
		ct == "text/css",
		ct == "text/csv",
		ct == "application/pdf",
		ct == "application/zip",
		ct == "application/gzip",
		ct == "application/x-shockwave-flash":
		return "non-script content type " + ct, true
	}
	return "", false
}

// --- bounded static analysis (RE2, linear time) ---

var (
	reSourceMap    = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL=([^\s'"]+)`)
	reFetch        = regexp.MustCompile(`\bfetch\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)
	reAxios        = regexp.MustCompile(`\baxios\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)
	reXHR          = regexp.MustCompile(`\.open\s*\(\s*["'` + "`" + `]([A-Za-z]+)["'` + "`" + `]\s*,\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)
	reWebSocket    = regexp.MustCompile(`new\s+WebSocket\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)
	reAbsURL       = regexp.MustCompile(`["'` + "`" + `](https?://[^\s"'` + "`" + `<>]+)["'` + "`" + `]`)
	rePathLiteral  = regexp.MustCompile(`["'` + "`" + `](/(?:api|rest|graphql|gql|v[0-9]+|internal|admin|auth|users?|accounts?|orders?|products?)(?:/[^"'` + "`" + `\s]*)?)`)
	reDynamicFetch = regexp.MustCompile(`\bfetch\s*\(\s*` + "`" + `([^` + "`" + `$]*)\$\{`)
)

func extractJSFindings(content, origin string, max int) ([]Record, string) {
	var sourceMapRef string
	if m := reSourceMap.FindStringSubmatch(content); m != nil {
		sourceMapRef = strings.TrimSpace(m[1])
	}

	type key struct{ method, origin, path string }
	seen := map[key]struct{}{}
	var out []Record

	add := func(method, rawEndpoint, evidenceType, evidence string, resolved bool) {
		if len(out) >= max {
			return
		}
		ep := buildEndpointCandidate(method, rawEndpoint, origin, resolved, evidenceType, evidence)
		if ep == nil {
			return
		}
		k := key{ep.Method, ep.Origin, ep.Path}
		if _, dup := seen[k]; dup {
			return
		}
		seen[k] = struct{}{}
		out = append(out, Record{Type: TypeApiEndpoint, URL: ep.URL, Provider: "builtin-js", Source: "js", Endpoint: ep})
	}

	for _, m := range reFetch.FindAllStringSubmatch(content, -1) {
		add("GET", m[1], "JS_FETCH", "fetch("+telemetry.RedactString(m[1])+")", true)
	}
	for _, m := range reAxios.FindAllStringSubmatch(content, -1) {
		add(strings.ToUpper(m[1]), m[2], "JS_AXIOS", "axios."+m[1]+"("+telemetry.RedactString(m[2])+")", true)
	}
	for _, m := range reXHR.FindAllStringSubmatch(content, -1) {
		add(strings.ToUpper(m[1]), m[2], "JS_XHR", "XMLHttpRequest.open("+m[1]+","+telemetry.RedactString(m[2])+")", true)
	}
	for _, m := range reWebSocket.FindAllStringSubmatch(content, -1) {
		add("WEBSOCKET", m[1], "JS_WEBSOCKET", "new WebSocket("+telemetry.RedactString(m[1])+")", true)
	}
	for _, m := range reAbsURL.FindAllStringSubmatch(content, -1) {
		add("GET", m[1], "JS_URL_LITERAL", "url literal "+telemetry.RedactString(m[1]), true)
	}
	for _, m := range rePathLiteral.FindAllStringSubmatch(content, -1) {
		add("GET", m[1], "JS_PATH_LITERAL", "path literal "+telemetry.RedactString(m[1]), true)
	}
	// Dynamic template literals: retain the static prefix as an unresolved candidate.
	for _, m := range reDynamicFetch.FindAllStringSubmatch(content, -1) {
		prefix := strings.TrimSpace(m[1])
		if prefix == "" {
			continue
		}
		add("GET", prefix, "JS_DYNAMIC", "fetch(`${...}`) dynamic prefix "+telemetry.RedactString(prefix), false)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Endpoint, out[j].Endpoint
		if a.Origin != b.Origin {
			return a.Origin < b.Origin
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Method < b.Method
	})
	return out, sourceMapRef
}

func buildEndpointCandidate(method, rawEndpoint, origin string, resolved bool, evidenceType, evidence string) *ApiEndpoint {
	rawEndpoint = strings.TrimSpace(rawEndpoint)
	if rawEndpoint == "" {
		return nil
	}
	ep := &ApiEndpoint{Method: method, DiscoveredVia: ViaJS, Resolved: resolved, Evidence: telemetry.RedactString(evidence), EvidenceType: evidenceType}
	var full string
	if strings.HasPrefix(rawEndpoint, "http://") || strings.HasPrefix(rawEndpoint, "https://") || strings.HasPrefix(rawEndpoint, "ws://") || strings.HasPrefix(rawEndpoint, "wss://") {
		u, err := url.Parse(rawEndpoint)
		if err != nil || u.Host == "" {
			return nil
		}
		ep.Origin = strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
		ep.Path = u.EscapedPath()
		full = rawEndpoint
		for _, name := range queryKeys(u.RawQuery) {
			ep.Parameters = appendParam(ep.Parameters, name, "query")
		}
	} else {
		p := rawEndpoint
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if i := strings.IndexAny(p, "?#"); i >= 0 {
			if q := p[i:]; strings.HasPrefix(q, "?") {
				for _, name := range queryKeys(strings.TrimPrefix(q, "?")) {
					ep.Parameters = appendParam(ep.Parameters, name, "query")
				}
			}
			p = p[:i]
		}
		ep.Origin = origin
		ep.Path = p
		if origin != "" {
			full = origin + p
		}
	}
	if ep.Path == "" {
		ep.Path = "/"
	}
	ep.URL = full
	return ep
}

func appendParam(params []ApiParameter, name, loc string) []ApiParameter {
	name = strings.TrimSpace(name)
	if name == "" {
		return params
	}
	for _, p := range params {
		if p.Name == name && p.Location == loc {
			return params
		}
	}
	return append(params, ApiParameter{Name: name, Location: loc, Evidence: "query parameter"})
}

func queryKeys(rawQuery string) []string {
	var names []string
	seen := map[string]bool{}
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		name := pair
		if i := strings.IndexByte(pair, '='); i >= 0 {
			name = pair[:i]
		}
		if dec, err := url.QueryUnescape(name); err == nil {
			name = dec
		}
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names
}

// filterEndpointRecords drops endpoint candidates whose origin is not authorized. Non-endpoint
// records are always kept. This prevents an artifact from introducing out-of-scope hosts.
func filterEndpointRecords(engine *scope.Engine, records []Record, capability string) ([]Record, int) {
	var kept []Record
	skipped := 0
	for _, r := range records {
		if r.Endpoint == nil || r.Endpoint.Origin == "" {
			kept = append(kept, r)
			continue
		}
		host, _, ok := matching.HostAndPort(r.Endpoint.Origin)
		if !ok || host == "" {
			kept = append(kept, r)
			continue
		}
		if engine.Check(scope.Request{Kind: "HOST", Value: host, Capability: capability}).Allowed {
			kept = append(kept, r)
		} else {
			skipped++
		}
	}
	return kept, skipped
}

// resolveAgainst resolves ref relative to an absolute base URL, returning ref unchanged on error.
func resolveAgainst(baseURL, ref string) string {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return ref
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return base.ResolveReference(r).String()
}
