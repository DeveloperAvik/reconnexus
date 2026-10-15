package discovery

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/reconnexus/workers/internal/matching"
	"github.com/reconnexus/workers/internal/scope"
)

const (
	defaultCrawlDepth     = 2
	defaultRequestBudget  = 500
	defaultCrawlTimeoutMs = 15000
	maxSitemaps           = 20
	maxStaticURLs         = 5000
)

// newGuardedClient builds an HTTP client whose DialContext enforces connection-bound scope and
// whose CheckRedirect reauthorizes every hop, reusing the Phase 3A transport.
func newGuardedClient(transport *http.Transport, engine *scope.Engine, timeout time.Duration, maxRedirects int) (*http.Client, *redirectRecorder) {
	rec := &redirectRecorder{max: maxRedirects}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: rec.checkRedirect(engine)}, rec
}

// authorizeURL canonicalizes a URL and checks it against the scope policy. Returns the canonical
// form, whether it is authorized, and whether it was malformed/unsupported.
func authorizeURL(engine *scope.Engine, capability, raw string) (canonical string, host string, authorized bool, malformed bool) {
	canon, err := matching.CanonicalURL(raw)
	if err != nil {
		return "", "", false, true
	}
	h, _, _ := matching.HostAndPort(canon)
	d := engine.Check(scope.Request{Kind: "URL", Value: canon, Capability: capability})
	return canon, h, d.Allowed, false
}

func buildURLRecord(raw, canonical, host, method, provider, source string, depth int, status *int) Record {
	classes, params := ClassifyURL(canonical)
	return Record{
		Type:            TypeURLObservation,
		URL:             raw,
		CanonicalURL:    canonical,
		Host:            host,
		Method:          method,
		Depth:           depth,
		StatusCode:      status,
		Source:          source,
		Provider:        provider,
		Classifications: classes,
		Parameters:      params,
	}
}

// --- builtin-crawler ---

type builtinCrawler struct{}

func (builtinCrawler) Name() string            { return "builtin-crawler" }
func (builtinCrawler) Kind() string            { return "URL_COLLECTION" }
func (builtinCrawler) Capability() string      { return "CRAWL" }
func (builtinCrawler) NetworkBehavior() string { return "ACTIVE" }

var linkAttrRe = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'#]+)`)

// scriptSrcRe matches the `src` attribute of a <script> tag. It is deliberately scoped to the
// script tag's src attribute: arbitrary inline script text is never treated as a URL.
var scriptSrcRe = regexp.MustCompile(`(?is)<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']`)

func (builtinCrawler) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{Coverage: Coverage{}}
	seeds := job.Inputs.SeedURLs
	if len(seeds) == 0 {
		res.StatusOverride = StatusSkipped
		res.Diagnostics = append(res.Diagnostics, "no seed URLs to crawl")
		return res, nil
	}
	maxDepth := job.Inputs.CrawlDepth
	if maxDepth <= 0 {
		maxDepth = defaultCrawlDepth
	}
	budget := job.Inputs.RequestBudget
	if budget <= 0 {
		budget = defaultRequestBudget
	}
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
		maxBytes = defaultMaxResponseBytes
	}
	maxRedirects := job.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = 5
	}

	transport, err := pc.buildTransport(job)
	if err != nil {
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "cannot build crawler transport: "+err.Error())
		return res, nil
	}

	var mu sync.Mutex
	var records []Record
	emitted := map[string]int{}
	var diagnostics []string
	visited := map[string]struct{}{}
	var budgetUsed int

	// emitOrUpdate appends a record for a canonical URL the first time it is seen, and
	// updates the status code in place on later fetches. This keeps one observation per
	// canonical URL per provider run while preserving cross-provider provenance.
	emitOrUpdate := func(rec Record, status *int) {
		if idx, ok := emitted[rec.CanonicalURL]; ok {
			if status != nil {
				records[idx].StatusCode = status
			}
			// Upgrade provenance when the same canonical URL is later seen as a <script src>:
			// the JavaScript classification and parent document are strictly more informative.
			if rec.ScriptRef && !records[idx].ScriptRef {
				records[idx].ScriptRef = true
				records[idx].ParentURL = rec.ParentURL
				records[idx].Classifications = mergeScriptRefClassifications(records[idx].Classifications, rec.Classifications)
			}
			return
		}
		emitted[rec.CanonicalURL] = len(records)
		records = append(records, rec)
	}

	type item struct {
		raw   string
		depth int
	}
	var frontier []item
	for _, s := range seeds {
		canon, host, ok, bad := authorizeURL(pc.Engine, "CRAWL", s)
		if bad {
			res.Coverage.Failed++
			continue
		}
		if !ok {
			res.Coverage.Skipped++
			continue
		}
		if _, seen := visited[canon]; seen {
			continue
		}
		visited[canon] = struct{}{}
		frontier = append(frontier, item{raw: canon, depth: 0})
		mu.Lock()
		emitOrUpdate(buildURLRecord(s, canon, host, MethodSeed, "builtin-crawler", "seed", 0, nil), nil)
		mu.Unlock()
	}
	res.Coverage.Attempted = len(seeds)

	for depth := 0; depth <= maxDepth && len(frontier) > 0; depth++ {
		if ctx.Err() != nil {
			break
		}
		var next []item
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup
		for _, it := range frontier {
			if ctx.Err() != nil || budgetUsed >= budget {
				break
			}
			mu.Lock()
			if budgetUsed >= budget {
				mu.Unlock()
				break
			}
			budgetUsed++
			mu.Unlock()
			wg.Add(1)
			sem <- struct{}{}
			go func(it item) {
				defer wg.Done()
				defer func() { <-sem }()
				client, _ := newGuardedClient(transport, pc.Engine, timeout, maxRedirects)
				req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, it.raw, nil)
				if rerr != nil {
					mu.Lock()
					diagnostics = append(diagnostics, "crawl request build failed: "+rerr.Error())
					mu.Unlock()
					return
				}
				req.Header.Set("User-Agent", "reconnexus/0.4 (+https://github.com/anomalyco/opencode)")
				resp, derr := doRequest(ctx, client, pc.Limiter, req)
				if derr != nil || resp == nil {
					mu.Lock()
					if derr != nil {
						diagnostics = append(diagnostics, fmt.Sprintf("crawl %s: %s", it.raw, truncate(derr.Error(), 160)))
					}
					mu.Unlock()
					return
				}
				defer resp.Body.Close()
				body, _, _ := readBounded(resp.Body, maxBytes)
				canon := it.raw
				if resp.Request != nil {
					if c, err := matching.CanonicalURL(resp.Request.URL.String()); err == nil {
						canon = c
					}
				}
				code := resp.StatusCode
				mu.Lock()
				emitOrUpdate(buildURLRecord(it.raw, canon, hostOf(canon), MethodCrawl, "builtin-crawler", "crawl", it.depth, &code), &code)
				mu.Unlock()
				if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "html") {
					return
				}
				// <script src> references first, so their classification is in place before the
				// generic link pass decides what to crawl. They become JavaScript candidates even
				// when the path is extensionless (a common bundler pattern), preserving the
				// parent-document provenance. They are not added to the crawl frontier below:
				// a script is not an HTML document, and Stage 07 retrieves it once with content
				// validation rather than the crawler fetching it twice.
				parent := resp.Request.URL.String()
				for _, sref := range extractScriptRefs(body, resp.Request.URL) {
					c, h, ok, bad := authorizeURL(pc.Engine, "CRAWL", sref)
					if bad || !ok {
						if !bad {
							mu.Lock()
							res.Coverage.Skipped++
							mu.Unlock()
						}
						continue
					}
					rec := buildURLRecord(sref, c, h, MethodCrawl, "builtin-crawler", "script-ref", it.depth+1, nil)
					if !markScriptRef(&rec, parent) {
						continue
					}
					mu.Lock()
					emitOrUpdate(rec, nil)
					mu.Unlock()
				}

				for _, link := range extractLinks(body, resp.Request.URL) {
					c, h, ok, bad := authorizeURL(pc.Engine, "CRAWL", link)
					if bad || !ok {
						if !bad {
							mu.Lock()
							res.Coverage.Skipped++
							mu.Unlock()
						}
						continue
					}
					mu.Lock()
					if _, seen := visited[c]; seen {
						mu.Unlock()
						continue
					}
					visited[c] = struct{}{}
					emitOrUpdate(buildURLRecord(link, c, h, MethodCrawl, "builtin-crawler", "crawl", it.depth+1, nil), nil)
					// Only links that could yield HTML are followed; static assets and scripts are
					// kept in the URL inventory but do not consume the crawl request budget.
					if it.depth+1 <= maxDepth && crawlable(records[emitted[c]]) {
						next = append(next, item{raw: c, depth: it.depth + 1})
					}
					mu.Unlock()
				}
			}(it)
		}
		wg.Wait()
		res.Coverage.Succeeded += len(frontier)
		res.Coverage.Attempted += len(frontier)
		frontier = next
	}

	res.Records = records
	res.Diagnostics = append(res.Diagnostics, diagnostics...)
	if ctx.Err() != nil {
		res.StatusOverride = StatusCancelled
	}
	return res, nil
}

func hostOf(canonical string) string {
	h, _, _ := matching.HostAndPort(canonical)
	return h
}

// extractScriptRefs returns the absolute, deduplicated URLs referenced by <script src> attributes,
// resolved against the effective document URL (so relative, root-relative, protocol-relative and
// query-bearing references are all handled). Only the src attribute of a script tag is considered;
// inline script bodies are never parsed for URLs.
func extractScriptRefs(body string, base *url.URL) []string {
	if base == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, m := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
		raw := strings.TrimSpace(m[1])
		if raw == "" || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "blob:") {
			continue
		}
		ref, err := url.Parse(raw)
		if err != nil {
			continue
		}
		resolved := base.ResolveReference(ref)
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			continue
		}
		s := resolved.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// crawlable reports whether following a URL could yield further HTML links. Scripts, static assets
// and downloads cannot, so they are recorded in the URL inventory but do not spend the request
// budget or risk parsing binary content as HTML.
func crawlable(rec Record) bool {
	for _, c := range rec.Classifications {
		switch c.Category {
		case "JAVASCRIPT", "STATIC_ASSET", "DOWNLOAD":
			return false
		}
	}
	return true
}

// markScriptRef annotates a URL record as a script reference. It returns false, leaving the record
// untouched, when the URL already carries a strong non-script classification, so an image or font
// misleadingly referenced from a <script> tag is never relabelled as JavaScript.
func markScriptRef(rec *Record, parentURL string) bool {
	for _, c := range rec.Classifications {
		switch c.Category {
		case "JAVASCRIPT":
			rec.ScriptRef = true
			rec.ParentURL = parentURL
			return true
		case "STATIC_ASSET", "DOWNLOAD":
			return false
		}
	}
	kept := make([]UrlClassification, 0, len(rec.Classifications)+1)
	for _, c := range rec.Classifications {
		if c.Category == "HTML_PAGE" || c.Category == "UNKNOWN" {
			continue
		}
		kept = append(kept, c)
	}
	kept = append(kept, UrlClassification{Category: "JAVASCRIPT", Confidence: 0.6, EvidenceType: "SCRIPT_REF", Evidence: "referenced by <script src> in " + parentURL})
	rec.Classifications = kept
	rec.ScriptRef = true
	rec.ParentURL = parentURL
	return true
}

// mergeScriptRefClassifications merges a script-reference classification into an existing set,
// dropping HTML_PAGE/UNKNOWN fallbacks that the reference supersedes.
func mergeScriptRefClassifications(existing, incoming []UrlClassification) []UrlClassification {
	seen := map[string]bool{}
	out := make([]UrlClassification, 0, len(existing)+len(incoming))
	for _, list := range [][]UrlClassification{existing, incoming} {
		for _, c := range list {
			if c.Category == "HTML_PAGE" || c.Category == "UNKNOWN" {
				continue
			}
			if seen[c.Category] {
				continue
			}
			seen[c.Category] = true
			out = append(out, c)
		}
	}
	return out
}

func extractLinks(body string, base *url.URL) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, m := range linkAttrRe.FindAllStringSubmatch(body, -1) {
		raw := strings.TrimSpace(m[1])
		if raw == "" || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "tel:") || strings.HasPrefix(raw, "data:") {
			continue
		}
		ref, err := url.Parse(raw)
		if err != nil {
			continue
		}
		resolved := base.ResolveReference(ref)
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			continue
		}
		s := resolved.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// --- builtin-static: robots.txt and sitemaps ---

type builtinStatic struct{}

func (builtinStatic) Name() string            { return "builtin-static" }
func (builtinStatic) Kind() string            { return "URL_COLLECTION" }
func (builtinStatic) Capability() string      { return "ACTIVE_HTTP" }
func (builtinStatic) NetworkBehavior() string { return "ACTIVE" }

func (builtinStatic) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{Coverage: Coverage{}}
	seeds := job.Inputs.SeedURLs
	if len(seeds) == 0 {
		res.StatusOverride = StatusSkipped
		res.Diagnostics = append(res.Diagnostics, "no origins for robots/sitemap discovery")
		return res, nil
	}
	timeout := time.Duration(job.RequestTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = defaultCrawlTimeoutMs * time.Millisecond
	}
	maxBytes := job.Limits.MaxArtifactBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxResponseBytes
	}
	transport, err := pc.buildTransport(job)
	if err != nil {
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "cannot build transport: "+err.Error())
		return res, nil
	}
	client, _ := newGuardedClient(transport, pc.Engine, timeout, job.MaxRedirects)

	var records []Record
	origins := map[string]struct{}{}
	for _, s := range seeds {
		u, err := url.Parse(s)
		if err != nil {
			continue
		}
		origins[strings.ToLower(u.Scheme)+"://"+strings.ToLower(u.Host)] = struct{}{}
	}
	res.Coverage.Attempted = len(origins)

	sitemaps := map[string]struct{}{}
	for origin := range origins {
		if ctx.Err() != nil {
			break
		}
		robotsURL := origin + "/robots.txt"
		if _, _, ok, bad := authorizeURL(pc.Engine, "ACTIVE_HTTP", robotsURL); bad || !ok {
			res.Coverage.Skipped++
			continue
		}
		body, status, ferr := fetchText(ctx, client, pc.Limiter, robotsURL, maxBytes)
		if ferr != nil {
			res.Coverage.Failed++
			res.Diagnostics = append(res.Diagnostics, "robots.txt "+origin+": "+truncate(ferr.Error(), 120))
			continue
		}
		if status == 200 {
			for _, line := range strings.Split(body, "\n") {
				line = strings.TrimSpace(line)
				low := strings.ToLower(line)
				if strings.HasPrefix(low, "sitemap:") {
					sm := strings.TrimSpace(line[len("sitemap:"):])
					if _, _, ok, bad := authorizeURL(pc.Engine, "ACTIVE_HTTP", sm); ok && !bad {
						sitemaps[sm] = struct{}{}
					}
				} else if strings.HasPrefix(low, "disallow:") || strings.HasPrefix(low, "allow:") {
					pth := strings.TrimSpace(line[strings.Index(line, ":")+1:])
					if pth == "" || pth == "/" {
						continue
					}
					cand := origin + pth
					// Robots rules are not authorization; recorded as candidates only.
					c, h, ok, bad := authorizeURL(pc.Engine, "ACTIVE_HTTP", cand)
					if ok && !bad {
						records = append(records, buildURLRecord(cand, c, h, MethodRobots, "builtin-static", "robots", 0, nil))
					}
				}
			}
			res.Coverage.Succeeded++
		} else {
			res.Diagnostics = append(res.Diagnostics, fmt.Sprintf("robots.txt %s returned %d", origin, status))
		}
	}

	// Default sitemap if none declared.
	for origin := range origins {
		if len(sitemaps) == 0 {
			sitemaps[origin+"/sitemap.xml"] = struct{}{}
		}
	}

	queue := stringKeys(sitemaps)
	seenSitemaps := map[string]struct{}{}
	urlCount := 0
	for len(queue) > 0 && len(seenSitemaps) < maxSitemaps && urlCount < maxStaticURLs && ctx.Err() == nil {
		sm := queue[0]
		queue = queue[1:]
		if _, seen := seenSitemaps[sm]; seen {
			continue
		}
		seenSitemaps[sm] = struct{}{}
		if _, _, ok, bad := authorizeURL(pc.Engine, "ACTIVE_HTTP", sm); !ok || bad {
			res.Coverage.Skipped++
			continue
		}
		body, status, ferr := fetchText(ctx, client, pc.Limiter, sm, maxBytes)
		if ferr != nil || status != 200 {
			res.Coverage.Failed++
			continue
		}
		locs, childSitemaps, perr := parseSitemap(body)
		if perr != nil {
			res.Diagnostics = append(res.Diagnostics, "malformed sitemap "+sm+": "+perr.Error())
			continue
		}
		for _, child := range childSitemaps {
			if _, _, ok, bad := authorizeURL(pc.Engine, "ACTIVE_HTTP", child); ok && !bad {
				queue = append(queue, child)
			}
		}
		for _, loc := range locs {
			if urlCount >= maxStaticURLs {
				break
			}
			c, h, ok, bad := authorizeURL(pc.Engine, "ACTIVE_HTTP", loc)
			if !ok || bad {
				if !bad {
					res.Coverage.Skipped++
				}
				continue
			}
			records = append(records, buildURLRecord(loc, c, h, MethodSitemap, "builtin-static", "sitemap", 0, nil))
			urlCount++
		}
	}

	if ctx.Err() != nil {
		res.StatusOverride = StatusCancelled
	}
	res.Records = records
	return res, nil
}

func fetchText(ctx context.Context, client *http.Client, limiter *rateLimiter, rawURL string, maxBytes int) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "reconnexus/0.4 (+https://github.com/anomalyco/opencode)")
	resp, err := doRequest(ctx, client, limiter, req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, _, _ := readBounded(resp.Body, maxBytes)
	return body, resp.StatusCode, nil
}

type sitemapDoc struct {
	XMLName  xml.Name
	Sitemaps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
	URLs []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
}

func parseSitemap(body string) (locs []string, childSitemaps []string, err error) {
	var doc sitemapDoc
	if err := xml.Unmarshal([]byte(strings.TrimSpace(body)), &doc); err != nil {
		return nil, nil, err
	}
	switch strings.ToLower(doc.XMLName.Local) {
	case "sitemapindex":
		for _, s := range doc.Sitemaps {
			if s.Loc != "" {
				childSitemaps = append(childSitemaps, strings.TrimSpace(s.Loc))
			}
		}
	case "urlset":
		for _, u := range doc.URLs {
			if u.Loc != "" {
				locs = append(locs, strings.TrimSpace(u.Loc))
			}
		}
	default:
		return nil, nil, errors.New("unrecognized sitemap root element: " + doc.XMLName.Local)
	}
	return locs, childSitemaps, nil
}

// --- external passive providers (gau, waybackurls) ---

// passiveURLProvider wraps an external passive tool (gau, waybackurls).
type passiveURLProvider struct {
	name      string
	buildArgv func(job Job) ([]string, error)
	input     func(job Job) string
}

func (p passiveURLProvider) Name() string            { return p.name }
func (p passiveURLProvider) Kind() string            { return "URL_COLLECTION" }
func (p passiveURLProvider) Capability() string      { return "PASSIVE" }
func (p passiveURLProvider) NetworkBehavior() string { return "PASSIVE" }

func (p passiveURLProvider) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	buildArgv := p.buildArgv
	if buildArgv == nil {
		buildArgv = func(Job) ([]string, error) { return nil, nil }
	}
	inner := &externalProvider{
		name: p.name, kind: "URL_COLLECTION", capability: "PASSIVE", networkBehavior: "PASSIVE",
		buildArgv: buildArgv, parse: parseURLPlaceholders, defaultTimeoutMs: 300000, defaultMaxBytes: 32 * 1024 * 1024,
	}
	if p.input != nil {
		inner.usesStdin = true
		inner.stdin = p.input
	}
	pr, err := inner.Run(ctx, pc)
	if err != nil {
		return pr, err
	}
	// Passively discovered URLs can be anywhere; keep only in-scope candidates.
	return filterExternal(ctx, pc, pr, p.name, "PASSIVE", MethodPassive), nil
}

// katanaProvider wraps the katana crawler (opt-in; see docs). It runs with redirects disabled and
// a scope regex, and every returned URL is re-checked against the scope policy.
type katanaProvider struct{}

func (katanaProvider) Name() string            { return "katana" }
func (katanaProvider) Kind() string            { return "URL_COLLECTION" }
func (katanaProvider) Capability() string      { return "CRAWL" }
func (katanaProvider) NetworkBehavior() string { return "ACTIVE" }

func (katanaProvider) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	inner := &externalProvider{
		name: "katana", kind: "URL_COLLECTION", capability: "CRAWL", networkBehavior: "ACTIVE",
		versionArgs: []string{"-version"},
		buildArgv: func(job Job) ([]string, error) {
			if len(job.Inputs.SeedURLs) == 0 {
				return nil, errors.New("seedUrls required")
			}
			depth := job.Inputs.CrawlDepth
			if depth <= 0 {
				depth = defaultCrawlDepth
			}
			conc := job.Limits.MaxConcurrency
			if conc <= 0 {
				conc = 10
			}
			timeout := job.RequestTimeoutMs / 1000
			if timeout <= 0 {
				timeout = 10
			}
			argv := []string{"-u", job.Inputs.SeedURLs[0], "-d", fmt.Sprint(depth), "-c", fmt.Sprint(conc), "-timeout", fmt.Sprint(timeout), "-jsonl", "-silent", "-nc", "-dr"}
			if re := scopeRegex(job); re != "" {
				argv = append(argv, "-cs", re)
			}
			return argv, nil
		},
		parse:            parseKatanaJSONL,
		defaultTimeoutMs: 600000,
		defaultMaxBytes:  64 * 1024 * 1024,
	}
	pr, err := inner.Run(ctx, pc)
	if err != nil {
		return pr, err
	}
	return filterExternal(ctx, pc, pr, "katana", "CRAWL", MethodCrawl), nil
}

func scopeRegex(job Job) string {
	var parts []string
	for _, d := range job.Policy.InScope.Domains {
		parts = append(parts, regexp.QuoteMeta(d.Value))
	}
	for _, h := range job.Policy.InScope.Hosts {
		parts = append(parts, regexp.QuoteMeta(h))
	}
	if len(parts) == 0 {
		return ""
	}
	return "(?:^|\\.)(?:" + strings.Join(parts, "|") + ")$"
}

// parseURLPlaceholders extracts plain URLs, one per line (gau, waybackurls).
func parseURLPlaceholders(stdout string) ([]Record, []string) {
	var records []Record
	var diagnostics []string
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		canon, err := matching.CanonicalURL(line)
		if err != nil {
			diagnostics = append(diagnostics, "malformed URL discarded: "+truncate(line, 80))
			continue
		}
		records = append(records, Record{Type: "URL_PLACEHOLDER", URL: line, CanonicalURL: canon})
	}
	return records, diagnostics
}

type katanaLine struct {
	Request struct {
		Endpoint string `json:"endpoint"`
		Method   string `json:"method"`
	} `json:"request"`
	Response struct {
		StatusCode int `json:"status_code"`
	} `json:"response"`
}

func parseKatanaJSONL(stdout string) ([]Record, []string) {
	var records []Record
	var diagnostics []string
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var l katanaLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			diagnostics = append(diagnostics, "discarded malformed katana line: "+truncate(line, 80))
			continue
		}
		ep := strings.TrimSpace(l.Request.Endpoint)
		if ep == "" {
			continue
		}
		canon, err := matching.CanonicalURL(ep)
		if err != nil {
			diagnostics = append(diagnostics, "discarded non-http katana endpoint: "+truncate(ep, 80))
			continue
		}
		records = append(records, Record{Type: "URL_PLACEHOLDER", URL: ep, CanonicalURL: canon})
	}
	return records, diagnostics
}

// filterExternal converts placeholder records into scope-checked, classified URL observations.
func filterExternal(ctx context.Context, pc ProviderContext, pr ProviderResult, provider, capability, method string) ProviderResult {
	var out []Record
	seen := map[string]struct{}{}
	skipped := 0
	for _, r := range pr.Records {
		if ctx.Err() != nil {
			break
		}
		if r.CanonicalURL == "" {
			continue
		}
		if _, dup := seen[r.CanonicalURL]; dup {
			continue
		}
		seen[r.CanonicalURL] = struct{}{}
		h, _, _ := matching.HostAndPort(r.CanonicalURL)
		d := pc.Engine.Check(scope.Request{Kind: "URL", Value: r.CanonicalURL, Capability: capability})
		if !d.Allowed {
			skipped++
			continue
		}
		out = append(out, buildURLRecord(r.URL, r.CanonicalURL, h, method, provider, strings.ToLower(method), 0, nil))
	}
	pr.Records = out
	pr.Coverage.Skipped += skipped
	return pr
}

// --- mock-url (fixture driven, for deterministic tests) ---

type mockURLProvider struct{}

func (mockURLProvider) Name() string            { return "mock-url" }
func (mockURLProvider) Kind() string            { return "URL_COLLECTION" }
func (mockURLProvider) Capability() string      { return "" }
func (mockURLProvider) NetworkBehavior() string { return "NONE" }

func (mockURLProvider) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	res := ProviderResult{}
	if pc.Job.FixturePath == "" {
		res.StatusOverride = StatusFailed
		res.Diagnostics = append(res.Diagnostics, "mock-url requires fixturePath")
		return res, nil
	}
	raw, err := os.ReadFile(pc.Job.FixturePath)
	if err != nil {
		res.StatusOverride = StatusFailed
		res.Diagnostics = append(res.Diagnostics, "cannot read fixture: "+err.Error())
		return res, nil
	}
	var fx struct {
		Version string   `json:"version"`
		URLs    []string `json:"urls"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		res.StatusOverride = StatusFailed
		res.Diagnostics = append(res.Diagnostics, "invalid fixture json: "+err.Error())
		return res, nil
	}
	res.ProviderVersion = fx.Version
	for _, rawURL := range fx.URLs {
		canon, h, malformed := canonicalizeForRecord(rawURL)
		if malformed {
			res.Diagnostics = append(res.Diagnostics, "mock-url malformed URL: "+truncate(rawURL, 80))
			continue
		}
		res.Records = append(res.Records, buildURLRecord(rawURL, canon, h, MethodPassive, "mock-url", "fixture", 0, nil))
		res.Coverage.Succeeded++
	}
	return res, nil
}

func canonicalizeForRecord(raw string) (string, string, bool) {
	canon, err := matching.CanonicalURL(raw)
	if err != nil {
		return "", "", true
	}
	h, _, _ := matching.HostAndPort(canon)
	return canon, h, false
}

// newGauProvider builds the gau passive provider.
func newGauProvider() Provider {
	return passiveURLProvider{
		name: "gau",
		buildArgv: func(job Job) ([]string, error) {
			if len(job.Inputs.Domains) == 0 {
				return nil, errors.New("gau requires at least one domain")
			}
			return []string{"--threads", "5", "--subs", job.Inputs.Domains[0]}, nil
		},
	}
}

// newWaybackProvider builds the waybackurls passive provider (reads domains on stdin).
func newWaybackProvider() Provider {
	return passiveURLProvider{
		name:  "waybackurls",
		input: func(job Job) string { return strings.Join(job.Inputs.Domains, "\n") },
	}
}

func stringKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
