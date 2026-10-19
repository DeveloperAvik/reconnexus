package discovery

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reconnexus/workers/internal/scope"
)

func urlJob(seeds, domains []string, opts ...func(*Job)) Job {
	p := testPolicy("PASSIVE", "DNS", "ACTIVE_HTTP", "CRAWL", "INTERNAL_NETWORK")
	p.InScope.IPs = []string{"127.0.0.1"}
	p.Exclusions.Hosts = []string{"blocked.example.com"}
	j := Job{
		SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "05", JobKey: "05",
		Kind: "URL_COLLECTION", Provider: "builtin-crawler", Policy: p, AllowRestrictedAddresses: true,
		Limits: scope.Limits{MaxConcurrency: 4, RequestsPerSecond: 20, CrawlDepth: 2, MaxRuntimeSeconds: 60, MaxArtifactBytes: 1 << 20},
		Inputs: Inputs{SeedURLs: seeds, Domains: domains},
	}
	for _, o := range opts {
		o(&j)
	}
	return j
}

func urlsOf(res Result) map[string]Record {
	out := map[string]Record{}
	for _, r := range res.Records {
		if r.Type == TypeURLObservation {
			out[r.CanonicalURL] = r
		}
	}
	return out
}

func TestCrawlerDiscoversInScopeLinksAndDropsOutOfScope(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprintf(w, `<a href="/a">a</a><a href="/b">b</a><a href="http://evil.other.net/x">e</a><script src="/app.js"></script>`)
		case "/a":
			fmt.Fprint(w, `<a href="/deep">deep</a>`)
		default:
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})

	seed := "http://example.com:" + portOf(t, srv.URL) + "/"
	res, _ := Run(context.Background(), urlJob([]string{seed}, []string{"example.com"}), nil)
	if res.Status != StatusSucceeded {
		t.Fatalf("status=%s diag=%v", res.Status, res.Diagnostics)
	}
	got := urlsOf(res)
	if _, ok := got["http://example.com:"+portOf(t, srv.URL)+"/a"]; !ok {
		t.Errorf("expected /a to be discovered; got %v", keysOf(got))
	}
	for u := range got {
		if strings.Contains(u, "evil.other.net") {
			t.Fatalf("out-of-scope link leaked into records: %s", u)
		}
	}
	// /app.js is a static asset link and should be recorded with a JAVASCRIPT classification.
	var jsFound bool
	for u, r := range got {
		if strings.HasSuffix(u, "/app.js") {
			jsFound = true
			if !hasCategory(r, "JAVASCRIPT") {
				t.Errorf("app.js not classified as JAVASCRIPT: %+v", r.Classifications)
			}
		}
	}
	if !jsFound {
		t.Errorf("expected app.js; got %v", keysOf(got))
	}
	if res.Coverage.Skipped != 1 {
		t.Errorf("expected exactly 1 skipped (the out-of-scope link), got %d", res.Coverage.Skipped)
	}
	// One record per canonical URL (no intra-provider duplicates).
	if len(got) != len(res.Records) {
		t.Errorf("duplicate URL records: %d records, %d unique", len(res.Records), len(got))
	}
}

func hasCategory(r Record, cat string) bool {
	for _, c := range r.Classifications {
		if c.Category == cat {
			return true
		}
	}
	return false
}

func keysOf(m map[string]Record) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("bad test URL %q: %v", raw, err)
	}
	return u
}

func TestExtractScriptRefsResolvesAndFilters(t *testing.T) {
	base := mustParseURL(t, "https://example.com/dir/page.html")
	body := `<html><head>
	<script src="/a.js"></script>
	<script src="b.js"></script>
	<script src="../c.js?x=1&y=2"></script>
	<script src="//cdn.example.com/d.js"></script>
	<script src="https://other.example/e.js"></script>
	<script src="/assets/bundle"></script>
	<script src="data:text/javascript,alert(1)"></script>
	<script src="javascript:void(0)"></script>
	<script type="module" defer src='quoted.mjs'></script>
	<script>var u = "/inline/should-not-appear.js";</script>
	<script src="/a.js"></script>
	</head></html>`
	got := extractScriptRefs(body, base)
	want := map[string]bool{
		"https://example.com/a.js":           true,
		"https://example.com/dir/b.js":       true,
		"https://example.com/c.js?x=1&y=2":   true,
		"https://cdn.example.com/d.js":       true,
		"https://other.example/e.js":         true,
		"https://example.com/assets/bundle":  true,
		"https://example.com/dir/quoted.mjs": true,
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d refs, got %d: %v", len(want), len(got), got)
	}
	for _, u := range got {
		if !want[u] {
			t.Errorf("unexpected ref %q", u)
		}
		if strings.Contains(u, "should-not-appear") || strings.Contains(u, "data:") || strings.Contains(u, "javascript:") {
			t.Errorf("forbidden ref extracted: %q", u)
		}
	}
}

func TestCrawlerMarksScriptRefsAndPreservesProvenance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<script src="/assets/bundle"></script>`+
				`<script src="/img.png"></script>`+
				`<script src="//evil.other.net/x.js"></script>`+
				`<script>var u="/inline/should-not-appear.js";</script>`+
				`<script src="/assets/bundle"></script>`)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	base := "http://example.com:" + portOf(t, srv.URL)
	res, _ := Run(context.Background(), urlJob([]string{base + "/"}, nil), nil)

	got := urlsOf(res)
	ref, ok := got[base+"/assets/bundle"]
	if !ok {
		t.Fatalf("extensionless script ref missing; got %v", keysOf(got))
	}
	if !ref.ScriptRef {
		t.Errorf("extensionless script ref not marked: %+v", ref)
	}
	if !hasCategory(ref, "JAVASCRIPT") {
		t.Errorf("extensionless script ref not classified JAVASCRIPT: %+v", ref.Classifications)
	}
	if ref.ParentURL == "" {
		t.Errorf("script ref missing parent-document provenance")
	}
	if png, ok := got[base+"/img.png"]; ok && png.ScriptRef {
		t.Errorf("image referenced by a script tag must not be marked as a script ref")
	}
	for u := range got {
		if strings.Contains(u, "evil.other.net") {
			t.Fatalf("out-of-scope script ref leaked: %s", u)
		}
		if strings.Contains(u, "should-not-appear") {
			t.Fatalf("inline script text was treated as a URL: %s", u)
		}
	}
	if res.Coverage.Skipped < 1 {
		t.Errorf("expected the out-of-scope script ref to be skipped, got %+v", res.Coverage)
	}
	// Extensionless refs are not fetched by the crawler (Stage 07 retrieves them with validation).
	if ref.StatusCode != nil {
		t.Errorf("script ref should be a candidate only, got statusCode=%v", *ref.StatusCode)
	}
}

func TestCrawlerResolvesScriptRefsAgainstEffectiveURL(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/sub/home", http.StatusFound)
		case "/sub/home":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<script src="app.js"></script>`)
		default:
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	base := "http://example.com:" + portOf(t, srv.URL)
	res, _ := Run(context.Background(), urlJob([]string{base + "/start"}, nil), nil)
	got := urlsOf(res)
	if _, ok := got[base+"/sub/app.js"]; !ok {
		t.Errorf("script ref not resolved against the effective (post-redirect) URL; got %v", keysOf(got))
	}
	if _, ok := got[base+"/start/app.js"]; ok {
		t.Errorf("script ref resolved against the pre-redirect URL")
	}
}

func TestCrawlerRespectsDepth(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<a href="/a">a</a>`)
		case "/a":
			fmt.Fprint(w, `<a href="/b">b</a>`)
		case "/b":
			fmt.Fprint(w, `<a href="/c">c</a>`)
		default:
			fmt.Fprint(w, "leaf")
		}
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	seed := "http://example.com:" + portOf(t, srv.URL) + "/"
	res, _ := Run(context.Background(), urlJob([]string{seed}, []string{"example.com"}, func(j *Job) { j.Inputs.CrawlDepth = 1 }), nil)
	got := urlsOf(res)
	a := got["http://example.com:"+portOf(t, srv.URL)+"/a"]
	if a.StatusCode == nil {
		t.Fatalf("/a should have been fetched at depth 1: %+v", a)
	}
	b := got["http://example.com:"+portOf(t, srv.URL)+"/b"]
	if b.StatusCode != nil {
		t.Fatalf("/b should be a candidate only (not fetched beyond depth 1)")
	}
}

func TestCrawlerDeniesRedirectToPrivateAddress(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://10.0.0.1/", http.StatusFound)
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	seed := "http://example.com:" + portOf(t, srv.URL) + "/"
	res, _ := Run(context.Background(), urlJob([]string{seed}, nil), nil)
	for u := range urlsOf(res) {
		if strings.Contains(u, "10.0.0.1") {
			t.Fatalf("redirect to private address leaked: %s", u)
		}
	}
	joined := strings.Join(res.Diagnostics, " ")
	if !strings.Contains(joined, "redirect denied") && !strings.Contains(joined, "denied") {
		t.Errorf("expected a redirect-denied diagnostic, got %v", res.Diagnostics)
	}
}

func TestCrawlerDnsRebindingBlocked(t *testing.T) {
	var calls int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<a href="/a">a</a>`)
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: func(_ context.Context, host string) ([]string, error) {
		// First lookup (seed) public; later lookups rebind to a private address.
		if atomic.AddInt32(&calls, 1) == 1 {
			return []string{"127.0.0.1"}, nil
		}
		return []string{"10.5.6.7"}, nil
	}})
	seed := "http://example.com:" + portOf(t, srv.URL) + "/"
	res, _ := Run(context.Background(), urlJob([]string{seed}, nil), nil)
	joined := strings.Join(res.Diagnostics, " ")
	if !strings.Contains(joined, "not permitted") && !strings.Contains(joined, "denied") {
		t.Errorf("expected rebinding denial, got %v", res.Diagnostics)
	}
}

func TestCrawlerCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(80 * time.Millisecond); cancel() }()
	seed := "http://example.com:" + portOf(t, srv.URL) + "/"
	res, _ := Run(ctx, urlJob([]string{seed}, nil), nil)
	if res.Status != StatusCancelled {
		t.Fatalf("status=%s want CANCELLED", res.Status)
	}
}

func TestStaticRobotsAndSitemap(t *testing.T) {
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			fmt.Fprintf(w, "User-agent: *\nDisallow: /private\nSitemap: %s/sitemap.xml\n", base)
		case "/sitemap.xml":
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, `<?xml version="1.0"?><urlset><url><loc>`+base+`/one</loc></url><url><loc>http://evil.other.net/two</loc></url></urlset>`)
		default:
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()
	base = srv.URL
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})

	res, _ := Run(context.Background(), urlJob([]string{base + "/"}, nil, func(j *Job) { j.Provider = "builtin-static" }), nil)
	got := urlsOf(res)
	if _, ok := got[base+"/one"]; !ok {
		t.Errorf("sitemap URL missing; got %v", keysOf(got))
	}
	if _, ok := got[base+"/private"]; !ok {
		t.Errorf("robots.txt candidate path missing; got %v", keysOf(got))
	}
	for u := range got {
		if strings.Contains(u, "evil.other.net") {
			t.Fatalf("out-of-scope sitemap URL leaked: %s", u)
		}
	}
}

func TestStaticSitemapIndexAndMalformed(t *testing.T) {
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			fmt.Fprintf(w, "Sitemap: %s/sitemap.xml\n", base)
		case "/sitemap.xml":
			fmt.Fprint(w, `<?xml version="1.0"?><sitemapindex><sitemap><loc>`+base+`/sitemap2.xml</loc></sitemap></sitemapindex>`)
		case "/sitemap2.xml":
			fmt.Fprint(w, `<?xml version="1.0"?><urlset><url><loc>`+base+`/deep</loc></url></urlset>`)
		case "/malformed.xml":
			fmt.Fprint(w, `<urlset><url><loc>unterminated`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	base = srv.URL
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})

	res, _ := Run(context.Background(), urlJob([]string{base + "/"}, nil, func(j *Job) { j.Provider = "builtin-static" }), nil)
	got := urlsOf(res)
	if _, ok := got[base+"/deep"]; !ok {
		t.Errorf("sitemap index child URL missing; got %v", keysOf(got))
	}
}

func TestStaticMalformedSitemapReported(t *testing.T) {
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			fmt.Fprintf(w, "Sitemap: %s/malformed.xml\n", base)
		case "/malformed.xml":
			fmt.Fprint(w, `<urlset><url><loc>unterminated`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	base = srv.URL
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), urlJob([]string{base + "/"}, nil, func(j *Job) { j.Provider = "builtin-static" }), nil)
	joined := strings.Join(res.Diagnostics, " ")
	if !strings.Contains(joined, "malformed sitemap") {
		t.Errorf("expected malformed-sitemap diagnostic, got %v", res.Diagnostics)
	}
}

func TestPassivePlaceholderParsing(t *testing.T) {
	stdout := "http://example.com/a\nnot a url\n# comment\nhttp://example.com/a?a=1&b=2\n"
	records, diag := parseURLPlaceholders(stdout)
	if len(records) != 2 {
		t.Fatalf("expected 2 valid URLs, got %d (%v)", len(records), diag)
	}
	if len(diag) == 0 {
		t.Errorf("expected a malformed-URL diagnostic")
	}
}

func TestPassiveProviderFakeBinary(t *testing.T) {
	script := writeScript(t, "#!/bin/sh\necho http://example.com/a\necho 'not a url'\necho http://evil.other.net/x\necho http://example.com/a\n")
	job := urlJob(nil, []string{"example.com"}, func(j *Job) { j.Provider = "gau"; j.BinaryPath = script })
	res, _ := Run(context.Background(), job, nil)
	got := urlsOf(res)
	// In-scope URLs, deduplicated within the provider.
	if len(got) != 1 {
		t.Fatalf("expected 1 unique in-scope URL, got %v", keysOf(got))
	}
	if _, ok := got["http://example.com/a"]; !ok {
		t.Errorf("expected http://example.com/a; got %v", keysOf(got))
	}
	// Malformed URL reported; out-of-scope URL counted as skipped, not persisted.
	joined := strings.Join(res.Diagnostics, " ")
	if !strings.Contains(joined, "malformed URL") {
		t.Errorf("expected malformed-URL diagnostic, got %v", res.Diagnostics)
	}
	if res.Coverage.Skipped < 1 {
		t.Errorf("expected the out-of-scope URL to be skipped, got coverage %+v", res.Coverage)
	}
}

func TestPassiveProviderUnavailable(t *testing.T) {
	job := urlJob(nil, []string{"example.com"}, func(j *Job) { j.Provider = "gau"; j.BinaryPath = "/nonexistent/gau-binary" })
	// A missing configured binary triggers a spawn error (truthful failure, not empty success).
	res, _ := Run(context.Background(), job, nil)
	if res.Status == StatusSucceeded && len(res.Records) == 0 {
		t.Fatalf("missing binary must not be reported as a successful empty result: %s", res.Status)
	}
}

func TestMockURLProviderDeduplicatesAndClassifies(t *testing.T) {
	dir := t.TempDir()
	fixture := dir + "/urls.json"
	if err := os.WriteFile(fixture, []byte(`{"version":"t","urls":["http://example.com/api/v1/users","http://example.com/login","http://example.com/a/../b"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	job := urlJob(nil, nil, func(j *Job) { j.Provider = "mock-url"; j.FixturePath = fixture })
	res, _ := Run(context.Background(), job, nil)
	got := urlsOf(res)
	if _, ok := got["http://example.com/api/v1/users"]; !ok {
		t.Errorf("expected api url; got %v", keysOf(got))
	}
	if _, ok := got["http://example.com/b"]; !ok {
		t.Errorf("dot-segment URL not canonicalized; got %v", keysOf(got))
	}
}

// A 404 robots.txt/sitemap.xml is a normal "no such file" answer and must not fail the provider
// (or make the URL-collection stage PARTIAL) when no other collection error occurred.
func TestStaticMissingRobotsAndSitemapIsNotFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})

	res, err := Run(context.Background(), urlJob([]string{srv.URL + "/"}, nil, func(j *Job) { j.Provider = "builtin-static" }), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusSucceeded {
		t.Fatalf("status=%s want SUCCEEDED (coverage=%+v diagnostics=%v)", res.Status, res.Coverage, res.Diagnostics)
	}
	if res.Coverage.Failed != 0 {
		t.Fatalf("coverage.failed=%d want 0", res.Coverage.Failed)
	}
}
