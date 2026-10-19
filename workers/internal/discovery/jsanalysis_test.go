package discovery

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reconnexus/workers/internal/scope"
)

func jsPolicy() scope.Policy {
	p := testPolicy("PASSIVE", "DNS", "ACTIVE_HTTP", "CRAWL", "JS_ANALYSIS", "API_DISCOVERY", "INTERNAL_NETWORK")
	p.InScope.IPs = []string{"127.0.0.1"}
	return p
}

func jsJob(urls []string, opts ...func(*Job)) Job {
	j := Job{
		SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "07", JobKey: "07",
		Kind: "JS_ANALYSIS", Provider: "builtin-js", Policy: jsPolicy(), AllowRestrictedAddresses: true,
		Limits: scope.Limits{MaxConcurrency: 4, RequestsPerSecond: 20, CrawlDepth: 1, MaxRuntimeSeconds: 60, MaxArtifactBytes: 1 << 20},
		Inputs: Inputs{JSURLs: urls},
	}
	for _, o := range opts {
		o(&j)
	}
	return j
}

func endpointsOf(res Result) []*ApiEndpoint {
	var out []*ApiEndpoint
	for _, r := range res.Records {
		if r.Type == TypeApiEndpoint && r.Endpoint != nil {
			out = append(out, r.Endpoint)
		}
	}
	return out
}

func findEndpoint(eps []*ApiEndpoint, method, path string) *ApiEndpoint {
	for _, e := range eps {
		if e.Method == method && e.Path == path {
			return e
		}
	}
	return nil
}

func TestJsAnalysisExtractsEndpoints(t *testing.T) {
	js := "//# sourceMappingURL=app.js.map\n" +
		"async function f(id){\n" +
		"  const a = await fetch(\"/api/v1/users\");\n" +
		"  axios.post(\"/api/v1/users\", {n:1});\n" +
		"  const x = new XMLHttpRequest(); x.open(\"DELETE\", \"/api/v1/users/1\");\n" +
		"  const ws = new WebSocket(\"wss://example.com/ws\");\n" +
		"  const ext = \"https://evil.other.net/x\";\n" +
		"  const dyn = fetch(`/api/users/${id}`);\n" +
		"  const token = \"Bearer SECRETTOKEN1234567890\";\n}"
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, js)
		case "/app.js.map":
			fmt.Fprint(w, `{"version":3,"sources":["src/a.ts","src/b.ts"],"sourcesContent":["x","y"]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})

	job := jsJob([]string{srv.URL + "/app.js"}, func(j *Job) { j.Inputs.FetchSourceMaps = true })
	res, _ := Run(context.Background(), job, nil)
	if res.Status != StatusSucceeded {
		t.Fatalf("status=%s diag=%v", res.Status, res.Diagnostics)
	}

	var artifact *JsArtifactInfo
	for _, r := range res.Records {
		if r.Type == TypeJSArtifact {
			artifact = r.Artifact
		}
	}
	if artifact == nil || artifact.Status != ArtifactRetrieved || len(artifact.ContentHash) != 64 {
		t.Fatalf("bad JS artifact: %+v", artifact)
	}

	eps := endpointsOf(res)
	for _, want := range []struct{ m, p string }{
		{"GET", "/api/v1/users"},
		{"POST", "/api/v1/users"},
		{"DELETE", "/api/v1/users/1"},
	} {
		if findEndpoint(eps, want.m, want.p) == nil {
			t.Errorf("missing endpoint %s %s; got %v", want.m, want.p, epList(eps))
		}
	}
	if e := findEndpoint(eps, "WEBSOCKET", "/ws"); e == nil || e.Origin != "wss://example.com" {
		t.Errorf("missing websocket endpoint; got %v", epList(eps))
	}
	// Dynamic template retained as an unresolved candidate, not a fabricated endpoint.
	if e := findEndpoint(eps, "GET", "/api/users/"); e == nil || e.Resolved {
		t.Errorf("expected unresolved dynamic candidate /api/users/; got %v", epList(eps))
	}
	// Out-of-scope origin dropped.
	for _, e := range eps {
		if strings.Contains(e.Origin, "evil.other.net") {
			t.Fatalf("out-of-scope endpoint leaked: %+v", e)
		}
	}
	if res.Coverage.Skipped < 1 {
		t.Errorf("expected the out-of-scope literal to be skipped")
	}
	// No secret-like value persisted in evidence.
	for _, e := range eps {
		if strings.Contains(e.Evidence, "SECRETTOKEN") {
			t.Fatalf("secret leaked into evidence: %q", e.Evidence)
		}
	}
	// Source map parsed, sources retained, no sourcesContent persisted.
	var sm *SourceMapInfo
	for _, r := range res.Records {
		if r.Type == TypeSourceMap {
			sm = r.SourceMap
		}
	}
	if sm == nil || sm.Status != "PARSED" || sm.SourcesCount != 2 || !sm.HasContent {
		t.Fatalf("bad source map: %+v", sm)
	}
}

func epList(eps []*ApiEndpoint) []string {
	var out []string
	for _, e := range eps {
		out = append(out, e.Method+" "+e.Origin+e.Path)
	}
	return out
}

func TestJsAnalysisHonestFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/missing.js":
			w.WriteHeader(404)
		case "/html.js":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<!DOCTYPE html><html>not js</html>")
		default:
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})

	res, _ := Run(context.Background(), jsJob([]string{srv.URL + "/missing.js", srv.URL + "/html.js"}), nil)
	var missing, mismatched bool
	for _, r := range res.Records {
		if r.Type == TypeJSArtifact {
			if r.Artifact.Status == ArtifactNotFound {
				missing = true
			}
			if r.Artifact.Status == ArtifactMismatchedMime {
				mismatched = true
			}
		}
	}
	if !missing {
		t.Errorf("expected NOT_FOUND for missing.js")
	}
	if !mismatched {
		t.Errorf("expected MISMATCHED_MIME for html served as js")
	}
}

func TestJsAnalysisOversizedAndBounded(t *testing.T) {
	// A pathological body: many quote characters (adversarial for naive scanners) plus dupes.
	big := strings.Repeat(`x="/a/b/c"; `, 200000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, big)
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	job := jsJob([]string{srv.URL + "/big.js"}, func(j *Job) { j.Limits.MaxArtifactBytes = 4096 })
	done := make(chan struct{})
	go func() {
		res, _ := Run(context.Background(), job, nil)
		if len(endpointsOf(res)) > maxJSFindings {
			t.Errorf("endpoint candidates exceeded cap")
		}
		var art *JsArtifactInfo
		for _, r := range res.Records {
			if r.Type == TypeJSArtifact {
				art = r.Artifact
			}
		}
		if art == nil || !art.Truncated || art.Status != ArtifactOversized {
			t.Errorf("expected OVERSIZED/truncated, got %+v", art)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("bounded analysis took too long (possible pathological input)")
	}
}

func TestJsAnalysisSourceMapDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, "//# sourceMappingURL=app.js.map\nvar x=1;")
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), jsJob([]string{srv.URL + "/app.js"}), nil) // fetchSourceMaps false
	var sm *SourceMapInfo
	for _, r := range res.Records {
		if r.Type == TypeSourceMap {
			sm = r.SourceMap
		}
	}
	if sm == nil || sm.Status != "DISABLED" {
		t.Fatalf("expected source map DISABLED, got %+v", sm)
	}
}

// Regression: a .js URL that actually returns a binary asset (e.g. a WordPress image) must not be
// parsed as JavaScript. The artifact is retrieved and classified SKIPPED with a rationale; no
// endpoints are invented from binary content.
func TestJsAnalysisRejectsNonScriptContent(t *testing.T) {
	jpeg := append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, []byte("JFIF...binary image body with /api/v1/fake inside...")...)
	css := []byte("body{background:url(/api/v1/thing.png)}")
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/photo.js":
			w.Header().Set("Content-Type", "image/jpeg")
			_, _ = w.Write(jpeg)
		case "/styles.js":
			w.Header().Set("Content-Type", "text/css")
			_, _ = w.Write(css)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})

	res, _ := Run(context.Background(), jsJob([]string{srv.URL + "/photo.js", srv.URL + "/styles.js"}), nil)
	if res.Status != StatusSucceeded {
		t.Fatalf("status=%s diag=%v", res.Status, res.Diagnostics)
	}
	skipped := 0
	for _, r := range res.Records {
		if r.Type == TypeJSArtifact && r.Artifact != nil && r.Artifact.Status == ArtifactSkipped {
			skipped++
		}
	}
	if skipped != 2 {
		t.Fatalf("expected both non-script artifacts SKIPPED, got %d", skipped)
	}
	if eps := endpointsOf(res); len(eps) != 0 {
		t.Fatalf("no endpoints should be extracted from non-script content, got %v", epList(eps))
	}
	if res.Coverage.Skipped < 2 {
		t.Fatalf("expected skipped coverage to reflect exclusions, got %+v", res.Coverage)
	}
}

func TestJsAnalysisBlockedWithoutCapability(t *testing.T) {
	p := jsPolicy()
	p.Authorization.Capabilities = []string{"PASSIVE"}
	job := jsJob([]string{"http://example.com/app.js"})
	job.Policy = p
	res, _ := Run(context.Background(), job, nil)
	if res.Status != StatusBlocked {
		t.Fatalf("status=%s want BLOCKED", res.Status)
	}
}
