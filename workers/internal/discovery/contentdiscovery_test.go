package discovery

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reconnexus/workers/internal/scope"
)

func contentPolicy(ips ...string) scope.Policy {
	p := loginFinderPolicy(ips...)
	p.Authorization.Capabilities = []string{"ACTIVE_HTTP", "CONTENT_DISCOVERY", "INTERNAL_NETWORK"}
	return p
}

func contentJob(origin string) Job {
	return Job{
		SchemaVersion:            1,
		Kind:                     "CONTENT_DISCOVERY",
		Provider:                 "builtin-content",
		Inputs:                   Inputs{URLs: []string{origin}},
		Limits:                   scope.Limits{MaxConcurrency: 8, MaxArtifactBytes: 256 * 1024},
		RequestTimeoutMs:         2000,
		MaxRedirects:             2,
		AllowRestrictedAddresses: true,
	}
}

func runContent(t *testing.T, h http.HandlerFunc) ProviderResult {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	host, _, _ := net.SplitHostPort(srv.Listener.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := (builtinContent{}).Run(ctx, ProviderContext{Job: contentJob(srv.URL + "/"), Engine: restrictedEngine(contentPolicy(host))})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return res
}

func contentByPath(res ProviderResult) map[string]*ContentInfo {
	m := map[string]*ContentInfo{}
	for _, r := range res.Records {
		if r.Content != nil {
			m[r.Content.Path] = r.Content
		}
	}
	return m
}

func TestContentDiscoveryConfirmsMarkersAndRejectsMissing(t *testing.T) {
	res := runContent(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.git/HEAD":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "ref: refs/heads/main\n")
		case "/.env":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "DB_PASSWORD=hunter2hunter2\nAPP_KEY=abc\n")
		case "/uploads/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1></body></html>")
		case "/admin-ish":
			_, _ = io.WriteString(w, "ignored")
		default:
			http.NotFound(w, r)
		}
	})
	got := contentByPath(res)
	if g := got["/.git/HEAD"]; g == nil || g.Status != ContentConfirmed || g.Severity != "HIGH" || g.Category != ContentVCS {
		t.Fatalf("/.git/HEAD = %+v", g)
	}
	if g := got["/.env"]; g == nil || g.Status != ContentConfirmed {
		t.Fatalf("/.env = %+v", g)
	}
	if g := got["/uploads/"]; g == nil || g.Category != ContentListing || g.Status != ContentConfirmed {
		t.Fatalf("/uploads/ = %+v", g)
	}
	if len(got) != 3 {
		t.Fatalf("expected exactly 3 hits, got %d: %v", len(got), got)
	}
	// Evidence must never carry body text.
	for _, r := range res.Records {
		if strings.Contains(r.Content.Evidence, "hunter2") {
			t.Fatal("secret value leaked into evidence")
		}
	}
}

func TestContentDiscoverySoftWildcardProducesNoHits(t *testing.T) {
	// An SPA that answers 200 + the same HTML shell for every path.
	res := runContent(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><title>App</title><body>shell "+strings.Repeat("x", 500)+"</body></html>")
	})
	if len(res.Records) != 0 {
		t.Fatalf("wildcard host produced %d records: %v", len(res.Records), contentByPath(res))
	}
}

func TestContentDiscoveryHTMLShellWithDifferentBodyIsNotAnEnvFile(t *testing.T) {
	// Calibration passes (404 for random paths) but a catch-all returns HTML for dotfiles.
	res := runContent(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.") {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<html><body>a=b "+r.URL.Path+" "+strings.Repeat("y", len(r.URL.Path)*50)+"</body></html>")
			return
		}
		http.NotFound(w, r)
	})
	if got := contentByPath(res); len(got) != 0 {
		t.Fatalf("HTML responses must not be hits: %v", got)
	}
}

func TestContentDiscoveryForbiddenIsInventoryOnly(t *testing.T) {
	res := runContent(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.htpasswd" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	})
	g := contentByPath(res)["/.htpasswd"]
	if g == nil || g.Severity != "INFO" || g.Status != ContentPossible || g.EvidenceType != "ACCESS_DENIED" {
		t.Fatalf("/.htpasswd = %+v", g)
	}
}

func TestContentDiscoveryRequiresCapability(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	host, _, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p := loginFinderPolicy(host) // ACTIVE_HTTP only
	job := contentJob(srv.URL + "/")
	job.Policy = p
	res, err := Run(context.Background(), job, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusBlocked {
		t.Fatalf("status = %s, want BLOCKED", res.Status)
	}
}

func TestContentCalibrationMatches(t *testing.T) {
	cal := calibration{sigs: []contentSignature{{status: 200, length: 1000, bodyHash: "a"}}}
	if !cal.matches(contentSignature{status: 200, length: 1030, bodyHash: "b"}) {
		t.Fatal("similar-size 200 should match calibration")
	}
	if cal.matches(contentSignature{status: 200, length: 5000, bodyHash: "c"}) {
		t.Fatal("very different body must not match")
	}
}
