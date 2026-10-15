package discovery

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reconnexus/workers/internal/scope"
)

// funcResolver is an injectable host resolver for deterministic HTTP tests.
type funcResolver struct {
	fn func(ctx context.Context, host string) ([]string, error)
}

func (f funcResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return f.fn(ctx, host)
}
func (f funcResolver) LookupCNAME(context.Context, string) (string, error)  { return "", nil }
func (f funcResolver) LookupAddr(context.Context, string) ([]string, error) { return nil, nil }

// httpPolicy authorizes the example.com registrable domain and explicitly authorizes only the
// loopback address 127.0.0.1 (so the test HTTP servers are reachable) while leaving all other
// restricted addresses denied. INTERNAL_NETWORK is deliberately absent.
func httpPolicy() scope.Policy {
	p := testPolicy("PASSIVE", "DNS", "ACTIVE_HTTP")
	p.InScope.IPs = []string{"127.0.0.1"}
	p.Exclusions.Hosts = []string{"blocked.example.com"}
	return p
}

func httpJob(urls []string, opts ...func(*Job)) Job {
	j := Job{
		SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "04", JobKey: "04",
		Kind: "HTTP_PROBE", Provider: "builtin-http", Policy: httpPolicy(),
		Limits: scope.Limits{MaxConcurrency: 4, RequestsPerSecond: 10, CrawlDepth: 1, MaxRuntimeSeconds: 60, MaxArtifactBytes: 1 << 20},
		Inputs: Inputs{URLs: urls},
	}
	for _, o := range opts {
		o(&j)
	}
	return j
}

func portOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Port()
}

func resolveExampleTo(addr string) func(context.Context, string) ([]string, error) {
	return func(_ context.Context, host string) ([]string, error) {
		if host == "example.com" || strings.HasSuffix(host, ".example.com") {
			return []string{addr}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
}

func statusOf(res Result) *HTTPDetails {
	for _, r := range res.Records {
		if r.Type == TypeHTTPObservation {
			return r.HTTP
		}
	}
	return nil
}

func techNames(res Result) map[string]TechDetails {
	out := map[string]TechDetails{}
	for _, r := range res.Records {
		if r.Type == TypeTechnology && r.Technology != nil {
			out[r.Technology.Name] = *r.Technology
		}
	}
	return out
}

func TestHttpBasicProbeAndFingerprint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Header().Set("X-Powered-By", "PHP/8.1.2")
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Set-Cookie", "PHPSESSID=abc; Path=/")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`<html><head><title>  Example   Site </title></head><body><div data-reactroot></div><a href="/wp-content/x">w</a></body></html>`))
	}))
	defer srv.Close()

	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	job := httpJob([]string{"http://example.com:" + portOf(t, srv.URL) + "/"})
	res, err := Run(context.Background(), job, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusSucceeded {
		t.Fatalf("status=%s diag=%v", res.Status, res.Diagnostics)
	}
	h := statusOf(res)
	if h == nil || h.StatusCode == nil || *h.StatusCode != 200 {
		t.Fatalf("bad http details: %+v", h)
	}
	if h.Title != "Example Site" {
		t.Errorf("title=%q", h.Title)
	}
	if h.Headers["server"] != "nginx/1.25.3" {
		t.Errorf("server header not captured: %v", h.Headers)
	}
	if _, ok := h.Headers["set-cookie"]; ok {
		t.Errorf("set-cookie must not be persisted")
	}
	tech := techNames(res)
	for _, want := range []string{"nginx", "PHP", "React", "WordPress"} {
		if _, ok := tech[want]; !ok {
			t.Errorf("expected technology %q; got %v", want, keys(tech))
		}
	}
	if tech["PHP"].Evidence == "" || tech["nginx"].Evidence == "" {
		t.Errorf("fingerprints must carry evidence: %+v", tech)
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestHttpRedirectInScopeFollowed(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("<title>Done</title>"))
			return
		}
		http.Redirect(w, r, "/final", http.StatusFound)
	}))
	defer srv.Close()

	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), httpJob([]string{"http://example.com:" + portOf(t, srv.URL) + "/start"}), nil)
	h := statusOf(res)
	if h == nil || h.FinalURL == "" || !strings.HasSuffix(h.FinalURL, "/final") {
		t.Fatalf("redirect not followed: %+v", h)
	}
	if len(h.RedirectChain) != 1 || h.RedirectChain[0].StatusCode == nil || *h.RedirectChain[0].StatusCode != 302 {
		t.Errorf("redirect chain = %+v", h.RedirectChain)
	}
}

func redirectServer(t *testing.T, location string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		http.Redirect(w, r, location, http.StatusFound)
	}))
}

func TestHttpRedirectEnforcement(t *testing.T) {
	cases := []struct {
		name     string
		location string
	}{
		{"excluded host", "http://blocked.example.com/next"},
		{"out-of-scope domain", "http://evil.other.net/next"},
		{"loopback different address", "http://127.0.0.2:9/next"},
		{"private address", "http://10.0.0.1/next"},
		{"cloud metadata", "http://169.254.169.254/latest/meta-data/"},
		{"ipv4-mapped private", "http://[::ffff:10.0.0.1]/next"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := redirectServer(t, tc.location)
			defer srv.Close()
			withResolver(t, funcResolver{fn: func(_ context.Context, host string) ([]string, error) {
				if host == "evil.other.net" {
					return []string{"203.0.113.5"}, nil
				}
				return []string{"127.0.0.1"}, nil
			}})
			res, _ := Run(context.Background(), httpJob([]string{"http://example.com:" + portOf(t, srv.URL) + "/start"}), nil)
			h := statusOf(res)
			if h == nil {
				t.Fatalf("no http observation")
			}
			if h.ProbeStatus != ProbeRedirectDenied {
				t.Fatalf("expected REDIRECT_DENIED, got %s (%s)", h.ProbeStatus, h.Error)
			}
			// The permitted pre-redirect response metadata is preserved.
			if h.StatusCode == nil || *h.StatusCode != 302 || h.Headers["server"] != "nginx" {
				t.Errorf("pre-redirect metadata not preserved: %+v", h)
			}
			if res.Status != StatusSucceeded {
				t.Errorf("status=%s (a denied redirect is an observed response)", res.Status)
			}
		})
	}
}

func TestHttpRedirectLoopIsBounded(t *testing.T) {
	// A self-referential redirect must terminate at the configured hop limit, not loop forever.
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), httpJob([]string{"http://example.com:" + portOf(t, srv.URL) + "/loop"}), nil)
	h := statusOf(res)
	if h == nil {
		t.Fatalf("no http observation")
	}
	if h.ProbeStatus != ProbeTooManyRedirects {
		t.Fatalf("expected TOO_MANY_REDIRECTS, got %s (%s)", h.ProbeStatus, h.Error)
	}
	// The chain is capped: the server is not hammered without bound.
	if got := atomic.LoadInt32(&hits); got > 12 {
		t.Fatalf("redirect loop not bounded: %d requests", got)
	}
	if len(h.RedirectChain) > 12 {
		t.Fatalf("unbounded redirect chain recorded: %d hops", len(h.RedirectChain))
	}
}

func TestHttpDnsRebindingBlockedAtConnection(t *testing.T) {
	var calls int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			w.WriteHeader(200)
			return
		}
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer srv.Close()

	// First lookup (initial connection) is public/allowed; subsequent lookups rebind to a
	// private address and must be blocked at dial time.
	withResolver(t, funcResolver{fn: func(_ context.Context, host string) ([]string, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return []string{"127.0.0.1"}, nil
		}
		return []string{"10.1.2.3"}, nil
	}})
	res, _ := Run(context.Background(), httpJob([]string{"http://example.com:" + portOf(t, srv.URL) + "/start"}), nil)
	h := statusOf(res)
	if h == nil || h.ProbeStatus != ProbeBlockedAddress {
		t.Fatalf("expected BLOCKED_ADDRESS after rebind, got %+v", h)
	}
}

func serverCAFile(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	cert := srv.Certificate()
	if cert == nil {
		t.Fatal("no certificate")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHttpTlsVerifiedWithTrustedCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<title>secure</title>"))
	}))
	defer srv.Close()
	caFile := serverCAFile(t, srv)
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})

	job := httpJob([]string{"https://example.com:" + portOf(t, srv.URL) + "/"}, func(j *Job) { j.TLSCaFile = caFile })
	res, _ := Run(context.Background(), job, nil)
	h := statusOf(res)
	if h == nil || h.ProbeStatus != ProbeOK {
		t.Fatalf("expected OK with trusted CA, got %+v", h)
	}
	if h.TLS == nil || h.TLS.SHA256 == "" || h.TLS.Subject == "" || h.TLS.Protocol == "" {
		t.Fatalf("TLS metadata missing: %+v", h.TLS)
	}
}

func TestHttpTlsUntrustedFailsWithoutGlobalBypass(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	// No CA file: the self-signed certificate must fail verification.
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), httpJob([]string{"https://example.com:" + portOf(t, srv.URL) + "/"}), nil)
	h := statusOf(res)
	if h == nil || h.ProbeStatus != ProbeTLSError {
		t.Fatalf("expected TLS_ERROR, got %+v", h)
	}
	_ = x509.NewCertPool() // keep import
}

func TestHttpTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	job := httpJob([]string{"http://example.com:" + portOf(t, srv.URL) + "/"}, func(j *Job) { j.RequestTimeoutMs = 250 })
	res, _ := Run(context.Background(), job, nil)
	h := statusOf(res)
	if h == nil || h.ProbeStatus != ProbeTimeout {
		t.Fatalf("expected TIMEOUT, got %+v", h)
	}
	if res.Coverage.Failed != 1 {
		t.Errorf("coverage.failed=%d want 1", res.Coverage.Failed)
	}
}

func TestHttpOversizedResponse(t *testing.T) {
	big := strings.Repeat("a", 5000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<title>Big</title>" + big))
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	job := httpJob([]string{"http://example.com:" + portOf(t, srv.URL) + "/"}, func(j *Job) { j.Limits.MaxArtifactBytes = 512 })
	res, _ := Run(context.Background(), job, nil)
	h := statusOf(res)
	if h == nil || h.ProbeStatus != ProbeOversized || !h.BodyTruncated {
		t.Fatalf("expected OVERSIZED/truncated, got %+v", h)
	}
	if h.Title != "Big" {
		t.Errorf("title should still be captured from the truncated body: %q", h.Title)
	}
}

func TestHttpCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	job := httpJob([]string{"http://example.com:" + portOf(t, srv.URL) + "/"}, func(j *Job) { j.RequestTimeoutMs = 5000 })
	res, _ := Run(ctx, job, nil)
	if res.Status != StatusCancelled {
		t.Fatalf("status=%s want CANCELLED", res.Status)
	}
}

func TestHttpOutOfScopeTargetSkipped(t *testing.T) {
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), httpJob([]string{"http://evil.other.net/", "http://example.com/"}), nil)
	if res.Coverage.Skipped != 1 {
		t.Fatalf("skipped=%d want 1 (out-of-scope host)", res.Coverage.Skipped)
	}
}

func TestHttpInvalidTargetSkipped(t *testing.T) {
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), httpJob([]string{"::::not a url"}), nil)
	if res.Coverage.Skipped != 1 {
		t.Fatalf("skipped=%d want 1", res.Coverage.Skipped)
	}
}

func TestHttpScopeDeniedWhenCapabilityMissing(t *testing.T) {
	p := httpPolicy()
	p.Authorization.Capabilities = []string{"PASSIVE"} // no ACTIVE_HTTP
	job := httpJob([]string{"http://example.com/"})
	job.Policy = p
	res, _ := Run(context.Background(), job, nil)
	if res.Status != StatusBlocked {
		t.Fatalf("status=%s want BLOCKED", res.Status)
	}
}
