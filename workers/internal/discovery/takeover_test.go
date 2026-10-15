package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reconnexus/workers/internal/scope"
)

// takeoverResolver returns a fixed dial address for every host and a configurable CNAME map.
type takeoverResolver struct {
	addr  string
	cname map[string]string
}

func (r takeoverResolver) LookupHost(context.Context, string) ([]string, error) {
	return []string{r.addr}, nil
}
func (r takeoverResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if c, ok := r.cname[host]; ok {
		return c, nil
	}
	return "", nil
}
func (r takeoverResolver) LookupAddr(context.Context, string) ([]string, error) { return nil, nil }

func takeoverPolicy() scope.Policy {
	p := testPolicy("PASSIVE", "DNS", "ACTIVE_HTTP", "TAKEOVER_CHECK")
	p.InScope.IPs = []string{"127.0.0.1"}
	return p
}

func takeoverJob(urls []string) Job {
	return Job{
		SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "13", JobKey: "13",
		Kind: "TAKEOVER", Provider: "builtin-takeover", Policy: takeoverPolicy(),
		Limits: scope.Limits{MaxConcurrency: 4, RequestsPerSecond: 20, CrawlDepth: 1, MaxRuntimeSeconds: 30, MaxArtifactBytes: 1 << 20},
		Inputs: Inputs{URLs: urls},
	}
}

func takeoverRecords(res Result) []*TakeoverInfo {
	var out []*TakeoverInfo
	for _, r := range res.Records {
		if r.Type == TypeTakeoverCandidate && r.Takeover != nil {
			out = append(out, r.Takeover)
		}
	}
	return out
}

func serving(body string, status int) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func runTakeover(t *testing.T, srv *httptest.Server, cname string) (Result, error) {
	t.Helper()
	caFile := serverCAFile(t, srv)
	withResolver(t, takeoverResolver{addr: "127.0.0.1", cname: map[string]string{"example.com": cname}})
	job := takeoverJob([]string{"https://example.com:" + portOf(t, srv.URL) + "/"})
	job.TLSCaFile = caFile
	return Run(context.Background(), job, nil)
}

func TestTakeoverSuspectedFromUnclaimedMarker(t *testing.T) {
	srv := serving("There isn't a GitHub Pages site here.", 404)
	defer srv.Close()
	res, _ := runTakeover(t, srv, "user.github.io")
	recs := takeoverRecords(res)
	if len(recs) != 1 {
		t.Fatalf("expected 1 candidate, got %d (%v)", len(recs), recs)
	}
	r := recs[0]
	if r.Status != TakeoverSuspected || r.Service != "GitHub Pages" || r.CNAME != "user.github.io" || r.Confidence < 0.8 {
		t.Fatalf("unexpected candidate: %+v", r)
	}
	if !strings.Contains(r.Evidence, "unclaimed marker matched") {
		t.Errorf("evidence should cite the matched marker: %q", r.Evidence)
	}
	if res.Status != StatusSucceeded {
		t.Errorf("status=%s", res.Status)
	}
}

// Regression: a 404 with no service-specific unclaimed marker must NOT be a candidate. Ordinary
// error pages on claimed resources return the same status and were the main false-positive source.
func TestTakeoverStatusOnlyIsInconclusiveNotCandidate(t *testing.T) {
	srv := serving("generic error page", 404)
	defer srv.Close()
	res, _ := runTakeover(t, srv, "user.herokuapp.com")
	recs := takeoverRecords(res)
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %+v", recs)
	}
	if recs[0].Status == TakeoverCandidate || recs[0].Status == TakeoverSuspected {
		t.Fatalf("status-only response must not be candidate/suspected, got %+v", recs[0])
	}
	if recs[0].Status != TakeoverInconclusive || recs[0].Service != "Heroku" {
		t.Fatalf("expected INCONCLUSIVE for Heroku, got %+v", recs[0])
	}
	if recs[0].EvidenceType != "STATUS_ONLY" {
		t.Errorf("expected STATUS_ONLY evidence type, got %q", recs[0].EvidenceType)
	}
}

// A generic phrase that used to be a marker ("bad request", "not found") must no longer raise a
// candidate on a shared-CDN CNAME.
func TestTakeoverGenericMarkerNoLongerSuspected(t *testing.T) {
	for _, tc := range []struct {
		body    string
		status  int
		cname   string
		service string
	}{
		{"Bad Request", 403, "d123.cloudfront.net", "Amazon CloudFront"},
		{"not found", 404, "x.trafficmanager.net", "Azure Traffic Manager"},
		{"page not found", 404, "x.statuspage.io", "Statuspage"},
	} {
		srv := serving(tc.body, tc.status)
		res, _ := runTakeover(t, srv, tc.cname)
		srv.Close()
		recs := takeoverRecords(res)
		if len(recs) != 1 {
			t.Fatalf("%s: expected 1 record, got %+v", tc.service, recs)
		}
		if recs[0].Status == TakeoverSuspected || recs[0].Status == TakeoverCandidate {
			t.Errorf("%s: generic body %q must not be a candidate, got %+v", tc.service, tc.body, recs[0])
		}
	}
}

func TestTakeoverNotVulnerableWhenClaimed(t *testing.T) {
	srv := serving("<h1>Welcome to my real site</h1>", 200)
	defer srv.Close()
	res, _ := runTakeover(t, srv, "user.netlify.app")
	recs := takeoverRecords(res)
	if len(recs) != 1 || recs[0].Status != TakeoverNotVuln {
		t.Fatalf("expected NOT_VULNERABLE, got %+v", recs)
	}
}

func TestTakeoverInconclusiveOnFetchFailure(t *testing.T) {
	srv := serving("x", 200)
	url := srv.URL
	srv.Close() // connection refused
	withResolver(t, takeoverResolver{addr: "127.0.0.1", cname: map[string]string{"example.com": "user.github.io"}})
	job := takeoverJob([]string{"https://example.com:" + portOf(t, url) + "/"})
	res, _ := Run(context.Background(), job, nil)
	recs := takeoverRecords(res)
	if len(recs) != 1 || recs[0].Status != TakeoverInconclusive {
		t.Fatalf("expected INCONCLUSIVE, got %+v", recs)
	}
}

func TestTakeoverIgnoresNoCnameAndUnknownService(t *testing.T) {
	srv := serving("There isn't a GitHub Pages site here.", 404)
	defer srv.Close()
	// CNAME equal to the host: no CNAME-based candidate.
	res, _ := runTakeover(t, srv, "example.com")
	if len(takeoverRecords(res)) != 0 {
		t.Fatalf("expected no candidate when there is no CNAME")
	}
	// CNAME to a service we do not fingerprint.
	res2, _ := runTakeover(t, srv, "host.some-unknown-service.example")
	if len(takeoverRecords(res2)) != 0 {
		t.Fatalf("expected no candidate for unknown service")
	}
}

func TestTakeoverOutOfScopeSkipped(t *testing.T) {
	withResolver(t, takeoverResolver{addr: "127.0.0.1", cname: map[string]string{}})
	res, _ := Run(context.Background(), takeoverJob([]string{"https://evil.other.net/"}), nil)
	if res.Coverage.Skipped != 1 {
		t.Fatalf("skipped=%d want 1", res.Coverage.Skipped)
	}
}

func TestTakeoverBlockedWithoutCapability(t *testing.T) {
	p := takeoverPolicy()
	p.Authorization.Capabilities = []string{"ACTIVE_HTTP"}
	job := takeoverJob([]string{"https://example.com/"})
	job.Policy = p
	res, _ := Run(context.Background(), job, nil)
	if res.Status != StatusBlocked {
		t.Fatalf("status=%s want BLOCKED", res.Status)
	}
}

func TestTakeoverCancellation(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()
	caFile := serverCAFile(t, srv)
	withResolver(t, takeoverResolver{addr: "127.0.0.1", cname: map[string]string{"example.com": "user.github.io"}})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(80 * time.Millisecond); cancel() }()
	job := takeoverJob([]string{"https://example.com:" + portOf(t, srv.URL) + "/"})
	job.TLSCaFile = caFile
	job.RequestTimeoutMs = 5000
	res, _ := Run(ctx, job, nil)
	if res.Status != StatusCancelled {
		t.Fatalf("status=%s want CANCELLED", res.Status)
	}
}
