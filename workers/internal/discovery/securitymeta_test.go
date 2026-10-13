package discovery

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reconnexus/workers/internal/scope"
)

func secPolicy() scope.Policy {
	p := testPolicy("PASSIVE", "ACTIVE_HTTP", "SECURITY_CHECKS")
	p.InScope.IPs = []string{"127.0.0.1"}
	return p
}

func secJob(urls []string, opts ...func(*Job)) Job {
	j := Job{
		SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "10", JobKey: "10",
		Kind: "SECURITY_META", Provider: "builtin-security-meta", Policy: secPolicy(),
		Limits: scope.Limits{MaxConcurrency: 4, RequestsPerSecond: 20, CrawlDepth: 1, MaxRuntimeSeconds: 30, MaxArtifactBytes: 1 << 20},
		Inputs: Inputs{URLs: urls},
	}
	for _, o := range opts {
		o(&j)
	}
	return j
}

func metasByCategory(res Result) map[string][]*SecurityMetadataInfo {
	out := map[string][]*SecurityMetadataInfo{}
	for _, r := range res.Records {
		if r.Type == TypeSecurityMetadata && r.Security != nil {
			out[r.Security.Category] = append(out[r.Security.Category], r.Security)
		}
	}
	return out
}

func findMeta(metas []*SecurityMetadataInfo, name string) *SecurityMetadataInfo {
	for _, m := range metas {
		if m.Name == name {
			return m
		}
	}
	return nil
}

func TestSecurityMetaHeadersCookiesCORSContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Add("Set-Cookie", "SID=SECRETCOOKIEVALUE; Path=/; Secure; HttpOnly; SameSite=Lax")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})

	res, _ := Run(context.Background(), secJob([]string{srv.URL + "/"}), nil)
	if res.Status != StatusSucceeded {
		t.Fatalf("status=%s", res.Status)
	}
	m := metasByCategory(res)

	hsts := findMeta(m["HSTS"], "strict-transport-security")
	if hsts == nil || hsts.Status != MetaObserved || hsts.Detail["includeSubDomains"] != true || hsts.Detail["preload"] != true {
		t.Fatalf("bad HSTS: %+v", hsts)
	}
	if findMeta(m["HEADER"], "x-content-type-options") == nil {
		t.Errorf("expected x-content-type-options observed")
	}
	// A missing header is NOT_OBSERVED, never a claim that the control is absent.
	frame := findMeta(m["HEADER"], "x-frame-options")
	if frame == nil || frame.Status != MetaNotObserved || frame.Observed {
		t.Errorf("expected x-frame-options NOT_OBSERVED, got %+v", frame)
	}

	cors := findMeta(m["CORS"], "cors")
	if cors == nil || cors.Status != MetaInconsistent || cors.Observed == false {
		t.Errorf("expected wildcard+credentials CORS INCONSISTENT, got %+v", cors)
	}

	cookies := m["COOKIE"]
	if len(cookies) != 1 || cookies[0].Name != "SID" {
		t.Fatalf("expected one cookie SID, got %+v", cookies)
	}
	if cookies[0].Detail["secure"] != true || cookies[0].Detail["httpOnly"] != true || cookies[0].Detail["sameSite"] != "Lax" {
		t.Errorf("bad cookie attributes: %+v", cookies[0].Detail)
	}
	// The cookie VALUE must never be persisted anywhere in the records.
	for _, r := range res.Records {
		if strings.Contains(r.Security.Evidence, "SECRETCOOKIEVALUE") || r.Security.Value == "SECRETCOOKIEVALUE" {
			t.Fatalf("cookie value leaked")
		}
	}

	ct := findMeta(m["CONTENT_TYPE"], "content-type")
	if ct == nil || ct.Status != MetaObserved || ct.Consistent == nil || !*ct.Consistent {
		t.Errorf("expected consistent content-type json, got %+v", ct)
	}
}

func TestSecurityMetaContentTypeMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`{"json":"but declared html"}`))
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), secJob([]string{srv.URL + "/"}), nil)
	ct := findMeta(metasByCategory(res)["CONTENT_TYPE"], "content-type")
	if ct == nil || ct.Status != MetaInconsistent || ct.Consistent == nil || *ct.Consistent {
		t.Fatalf("expected INCONSISTENT content-type, got %+v", ct)
	}
}

func TestSecurityMetaTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=100")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	caFile := serverCAFile(t, srv)
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	job := secJob([]string{"https://example.com:" + portOf(t, srv.URL) + "/"}, func(j *Job) { j.TLSCaFile = caFile })
	res, _ := Run(context.Background(), job, nil)
	tlsMeta := findMeta(metasByCategory(res)["TLS"], "certificate")
	if tlsMeta == nil || tlsMeta.Status != MetaObserved {
		t.Fatalf("expected TLS OBSERVED, got %+v", tlsMeta)
	}
	if tlsMeta.Detail["validNow"] != true || tlsMeta.Detail["hostnameMatch"] != true {
		t.Errorf("bad TLS detail: %+v", tlsMeta.Detail)
	}
	if tlsMeta.Detail["sha256"] == nil || tlsMeta.Detail["sha256"] == "" {
		t.Errorf("expected certificate sha256 for correlation")
	}
}

func TestSecurityMetaPlaintextHTTPSNotObserved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), secJob([]string{srv.URL + "/"}), nil)
	tlsMeta := findMeta(metasByCategory(res)["TLS"], "certificate")
	if tlsMeta == nil || tlsMeta.Status != MetaNotObserved {
		t.Fatalf("expected TLS NOT_OBSERVED over http, got %+v", tlsMeta)
	}
}

func TestSecurityMetaCollectionFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL + "/"
	srv.Close() // connection refused
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), secJob([]string{url}), nil)
	m := metasByCategory(res)
	found := false
	for _, h := range m["HEADER"] {
		if h.Status == MetaCollectionFailed {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected COLLECTION_FAILED, got %+v", res.Records)
	}
	if res.Coverage.Failed != 1 {
		t.Errorf("coverage.failed=%d want 1", res.Coverage.Failed)
	}
}

func TestSecurityMetaOutOfScopeSkipped(t *testing.T) {
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), secJob([]string{"http://evil.other.net/"}), nil)
	if res.Coverage.Skipped != 1 {
		t.Fatalf("skipped=%d want 1", res.Coverage.Skipped)
	}
}

func TestSecurityMetaCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(80 * time.Millisecond); cancel() }()
	job := secJob([]string{srv.URL + "/"}, func(j *Job) { j.RequestTimeoutMs = 5000 })
	res, _ := Run(ctx, job, nil)
	if res.Status != StatusCancelled {
		t.Fatalf("status=%s want CANCELLED", res.Status)
	}
}

func TestSecurityMetaBlockedWithoutCapability(t *testing.T) {
	p := secPolicy()
	p.Authorization.Capabilities = []string{"ACTIVE_HTTP"}
	job := secJob([]string{"http://example.com/"})
	job.Policy = p
	res, _ := Run(context.Background(), job, nil)
	if res.Status != StatusBlocked {
		t.Fatalf("status=%s want BLOCKED", res.Status)
	}
}

func TestCertDetailValidityBoundaries(t *testing.T) {
	now := time.Now()
	mk := func(nb, na time.Time) *x509.Certificate {
		return &x509.Certificate{
			Subject:   pkix.Name{CommonName: "x"},
			Issuer:    pkix.Name{CommonName: "x"},
			NotBefore: nb,
			NotAfter:  na,
			DNSNames:  []string{"example.com"},
			SerialNumber: big.NewInt(1),
		}
	}
	if _, ok := certDetail(mk(now.Add(-time.Hour), now.Add(time.Hour)), 0x0304, "example.com", now); !ok {
		t.Errorf("valid certificate should report validNow=true")
	}
	if _, ok := certDetail(mk(now.Add(-2*time.Hour), now.Add(-time.Hour)), 0x0304, "example.com", now); ok {
		t.Errorf("expired certificate should report validNow=false")
	}
	if _, ok := certDetail(mk(now.Add(time.Hour), now.Add(2*time.Hour)), 0x0304, "example.com", now); ok {
		t.Errorf("not-yet-valid certificate should report validNow=false")
	}
	d, _ := certDetail(mk(now.Add(-time.Hour), now.Add(48*time.Hour)), 0x0304, "example.com", now)
	if d["daysToExpiry"].(int) < 1 {
		t.Errorf("daysToExpiry should be positive: %v", d["daysToExpiry"])
	}
	if d["hostnameMatch"] != true || d["expiredOrNotYet"] != false {
		t.Errorf("unexpected detail: %+v", d)
	}
}
