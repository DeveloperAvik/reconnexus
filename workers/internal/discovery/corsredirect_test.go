package discovery

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reconnexus/workers/internal/scope"
)

func corsRedirectPolicy(ips ...string) scope.Policy {
	p := loginFinderPolicy(ips...)
	p.Authorization.Capabilities = []string{"ACTIVE_HTTP", "CORS_REDIRECT_CHECK", "INTERNAL_NETWORK"}
	return p
}

func runCorsCheck(t *testing.T, h http.HandlerFunc) ProviderResult {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	host, _, _ := net.SplitHostPort(srv.Listener.Addr().String())
	job := Job{
		SchemaVersion:            1,
		Kind:                     "CORS_REDIRECT",
		Provider:                 "builtin-cors-redirect",
		Inputs:                   Inputs{URLs: []string{srv.URL + "/"}},
		Limits:                   scope.Limits{MaxConcurrency: 4, MaxArtifactBytes: 256 * 1024},
		RequestTimeoutMs:         2000,
		MaxRedirects:             2,
		AllowRestrictedAddresses: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := (builtinCorsRedirect{}).Run(ctx, ProviderContext{Job: job, Engine: restrictedEngine(corsRedirectPolicy(host))})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return res
}

func runRedirectCheck(t *testing.T, pathAndQuery, parameter string, h http.HandlerFunc) ProviderResult {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	host, _, _ := net.SplitHostPort(srv.Listener.Addr().String())
	job := Job{
		SchemaVersion:            1,
		Kind:                     "CORS_REDIRECT",
		Provider:                 "builtin-cors-redirect",
		Inputs:                   Inputs{RedirectCandidates: []RedirectCandidate{{URL: srv.URL + pathAndQuery, Parameter: parameter}}},
		Limits:                   scope.Limits{MaxConcurrency: 4, MaxArtifactBytes: 256 * 1024},
		RequestTimeoutMs:         2000,
		MaxRedirects:             2,
		AllowRestrictedAddresses: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := (builtinCorsRedirect{}).Run(ctx, ProviderContext{Job: job, Engine: restrictedEngine(corsRedirectPolicy(host))})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return res
}

func TestCorsReflectsArbitraryOriginWithCredentials(t *testing.T) {
	res := runCorsCheck(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	})
	if len(res.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(res.Records))
	}
	info := res.Records[0].Cors
	if info.Status != CorsReflectsArbitraryOriginWithCredentials || info.Confidence < 0.8 {
		t.Fatalf("info = %+v", info)
	}
}

func TestCorsReflectsArbitraryOriginWithoutCredentials(t *testing.T) {
	res := runCorsCheck(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	})
	info := res.Records[0].Cors
	if info.Status != CorsReflectsArbitraryOrigin || info.AllowCredentials {
		t.Fatalf("info = %+v", info)
	}
}

func TestCorsNotVulnerableWhenNotReflected(t *testing.T) {
	res := runCorsCheck(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example.com")
	})
	info := res.Records[0].Cors
	if info.Status != CorsNotVulnerable {
		t.Fatalf("info = %+v", info)
	}
}

func TestOpenRedirectConfirmed(t *testing.T) {
	res := runRedirectCheck(t, "/login?next=/dashboard", "next", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", r.URL.Query().Get("next"))
		w.WriteHeader(http.StatusFound)
	})
	if len(res.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(res.Records))
	}
	info := res.Records[0].OpenRedirect
	if info.Status != RedirectConfirmed || info.Confidence < 0.8 {
		t.Fatalf("info = %+v", info)
	}
}

func TestOpenRedirectNotVulnerableWhenLocationDiffers(t *testing.T) {
	res := runRedirectCheck(t, "/login?next=/dashboard", "next", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/home")
		w.WriteHeader(http.StatusFound)
	})
	info := res.Records[0].OpenRedirect
	if info.Status != RedirectNotVulnerable {
		t.Fatalf("info = %+v", info)
	}
}

func TestOpenRedirectNotVulnerableWhenNoRedirectOccurs(t *testing.T) {
	res := runRedirectCheck(t, "/login?next=/dashboard", "next", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	info := res.Records[0].OpenRedirect
	if info.Status != RedirectNotVulnerable || info.EvidenceType != "NO_REDIRECT" {
		t.Fatalf("info = %+v", info)
	}
}

func TestCorsRedirectRequiresCapability(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	host, _, _ := net.SplitHostPort(srv.Listener.Addr().String())
	job := Job{
		SchemaVersion: 1,
		Kind:          "CORS_REDIRECT",
		Provider:      "builtin-cors-redirect",
		Inputs:        Inputs{URLs: []string{srv.URL + "/"}},
		Limits:        scope.Limits{MaxConcurrency: 4, MaxArtifactBytes: 256 * 1024},
		Policy:        loginFinderPolicy(host), // ACTIVE_HTTP only, no CORS_REDIRECT_CHECK
	}
	res, err := Run(context.Background(), job, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusBlocked {
		t.Fatalf("status = %s, want BLOCKED", res.Status)
	}
}

func TestCorsRedirectNoCandidatesIsSkipped(t *testing.T) {
	job := Job{
		SchemaVersion: 1,
		Kind:          "CORS_REDIRECT",
		Provider:      "builtin-cors-redirect",
		Inputs:        Inputs{},
		Limits:        scope.Limits{MaxConcurrency: 4, MaxArtifactBytes: 256 * 1024},
		Policy:        corsRedirectPolicy(),
	}
	res, err := (builtinCorsRedirect{}).Run(context.Background(), ProviderContext{Job: job, Engine: scope.NewEngine(&job.Policy)})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusOverride != StatusSkipped {
		t.Fatalf("StatusOverride = %s, want SKIPPED", res.StatusOverride)
	}
}
