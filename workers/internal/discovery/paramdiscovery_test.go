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

func paramDiscoveryPolicy(ips ...string) scope.Policy {
	p := loginFinderPolicy(ips...)
	p.Authorization.Capabilities = []string{"ACTIVE_HTTP", "PARAMETER_DISCOVERY", "INTERNAL_NETWORK"}
	return p
}

func runParamDiscovery(t *testing.T, h http.HandlerFunc) ProviderResult {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	host, _, _ := net.SplitHostPort(srv.Listener.Addr().String())
	job := Job{
		SchemaVersion:            1,
		Kind:                     "PARAMETER_DISCOVERY",
		Provider:                 "builtin-param-discovery",
		Inputs:                   Inputs{URLs: []string{srv.URL + "/search"}},
		Limits:                   scope.Limits{MaxConcurrency: 1, MaxArtifactBytes: 256 * 1024},
		RequestTimeoutMs:         2000,
		MaxRedirects:             2,
		AllowRestrictedAddresses: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := (builtinParamDiscovery{}).Run(ctx, ProviderContext{Job: job, Engine: restrictedEngine(paramDiscoveryPolicy(host))})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return res
}

func TestParamDiscoveryReflectedValue(t *testing.T) {
	res := runParamDiscovery(t, func(w http.ResponseWriter, r *http.Request) {
		if v := r.URL.Query().Get("debug"); v != "" {
			_, _ = io.WriteString(w, "stable page body padding padding padding echo:"+v)
			return
		}
		_, _ = io.WriteString(w, "stable page body padding padding padding")
	})
	if len(res.Records) != 1 {
		t.Fatalf("expected exactly 1 discovered parameter, got %d: %+v", len(res.Records), res.Records)
	}
	info := res.Records[0].ParamDiscovery
	if info.Parameter != "debug" || info.EvidenceType != "REFLECTED_VALUE" {
		t.Fatalf("info = %+v", info)
	}
}

func TestParamDiscoveryStatusCodeChange(t *testing.T) {
	res := runParamDiscovery(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("admin") != "" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "stable page body padding padding padding")
			return
		}
		_, _ = io.WriteString(w, "stable page body padding padding padding")
	})
	found := false
	for _, r := range res.Records {
		if r.ParamDiscovery.Parameter == "admin" && r.ParamDiscovery.EvidenceType == "STATUS_CODE_CHANGE" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a STATUS_CODE_CHANGE record for 'admin', got %+v", res.Records)
	}
}

func TestParamDiscoveryNoDifferenceIsNotRecorded(t *testing.T) {
	res := runParamDiscovery(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "always exactly the same stable response body")
	})
	if len(res.Records) != 0 {
		t.Fatalf("expected no records when nothing differs, got %+v", res.Records)
	}
}

func TestParamDiscoverySkipsUnstableBaseline(t *testing.T) {
	n := 0
	res := runParamDiscovery(t, func(w http.ResponseWriter, r *http.Request) {
		n++
		// Each unmodified request returns a wildly different body length, so the calibration
		// baseline itself is unstable and no wordlist probing should occur.
		_, _ = io.WriteString(w, strings.Repeat("x", 10+n*500))
	})
	if len(res.Records) != 0 {
		t.Fatalf("expected no records when the baseline itself is unstable, got %+v", res.Records)
	}
	if res.Coverage.Skipped == 0 {
		t.Fatalf("expected the unstable candidate to be counted as skipped, coverage = %+v", res.Coverage)
	}
}

func TestParamDiscoveryRequiresCapability(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	host, _, _ := net.SplitHostPort(srv.Listener.Addr().String())
	job := Job{
		SchemaVersion: 1,
		Kind:          "PARAMETER_DISCOVERY",
		Provider:      "builtin-param-discovery",
		Inputs:        Inputs{URLs: []string{srv.URL + "/search"}},
		Limits:        scope.Limits{MaxConcurrency: 1, MaxArtifactBytes: 256 * 1024},
		Policy:        loginFinderPolicy(host), // ACTIVE_HTTP only, no PARAMETER_DISCOVERY
	}
	res, err := Run(context.Background(), job, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusBlocked {
		t.Fatalf("status = %s, want BLOCKED", res.Status)
	}
}

func TestParamDiscoveryNoCandidatesIsSkipped(t *testing.T) {
	job := Job{
		SchemaVersion: 1,
		Kind:          "PARAMETER_DISCOVERY",
		Provider:      "builtin-param-discovery",
		Inputs:        Inputs{},
		Limits:        scope.Limits{MaxConcurrency: 1, MaxArtifactBytes: 256 * 1024},
		Policy:        paramDiscoveryPolicy(),
	}
	res, err := (builtinParamDiscovery{}).Run(context.Background(), ProviderContext{Job: job, Engine: scope.NewEngine(&job.Policy)})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusOverride != StatusSkipped {
		t.Fatalf("StatusOverride = %s, want SKIPPED", res.StatusOverride)
	}
}
