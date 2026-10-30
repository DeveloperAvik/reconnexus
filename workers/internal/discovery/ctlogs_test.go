package discovery

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCTLogsDiscoversInScopeNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[
			{"common_name":"app.example.com","name_value":"app.example.com\napi.example.com"},
			{"common_name":"*.other.com","name_value":"*.other.com\nunrelated.org"}
		]`)
	}))
	defer srv.Close()

	job := Job{
		SchemaVersion: 1,
		Kind:          "SUBDOMAINS",
		Provider:      "builtin-ctlogs",
		Inputs:        Inputs{RootDomain: "example.com"},
		CtLogBaseURL:  srv.URL,
	}
	res, err := (builtinCTLogs{}).Run(context.Background(), ProviderContext{Job: job})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	hosts := map[string]bool{}
	for _, r := range res.Records {
		hosts[r.Host] = true
	}
	if !hosts["app.example.com"] || !hosts["api.example.com"] {
		t.Fatalf("expected app.example.com and api.example.com, got %+v", res.Records)
	}
	if hosts["other.com"] || hosts["unrelated.org"] {
		t.Fatalf("names outside the queried domain must be discarded, got %+v", res.Records)
	}
}

func TestCTLogsSourceUnavailableOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	job := Job{Kind: "SUBDOMAINS", Provider: "builtin-ctlogs", Inputs: Inputs{RootDomain: "example.com"}, CtLogBaseURL: srv.URL}
	res, err := (builtinCTLogs{}).Run(context.Background(), ProviderContext{Job: job})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusOverride != StatusSourceUnavailable {
		t.Fatalf("StatusOverride = %s, want SOURCE_UNAVAILABLE", res.StatusOverride)
	}
}

func TestCTLogsRequiresRootDomain(t *testing.T) {
	job := Job{Kind: "SUBDOMAINS", Provider: "builtin-ctlogs", Inputs: Inputs{}}
	res, err := (builtinCTLogs{}).Run(context.Background(), ProviderContext{Job: job})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusOverride != StatusFailed {
		t.Fatalf("StatusOverride = %s, want FAILED", res.StatusOverride)
	}
}
