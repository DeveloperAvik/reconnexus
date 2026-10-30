package discovery

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWaybackDiffFindsUnobservedArchivedPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[
			["timestamp","original","statuscode","mimetype"],
			["20180512000000","https://example.com/old-admin/","200","text/html"],
			["20190101000000","https://example.com/current-page","200","text/html"],
			["20150101000000","https://example.com/gone-404","404","text/html"]
		]`)
	}))
	defer srv.Close()

	job := Job{
		Kind: "WAYBACK_DIFF", Provider: "builtin-wayback-diff",
		Inputs:         Inputs{RootDomain: "example.com", URLs: []string{"https://example.com/current-page?x=1"}},
		WaybackAPIBase: srv.URL,
	}
	res, err := (builtinWaybackDiff{}).Run(context.Background(), ProviderContext{Job: job})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 {
		t.Fatalf("expected exactly 1 diffed record, got %d: %+v", len(res.Records), res.Records)
	}
	if res.Records[0].URL != "https://example.com/old-admin/" {
		t.Fatalf("record = %+v", res.Records[0])
	}
}

func TestWaybackDiffSourceUnavailableOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	job := Job{Kind: "WAYBACK_DIFF", Provider: "builtin-wayback-diff", Inputs: Inputs{RootDomain: "example.com"}, WaybackAPIBase: srv.URL}
	res, err := (builtinWaybackDiff{}).Run(context.Background(), ProviderContext{Job: job})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusOverride != StatusSourceUnavailable {
		t.Fatalf("StatusOverride = %s, want SOURCE_UNAVAILABLE", res.StatusOverride)
	}
}

func TestWaybackDiffRequiresRootDomain(t *testing.T) {
	job := Job{Kind: "WAYBACK_DIFF", Provider: "builtin-wayback-diff", Inputs: Inputs{}}
	res, err := (builtinWaybackDiff{}).Run(context.Background(), ProviderContext{Job: job})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusOverride != StatusFailed {
		t.Fatalf("StatusOverride = %s, want FAILED", res.StatusOverride)
	}
}
