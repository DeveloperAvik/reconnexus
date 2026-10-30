package discovery

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reconnexus/workers/internal/scope"
)

func cloudStoragePolicy(ips ...string) scope.Policy {
	p := loginFinderPolicy(ips...)
	p.Authorization.Capabilities = []string{"ACTIVE_HTTP", "CLOUD_STORAGE_CHECK", "INTERNAL_NETWORK"}
	return p
}

func cloudStorageJob(origin string) Job {
	return Job{
		SchemaVersion:            1,
		Kind:                     "CLOUD_STORAGE",
		Provider:                 "builtin-cloud-storage",
		Inputs:                   Inputs{CloudCandidates: []CloudStorageCandidate{{URL: origin, Provider: CloudProviderS3, Bucket: "static-example"}}},
		Limits:                   scope.Limits{MaxConcurrency: 4, MaxArtifactBytes: 256 * 1024},
		RequestTimeoutMs:         2000,
		MaxRedirects:             2,
		AllowRestrictedAddresses: true,
	}
}

func runCloudStorage(t *testing.T, h http.HandlerFunc) ProviderResult {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	host, _, _ := net.SplitHostPort(srv.Listener.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := (builtinCloudStorage{}).Run(ctx, ProviderContext{Job: cloudStorageJob(srv.URL + "/"), Engine: restrictedEngine(cloudStoragePolicy(host))})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return res
}

func TestCloudStorageListableBucket(t *testing.T) {
	res := runCloudStorage(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, `<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>static-example</Name><Contents><Key>a.txt</Key></Contents><Contents><Key>b.txt</Key></Contents></ListBucketResult>`)
	})
	if len(res.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(res.Records))
	}
	info := res.Records[0].CloudStorage
	if info.Status != CloudStorageListable || info.ObjectCount != 2 || info.Confidence < 0.8 {
		t.Fatalf("info = %+v", info)
	}
}

func TestCloudStorageAccessDeniedIsNotAFinding(t *testing.T) {
	res := runCloudStorage(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`)
	})
	info := res.Records[0].CloudStorage
	if info.Status != CloudStorageNotListable || info.EvidenceType != "ACCESS_DENIED" {
		t.Fatalf("info = %+v", info)
	}
}

func TestCloudStorageNoSuchBucketIsInconclusiveNotExposure(t *testing.T) {
	res := runCloudStorage(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `<Error><Code>NoSuchBucket</Code></Error>`)
	})
	info := res.Records[0].CloudStorage
	if info.Status != CloudStorageInconclusive {
		t.Fatalf("info = %+v, want INCONCLUSIVE (this is a takeover question, not exposure)", info)
	}
}

func TestCloudStorageUnrecognizedResponseNeverClaimsListable(t *testing.T) {
	res := runCloudStorage(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><body>some CDN error page, not S3</body></html>`)
	})
	info := res.Records[0].CloudStorage
	if info.Status == CloudStorageListable {
		t.Fatalf("an unrelated 200 page must never be classified as a public bucket: %+v", info)
	}
	if info.Status != CloudStorageInconclusive {
		t.Fatalf("info = %+v", info)
	}
}

func TestCloudStorageRequiresCapability(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	host, _, _ := net.SplitHostPort(srv.Listener.Addr().String())
	job := cloudStorageJob(srv.URL + "/")
	job.Policy = loginFinderPolicy(host) // ACTIVE_HTTP only, no CLOUD_STORAGE_CHECK
	res, err := Run(context.Background(), job, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusBlocked {
		t.Fatalf("status = %s, want BLOCKED", res.Status)
	}
}

func TestCloudStorageNoCandidatesIsSkipped(t *testing.T) {
	job := cloudStorageJob("http://example.invalid/")
	job.Inputs.CloudCandidates = nil
	job.Policy = cloudStoragePolicy()
	res, err := (builtinCloudStorage{}).Run(context.Background(), ProviderContext{Job: job, Engine: scope.NewEngine(&job.Policy)})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusOverride != StatusSkipped {
		t.Fatalf("StatusOverride = %s, want SKIPPED", res.StatusOverride)
	}
}
