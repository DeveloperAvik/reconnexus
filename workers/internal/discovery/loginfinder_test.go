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

func loginFinderPolicy(ips ...string) scope.Policy {
	return scope.Policy{
		SchemaVersion: 1,
		Authorization: scope.Authorization{
			Reference:    "test",
			AuthorizedBy: "test",
			ValidFrom:    time.Now().Add(-time.Hour).UTC(),
			ValidUntil:   time.Now().Add(time.Hour).UTC(),
			Capabilities: []string{"ACTIVE_HTTP"},
		},
		InScope: scope.InScope{IPs: ips},
		Limits:  scope.Limits{MaxConcurrency: 4, RequestsPerSecond: 0, MaxArtifactBytes: 256 * 1024},
	}
}

func loginFinderJob(origin string) Job {
	return Job{
		SchemaVersion:    1,
		Kind:             "LOGIN_FINDER",
		Provider:         "builtin-login-finder",
		Inputs:           Inputs{URLs: []string{origin}},
		Limits:           scope.Limits{MaxConcurrency: 4, MaxArtifactBytes: 256 * 1024},
		RequestTimeoutMs: 2000,
		MaxRedirects:     2,
	}
}

func policyPtr(p scope.Policy) *scope.Policy { return &p }

func TestLoginFinderDetectsAdminAndCpanel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/login":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<html><head><title>Admin Login</title></head><body><form><input type="text" name="user"><input type="password" name="password"></form></body></html>`)
		case "/wp-login.php":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<html><head><title>Log In</title></head><body><form id="loginform"><input name="log"><input type="password" name="pwd"><input type="submit" value="Log In"></form><input type="hidden" name="wp-submit"></body></html>`)
		case "/cpanel":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<html><head><title>cPanel Login</title></head><body><form><input type="password" name="pass"></form></body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	host, _, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pc := ProviderContext{
		Job:    loginFinderJob(srv.URL + "/"),
		Engine: scope.NewEngine(policyPtr(loginFinderPolicy(host))),
	}
	res, err := (builtinLoginFinder{}).Run(context.Background(), pc)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	var admin, cpanel int
	for _, rec := range res.Records {
		if rec.Type != TypeLoginInterface || rec.Login == nil {
			continue
		}
		switch rec.Login.Kind {
		case LoginKindAdmin:
			admin++
		case LoginKindCpanel:
			cpanel++
		default:
			t.Fatalf("unexpected kind %q", rec.Login.Kind)
		}
		if rec.Login.Status != LoginDetected {
			t.Fatalf("expected DETECTED for %s, got %s (%s)", rec.URL, rec.Login.Status, rec.Login.Evidence)
		}
	}
	if admin < 2 {
		t.Fatalf("expected at least 2 admin interfaces, got %d", admin)
	}
	if cpanel != 1 {
		t.Fatalf("expected 1 cPanel interface, got %d", cpanel)
	}
}

func TestLoginFinderIgnoresGenericPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><head><title>Welcome</title></head><body>Nothing to see here.</body></html>`)
	}))
	defer srv.Close()

	host, _, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pc := ProviderContext{
		Job:    loginFinderJob(srv.URL + "/"),
		Engine: scope.NewEngine(policyPtr(loginFinderPolicy(host))),
	}
	res, err := (builtinLoginFinder{}).Run(context.Background(), pc)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.Records) != 0 {
		t.Fatalf("generic pages must not be reported, got %d record(s)", len(res.Records))
	}
}

func TestLoginFinderHonorsPathExclusions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/login" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<html><head><title>Admin Login</title></head><body><input type="password"></body></html>`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	host, _, _ := net.SplitHostPort(srv.Listener.Addr().String())
	policy := loginFinderPolicy(host)
	policy.Exclusions.Paths = []string{"/admin"}
	pc := ProviderContext{Job: loginFinderJob(srv.URL + "/"), Engine: scope.NewEngine(&policy)}
	res, err := (builtinLoginFinder{}).Run(context.Background(), pc)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, rec := range res.Records {
		if rec.Login != nil && rec.Login.Kind == LoginKindAdmin {
			t.Fatalf("admin path should have been excluded, got %s", rec.URL)
		}
	}
}
