package discovery

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func withGithubToken(t *testing.T, token string) {
	t.Helper()
	old, had := os.LookupEnv(githubTokenEnv)
	if token == "" {
		_ = os.Unsetenv(githubTokenEnv)
	} else {
		_ = os.Setenv(githubTokenEnv, token)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(githubTokenEnv, old)
		} else {
			_ = os.Unsetenv(githubTokenEnv)
		}
	})
}

func TestGithubLeaksSourceUnavailableWithoutToken(t *testing.T) {
	withGithubToken(t, "")
	job := Job{Kind: "GITHUB_LEAK_SEARCH", Provider: "builtin-github-leaks", Inputs: Inputs{RootDomain: "example.com"}}
	res, err := (builtinGithubLeaks{}).Run(context.Background(), ProviderContext{Job: job})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusOverride != StatusSourceUnavailable {
		t.Fatalf("StatusOverride = %s, want SOURCE_UNAVAILABLE", res.StatusOverride)
	}
}

func TestGithubLeaksParsesMatchesAndRedacts(t *testing.T) {
	withGithubToken(t, "test-token")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "token test-token" {
			t.Fatalf("missing/incorrect Authorization header: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"items":[{"path":"config.yml","sha":"abc123","html_url":"https://github.com/org/repo/blob/main/config.yml","score":1.0,"repository":{"full_name":"org/repo"},"text_matches":[{"fragment":"host: example.com\napi_key: AKIAABCDEFGHIJKLMNOP"}]}]}`)
	}))
	defer srv.Close()

	job := Job{Kind: "GITHUB_LEAK_SEARCH", Provider: "builtin-github-leaks", Inputs: Inputs{RootDomain: "example.com"}, GithubAPIBase: srv.URL}
	res, err := (builtinGithubLeaks{}).Run(context.Background(), ProviderContext{Job: job})
	if err != nil {
		t.Fatal(err)
	}
	var matchRec *Record
	var secretRecs int
	for i := range res.Records {
		if res.Records[i].Type == TypeGithubCodeMatch {
			matchRec = &res.Records[i]
		}
		if res.Records[i].Type == TypeSecretCandidate {
			secretRecs++
		}
	}
	if matchRec == nil {
		t.Fatalf("expected a GITHUB_CODE_MATCH record, got %+v", res.Records)
	}
	if matchRec.GithubMatch.Repository != "org/repo" || matchRec.GithubMatch.Path != "config.yml" {
		t.Fatalf("info = %+v", matchRec.GithubMatch)
	}
	if secretRecs == 0 {
		t.Fatalf("expected the AWS-key-shaped fragment to also produce a SECRET_CANDIDATE record, got %+v", res.Records)
	}
}

func TestGithubLeaksRequiresRootDomain(t *testing.T) {
	withGithubToken(t, "test-token")
	job := Job{Kind: "GITHUB_LEAK_SEARCH", Provider: "builtin-github-leaks", Inputs: Inputs{}}
	res, err := (builtinGithubLeaks{}).Run(context.Background(), ProviderContext{Job: job})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusOverride != StatusFailed {
		t.Fatalf("StatusOverride = %s, want FAILED", res.StatusOverride)
	}
}
