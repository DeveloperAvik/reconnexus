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

func graphQLPolicy(ips ...string) scope.Policy {
	p := loginFinderPolicy(ips...)
	p.Authorization.Capabilities = []string{"ACTIVE_HTTP", "GRAPHQL_INTROSPECTION", "INTERNAL_NETWORK"}
	return p
}

func runGraphQL(t *testing.T, h http.HandlerFunc) ProviderResult {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	host, _, _ := net.SplitHostPort(srv.Listener.Addr().String())
	job := Job{
		SchemaVersion:            1,
		Kind:                     "GRAPHQL",
		Provider:                 "builtin-graphql",
		Inputs:                   Inputs{URLs: []string{srv.URL + "/graphql"}},
		Limits:                   scope.Limits{MaxConcurrency: 4, MaxArtifactBytes: 256 * 1024},
		RequestTimeoutMs:         2000,
		MaxRedirects:             2,
		AllowRestrictedAddresses: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := (builtinGraphQL{}).Run(ctx, ProviderContext{Job: job, Engine: restrictedEngine(graphQLPolicy(host))})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return res
}

func TestGraphQLIntrospectionEnabled(t *testing.T) {
	res := runGraphQL(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"subscriptionType":null,"types":[{"name":"Query","kind":"OBJECT"},{"name":"User","kind":"OBJECT"}]}}}`)
	})
	if len(res.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(res.Records))
	}
	info := res.Records[0].GraphQL
	if info.Status != GraphQLIntrospectionEnabled || info.QueryType != "Query" || info.MutationType != "Mutation" || info.TypeCount != 2 {
		t.Fatalf("info = %+v", info)
	}
}

func TestGraphQLIntrospectionDisabled(t *testing.T) {
	res := runGraphQL(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"errors":[{"message":"introspection is disabled"}]}`)
	})
	info := res.Records[0].GraphQL
	if info.Status != GraphQLIntrospectionDisabled {
		t.Fatalf("info = %+v", info)
	}
}

func TestGraphQLNotGraphQLWhenNotJSON(t *testing.T) {
	res := runGraphQL(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html>not graphql</html>`)
	})
	info := res.Records[0].GraphQL
	if info.Status != GraphQLNotGraphQL {
		t.Fatalf("info = %+v", info)
	}
}

func TestGraphQLNotGraphQLWhenJSONHasNeitherDataNorErrors(t *testing.T) {
	res := runGraphQL(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	info := res.Records[0].GraphQL
	if info.Status != GraphQLNotGraphQL {
		t.Fatalf("info = %+v", info)
	}
}

func TestGraphQLRequiresCapability(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	host, _, _ := net.SplitHostPort(srv.Listener.Addr().String())
	job := Job{
		SchemaVersion: 1,
		Kind:          "GRAPHQL",
		Provider:      "builtin-graphql",
		Inputs:        Inputs{URLs: []string{srv.URL + "/graphql"}},
		Limits:        scope.Limits{MaxConcurrency: 4, MaxArtifactBytes: 256 * 1024},
		Policy:        loginFinderPolicy(host), // ACTIVE_HTTP only, no GRAPHQL_INTROSPECTION
	}
	res, err := Run(context.Background(), job, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusBlocked {
		t.Fatalf("status = %s, want BLOCKED", res.Status)
	}
}

func TestGraphQLNoCandidatesIsSkipped(t *testing.T) {
	job := Job{
		SchemaVersion: 1,
		Kind:          "GRAPHQL",
		Provider:      "builtin-graphql",
		Inputs:        Inputs{},
		Limits:        scope.Limits{MaxConcurrency: 4, MaxArtifactBytes: 256 * 1024},
		Policy:        graphQLPolicy(),
	}
	res, err := (builtinGraphQL{}).Run(context.Background(), ProviderContext{Job: job, Engine: scope.NewEngine(&job.Policy)})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusOverride != StatusSkipped {
		t.Fatalf("StatusOverride = %s, want SKIPPED", res.StatusOverride)
	}
}
