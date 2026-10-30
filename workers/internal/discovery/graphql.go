package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/reconnexus/workers/internal/matching"
	"github.com/reconnexus/workers/internal/scope"
)

// builtinGraphQL sends a read-only GraphQL introspection query to a candidate endpoint and
// reports whether introspection is enabled. It never sends a mutation, and the only query used
// is the standard `__schema` introspection query (plus, when that succeeds, one follow-up query
// per discovered root type to count its top-level fields) — never an attempt to read or modify
// application data.
type builtinGraphQL struct{}

func (builtinGraphQL) Name() string            { return "builtin-graphql" }
func (builtinGraphQL) Kind() string            { return "GRAPHQL" }
func (builtinGraphQL) Capability() string      { return "GRAPHQL_INTROSPECTION" }
func (builtinGraphQL) NetworkBehavior() string { return "ACTIVE" }

const (
	GraphQLIntrospectionEnabled  = "INTROSPECTION_ENABLED"
	GraphQLIntrospectionDisabled = "INTROSPECTION_DISABLED"
	GraphQLNotGraphQL            = "NOT_GRAPHQL"
)

const (
	maxGraphQLCandidates = 30
	maxGraphQLBodyBytes  = 512 * 1024
)

const schemaIntrospectionQuery = `{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind } } }"}`

func (builtinGraphQL) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{Coverage: Coverage{}}
	candidates := job.Inputs.URLs
	if len(candidates) > maxGraphQLCandidates {
		candidates = candidates[:maxGraphQLCandidates]
	}
	if len(candidates) == 0 {
		res.StatusOverride = StatusSkipped
		res.Diagnostics = append(res.Diagnostics, "no GraphQL candidates to check")
		return res, nil
	}

	concurrency := job.Limits.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 4
	}
	if concurrency > 8 {
		concurrency = 8
	}
	timeout := time.Duration(job.RequestTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = time.Duration(defaultCrawlTimeoutMs) * time.Millisecond
	}
	transport, err := pc.buildTransport(job)
	if err != nil {
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "cannot build transport: "+err.Error())
		return res, nil
	}

	var mu sync.Mutex
	var records []Record
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for _, cand := range candidates {
		cand := cand
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			client, _ := newGuardedClient(transport, pc.Engine, timeout, job.MaxRedirects)
			rec, outcome := checkGraphQL(ctx, client, pc, cand)
			mu.Lock()
			defer mu.Unlock()
			res.Coverage.Attempted++
			switch outcome {
			case interfaceHit, interfaceMiss:
				res.Coverage.Succeeded++
			case interfaceSkipped:
				res.Coverage.Skipped++
			default:
				res.Coverage.Failed++
			}
			if rec != nil {
				records = append(records, *rec)
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		res.StatusOverride = StatusCancelled
	}
	res.Records = records
	if len(records) == 0 {
		res.Diagnostics = append(res.Diagnostics, "no candidate produced a classifiable response")
	}
	return res, nil
}

func checkGraphQL(ctx context.Context, client *http.Client, pc ProviderContext, candidate string) (*Record, interfaceResult) {
	canon, cerr := matching.CanonicalURL(strings.TrimSpace(candidate))
	if cerr != nil {
		return nil, interfaceSkipped
	}
	d := pc.Engine.Check(scope.Request{Kind: "URL", Value: canon, Capability: "GRAPHQL_INTROSPECTION"})
	if !d.Allowed {
		return nil, interfaceSkipped
	}
	parsedURL, perr := url.Parse(canon)
	if perr != nil || parsedURL.Hostname() == "" {
		return nil, interfaceSkipped
	}
	host := parsedURL.Hostname()

	status, body, ok := postGraphQL(ctx, client, pc, canon, schemaIntrospectionQuery)
	if !ok {
		return nil, interfaceFailed
	}

	info := classifyGraphQL(status, body)
	if info.Status == GraphQLIntrospectionEnabled {
		if info.QueryType != "" {
			info.QueryFieldCount = fetchFieldCount(ctx, client, pc, canon, info.QueryType)
		}
		if info.MutationType != "" {
			info.MutationFieldCount = fetchFieldCount(ctx, client, pc, canon, info.MutationType)
		}
	}
	return &Record{Type: TypeGraphQLSchema, URL: canon, Host: host, Provider: "builtin-graphql", Source: "graphql", GraphQL: info}, interfaceHit
}

func postGraphQL(ctx context.Context, client *http.Client, pc ProviderContext, url, jsonBody string) (int, string, bool) {
	req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(jsonBody))
	if rerr != nil {
		return 0, "", false
	}
	req.Header.Set("User-Agent", "reconnexus/0.20 (+https://github.com/anomalyco/opencode)")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, derr := doRequest(ctx, client, pc.Limiter, req)
	if derr != nil || resp == nil {
		return 0, "", false
	}
	defer resp.Body.Close()
	b, _, _ := readBounded(resp.Body, maxGraphQLBodyBytes)
	return resp.StatusCode, b, true
}

// classifyGraphQL never reports INTROSPECTION_ENABLED without a non-null `data.__schema` object:
// a generic JSON error page that happens to parse is not read as a schema disclosure.
func classifyGraphQL(status int, body string) *GraphQLInfo {
	info := &GraphQLInfo{HTTPStatus: &status}
	var parsed struct {
		Data struct {
			Schema *struct {
				QueryType        *struct{ Name string } `json:"queryType"`
				MutationType     *struct{ Name string } `json:"mutationType"`
				SubscriptionType *struct{ Name string } `json:"subscriptionType"`
				Types            []struct {
					Name string `json:"name"`
					Kind string `json:"kind"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		info.Status, info.Confidence = GraphQLNotGraphQL, 0.7
		info.EvidenceType, info.Evidence = "UNPARSEABLE_RESPONSE", "response is not valid JSON; does not look like a GraphQL endpoint"
		return info
	}
	if parsed.Data.Schema != nil {
		info.Status, info.Confidence = GraphQLIntrospectionEnabled, 0.95
		info.TypeCount = len(parsed.Data.Schema.Types)
		if parsed.Data.Schema.QueryType != nil {
			info.QueryType = parsed.Data.Schema.QueryType.Name
		}
		if parsed.Data.Schema.MutationType != nil {
			info.MutationType = parsed.Data.Schema.MutationType.Name
		}
		if parsed.Data.Schema.SubscriptionType != nil {
			info.SubscriptionType = parsed.Data.Schema.SubscriptionType.Name
		}
		info.EvidenceType = "SCHEMA_DISCLOSED"
		info.Evidence = "introspection query returned a non-null __schema object"
		return info
	}
	if len(parsed.Errors) > 0 {
		info.Status, info.Confidence = GraphQLIntrospectionDisabled, 0.85
		info.EvidenceType = "INTROSPECTION_REJECTED"
		info.Evidence = "GraphQL endpoint responded with an error for the introspection query: " + truncate(parsed.Errors[0].Message, 200)
		return info
	}
	info.Status, info.Confidence = GraphQLNotGraphQL, 0.5
	info.EvidenceType, info.Evidence = "NOT_GRAPHQL_SHAPE", "response is valid JSON but has neither a GraphQL 'data' nor 'errors' key"
	return info
}

func fetchFieldCount(ctx context.Context, client *http.Client, pc ProviderContext, url, typeName string) int {
	query := `{"query":"{ __type(name: \"` + strings.ReplaceAll(typeName, `"`, "") + `\") { fields { name } } }"}`
	status, body, ok := postGraphQL(ctx, client, pc, url, query)
	if !ok || status != http.StatusOK {
		return 0
	}
	var parsed struct {
		Data struct {
			Type *struct {
				Fields []struct{ Name string } `json:"fields"`
			} `json:"__type"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil || parsed.Data.Type == nil {
		return 0
	}
	return len(parsed.Data.Type.Fields)
}
