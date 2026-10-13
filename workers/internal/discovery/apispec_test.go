package discovery

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reconnexus/workers/internal/scope"
)

func apiJob(urls []string, opts ...func(*Job)) Job {
	j := Job{
		SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "08", JobKey: "08",
		Kind: "API_SPEC", Provider: "builtin-api", Policy: jsPolicy(),
		Limits: scope.Limits{MaxConcurrency: 4, RequestsPerSecond: 20, CrawlDepth: 1, MaxRuntimeSeconds: 60, MaxArtifactBytes: 1 << 20},
		Inputs: Inputs{SpecURLs: urls},
	}
	for _, o := range opts {
		o(&j)
	}
	return j
}

const openapi3JSON = `{
  "openapi": "3.0.0",
  "info": { "title": "Test API" },
  "servers": [ { "url": "https://example.com/api" } ],
  "components": {
    "securitySchemes": { "bearerAuth": { "type": "http", "scheme": "bearer" } },
    "parameters": { "PageParam": { "name": "page", "in": "query", "required": false, "schema": { "type": "integer" } } }
  },
  "paths": {
    "/users": {
      "get": {
        "operationId": "listUsers",
        "tags": ["users"],
        "parameters": [
          { "name": "q", "in": "query", "required": false, "schema": { "type": "string" } },
          { "$ref": "#/components/parameters/PageParam" },
          { "$ref": "https://remote.example/schema.json#/nope" }
        ],
        "responses": { "200": { "content": { "application/json": {} } } }
      },
      "post": {
        "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "name": {"type":"string"}, "email": {"type":"string"} } } } } },
        "responses": { "201": {} }
      }
    },
    "/users/{id}": {
      "get": {
        "parameters": [ { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "responses": { "200": {} }
      }
    }
  }
}`

const swagger2YAML = `swagger: "2.0"
info:
  title: Yaml API
host: example.com
basePath: /v2
schemes: [https]
securityDefinitions:
  apiKey:
    type: apiKey
    name: X-Key
    in: header
paths:
  /pets:
    get:
      parameters:
        - name: limit
          in: query
          type: integer
      responses:
        "200": {}
`

func specRecord(res Result) *ApiSpecInfo {
	for _, r := range res.Records {
		if r.Type == TypeApiSpec {
			return r.ApiSpec
		}
	}
	return nil
}

func TestApiSpecOpenAPI3JSON(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, openapi3JSON)
		case "/bad.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, "{ this is not json or yaml : :")
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})

	res, _ := Run(context.Background(), apiJob([]string{srv.URL + "/openapi.json", srv.URL + "/bad.json"}), nil)
	info := specRecord(res)
	// Two spec records (one per URL); find the parsed one.
	for _, r := range res.Records {
		if r.Type == TypeApiSpec && r.ApiSpec.ParseStatus == "PARSED" {
			info = r.ApiSpec
		}
	}
	if info == nil || info.ParseStatus != "PARSED" {
		t.Fatalf("expected a PARSED spec, got %+v", info)
	}
	if info.SpecVersion != "openapi:3.0.0" || info.Title != "Test API" {
		t.Errorf("bad spec meta: %+v", info)
	}
	if info.PathCount != 2 || info.OperationCount != 3 {
		t.Errorf("pathCount=%d operationCount=%d", info.PathCount, info.OperationCount)
	}
	if len(info.SecuritySchemes) != 1 || info.SecuritySchemes[0] != "bearerAuth" {
		t.Errorf("securitySchemes=%v", info.SecuritySchemes)
	}
	if info.UnresolvedRefs < 1 {
		t.Errorf("expected an unresolved remote $ref, got %d", info.UnresolvedRefs)
	}

	eps := endpointsOf(res)
	get := findEndpoint(eps, "GET", "/api/users")
	if get == nil {
		t.Fatalf("missing GET /api/users; got %v", epList(eps))
	}
	if get.OperationID != "listUsers" || !get.Documented {
		t.Errorf("bad GET /users: %+v", get)
	}
	if !hasParam(get.Parameters, "page", "query") || !hasParam(get.Parameters, "q", "query") {
		t.Errorf("missing query params on GET /users: %+v", get.Parameters)
	}
	post := findEndpoint(eps, "POST", "/api/users")
	if post == nil || !hasParam(post.Parameters, "name", "body") {
		t.Errorf("expected body param 'name' on POST /users: %+v", post)
	}
	idEp := findEndpoint(eps, "GET", "/api/users/{id}")
	if idEp == nil || !hasParamRequired(idEp.Parameters, "id", "path") {
		t.Errorf("expected required path param id: %+v", idEp)
	}

	// Malformed spec must be reported, not silently dropped.
	var malformed bool
	for _, r := range res.Records {
		if r.Type == TypeApiSpec && r.ApiSpec.ParseStatus == "MALFORMED" {
			malformed = true
		}
	}
	if !malformed {
		t.Errorf("expected MALFORMED for bad.json")
	}
}

func TestApiSpecSwagger2YAML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		fmt.Fprint(w, swagger2YAML)
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), apiJob([]string{srv.URL + "/swagger.yaml"}), nil)
	info := specRecord(res)
	if info == nil || info.ParseStatus != "PARSED" || info.Format != "YAML" {
		t.Fatalf("bad yaml spec: %+v", info)
	}
	if info.SpecVersion != "swagger:2.0" || info.Title != "Yaml API" {
		t.Errorf("bad meta: %+v", info)
	}
	eps := endpointsOf(res)
	get := findEndpoint(eps, "GET", "/v2/pets")
	if get == nil || !hasParam(get.Parameters, "limit", "query") {
		t.Fatalf("expected GET /v2/pets with limit param; got %v", epList(eps))
	}
	if len(info.SecuritySchemes) != 1 || info.SecuritySchemes[0] != "apiKey" {
		t.Errorf("securitySchemes=%v", info.SecuritySchemes)
	}
}

func TestApiSpecOutOfScopeServerDropped(t *testing.T) {
	spec := `{"openapi":"3.0.0","info":{"title":"x"},"servers":[{"url":"https://evil.other.net/api"}],"paths":{"/x":{"get":{"responses":{"200":{}}}}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, spec)
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), apiJob([]string{srv.URL + "/openapi.json"}), nil)
	for _, e := range endpointsOf(res) {
		if strings.Contains(e.Origin, "evil.other.net") {
			t.Fatalf("out-of-scope server endpoint leaked: %+v", e)
		}
	}
	if res.Coverage.Skipped < 1 {
		t.Errorf("expected out-of-scope endpoint to be skipped")
	}
}

func TestApiSpecNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), apiJob([]string{srv.URL + "/openapi.json"}), nil)
	info := specRecord(res)
	if info == nil || info.ParseStatus != "NOT_FOUND" {
		t.Fatalf("expected NOT_FOUND, got %+v", info)
	}
}

func hasParam(params []ApiParameter, name, loc string) bool {
	for _, p := range params {
		if p.Name == name && p.Location == loc {
			return true
		}
	}
	return false
}

func hasParamRequired(params []ApiParameter, name, loc string) bool {
	for _, p := range params {
		if p.Name == name && p.Location == loc && p.Required {
			return true
		}
	}
	return false
}

// A speculative well-known path becomes a record only when a specification is actually served.
// Everything else is coverage: a definitive "nothing here" is a completed check, and an origin
// that refuses to answer costs no coverage because nothing referenced the path to begin with.
func TestApiSpecWellKnownProbes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(openapi3JSON))
		case "/swagger.json":
			// A single-page app answers every path with its shell.
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<!doctype html><html><body>app</body></html>"))
		case "/api/openapi.json":
			// Structured, but not a specification.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"region":"us","featureFlags":{"a":true}}`))
		case "/api-docs":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})

	probes := []string{
		srv.URL + "/openapi.json",
		srv.URL + "/swagger.json",
		srv.URL + "/api/openapi.json",
		srv.URL + "/api-docs",
		srv.URL + "/v3/api-docs",
	}
	res, err := Run(context.Background(), apiJob(nil, func(j *Job) { j.Inputs.SpecProbeURLs = probes }), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != StatusSucceeded {
		t.Fatalf("status = %s (diagnostics %v)", res.Status, res.Diagnostics)
	}
	// Found 1 (openapi.json), absent 3 (html shell, non-spec json, 404), undetermined 1 (403).
	if res.Coverage.Succeeded != 4 || res.Coverage.Skipped != 1 || res.Coverage.Failed != 0 {
		t.Errorf("coverage = %+v; want succeeded=4 skipped=1 failed=0", res.Coverage)
	}
	specs := 0
	for _, r := range res.Records {
		if r.Type != TypeApiSpec {
			continue
		}
		specs++
		if r.ApiSpec.URL != srv.URL+"/openapi.json" {
			t.Errorf("unexpected specification record for %s (%s)", r.ApiSpec.URL, r.ApiSpec.ParseStatus)
		}
		if r.ApiSpec.ParseStatus != "PARSED" {
			t.Errorf("parseStatus = %s, want PARSED", r.ApiSpec.ParseStatus)
		}
	}
	if specs != 1 {
		t.Errorf("got %d specification record(s), want 1 — a probe that finds nothing must not create one", specs)
	}
	if !strings.Contains(strings.Join(res.Diagnostics, "\n"), "1 found, 3 absent, 1 could not be checked") {
		t.Errorf("diagnostics do not summarize the probe outcome: %v", res.Diagnostics)
	}
}

// A referenced specification URL that serves something else is still recorded: something pointed
// at it, so its absence is evidence.
func TestApiSpecReferencedUrlServingHtmlIsRecorded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html><html></html>"))
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})

	res, _ := Run(context.Background(), apiJob([]string{srv.URL + "/openapi.json"}), nil)
	info := specRecord(res)
	if info == nil || info.ParseStatus != "NOT_FOUND" {
		t.Fatalf("expected a NOT_FOUND record, got %+v", info)
	}
	if !strings.Contains(info.Error, "not an API specification") {
		t.Errorf("error = %q; want it to say the response is not a specification", info.Error)
	}
	if res.Coverage.Succeeded != 1 || res.Coverage.Failed != 0 {
		t.Errorf("coverage = %+v; a definitive answer is not a failure", res.Coverage)
	}
}
