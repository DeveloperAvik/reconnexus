package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/reconnexus/workers/internal/telemetry"
	"gopkg.in/yaml.v3"
)

// builtinAPIProvider retrieves and parses OpenAPI/Swagger specifications. Local $ref targets are
// resolved with recursion/cycle limits; remote $ref targets are never fetched automatically.
type builtinAPIProvider struct{}

func (builtinAPIProvider) Name() string            { return "builtin-api" }
func (builtinAPIProvider) Kind() string            { return "API_SPEC" }
func (builtinAPIProvider) Capability() string      { return "API_DISCOVERY" }
func (builtinAPIProvider) NetworkBehavior() string { return "ACTIVE" }

const (
	maxSpecBytes    = 4 * 1024 * 1024
	maxSpecEndpoint = 2000
	maxRefDepth     = 20
)

var httpMethods = []string{"get", "post", "put", "patch", "delete", "head", "options", "trace"}

func (builtinAPIProvider) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{Coverage: Coverage{}}
	// Referenced specifications and speculative well-known paths are both retrieved, but an
	// absent speculative path is recorded as coverage only: nothing pointed at it, so it is not
	// evidence of anything and must not enter the asset graph.
	targets := make([]specTarget, 0, len(job.Inputs.SpecURLs)+len(job.Inputs.SpecProbeURLs))
	for _, u := range job.Inputs.SpecURLs {
		targets = append(targets, specTarget{url: u})
	}
	for _, u := range job.Inputs.SpecProbeURLs {
		targets = append(targets, specTarget{url: u, probe: true})
	}
	if len(targets) == 0 {
		res.StatusOverride = StatusSkipped
		res.Diagnostics = append(res.Diagnostics, "no API specification URLs to parse")
		return res, nil
	}
	res.Coverage.Attempted = len(targets)
	timeout := time.Duration(job.RequestTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = defaultCrawlTimeoutMs * time.Millisecond
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
	var diagnostics []string
	var wg sync.WaitGroup
	var probed, absent, found, undetermined int
	sem := make(chan struct{}, 8)
	for _, target := range targets {
		target := target
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			client, _ := newGuardedClient(transport, pc.Engine, timeout, job.MaxRedirects)
			recs, diag, outcome, skipped := parseOneSpec(ctx, client, pc, target.url)
			mu.Lock()
			defer mu.Unlock()
			res.Coverage.Skipped += skipped
			if target.probe {
				probed++
			}
			switch outcome {
			case specFound:
				found++
				res.Coverage.Succeeded++
			case specAbsent:
				// A definitive "nothing here" is a completed check, not a collection failure.
				absent++
				res.Coverage.Succeeded++
			default:
				undetermined++
				if target.probe {
					// Nothing referenced this path and the origin refused to say (401/403/5xx),
					// so no coverage was promised and none was lost.
					res.Coverage.Skipped++
				} else {
					// Something pointed at this URL and it could not be retrieved.
					res.Coverage.Failed++
				}
			}
			// A speculative path becomes a record only when a specification is actually there.
			if !target.probe || outcome == specFound {
				records = append(records, recs...)
				diagnostics = append(diagnostics, diag...)
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		res.StatusOverride = StatusCancelled
	}
	if probed > 0 {
		res.Diagnostics = append(res.Diagnostics, fmt.Sprintf("checked %d well-known specification path(s): %d found, %d absent, %d could not be checked", probed, found, absent, undetermined))
	}
	res.Records = records
	res.Diagnostics = append(res.Diagnostics, diagnostics...)
	return res, nil
}

// specTarget is one specification URL to retrieve. A probe target was never referenced by
// anything; it is a well-known path checked on an origin that shows evidence of an API.
type specTarget struct {
	url   string
	probe bool
}

// specOutcome records whether a specification was retrieved, definitively absent, or could not
// be checked.
type specOutcome int

const (
	specFailed specOutcome = iota
	specFound
	specAbsent
)

func parseOneSpec(ctx context.Context, client *http.Client, pc ProviderContext, raw string) ([]Record, []string, specOutcome, int) {
	var out []Record
	info := ApiSpecInfo{URL: raw, Format: "UNKNOWN"}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		info.ParseStatus = "ERROR"
		info.Error = err.Error()
		return []Record{{Type: TypeApiSpec, URL: raw, Provider: "builtin-api", Source: "spec", ApiSpec: &info}}, nil, specFailed, 0
	}
	req.Header.Set("User-Agent", "reconnexus/0.5 (+https://github.com/anomalyco/opencode)")
	req.Header.Set("Accept", "application/json, application/yaml, text/yaml, */*")
	resp, derr := client.Do(req)
	if derr != nil {
		info.ParseStatus = "ERROR"
		info.Error = telemetry.RedactString(derr.Error())
		return []Record{{Type: TypeApiSpec, URL: raw, Provider: "builtin-api", Source: "spec", ApiSpec: &info}}, []string{"spec fetch failed: " + truncate(derr.Error(), 120)}, specFailed, 0
	}
	defer resp.Body.Close()
	record := func() []Record {
		return []Record{{Type: TypeApiSpec, URL: raw, Provider: "builtin-api", Source: "spec", ApiSpec: &info}}
	}
	// A path that answers 404/405/410 definitively has no specification. 401/403 and 5xx mean the
	// question could not be answered, which is a failure rather than an absence.
	switch resp.StatusCode {
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusGone:
		info.ParseStatus = "NOT_FOUND"
		info.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return record(), nil, specAbsent, 0
	}
	if resp.StatusCode >= 400 {
		info.ParseStatus = "ERROR"
		info.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return record(), nil, specFailed, 0
	}
	body, _, _ := readBounded(resp.Body, maxSpecBytes)

	contentType := resp.Header.Get("Content-Type")
	doc, format, perr := decodeSpec(body, contentType)
	info.Format = format
	if perr != nil {
		// A body that is not structured data at all is not a broken specification — it is some
		// other resource (an SPA's catch-all HTML, typically). Only a document that was served as
		// JSON or YAML can be called malformed.
		if !looksStructured(body, contentType) {
			info.ParseStatus = "NOT_FOUND"
			info.Error = "response is not an API specification" + describeContentType(contentType)
			return record(), nil, specAbsent, 0
		}
		info.ParseStatus = "MALFORMED"
		info.Error = telemetry.RedactString(perr.Error())
		return record(), []string{"malformed spec " + truncate(raw, 80) + ": " + truncate(perr.Error(), 120)}, specFailed, 0
	}
	// Structured data that never declares itself an OpenAPI/Swagger document (a config blob, an
	// API's own JSON response) is not a specification.
	if !isSpecDocument(doc) {
		info.ParseStatus = "NOT_FOUND"
		info.Error = "response is not an API specification" + describeContentType(contentType)
		return record(), nil, specAbsent, 0
	}

	endpoints, meta := extractSpec(doc, raw)
	info.SpecVersion = meta.version
	info.Title = meta.title
	info.Servers = meta.servers
	info.PathCount = meta.pathCount
	info.OperationCount = meta.operationCount
	info.SecuritySchemes = meta.securitySchemes
	info.UnresolvedRefs = meta.unresolvedRefs
	info.ParseStatus = "PARSED"

	out = append(out, Record{Type: TypeApiSpec, URL: raw, Provider: "builtin-api", Source: "spec", ApiSpec: &info})
	for i := range endpoints {
		endpoints[i].Endpoint.SourceURL = raw
	}
	kept, skipped := filterEndpointRecords(pc.Engine, endpoints, "API_DISCOVERY")
	out = append(out, kept...)
	return out, nil, specFound, skipped
}

// isSpecDocument reports whether a decoded document declares itself an OpenAPI or Swagger
// specification. A `paths` mapping alone is accepted because some servers omit the version key.
func isSpecDocument(doc map[string]any) bool {
	if _, ok := doc["openapi"]; ok {
		return true
	}
	if _, ok := doc["swagger"]; ok {
		return true
	}
	if paths, ok := doc["paths"].(map[string]any); ok && len(paths) > 0 {
		return true
	}
	return false
}

// looksStructured reports whether the response was served as — or plausibly is — JSON or YAML.
// An HTML page is not, so a decode failure on one means "no specification here" rather than
// "broken specification".
func looksStructured(body, contentType string) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "html") || strings.Contains(ct, "xml") {
		return false
	}
	if strings.Contains(ct, "json") || strings.Contains(ct, "yaml") || strings.Contains(ct, "yml") {
		return true
	}
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "<") {
		return false
	}
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

// describeContentType renders a content type for a diagnostic, without its parameters.
func describeContentType(contentType string) string {
	ct := strings.TrimSpace(strings.Split(contentType, ";")[0])
	if ct == "" {
		return ""
	}
	return " (" + ct + ")"
}

func decodeSpec(body, contentType string) (map[string]any, string, error) {
	trimmed := strings.TrimSpace(body)
	ct := strings.ToLower(contentType)
	// Try JSON first for JSON content types or when the body clearly looks like JSON.
	if strings.Contains(ct, "json") || strings.HasPrefix(trimmed, "{") {
		var doc map[string]any
		if err := json.Unmarshal([]byte(trimmed), &doc); err == nil {
			return doc, "JSON", nil
		}
	}
	var rawAny any
	if err := yaml.Unmarshal([]byte(trimmed), &rawAny); err != nil {
		// Retry JSON as a fallback.
		var doc map[string]any
		if jerr := json.Unmarshal([]byte(trimmed), &doc); jerr == nil {
			return doc, "JSON", nil
		}
		return nil, "UNKNOWN", err
	}
	doc := asStringMap(rawAny)
	if doc == nil {
		return nil, "UNKNOWN", fmt.Errorf("spec root is not a mapping")
	}
	format := "YAML"
	if strings.Contains(ct, "json") {
		format = "JSON"
	}
	return doc, format, nil
}

func asStringMap(v any) map[string]any {
	switch m := v.(type) {
	case map[string]any:
		return m
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[fmt.Sprint(k)] = val
		}
		return out
	default:
		return nil
	}
}

type specMeta struct {
	version         string
	title           string
	servers         []string
	pathCount       int
	operationCount  int
	securitySchemes []string
	unresolvedRefs  int
}

func extractSpec(doc map[string]any, specURL string) ([]Record, specMeta) {
	var meta specMeta
	if v, ok := doc["openapi"].(string); ok {
		meta.version = "openapi:" + v
	} else if v, ok := doc["swagger"].(string); ok {
		meta.version = "swagger:" + v
	}
	if info := asStringMap(doc["info"]); info != nil {
		if t, ok := info["title"].(string); ok {
			meta.title = t
		}
	}

	var origins []string
	if servers, ok := doc["servers"].([]any); ok {
		for _, s := range servers {
			if sm := asStringMap(s); sm != nil {
				if u, ok := sm["url"].(string); ok && u != "" {
					meta.servers = append(meta.servers, u)
					if o := originOfURL(u); o != "" {
						origins = append(origins, o)
					}
				}
			}
		}
	}
	// Swagger 2.0 host/basePath/schemes.
	if sw := asStringMap(doc); sw != nil {
		host, _ := doc["host"].(string)
		basePath, _ := doc["basePath"].(string)
		if host != "" {
			scheme := "https"
			if schemes, ok := doc["schemes"].([]any); ok && len(schemes) > 0 {
				if s, ok := schemes[0].(string); ok {
					scheme = s
				}
			}
			full := scheme + "://" + host + basePath
			meta.servers = append(meta.servers, full)
			if o := originOfURL(full); o != "" {
				origins = append(origins, o)
			}
		}
	}
	specOrigin := originOfURL(specURL)
	if specOrigin != "" {
		origins = append(origins, specOrigin)
	}
	origin := ""
	basePath := ""
	if len(origins) > 0 {
		origin = origins[0]
	}
	if len(meta.servers) > 0 {
		if u, err := url.Parse(meta.servers[0]); err == nil {
			basePath = strings.TrimRight(u.EscapedPath(), "/")
		}
	}

	for _, key := range []string{"components", "securityDefinitions"} {
		if comp := asStringMap(doc[key]); comp != nil {
			section := comp
			if sub := asStringMap(comp["securitySchemes"]); sub != nil {
				section = sub
			}
			for name := range section {
				meta.securitySchemes = append(meta.securitySchemes, name)
			}
		}
	}

	paths := asStringMap(doc["paths"])
	if paths == nil {
		return nil, meta
	}
	meta.pathCount = len(paths)

	var out []Record
	seen := map[string]struct{}{}
	for _, p := range sortedKeys(paths) {
		item := asStringMap(paths[p])
		if item == nil {
			continue
		}
		pathParams := extractParams(doc, item["parameters"], &meta)
		for _, method := range httpMethods {
			op := asStringMap(item[method])
			if op == nil {
				continue
			}
			meta.operationCount++
			params := append([]ApiParameter{}, pathParams...)
			params = append(params, extractParams(doc, op["parameters"], &meta)...)
			fullPath := joinURLPath(basePath, p)
			ep := ApiEndpoint{
				Method:        strings.ToUpper(method),
				Origin:        origin,
				Path:          fullPath,
				DiscoveredVia: ViaSpec,
				Documented:    true,
				Resolved:      true,
				Parameters:    params,
				AuthSchemes:   meta.securitySchemes,
				Evidence:      "declared in " + truncate(specURL, 120),
				EvidenceType:  "OPENAPI",
			}
			if origin != "" {
				ep.URL = origin + fullPath
			}
			if v, ok := op["operationId"].(string); ok {
				ep.OperationID = v
			}
			if tags, ok := op["tags"].([]any); ok {
				for _, t := range tags {
					if s, ok := t.(string); ok {
						ep.Tags = append(ep.Tags, s)
					}
				}
			}
			if rb := asStringMap(op["requestBody"]); rb != nil {
				if content := asStringMap(rb["content"]); content != nil {
					for _, ct := range sortedKeys(content) {
						ep.ContentTypes = append(ep.ContentTypes, ct)
						if media := asStringMap(content[ct]); media != nil {
							ep.Parameters = append(ep.Parameters, extractSchemaParams(doc, media["schema"], "body")...)
						}
					}
				}
			}
			if responses := asStringMap(op["responses"]); responses != nil {
				for _, code := range sortedKeys(responses) {
					if r := asStringMap(responses[code]); r != nil {
						if content := asStringMap(r["content"]); content != nil {
							for _, ct := range sortedKeys(content) {
								ep.ContentTypes = appendUnique(ep.ContentTypes, ct)
							}
						}
					}
				}
			}
			ep.ContentTypes = dedupeStrings(ep.ContentTypes)
			k := ep.Method + " " + ep.Origin + " " + ep.Path
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, Record{Type: TypeApiEndpoint, URL: ep.URL, Provider: "builtin-api", Source: "spec", Endpoint: &ep})
			if len(out) >= maxSpecEndpoint {
				return out, meta
			}
		}
	}
	meta.securitySchemes = dedupeStrings(meta.securitySchemes)
	sort.Strings(meta.securitySchemes)
	return out, meta
}

func extractParams(doc map[string]any, raw any, meta *specMeta) []ApiParameter {
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	var out []ApiParameter
	for _, p := range list {
		pm := asStringMap(p)
		if pm == nil {
			continue
		}
		if ref, ok := pm["$ref"].(string); ok {
			resolved, ok := resolveLocalRef(doc, ref, 0, map[string]bool{})
			if !ok {
				meta.unresolvedRefs++
				continue
			}
			pm = resolved
		}
		name, _ := pm["name"].(string)
		if name == "" {
			continue
		}
		loc, _ := pm["in"].(string)
		required, _ := pm["required"].(bool)
		typ := ""
		if schema := asStringMap(pm["schema"]); schema != nil {
			if t, ok := schema["type"].(string); ok {
				typ = t
			}
		}
		if t, ok := pm["type"].(string); ok && typ == "" {
			typ = t
		}
		out = append(out, ApiParameter{Name: name, Location: normalizeParamLoc(loc), Required: required, Type: typ, Evidence: "spec parameter"})
	}
	return out
}

func extractSchemaParams(doc map[string]any, raw any, loc string) []ApiParameter {
	schema := asStringMap(raw)
	if schema == nil {
		return nil
	}
	if ref, ok := schema["$ref"].(string); ok {
		if resolved, ok := resolveLocalRef(doc, ref, 0, map[string]bool{}); ok {
			schema = resolved
		}
	}
	props := asStringMap(schema["properties"])
	if props == nil {
		return nil
	}
	var out []ApiParameter
	for _, name := range sortedKeys(props) {
		typ := ""
		if ps := asStringMap(props[name]); ps != nil {
			if t, ok := ps["type"].(string); ok {
				typ = t
			}
		}
		out = append(out, ApiParameter{Name: name, Location: loc, Type: typ, Evidence: "spec request body"})
	}
	return out
}

// resolveLocalRef resolves a local JSON pointer ("#/...") with depth/cycle limits.
func resolveLocalRef(doc map[string]any, ref string, depth int, seen map[string]bool) (map[string]any, bool) {
	if depth > maxRefDepth || !strings.HasPrefix(ref, "#/") {
		return nil, false
	}
	if seen[ref] {
		return nil, false
	}
	seen[ref] = true
	parts := strings.Split(strings.TrimPrefix(ref, "#/"), "/")
	var cur any = doc
	for _, part := range parts {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		m := asStringMap(cur)
		if m == nil {
			return nil, false
		}
		cur = m[part]
		if cur == nil {
			return nil, false
		}
	}
	return asStringMap(cur), true
}

func joinURLPath(base, p string) string {
	if base == "" {
		if p == "" {
			return "/"
		}
		if !strings.HasPrefix(p, "/") {
			return "/" + p
		}
		return p
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return base + p
}

func normalizeParamLoc(loc string) string {
	switch strings.ToLower(loc) {
	case "query", "path", "header", "cookie", "body":
		return strings.ToLower(loc)
	default:
		return "unknown"
	}
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func dedupeStrings(list []string) []string {
	seen := map[string]bool{}
	out := list[:0]
	for _, v := range list {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
