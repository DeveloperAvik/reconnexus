// URL collection: shared constants and helpers (scope authorization, canonicalization, record
// construction, link/script extraction, external-tool normalisation). Provider implementations live
// in urlcollect_crawler.go, urlcollect_static.go, urlcollect_passive.go, urlcollect_katana.go and
// urlcollect_mock.go.

package discovery

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/reconnexus/workers/internal/matching"
	"github.com/reconnexus/workers/internal/scope"
)

const (
	defaultCrawlDepth     = 2
	defaultRequestBudget  = 500
	defaultCrawlTimeoutMs = 15000
	maxSitemaps           = 20
	maxStaticURLs         = 5000
)

// newGuardedClient builds an HTTP client whose DialContext enforces connection-bound scope and
// whose CheckRedirect reauthorizes every hop, reusing the Phase 3A transport.
func newGuardedClient(transport *http.Transport, engine *scope.Engine, timeout time.Duration, maxRedirects int) (*http.Client, *redirectRecorder) {
	rec := &redirectRecorder{max: maxRedirects}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: rec.checkRedirect(engine)}, rec
}

// authorizeURL canonicalizes a URL and checks it against the scope policy. Returns the canonical
// form, whether it is authorized, and whether it was malformed/unsupported.
func authorizeURL(engine *scope.Engine, capability, raw string) (canonical string, host string, authorized bool, malformed bool) {
	canon, err := matching.CanonicalURL(raw)
	if err != nil {
		return "", "", false, true
	}
	h, _, _ := matching.HostAndPort(canon)
	d := engine.Check(scope.Request{Kind: "URL", Value: canon, Capability: capability})
	return canon, h, d.Allowed, false
}

func buildURLRecord(raw, canonical, host, method, provider, source string, depth int, status *int) Record {
	classes, params := ClassifyURL(canonical)
	return Record{
		Type:            TypeURLObservation,
		URL:             raw,
		CanonicalURL:    canonical,
		Host:            host,
		Method:          method,
		Depth:           depth,
		StatusCode:      status,
		Source:          source,
		Provider:        provider,
		Classifications: classes,
		Parameters:      params,
	}
}

var linkAttrRe = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'#]+)`)

// scriptSrcRe matches the `src` attribute of a <script> tag. It is deliberately scoped to the
// script tag's src attribute: arbitrary inline script text is never treated as a URL.
var scriptSrcRe = regexp.MustCompile(`(?is)<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']`)

func hostOf(canonical string) string {
	h, _, _ := matching.HostAndPort(canonical)
	return h
}

// extractScriptRefs returns the absolute, deduplicated URLs referenced by <script src> attributes,
// resolved against the effective document URL (so relative, root-relative, protocol-relative and
// query-bearing references are all handled). Only the src attribute of a script tag is considered;
// inline script bodies are never parsed for URLs.
func extractScriptRefs(body string, base *url.URL) []string {
	if base == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, m := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
		raw := strings.TrimSpace(m[1])
		if raw == "" || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "blob:") {
			continue
		}
		ref, err := url.Parse(raw)
		if err != nil {
			continue
		}
		resolved := base.ResolveReference(ref)
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			continue
		}
		s := resolved.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func extractLinks(body string, base *url.URL) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, m := range linkAttrRe.FindAllStringSubmatch(body, -1) {
		raw := strings.TrimSpace(m[1])
		if raw == "" || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "tel:") || strings.HasPrefix(raw, "data:") {
			continue
		}
		ref, err := url.Parse(raw)
		if err != nil {
			continue
		}
		resolved := base.ResolveReference(ref)
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			continue
		}
		s := resolved.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// parseURLPlaceholders extracts plain URLs, one per line (gau, waybackurls).
func parseURLPlaceholders(stdout string) ([]Record, []string) {
	var records []Record
	var diagnostics []string
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		canon, err := matching.CanonicalURL(line)
		if err != nil {
			diagnostics = append(diagnostics, "malformed URL discarded: "+truncate(line, 80))
			continue
		}
		records = append(records, Record{Type: "URL_PLACEHOLDER", URL: line, CanonicalURL: canon})
	}
	return records, diagnostics
}

// filterExternal converts placeholder records into scope-checked, classified URL observations.
func filterExternal(ctx context.Context, pc ProviderContext, pr ProviderResult, provider, capability, method string) ProviderResult {
	var out []Record
	seen := map[string]struct{}{}
	skipped := 0
	for _, r := range pr.Records {
		if ctx.Err() != nil {
			break
		}
		if r.CanonicalURL == "" {
			continue
		}
		if _, dup := seen[r.CanonicalURL]; dup {
			continue
		}
		seen[r.CanonicalURL] = struct{}{}
		h, _, _ := matching.HostAndPort(r.CanonicalURL)
		d := pc.Engine.Check(scope.Request{Kind: "URL", Value: r.CanonicalURL, Capability: capability})
		if !d.Allowed {
			skipped++
			continue
		}
		out = append(out, buildURLRecord(r.URL, r.CanonicalURL, h, method, provider, strings.ToLower(method), 0, nil))
	}
	pr.Records = out
	pr.Coverage.Skipped += skipped
	return pr
}

func canonicalizeForRecord(raw string) (string, string, bool) {
	canon, err := matching.CanonicalURL(raw)
	if err != nil {
		return "", "", true
	}
	h, _, _ := matching.HostAndPort(canon)
	return canon, h, false
}

func stringKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
