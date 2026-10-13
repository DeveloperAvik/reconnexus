package discovery

import (
	"net/url"
	"strings"
)

// ClassifyURL returns reconnaissance classifications and parameter roles for a canonical URL.
// These are context hints derived from the URL alone — never vulnerability findings. Multiple
// hypotheses may be returned when evidence is ambiguous, and generic routes receive low
// confidence rather than an overconfident label.
func ClassifyURL(canonical string) ([]UrlClassification, []UrlParameter) {
	u, err := url.Parse(canonical)
	if err != nil {
		return []UrlClassification{{Category: "UNKNOWN", Confidence: 0.2, EvidenceType: "PARSE", Evidence: "unparseable URL"}}, nil
	}
	path := strings.ToLower(u.EscapedPath())
	segs := segments(path)
	last := ""
	if len(segs) > 0 {
		last = segs[len(segs)-1]
	}
	ext := extension(last)

	var out []UrlClassification
	add := func(cat string, conf float64, evType, ev string) {
		out = append(out, UrlClassification{Category: cat, Confidence: conf, EvidenceType: evType, Evidence: ev})
	}
	containsSeg := func(name string) bool {
		for _, s := range segs {
			if s == name || strings.Contains(s, name) {
				return true
			}
		}
		return false
	}

	// Static assets / JavaScript.
	switch ext {
	case ".js", ".mjs":
		add("JAVASCRIPT", 0.9, "EXTENSION", "extension "+ext)
	case ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webm":
		add("STATIC_ASSET", 0.9, "EXTENSION", "extension "+ext)
	case ".pdf", ".zip", ".tar", ".gz", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx":
		add("DOWNLOAD", 0.7, "EXTENSION", "downloadable extension "+ext)
	}

	// API specification / GraphQL / docs / developer tooling.
	if strings.HasSuffix(last, "openapi.json") || strings.HasSuffix(last, "openapi.yaml") || strings.HasSuffix(last, "swagger.json") || strings.HasSuffix(last, "swagger.yaml") || containsSeg("swagger") || containsSeg("openapi") {
		add("API_SPEC", 0.85, "PATH", "API specification path")
	}
	if containsSeg("graphql") || containsSeg("graphiql") || strings.HasSuffix(path, "/graphql") {
		add("GRAPHQL", 0.8, "PATH", "graphql path segment")
	}
	if containsSeg("docs") || containsSeg("documentation") || containsSeg("wiki") || containsSeg("manual") || containsSeg("help") {
		add("DOCUMENTATION", 0.6, "PATH", "documentation path segment")
	}
	if containsSeg("console") || containsSeg("playground") || containsSeg("developer") || containsSeg("dev") {
		add("DEVELOPER", 0.55, "PATH", "developer endpoint segment")
	}

	// Administrative.
	if containsSeg("admin") || containsSeg("administrator") || containsSeg("manage") || containsSeg("dashboard") || containsSeg("cpanel") || containsSeg("wp-admin") || containsSeg("phpmyadmin") {
		add("ADMIN", 0.6, "PATH", "administrative path segment")
	}

	// Auth lifecycle.
	if containsSeg("login") || containsSeg("signin") || containsSeg("sign-in") || containsSeg("auth") || containsSeg("oauth") || containsSeg("sso") {
		add("AUTHENTICATION", 0.7, "PATH", "authentication path segment")
	}
	if containsSeg("register") || containsSeg("signup") || containsSeg("sign-up") {
		add("REGISTRATION", 0.7, "PATH", "registration path segment")
	}
	if containsSeg("forgot") || containsSeg("reset-password") || containsSeg("recover") || (containsSeg("password") && containsSeg("reset")) {
		add("PASSWORD_RECOVERY", 0.7, "PATH", "password-recovery path segment")
	}
	if containsSeg("logout") || containsSeg("signout") || containsSeg("session") {
		add("SESSION", 0.6, "PATH", "session path segment")
	}

	// Uploads / exports / downloads.
	if containsSeg("upload") || containsSeg("import") {
		add("UPLOAD", 0.6, "PATH", "upload/import path segment")
	}
	if containsSeg("download") || containsSeg("files") {
		add("DOWNLOAD", 0.6, "PATH", "download path segment")
	}
	if containsSeg("export") || containsSeg("report") || ext == ".csv" {
		add("EXPORT", 0.6, "PATH", "export path/extension")
	}
	if containsSeg("search") {
		add("SEARCH", 0.6, "PATH", "search path segment")
	}

	// API endpoint heuristics.
	if containsSeg("api") || containsSeg("rest") || containsSeg("graphql") || containsSeg("json") || versionSegment(segs) {
		add("API_ENDPOINT", 0.6, "PATH", "API-like path segment")
	}

	// Query-parameter driven classifications.
	params := parameters(u)
	paramNames := map[string]bool{}
	for _, p := range params {
		paramNames[p.Name] = true
	}
	if hasAny(paramNames, "q", "query", "s", "search", "keyword", "kw") {
		add("SEARCH", 0.7, "PARAMETER", "search-like query parameter")
	}
	if hasAny(paramNames, "page", "p", "offset", "limit", "per_page", "pagesize", "start", "count") {
		add("PAGINATION", 0.7, "PARAMETER", "pagination query parameter")
	}
	if hasAny(paramNames, "filter", "sort", "order", "category", "tag", "type", "status", "brand", "price", "color", "size") {
		add("FILTER", 0.6, "PARAMETER", "filter/sort query parameter")
	}
	if hasAny(paramNames, "redirect", "url", "next", "return", "returnurl", "returnto", "callback", "continue", "dest", "destination", "goto", "redir", "target") {
		add("REDIRECT", 0.5, "PARAMETER", "redirect-like query parameter (hint only; not a vulnerability claim)")
	}

	// Fallback.
	if len(out) == 0 {
		if ext == "" || ext == ".html" || ext == ".htm" || ext == ".php" || ext == ".asp" || ext == ".aspx" || ext == ".jsp" {
			add("HTML_PAGE", 0.4, "PATH", "no distinguishing markers")
		} else {
			add("UNKNOWN", 0.3, "PATH", "unrecognized resource")
		}
	}
	return out, params
}

func parameters(u *url.URL) []UrlParameter {
	q := u.Query()
	// Preserve query order by re-parsing the raw query (url.Values is a map).
	var names []string
	seen := map[string]bool{}
	for _, pair := range strings.Split(u.RawQuery, "&") {
		if pair == "" {
			continue
		}
		name := pair
		if i := strings.Index(pair, "="); i >= 0 {
			name = pair[:i]
		}
		if dec, err := url.QueryUnescape(name); err == nil {
			name = dec
		}
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	_ = q
	out := make([]UrlParameter, 0, len(names))
	for _, name := range names {
		out = append(out, UrlParameter{Name: name, Roles: parameterRoles(name)})
	}
	return out
}

func parameterRoles(name string) []UrlParamRole {
	l := strings.ToLower(name)
	var roles []UrlParamRole
	add := func(role string, conf float64) {
		roles = append(roles, UrlParamRole{Role: role, Confidence: conf, Evidence: "parameter name '" + name + "'"})
	}
	switch l {
	case "page", "p", "offset", "limit", "per_page", "pagesize", "start", "count":
		add("pagination", 0.7)
	case "q", "query", "s", "search", "keyword", "kw":
		add("search", 0.7)
	}
	if inSet(l, "filter", "sort", "order", "category", "tag", "type", "status", "brand", "price", "color", "size", "from", "to") {
		add("filter", 0.6)
	}
	if inSet(l, "id", "uid", "uuid", "user_id", "account", "pid", "gid", "no", "num") {
		add("identifier", 0.6)
	}
	if inSet(l, "redirect", "url", "next", "return", "returnurl", "returnto", "callback", "continue", "dest", "destination", "goto", "redir", "target") {
		add("redirect", 0.5)
	}
	if inSet(l, "file", "path", "filename", "filepath", "dir", "folder", "download", "upload", "doc", "document") {
		add("file_path", 0.6)
	}
	if inSet(l, "token", "access_token", "apikey", "api_key", "auth", "session", "sig", "signature") {
		add("auth_token", 0.6)
	}
	if len(roles) == 0 {
		add("unknown", 0.2)
	}
	return roles
}

func segments(path string) []string {
	parts := strings.Split(path, "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func extension(last string) string {
	i := strings.LastIndex(last, ".")
	if i < 0 || i == len(last)-1 {
		return ""
	}
	ext := last[i:]
	if len(ext) > 12 {
		return ""
	}
	return ext
}

func versionSegment(segs []string) bool {
	for _, s := range segs {
		if len(s) >= 2 && s[0] == 'v' {
			allDigits := true
			for _, r := range s[1:] {
				if r < '0' || r > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				return true
			}
		}
	}
	return false
}

func hasAny(set map[string]bool, names ...string) bool {
	for _, n := range names {
		if set[n] {
			return true
		}
	}
	return false
}

func inSet(v string, opts ...string) bool {
	for _, o := range opts {
		if v == o {
			return true
		}
	}
	return false
}
