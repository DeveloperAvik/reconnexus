package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/reconnexus/workers/internal/matching"
	"github.com/reconnexus/workers/internal/scope"
	"github.com/reconnexus/workers/internal/telemetry"
)

// builtinContent looks for exposed files, backups, debug endpoints and directory listings by
// requesting a curated, fixed path list on in-scope origins. It is read-only (unauthenticated GET
// only), every candidate is reauthorized against the scope policy, and every origin is calibrated
// with random missing paths first so wildcard routing and soft-404 pages are not reported as hits.
// Response bodies are inspected in memory for a marker and never persisted or echoed: evidence is
// the marker's name, so an exposed .env or dump does not leak into the evidence store.
type builtinContent struct{}

func (builtinContent) Name() string            { return "builtin-content" }
func (builtinContent) Kind() string            { return "CONTENT_DISCOVERY" }
func (builtinContent) Capability() string      { return "CONTENT_DISCOVERY" }
func (builtinContent) NetworkBehavior() string { return "ACTIVE" }

// Content categories.
const (
	ContentVCS      = "VCS"
	ContentConfig   = "CONFIG"
	ContentBackup   = "BACKUP"
	ContentDebug    = "DEBUG"
	ContentLog      = "LOG"
	ContentListing  = "DIRECTORY_LISTING"
	ContentMetadata = "METADATA"
)

// Content statuses. CONFIRMED means the response body carried the path's content marker; POSSIBLE
// means the path answered differently from a missing path but no marker was found (or none exists).
const (
	ContentConfirmed = "CONFIRMED"
	ContentPossible  = "POSSIBLE"
)

const (
	maxContentOrigins    = 100
	maxContentBodyBytes  = 64 * 1024
	contentCalibrations  = 3
	maxContentTitleChars = 120
)

type contentPath struct {
	path     string
	category string
	// severity is the impact if the exposure is real; inventory-only hits are INFO.
	severity string
	// marker, when set, must appear in the body for the hit to be CONFIRMED.
	marker string
	// markerName is the human-readable evidence recorded instead of any body text.
	markerName string
	// markerRe is an alternative to marker for content that needs line structure to be credible.
	markerRe *regexp.Regexp
	// dir marks paths that are directories (a redirect to path+"/" is a hit).
	dir bool
}

// contentPaths is deliberately short and high-signal. Entries with a marker are confirmed by
// content; entries without one can only ever be POSSIBLE. Nothing here submits data or relies on
// a payload: these are the paths a browser would request.
var contentPaths = []contentPath{
	// Version control
	{path: "/.git/HEAD", category: ContentVCS, severity: "HIGH", marker: "ref:", markerName: "git HEAD reference"},
	{path: "/.git/config", category: ContentVCS, severity: "HIGH", marker: "[core]", markerName: "git config section"},
	{path: "/.svn/entries", category: ContentVCS, severity: "HIGH"},
	{path: "/.svn/wc.db", category: ContentVCS, severity: "HIGH", marker: "SQLite format", markerName: "SQLite header"},
	{path: "/.hg/hgrc", category: ContentVCS, severity: "HIGH", marker: "[paths]", markerName: "mercurial paths section"},
	{path: "/.bzr/branch-format", category: ContentVCS, severity: "MEDIUM", marker: "Bazaar", markerName: "bazaar branch format"},
	// Environment and configuration
	{path: "/.env", category: ContentConfig, severity: "HIGH", markerRe: envLineRe, markerName: "KEY=value lines"},
	{path: "/.env.local", category: ContentConfig, severity: "HIGH", markerRe: envLineRe, markerName: "KEY=value lines"},
	{path: "/.env.production", category: ContentConfig, severity: "HIGH", markerRe: envLineRe, markerName: "KEY=value lines"},
	{path: "/.env.backup", category: ContentConfig, severity: "HIGH", markerRe: envLineRe, markerName: "KEY=value lines"},
	{path: "/.htpasswd", category: ContentConfig, severity: "HIGH", marker: ":$", markerName: "password hash entry"},
	{path: "/.htaccess", category: ContentConfig, severity: "LOW", marker: "RewriteEngine", markerName: "rewrite rules"},
	{path: "/web.config", category: ContentConfig, severity: "MEDIUM", marker: "<configuration", markerName: "web.config root element"},
	{path: "/appsettings.json", category: ContentConfig, severity: "HIGH", marker: "ConnectionStrings", markerName: "ASP.NET connection strings"},
	{path: "/config.json", category: ContentConfig, severity: "MEDIUM"},
	{path: "/config.yml", category: ContentConfig, severity: "MEDIUM"},
	{path: "/wp-config.php.bak", category: ContentConfig, severity: "HIGH", marker: "DB_PASSWORD", markerName: "WordPress DB_PASSWORD"},
	{path: "/wp-config.php~", category: ContentConfig, severity: "HIGH", marker: "DB_PASSWORD", markerName: "WordPress DB_PASSWORD"},
	{path: "/config.php.bak", category: ContentConfig, severity: "HIGH"},
	{path: "/configuration.php.bak", category: ContentConfig, severity: "HIGH"},
	{path: "/docker-compose.yml", category: ContentConfig, severity: "MEDIUM", marker: "services:", markerName: "compose services block"},
	{path: "/Dockerfile", category: ContentConfig, severity: "LOW", marker: "FROM ", markerName: "Dockerfile FROM instruction"},
	{path: "/.npmrc", category: ContentConfig, severity: "HIGH", marker: "_auth", markerName: "npm auth setting"},
	{path: "/.dockercfg", category: ContentConfig, severity: "HIGH"},
	{path: "/.aws/credentials", category: ContentConfig, severity: "HIGH", marker: "aws_access_key_id", markerName: "AWS credentials profile"},
	{path: "/id_rsa", category: ContentConfig, severity: "HIGH", marker: "PRIVATE KEY", markerName: "private key header"},
	{path: "/composer.json", category: ContentMetadata, severity: "INFO", marker: "\"require\"", markerName: "composer requirements"},
	{path: "/package.json", category: ContentMetadata, severity: "INFO", marker: "\"dependencies\"", markerName: "npm dependencies"},
	{path: "/.DS_Store", category: ContentMetadata, severity: "LOW", marker: "Bud1", markerName: "DS_Store header"},
	// Backups and database dumps
	{path: "/backup.zip", category: ContentBackup, severity: "HIGH", marker: "PK\x03\x04", markerName: "zip archive header"},
	{path: "/backup.tar.gz", category: ContentBackup, severity: "HIGH", marker: "\x1f\x8b", markerName: "gzip header"},
	{path: "/backup.sql", category: ContentBackup, severity: "HIGH", marker: "CREATE TABLE", markerName: "SQL dump"},
	{path: "/db.sql", category: ContentBackup, severity: "HIGH", marker: "CREATE TABLE", markerName: "SQL dump"},
	{path: "/dump.sql", category: ContentBackup, severity: "HIGH", marker: "CREATE TABLE", markerName: "SQL dump"},
	{path: "/database.sql", category: ContentBackup, severity: "HIGH", marker: "CREATE TABLE", markerName: "SQL dump"},
	{path: "/site.zip", category: ContentBackup, severity: "HIGH", marker: "PK\x03\x04", markerName: "zip archive header"},
	{path: "/www.zip", category: ContentBackup, severity: "HIGH", marker: "PK\x03\x04", markerName: "zip archive header"},
	{path: "/public_html.zip", category: ContentBackup, severity: "HIGH", marker: "PK\x03\x04", markerName: "zip archive header"},
	{path: "/backup/", category: ContentBackup, severity: "MEDIUM", dir: true},
	{path: "/backups/", category: ContentBackup, severity: "MEDIUM", dir: true},
	// Debug and framework endpoints
	{path: "/phpinfo.php", category: ContentDebug, severity: "MEDIUM", marker: "PHP Version", markerName: "phpinfo output"},
	{path: "/info.php", category: ContentDebug, severity: "MEDIUM", marker: "PHP Version", markerName: "phpinfo output"},
	{path: "/server-status", category: ContentDebug, severity: "MEDIUM", marker: "Apache Server Status", markerName: "Apache server-status"},
	{path: "/server-info", category: ContentDebug, severity: "MEDIUM", marker: "Apache Server Information", markerName: "Apache server-info"},
	{path: "/nginx_status", category: ContentDebug, severity: "LOW", marker: "Active connections", markerName: "nginx stub_status"},
	{path: "/actuator", category: ContentDebug, severity: "MEDIUM", marker: "_links", markerName: "Spring actuator links"},
	{path: "/actuator/env", category: ContentDebug, severity: "HIGH", marker: "propertySources", markerName: "Spring actuator env"},
	{path: "/actuator/heapdump", category: ContentDebug, severity: "HIGH"},
	{path: "/actuator/health", category: ContentDebug, severity: "INFO", marker: "\"status\"", markerName: "Spring actuator health"},
	{path: "/env", category: ContentDebug, severity: "HIGH", marker: "propertySources", markerName: "Spring env endpoint"},
	{path: "/heapdump", category: ContentDebug, severity: "HIGH"},
	{path: "/jolokia", category: ContentDebug, severity: "HIGH", marker: "\"agent\"", markerName: "Jolokia agent"},
	{path: "/_profiler/", category: ContentDebug, severity: "MEDIUM", marker: "Symfony", markerName: "Symfony profiler"},
	{path: "/_debugbar/open", category: ContentDebug, severity: "MEDIUM"},
	{path: "/telescope", category: ContentDebug, severity: "MEDIUM", marker: "Laravel Telescope", markerName: "Laravel Telescope"},
	{path: "/elmah.axd", category: ContentDebug, severity: "MEDIUM", marker: "Error Log", markerName: "ELMAH error log"},
	{path: "/trace.axd", category: ContentDebug, severity: "MEDIUM", marker: "Application Trace", markerName: "ASP.NET trace"},
	{path: "/__debug__/", category: ContentDebug, severity: "MEDIUM"},
	{path: "/debug/default/view", category: ContentDebug, severity: "MEDIUM"},
	{path: "/console", category: ContentDebug, severity: "HIGH", marker: "Werkzeug", markerName: "Werkzeug debug console"},
	{path: "/debug/pprof/", category: ContentDebug, severity: "MEDIUM", marker: "goroutine", markerName: "Go pprof index"},
	{path: "/metrics", category: ContentDebug, severity: "LOW", marker: "# HELP", markerName: "Prometheus metrics"},
	{path: "/.well-known/security.txt", category: ContentMetadata, severity: "INFO", marker: "Contact:", markerName: "security.txt contact"},
	{path: "/crossdomain.xml", category: ContentMetadata, severity: "INFO", marker: "cross-domain-policy", markerName: "crossdomain policy"},
	// Logs
	{path: "/error_log", category: ContentLog, severity: "MEDIUM"},
	{path: "/error.log", category: ContentLog, severity: "MEDIUM"},
	{path: "/debug.log", category: ContentLog, severity: "MEDIUM"},
	{path: "/npm-debug.log", category: ContentLog, severity: "LOW", marker: "verbose", markerName: "npm debug log"},
	{path: "/storage/logs/laravel.log", category: ContentLog, severity: "MEDIUM", marker: "local.ERROR", markerName: "Laravel log entry"},
	{path: "/logs/", category: ContentLog, severity: "MEDIUM", dir: true},
	// Common listable directories
	{path: "/uploads/", category: ContentListing, severity: "LOW", dir: true},
	{path: "/files/", category: ContentListing, severity: "LOW", dir: true},
	{path: "/old/", category: ContentListing, severity: "LOW", dir: true},
	{path: "/tmp/", category: ContentListing, severity: "MEDIUM", dir: true},
	{path: "/test/", category: ContentListing, severity: "LOW", dir: true},
	{path: "/.git/", category: ContentVCS, severity: "MEDIUM", dir: true},
}

var envLineRe = regexp.MustCompile(`(?m)^[A-Za-z_][A-Za-z0-9_]*=`)

// htmlExpected lists the paths whose real content is an HTML page.
var htmlExpected = map[string]bool{
	"/phpinfo.php": true, "/info.php": true, "/server-status": true, "/server-info": true,
	"/_profiler/": true, "/telescope": true, "/elmah.axd": true, "/trace.axd": true,
	"/console": true, "/__debug__/": true, "/debug/default/view": true,
}

var directoryListingRe = regexp.MustCompile(`(?i)<title>\s*index of /|<h1>\s*index of /|directory listing for /|<pre>\s*<a href="\?c=n;o=d">`)

// contentSignature summarizes a response well enough to tell a real resource from the server's
// answer for a path that does not exist.
type contentSignature struct {
	status   int
	length   int
	bodyHash string
	location string
}

type contentCandidate struct {
	origin string
	entry  contentPath
	url    string
}

// calibration is the per-origin set of responses for random missing paths.
type calibration struct {
	sigs []contentSignature
}

func (c calibration) matches(sig contentSignature) bool {
	for _, k := range c.sigs {
		if k.status != sig.status {
			continue
		}
		if k.bodyHash == sig.bodyHash {
			return true
		}
		// Same status and a similar size is the soft-404 / wildcard-route pattern even when the
		// body embeds the request path.
		if k.length > 0 && absInt(k.length-sig.length)*20 <= k.length+20 {
			return true
		}
		if k.status >= 300 && k.status < 400 && k.location != "" && k.location == sig.location {
			return true
		}
	}
	return false
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func (builtinContent) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{Coverage: Coverage{}}
	origins := uniqueOrigins(job.Inputs.URLs)
	if len(origins) == 0 {
		res.StatusOverride = StatusSkipped
		res.Diagnostics = append(res.Diagnostics, "no origins to check for exposed content")
		return res, nil
	}
	if len(origins) > maxContentOrigins {
		origins = origins[:maxContentOrigins]
	}

	concurrency := job.Limits.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 4
	}
	if concurrency > 16 {
		concurrency = 16
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
	seen := map[string]struct{}{}
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for _, origin := range origins {
		origin := origin
		if ctx.Err() != nil {
			break
		}
		client, _ := newGuardedClient(transport, pc.Engine, timeout, job.MaxRedirects)
		// A redirect to another place is evidence in itself (a directory redirect, a login bounce),
		// so redirects are inspected, not followed.
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

		cal, ok := calibrateOrigin(ctx, client, pc, origin)
		if !ok {
			mu.Lock()
			res.Coverage.Attempted++
			res.Coverage.Failed++
			res.Diagnostics = append(res.Diagnostics, "calibration failed (origin unreachable or out of scope): "+origin)
			mu.Unlock()
			continue
		}

		for _, entry := range contentPaths {
			entry := entry
			if ctx.Err() != nil {
				break
			}
			cand := contentCandidate{origin: origin, entry: entry, url: strings.TrimRight(origin, "/") + entry.path}
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				rec, outcome := checkContent(ctx, client, pc, cal, cand)
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
					if _, dup := seen[rec.URL]; !dup {
						seen[rec.URL] = struct{}{}
						records = append(records, *rec)
					}
				}
			}()
		}
	}
	wg.Wait()
	if ctx.Err() != nil {
		res.StatusOverride = StatusCancelled
	}
	res.Records = records
	if len(records) == 0 {
		res.Diagnostics = append(res.Diagnostics, fmt.Sprintf("no exposed content found across %d origin(s); the path list is short and fixed, so this is not proof of absence", len(origins)))
	}
	return res, nil
}

func uniqueOrigins(raw []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, r := range raw {
		u, err := url.Parse(strings.TrimSpace(r))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			continue
		}
		o := u.Scheme + "://" + u.Host
		if _, dup := seen[o]; dup {
			continue
		}
		seen[o] = struct{}{}
		out = append(out, o)
	}
	return out
}

func fetchSignature(ctx context.Context, client *http.Client, pc ProviderContext, target string, wantBody bool) (contentSignature, string, http.Header, error) {
	canon, err := matching.CanonicalURL(target)
	if err != nil {
		return contentSignature{}, "", nil, err
	}
	d := pc.Engine.Check(scope.Request{Kind: "URL", Value: canon, Capability: "CONTENT_DISCOVERY"})
	if !d.Allowed {
		return contentSignature{}, "", nil, errOutOfScope
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, canon, nil)
	if err != nil {
		return contentSignature{}, "", nil, err
	}
	req.Header.Set("User-Agent", "reconnexus/0.20 (+https://github.com/anomalyco/opencode)")
	req.Header.Set("Accept", "*/*")
	resp, err := doRequest(ctx, client, pc.Limiter, req)
	if err != nil || resp == nil {
		if err == nil {
			err = fmt.Errorf("no response")
		}
		return contentSignature{}, "", nil, err
	}
	defer resp.Body.Close()
	body, _, _ := readBounded(resp.Body, maxContentBodyBytes)
	sum := sha256.Sum256([]byte(body))
	sig := contentSignature{status: resp.StatusCode, length: len(body), bodyHash: hex.EncodeToString(sum[:8]), location: normalizeLocation(resp.Header.Get("Location"), canon)}
	return sig, body, resp.Header, nil
}

var errOutOfScope = fmt.Errorf("out of scope")

// normalizeLocation reduces a Location header to a comparable form: the path component only, so a
// "/<random>" -> "/login" bounce compares equal across probes.
func normalizeLocation(loc, base string) string {
	if loc == "" {
		return ""
	}
	b, err := url.Parse(base)
	if err != nil {
		return loc
	}
	l, err := b.Parse(loc)
	if err != nil {
		return loc
	}
	return l.Host + l.Path
}

// calibrateOrigin requests random, certainly-missing paths and records how the origin answers.
// Calibration is a requirement: without it a wildcard host would flood the stage with false hits.
func calibrateOrigin(ctx context.Context, client *http.Client, pc ProviderContext, origin string) (calibration, bool) {
	var cal calibration
	for i := 0; i < contentCalibrations; i++ {
		name := "rn-" + strconv.FormatInt(time.Now().UnixNano()+int64(i*7919), 36)
		paths := []string{"/" + name, "/" + name + "/", "/" + name + ".php"}
		sig, _, _, err := fetchSignature(ctx, client, pc, strings.TrimRight(origin, "/")+paths[i%len(paths)], true)
		if err != nil {
			if i == 0 {
				return cal, false
			}
			continue
		}
		cal.sigs = append(cal.sigs, sig)
	}
	return cal, len(cal.sigs) > 0
}

func checkContent(ctx context.Context, client *http.Client, pc ProviderContext, cal calibration, cand contentCandidate) (*Record, interfaceResult) {
	sig, body, header, err := fetchSignature(ctx, client, pc, cand.url, true)
	if err != nil {
		if err == errOutOfScope {
			return nil, interfaceSkipped
		}
		return nil, interfaceFailed
	}
	info := classifyContent(cand.entry, cal, sig, body, header)
	if info == nil {
		return nil, interfaceMiss
	}
	canon, cerr := matching.CanonicalURL(cand.url)
	if cerr != nil {
		canon = cand.url
	}
	host, _, _ := matching.HostAndPort(canon)
	return &Record{
		Type:     TypeContentDiscovery,
		URL:      canon,
		Host:     host,
		Provider: "builtin-content",
		Source:   "content-discovery",
		Content:  info,
	}, interfaceHit
}

// classifyContent decides whether a response is real content for the candidate path. A response
// that looks like the origin's answer for a missing path is never a hit. Only 200s can be
// CONFIRMED; 401/403 show the path exists but is protected and stay inventory (INFO).
func classifyContent(entry contentPath, cal calibration, sig contentSignature, body string, header http.Header) *ContentInfo {
	if sig.status >= 500 || sig.status == http.StatusNotFound || sig.status == http.StatusGone || sig.status == http.StatusBadRequest || sig.status == http.StatusMethodNotAllowed {
		return nil
	}
	if cal.matches(sig) {
		return nil
	}
	info := &ContentInfo{
		Path:        entry.path,
		Category:    entry.category,
		HTTPStatus:  sig.status,
		ContentSize: sig.length,
		ContentType: truncate(header.Get("Content-Type"), 80),
		Title:       truncate(telemetry.RedactString(extractTitle(body)), maxContentTitleChars),
	}
	switch {
	case sig.status >= 300 && sig.status < 400:
		// Redirects are routing (login bounces, canonical redirects), not exposure.
		return nil
	case sig.status == http.StatusUnauthorized || sig.status == http.StatusForbidden:
		info.Status, info.Severity, info.Confidence = ContentPossible, "INFO", 0.5
		info.Evidence, info.EvidenceType = "path exists but access is denied", "ACCESS_DENIED"
		return info
	case sig.status != http.StatusOK && sig.status != http.StatusPartialContent:
		return nil
	}

	if directoryListingRe.MatchString(body) {
		info.Category = ContentListing
		info.Status, info.Severity, info.Confidence = ContentConfirmed, maxSeverity(entry.severity, "MEDIUM"), 0.9
		info.Evidence, info.EvidenceType = "web server directory index is enabled", "DIRECTORY_LISTING"
		return info
	}
	// A directory entry only counts through a listing (above); an HTML page at it is not exposure.
	if entry.dir {
		return nil
	}
	isHTML := strings.Contains(strings.ToLower(header.Get("Content-Type")), "text/html")
	// Files such as .env or a SQL dump are never HTML; an HTML page at the path is the application
	// shell answering for an unknown route, whatever characters it happens to contain.
	if isHTML && !htmlExpected[entry.path] {
		return nil
	}
	if entry.marker != "" || entry.markerRe != nil {
		if (entry.marker != "" && strings.Contains(body, entry.marker)) || (entry.markerRe != nil && entry.markerRe.MatchString(body)) {
			info.Status, info.Severity, info.Confidence = ContentConfirmed, entry.severity, 0.9
			info.Evidence, info.EvidenceType = "content marker present: "+entry.markerName, "CONTENT_MARKER"
			return info
		}
		// A marker is defined and absent, so this is weak and must not claim impact.
		info.Status, info.Severity, info.Confidence = ContentPossible, capSeverity(entry.severity, "LOW"), 0.3
		info.Evidence, info.EvidenceType = "path answered differently from a missing path; expected content marker not found", "STATUS_DIFFERENCE"
		return info
	}
	info.Status, info.Severity, info.Confidence = ContentPossible, capSeverity(entry.severity, "MEDIUM"), 0.45
	info.Evidence, info.EvidenceType = "non-HTML response differing from a missing path", "STATUS_DIFFERENCE"
	return info
}

var severityRank = map[string]int{"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}

func capSeverity(s, cap string) string {
	if severityRank[s] > severityRank[cap] {
		return cap
	}
	return s
}

func maxSeverity(s, floor string) string {
	if severityRank[s] < severityRank[floor] {
		return floor
	}
	return s
}
