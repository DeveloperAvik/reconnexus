package discovery

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/reconnexus/workers/internal/matching"
	"github.com/reconnexus/workers/internal/scope"
	"github.com/reconnexus/workers/internal/telemetry"
)

// builtinLoginFinder discovers administrative login pages and hosting control panels
// (cPanel/WHM/webmail) by requesting a small, fixed set of well-known paths on in-scope origins.
// It is read-only: only unauthenticated GET requests are issued and no credentials are ever
// submitted. Every candidate URL is reauthorized against the scope policy (including path
// exclusions) and every request uses the connection-bound transport with per-hop redirect
// reauthorization.
type builtinLoginFinder struct{}

func (builtinLoginFinder) Name() string            { return "builtin-login-finder" }
func (builtinLoginFinder) Kind() string            { return "LOGIN_FINDER" }
func (builtinLoginFinder) Capability() string      { return "ACTIVE_HTTP" }
func (builtinLoginFinder) NetworkBehavior() string { return "ACTIVE" }

var adminLoginPaths = []string{
	"/admin",
	"/admin/login",
	"/administrator",
	"/login",
	"/signin",
	"/wp-admin/",
	"/wp-login.php",
	"/phpmyadmin/",
	"/manager/html",
	"/admin/index.php",
}

var cpanelPaths = []string{"/cpanel", "/whm", "/webmail"}

// Well-known cPanel/WHM/webmail ports. These are speculative by nature: most hosts will not
// listen on them, so transport failures there are recorded as skipped rather than failed.
var cpanelPorts = []struct {
	scheme string
	port   string
}{
	{"https", "2083"},
	{"http", "2082"},
	{"https", "2087"},
	{"http", "2086"},
	{"https", "2096"},
	{"http", "2095"},
}

const maxInterfaceCandidates = 800

var passwordInputRe = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*["']?password`)

type interfaceCandidate struct {
	kind        string
	url         string
	path        string
	port        string
	speculative bool
}

type interfaceResult int

const (
	interfaceHit interfaceResult = iota
	interfaceMiss
	interfaceSkipped
	interfaceFailed
)

func (builtinLoginFinder) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{Coverage: Coverage{}}
	origins := job.Inputs.URLs
	if len(origins) == 0 {
		res.StatusOverride = StatusSkipped
		res.Diagnostics = append(res.Diagnostics, "no origins to check for login interfaces")
		return res, nil
	}

	candidates := buildInterfaceCandidates(origins)
	if len(candidates) == 0 {
		res.StatusOverride = StatusSkipped
		res.Diagnostics = append(res.Diagnostics, "no valid origins to check for login interfaces")
		return res, nil
	}
	res.Coverage.Attempted = len(candidates)

	concurrency := job.Limits.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 8
	}
	if concurrency > 32 {
		concurrency = 32
	}
	timeout := time.Duration(job.RequestTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = time.Duration(defaultCrawlTimeoutMs) * time.Millisecond
	}
	maxBytes := job.Limits.MaxArtifactBytes
	if maxBytes <= 0 {
		maxBytes = 256 * 1024
	}
	if maxBytes > defaultMaxResponseBytes {
		maxBytes = defaultMaxResponseBytes
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
			rec, outcome := checkInterface(ctx, client, pc, cand, maxBytes)
			mu.Lock()
			if rec != nil {
				records = append(records, *rec)
			}
			switch outcome {
			case interfaceHit, interfaceMiss:
				res.Coverage.Succeeded++
			case interfaceSkipped:
				res.Coverage.Skipped++
			default:
				res.Coverage.Failed++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		res.StatusOverride = StatusCancelled
	}
	res.Records = records
	if len(records) == 0 {
		res.Diagnostics = append(res.Diagnostics, fmt.Sprintf("no login interfaces detected across %d candidate URL(s)", len(candidates)))
	}
	return res, nil
}

// buildInterfaceCandidates expands in-scope origins into the fixed path/port probe set. The
// origins are already scope-filtered by the job runner; each candidate is independently
// reauthorized before a request is made.
func buildInterfaceCandidates(origins []string) []interfaceCandidate {
	seen := map[string]struct{}{}
	out := make([]interfaceCandidate, 0, len(origins)*(len(adminLoginPaths)+len(cpanelPaths)+len(cpanelPorts)))
	add := func(c interfaceCandidate) {
		key := c.kind + "\x00" + c.url
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}

	for _, raw := range origins {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			continue
		}
		base := &url.URL{Scheme: u.Scheme, Host: u.Host}
		for _, p := range adminLoginPaths {
			c := *base
			c.Path = p
			add(interfaceCandidate{kind: LoginKindAdmin, url: c.String(), path: p})
		}
		for _, p := range cpanelPaths {
			c := *base
			c.Path = p
			add(interfaceCandidate{kind: LoginKindCpanel, url: c.String(), path: p})
		}
		for _, cp := range cpanelPorts {
			hostPort := net.JoinHostPort(u.Hostname(), cp.port)
			c := url.URL{Scheme: cp.scheme, Host: hostPort, Path: "/"}
			add(interfaceCandidate{kind: LoginKindCpanel, url: c.String(), path: "/", port: cp.port, speculative: true})
		}
		if len(out) >= maxInterfaceCandidates {
			return out[:maxInterfaceCandidates]
		}
	}
	return out
}

func checkInterface(ctx context.Context, client *http.Client, pc ProviderContext, cand interfaceCandidate, maxBytes int) (*Record, interfaceResult) {
	canon, err := matching.CanonicalURL(cand.url)
	if err != nil {
		return nil, interfaceSkipped
	}
	host, _, _ := matching.HostAndPort(canon)
	d := pc.Engine.Check(scope.Request{Kind: "URL", Value: canon, Capability: "ACTIVE_HTTP"})
	if !d.Allowed {
		return nil, interfaceSkipped
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, canon, nil)
	if err != nil {
		return nil, interfaceSkipped
	}
	req.Header.Set("User-Agent", "reconnexus/0.20 (+https://github.com/anomalyco/opencode)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	resp, derr := doRequest(ctx, client, pc.Limiter, req)
	if derr != nil || resp == nil {
		if cand.speculative {
			return nil, interfaceSkipped
		}
		return nil, interfaceFailed
	}
	defer resp.Body.Close()
	body, _, _ := readBounded(resp.Body, maxBytes)
	finalURL := canon
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}

	info := classifyInterface(cand, resp.StatusCode, resp.Header, body)
	if info == nil {
		return nil, interfaceMiss
	}
	info.FinalURL = finalURL
	sc := resp.StatusCode
	info.HTTPStatus = &sc
	return &Record{
		Type:     TypeLoginInterface,
		URL:      canon,
		Host:     host,
		Provider: "builtin-login-finder",
		Source:   "login-finder",
		Login:    info,
	}, interfaceHit
}

// classifyInterface decides whether a response is a login/control-panel interface. Weak
// evidence (a protected status on a known administrative path) yields POSSIBLE; concrete
// markers (password form, service-specific headers/cookies, control-panel title) yield DETECTED.
// A generic 200 response with no marker is never reported.
func classifyInterface(cand interfaceCandidate, status int, header http.Header, body string) *LoginInterfaceInfo {
	title := telemetry.RedactString(extractTitle(body))
	lowerTitle := strings.ToLower(title)
	lowerBody := strings.ToLower(body)
	server := strings.ToLower(header.Get("server"))
	cookies := strings.ToLower(strings.Join(header.Values("set-cookie"), ";"))
	hasPassword := passwordInputRe.MatchString(body)

	if cand.kind == LoginKindCpanel {
		cpanelHeader := strings.Contains(server, "cpsrvd") || strings.Contains(server, "cpanel") ||
			strings.Contains(cookies, "cpanel") || strings.Contains(cookies, "cpsession")
		cpanelBody := strings.Contains(lowerBody, "cpsrvd") || strings.Contains(lowerBody, "cpanel") || strings.Contains(lowerBody, "whm")
		cpanelTitle := strings.Contains(lowerTitle, "cpanel") || strings.Contains(lowerTitle, "whm") || strings.Contains(lowerTitle, "webmail")
		portResponded := cand.speculative && (status == http.StatusOK || status == http.StatusUnauthorized || status == http.StatusForbidden)
		protectedPath := (cand.path == "/cpanel" || cand.path == "/whm" || cand.path == "/webmail") &&
			(status == http.StatusUnauthorized || status == http.StatusForbidden)

		evidence := []string{}
		evidenceType := ""
		switch {
		case cpanelHeader:
			evidence = append(evidence, "control-panel server/cookie marker")
			evidenceType = "CPANEL_HEADER"
		case cpanelTitle && (hasPassword || cpanelBody):
			evidence = append(evidence, "control-panel title")
			evidenceType = "CPANEL_TITLE"
		case portResponded && (hasPassword || cpanelBody || cpanelTitle):
			evidence = append(evidence, "control-panel port response")
			evidenceType = "CPANEL_PORT"
		case portResponded:
			evidence = append(evidence, "control-panel port responded")
			evidenceType = "CPANEL_PORT"
		case hasPassword && (cpanelBody || cand.path == "/cpanel" || cand.path == "/whm" || cand.path == "/webmail"):
			evidence = append(evidence, "password form with control-panel markers")
			evidenceType = "LOGIN_FORM"
		case protectedPath:
			evidence = append(evidence, "authentication required on control-panel path")
			evidenceType = "AUTH_REQUIRED"
		default:
			return nil
		}
		if hasPassword {
			evidence = append(evidence, "password form present")
		}
		if cand.port != "" {
			evidence = append(evidence, "port "+cand.port)
		}
		if title != "" {
			evidence = append(evidence, fmt.Sprintf("title %q", title))
		}
		statusValue, confidence := LoginPossible, 0.6
		if evidenceType != "AUTH_REQUIRED" && evidenceType != "CPANEL_PORT" {
			statusValue, confidence = LoginDetected, 0.9
		} else if evidenceType == "CPANEL_PORT" && (hasPassword || cpanelTitle || cpanelBody || cpanelHeader) {
			statusValue, confidence = LoginDetected, 0.85
		}
		return &LoginInterfaceInfo{
			Kind:         LoginKindCpanel,
			Status:       statusValue,
			Confidence:   confidence,
			Title:        title,
			Evidence:     telemetry.RedactString(fmt.Sprintf("HTTP %d; %s", status, strings.Join(evidence, "; "))),
			EvidenceType: evidenceType,
		}
	}

	// Administrative login paths.
	jenkinsHeader := header.Get("x-jenkins") != ""
	marker := loginFormMarker(lowerBody)
	loginTitle := containsAny(lowerTitle, "login", "log in", "sign in", "sign-in", "administrator", "admin login", "dashboard", "control panel")

	evidence := []string{}
	evidenceType := ""
	statusValue := LoginPossible
	confidence := 0.55
	switch {
	case jenkinsHeader:
		evidence = append(evidence, "x-jenkins header")
		evidenceType = "JENKINS_HEADER"
		statusValue, confidence = LoginDetected, 0.9
	case hasPassword && (loginTitle || marker != ""):
		evidence = append(evidence, "password form present")
		if marker != "" {
			evidence = append(evidence, "login form marker "+marker)
		}
		evidenceType = "LOGIN_FORM"
		statusValue, confidence = LoginDetected, 0.85
	case hasPassword:
		evidence = append(evidence, "password form present")
		evidenceType = "LOGIN_FORM"
		statusValue, confidence = LoginDetected, 0.8
	case status == http.StatusUnauthorized:
		evidence = append(evidence, "authentication required")
		evidenceType = "AUTH_REQUIRED"
		statusValue, confidence = LoginPossible, 0.7
	case status == http.StatusForbidden:
		evidence = append(evidence, "access forbidden on administrative path")
		evidenceType = "ACCESS_DENIED"
		statusValue, confidence = LoginPossible, 0.55
	case loginTitle:
		evidence = append(evidence, "login/admin title")
		evidenceType = "LOGIN_TITLE"
		statusValue, confidence = LoginPossible, 0.55
	default:
		return nil
	}
	if title != "" {
		evidence = append(evidence, fmt.Sprintf("title %q", title))
	}
	return &LoginInterfaceInfo{
		Kind:         LoginKindAdmin,
		Status:       statusValue,
		Confidence:   confidence,
		Title:        title,
		Evidence:     telemetry.RedactString(strings.Join(evidence, "; ")),
		EvidenceType: evidenceType,
	}
}

// loginFormMarker returns the first service-specific login form marker found in the body.
func loginFormMarker(lowerBody string) string {
	for _, m := range []string{"wp-submit", "user_login", "pma_password", "j_username", "login-form", "name=\"password\"", "name='password'"} {
		if strings.Contains(lowerBody, m) {
			return m
		}
	}
	return ""
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}
