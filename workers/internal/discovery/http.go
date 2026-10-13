package discovery

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/reconnexus/workers/internal/matching"
	"github.com/reconnexus/workers/internal/scope"
)

// builtinHTTP is the HTTP probing provider. It is implemented in-process (rather than via
// httpx) because the mandatory SSRF controls — reauthorizing every redirect hop and binding a
// validated IP decision to the actual socket — require a custom transport. httpx resolves and
// follows redirects internally, so it cannot provide those guarantees.
type builtinHTTP struct{}

func (builtinHTTP) Name() string            { return "builtin-http" }
func (builtinHTTP) Kind() string            { return "HTTP_PROBE" }
func (builtinHTTP) Capability() string      { return "ACTIVE_HTTP" }
func (builtinHTTP) NetworkBehavior() string { return "ACTIVE" }

// scopeDeniedError is returned by the dialer when a resolved address is not permitted.
type scopeDeniedError struct{ reason string }

func (e *scopeDeniedError) Error() string { return "scope denied: " + e.reason }

type redirectDeniedError struct {
	decision scope.Decision
}

func (e *redirectDeniedError) Error() string { return "redirect denied: " + e.decision.Reason }

var errTooManyRedirects = errors.New("too many redirects")

const (
	defaultConnectTimeoutMs = 10000
	defaultRequestTimeoutMs = 20000
	defaultMaxResponseBytes = 1 << 20 // 1 MiB
)

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

var sensitiveHeaderRe = regexp.MustCompile(`(?i)(set-cookie|^cookie$|authorization|proxy-authorization|x-api-key|token|secret|session)`)

func (builtinHTTP) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{Coverage: Coverage{}}

	urls := job.Inputs.URLs
	if len(urls) == 0 {
		res.StatusOverride = StatusSkipped
		res.Diagnostics = append(res.Diagnostics, "no URLs to probe")
		return res, nil
	}
	res.Coverage.Attempted = len(urls)

	concurrency := job.Limits.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 8
	}
	if concurrency > 32 {
		concurrency = 32
	}
	maxRedirects := job.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = 5
	}
	if maxRedirects > 10 {
		maxRedirects = 10
	}
	requestTimeout := time.Duration(job.RequestTimeoutMs) * time.Millisecond
	if requestTimeout <= 0 {
		requestTimeout = time.Duration(defaultRequestTimeoutMs) * time.Millisecond
	}
	maxBytes := job.Limits.MaxArtifactBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxResponseBytes
	}

	transport, err := pc.buildTransport(job)
	if err != nil {
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "cannot build HTTP client: "+err.Error())
		return res, nil
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for _, rawURL := range urls {
		rawURL := rawURL
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			outcome := probeOne(ctx, transport, requestTimeout, pc, rawURL, maxBytes, maxRedirects)
			mu.Lock()
			res.Records = append(res.Records, outcome.records...)
			res.Diagnostics = append(res.Diagnostics, outcome.diagnostics...)
			switch outcome.result {
			case probeSucceeded:
				res.Coverage.Succeeded++
			case probeFailed:
				res.Coverage.Failed++
			default:
				res.Coverage.Skipped++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if ctx.Err() != nil {
		res.StatusOverride = StatusCancelled
	}
	return res, nil
}

type probeResult int

const (
	probeSucceeded probeResult = iota
	probeFailed
	probeSkipped
)

type probeOutcome struct {
	result      probeResult
	records     []Record
	diagnostics []string
}

func probeOne(ctx context.Context, transport *http.Transport, requestTimeout time.Duration, pc ProviderContext, rawURL string, maxBytes int, maxRedirects int) probeOutcome {
	var out probeOutcome
	client := &http.Client{Transport: transport, Timeout: requestTimeout}

	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		out.result = probeSkipped
		out.diagnostics = append(out.diagnostics, "invalid target URL: "+truncate(rawURL, 120))
		return out
	}
	host := matching.CanonicalHost(parsed.Hostname())

	// Pre-flight authorization of the host (address-level checks happen at dial time).
	d := pc.Engine.Check(scope.Request{Kind: "URL", Value: rawURL, Capability: "ACTIVE_HTTP"})
	if !d.Allowed {
		out.result = probeSkipped
		out.diagnostics = append(out.diagnostics, fmt.Sprintf("host %s not authorized for HTTP: %s", host, d.Code))
		// Emit a skipped observation so the denial is visible and auditable.
		out.records = append(out.records, httpRecord(rawURL, host, &HTTPDetails{
			FinalURL:    rawURL,
			ProbeStatus: ProbeBlockedAddress,
			Error:       d.Reason,
		}))
		return out
	}

	chain := &redirectRecorder{max: maxRedirects}
	client.CheckRedirect = chain.checkRedirect(pc.Engine)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		out.result = probeFailed
		out.records = append(out.records, httpRecord(rawURL, host, &HTTPDetails{FinalURL: rawURL, ProbeStatus: ProbeError, Error: err.Error()}))
		return out
	}
	req.Header.Set("User-Agent", "reconnexus/0.3 (+https://github.com/anomalyco/opencode)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	details := &HTTPDetails{ProbeStatus: ProbeOK, RedirectChain: chain.hops}
	if err != nil {
		// A denied redirect still returns the pre-redirect response; preserve its metadata.
		if resp != nil {
			details.FinalURL = resp.Request.URL.String()
			status := resp.StatusCode
			details.StatusCode = &status
			details.StatusText = resp.Status
			details.ContentType = resp.Header.Get("Content-Type")
			details.Headers = selectHeaders(resp.Header)
			if resp.TLS != nil {
				details.TLS = tlsInfo(resp.TLS)
			}
		}
		classifyProbeError(&out, details, err, chain, rawURL, host)
		return out
	}
	defer resp.Body.Close()

	details.FinalURL = resp.Request.URL.String()
	status := resp.StatusCode
	details.StatusCode = &status
	details.StatusText = resp.Status
	details.ContentType = resp.Header.Get("Content-Type")
	if resp.TLS != nil {
		details.TLS = tlsInfo(resp.TLS)
	}

	body, truncated, bodyErr := readBounded(resp.Body, maxBytes)
	if bodyErr != nil && !errors.Is(bodyErr, io.EOF) {
		out.diagnostics = append(out.diagnostics, "body read error for "+host+": "+bodyErr.Error())
	}
	details.BodyTruncated = truncated

	cookieNames := cookieNames(resp)
	headers := selectHeaders(resp.Header)
	details.Headers = headers
	details.Title = extractTitle(body)

	out.records = append(out.records, httpRecord(rawURL, host, details))

	// Evidence-backed fingerprinting on the (possibly truncated) body and metadata.
	hits := Fingerprint(fingerprintInput{
		Headers:   headers,
		Body:      strings.ToLower(body),
		Title:     details.Title,
		Cookies:   cookieNames,
		TLSIssuer: issuerString(resp.TLS),
	})
	for _, hit := range hits {
		out.records = append(out.records, Record{
			Type:       TypeTechnology,
			URL:        details.FinalURL,
			Host:       host,
			Provider:   "builtin-http",
			Technology: &hit,
		})
	}

	if truncated || errors.Is(chain.err, errTooManyRedirects) {
		if truncated {
			details.ProbeStatus = ProbeOversized
		}
	}
	out.result = probeSucceeded
	return out
}

func classifyProbeError(out *probeOutcome, details *HTTPDetails, err error, chain *redirectRecorder, rawURL, host string) {
	details.ProbeStatus = ProbeError
	details.Error = err.Error()

	var de *redirectDeniedError
	var se *scopeDeniedError
	switch {
	case errors.As(err, &de):
		details.ProbeStatus = ProbeRedirectDenied
		details.Error = de.Error()
		out.diagnostics = append(out.diagnostics, "redirect denied for "+host+": "+de.decision.Reason)
		out.result = probeSucceeded // we observed the pre-redirect response
	case errors.As(err, &se):
		details.ProbeStatus = ProbeBlockedAddress
		out.result = probeFailed
	case errors.Is(err, errTooManyRedirects):
		details.ProbeStatus = ProbeTooManyRedirects
		out.result = probeSucceeded
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		details.ProbeStatus = ProbeTimeout
		out.result = probeFailed
	case isTLSError(err):
		details.ProbeStatus = ProbeTLSError
		details.Error = "TLS verification failed: " + err.Error()
		out.result = probeFailed
	case isTimeout(err):
		details.ProbeStatus = ProbeTimeout
		out.result = probeFailed
	default:
		details.ProbeStatus = ProbeConnectionError
		out.result = probeFailed
	}
	// Preserve any hops recorded before the failure.
	details.RedirectChain = chain.hops
	out.records = append(out.records, httpRecord(rawURL, host, details))
}

// redirectRecorder captures redirect hops and enforces per-hop authorization.
type redirectRecorder struct {
	hops []RedirectHop
	max  int
	err  error
}

func (r *redirectRecorder) checkRedirect(engine *scope.Engine) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= r.max {
			r.err = errTooManyRedirects
			return errTooManyRedirects
		}
		code := 0
		from := ""
		if req.Response != nil {
			code = req.Response.StatusCode
			if req.Response.Request != nil {
				from = req.Response.Request.URL.String()
			}
		}
		r.hops = append(r.hops, RedirectHop{From: from, To: req.URL.String(), StatusCode: &code})

		// Reauthorize the redirect destination independently of the original target.
		d := engine.Check(scope.Request{Kind: "URL", Value: req.URL.String(), Capability: "ACTIVE_HTTP", IsRedirect: true})
		if !d.Allowed {
			r.err = &redirectDeniedError{decision: d}
			return r.err
		}
		return nil
	}
}

func (pc ProviderContext) buildTransport(job Job) (*http.Transport, error) {
	engine := pc.Engine
	resolver := resolverFactory(job)

	connectTimeout := time.Duration(defaultConnectTimeoutMs) * time.Millisecond

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		addrs, err := resolveForDial(ctx, resolver, host)
		if err != nil {
			return nil, err
		}
		// Validate the host together with the addresses we are about to connect to. This binds
		// the scope decision to the actual connection and defeats DNS rebinding.
		d := engine.Check(scope.Request{Kind: "HOST", Value: host, Capability: "ACTIVE_HTTP", ResolvedAddresses: addrs})
		if !d.Allowed {
			return nil, &scopeDeniedError{reason: d.Reason}
		}
		dialer := &net.Dialer{Timeout: connectTimeout}
		var lastErr error
		for _, a := range addrs {
			conn, derr := dialer.DialContext(ctx, network, net.JoinHostPort(a, port))
			if derr == nil {
				return conn, nil
			}
			lastErr = derr
		}
		if lastErr == nil {
			lastErr = errors.New("no addresses to dial")
		}
		return nil, lastErr
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if job.TLSCaFile != "" {
		pem, err := os.ReadFile(job.TLSCaFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read tlsCaFile: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("tlsCaFile contained no valid certificates")
		}
		tlsCfg.RootCAs = pool
	}
	// Certificate validation is never disabled; verification uses the system roots unless a
	// CA bundle is explicitly configured (test/config only).

	transport := &http.Transport{
		DialContext:           dial,
		TLSClientConfig:       tlsCfg,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		DisableKeepAlives:     true,
	}
	return transport, nil
}

func resolveForDial(ctx context.Context, resolver hostResolver, host string) ([]string, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []string{addr.Unmap().String()}, nil
	}
	addrs, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("no addresses for " + host)
	}
	return addrs, nil
}

func readBounded(r io.Reader, max int) (string, bool, error) {
	limited := io.LimitReader(r, int64(max)+1)
	buf, err := io.ReadAll(limited)
	truncated := false
	if int64(len(buf)) > int64(max) {
		buf = buf[:max]
		truncated = true
	}
	return string(buf), truncated, err
}

func extractTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	t := html.UnescapeString(m[1])
	t = strings.Join(strings.Fields(t), " ")
	if len(t) > 200 {
		t = t[:200]
	}
	return t
}

func cookieNames(resp *http.Response) []string {
	var names []string
	for _, c := range resp.Cookies() {
		names = append(names, strings.ToLower(c.Name))
	}
	return names
}

func selectHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		if sensitiveHeaderRe.MatchString(k) {
			continue
		}
		if len(out) >= 30 {
			break
		}
		val := strings.Join(v, ", ")
		if len(val) > 300 {
			val = val[:300]
		}
		out[strings.ToLower(k)] = val
	}
	return out
}

func tlsInfo(state *tls.ConnectionState) *TLSInfo {
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	cert := state.PeerCertificates[0]
	sum := sha256.Sum256(cert.Raw)
	info := &TLSInfo{
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		NotBefore: cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  cert.NotAfter.UTC().Format(time.RFC3339),
		SHA256:    hex.EncodeToString(sum[:]),
		Protocol:  tls.VersionName(state.Version),
	}
	for _, dns := range cert.DNSNames {
		info.SANs = append(info.SANs, dns)
	}
	return info
}

func issuerString(state *tls.ConnectionState) string {
	if state == nil || len(state.PeerCertificates) == 0 {
		return ""
	}
	return state.PeerCertificates[0].Issuer.String()
}

func httpRecord(rawURL, host string, details *HTTPDetails) Record {
	return Record{
		Type:     TypeHTTPObservation,
		URL:      rawURL,
		Host:     host,
		Provider: "builtin-http",
		Source:   "http",
		HTTP:     details,
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}

func isTLSError(err error) bool {
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return true
	}
	var unknownAuth x509.UnknownAuthorityError
	if errors.As(err, &unknownAuth) {
		return true
	}
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return true
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "tls") || strings.Contains(msg, "x509") || strings.Contains(msg, "certificate")
}
