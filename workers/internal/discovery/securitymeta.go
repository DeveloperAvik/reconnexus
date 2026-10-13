package discovery

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/reconnexus/workers/internal/matching"
	"github.com/reconnexus/workers/internal/telemetry"
)

// builtinSecurityMeta observes security-relevant metadata from in-scope service responses. It is
// read-only: it issues a single GET per service (no payloads, no crawling) and records exactly
// what was observed. A missing header is recorded as NOT_OBSERVED — never as "control absent".
type builtinSecurityMeta struct{}

func (builtinSecurityMeta) Name() string            { return "builtin-security-meta" }
func (builtinSecurityMeta) Kind() string            { return "SECURITY_META" }
func (builtinSecurityMeta) Capability() string      { return "SECURITY_CHECKS" }
func (builtinSecurityMeta) NetworkBehavior() string { return "ACTIVE" }

var securityHeaders = []string{
	"strict-transport-security",
	"content-security-policy",
	"x-frame-options",
	"x-content-type-options",
	"referrer-policy",
	"permissions-policy",
	"cross-origin-opener-policy",
	"cross-origin-resource-policy",
	"cross-origin-embedder-policy",
}

func (builtinSecurityMeta) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{Coverage: Coverage{}}
	urls := job.Inputs.URLs
	if len(urls) == 0 {
		res.StatusOverride = StatusSkipped
		res.Diagnostics = append(res.Diagnostics, "no service URLs to enrich")
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
	timeout := time.Duration(job.RequestTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = defaultCrawlTimeoutMs * time.Millisecond
	}
	maxBytes := job.Limits.MaxArtifactBytes
	if maxBytes <= 0 {
		maxBytes = 256 * 1024
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
	for _, raw := range urls {
		raw := raw
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			client, _ := newGuardedClient(transport, pc.Engine, timeout, job.MaxRedirects)
			recs, ok := observeService(ctx, client, raw, maxBytes)
			mu.Lock()
			records = append(records, recs...)
			if ok {
				res.Coverage.Succeeded++
			} else {
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
	return res, nil
}

func observeService(ctx context.Context, client *http.Client, raw string, maxBytes int) ([]Record, bool) {
	canon, err := matching.CanonicalURL(raw)
	if err != nil {
		return []Record{metaRecord(raw, "", CatHeader, "response", MetaCollectionFailed, false, "", nil, nil, "invalid URL", "PARSE")}, false
	}
	host, _, _ := matching.HostAndPort(canon)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, canon, nil)
	if err != nil {
		return []Record{metaRecord(canon, host, CatHeader, "response", MetaCollectionFailed, false, "", nil, nil, err.Error(), "REQUEST")}, false
	}
	req.Header.Set("User-Agent", "reconnexus/0.6 (+https://github.com/anomalyco/opencode)")
	resp, derr := client.Do(req)
	if derr != nil {
		return []Record{metaRecord(canon, host, CatHeader, "response", MetaCollectionFailed, false, "", nil, nil, telemetry.RedactString(derr.Error()), "TRANSPORT")}, false
	}
	defer resp.Body.Close()
	finalURL := canon
	if resp.Request != nil {
		finalURL = resp.Request.URL.String()
	}
	body, _, _ := readBounded(resp.Body, maxBytes)

	var out []Record
	// TLS / certificate metadata.
	out = append(out, tlsMetadata(resp, finalURL, host)...)
	// Security headers (explicit NOT_OBSERVED when absent).
	for _, name := range securityHeaders {
		v := resp.Header.Get(name)
		if name == "strict-transport-security" {
			out = append(out, hstsMetadata(finalURL, host, v, strings.HasPrefix(finalURL, "https://")))
			continue
		}
		if v == "" {
			out = append(out, metaRecord(finalURL, host, CatHeader, name, MetaNotObserved, false, "", map[string]any{"limitation": "header absent in this response only; not proof the control is absent"}, nil, "header not present", "HEADER"))
		} else {
			out = append(out, metaRecord(finalURL, host, CatHeader, name, MetaObserved, true, truncate(telemetry.RedactString(v), 300), nil, nil, "header "+name, "HEADER"))
		}
	}
	// CORS policy.
	if cors := corsMetadata(resp, finalURL, host); cors != nil {
		out = append(out, *cors)
	}
	// Cookies (attributes only; values are never recorded).
	out = append(out, cookieMetadata(resp, finalURL, host)...)
	// Content-type consistency.
	out = append(out, contentTypeMetadata(resp, finalURL, host, body))
	return out, true
}

func metaRecord(url, host, category, name, status string, observed bool, value string, detail map[string]any, consistent *bool, evidence, evidenceType string) Record {
	if detail == nil {
		detail = map[string]any{}
	}
	return Record{
		Type:     TypeSecurityMetadata,
		URL:      url,
		Host:     host,
		Provider: "builtin-security-meta",
		Source:   "security-metadata",
		Security: &SecurityMetadataInfo{
			Category:     category,
			Name:         name,
			Status:       status,
			Observed:     observed,
			Value:        value,
			Detail:       detail,
			Consistent:   consistent,
			Evidence:     telemetry.RedactString(evidence),
			EvidenceType: evidenceType,
		},
	}
}

func boolPtr(b bool) *bool { return &b }

// certDetail computes evidence-backed certificate metadata and whether the certificate is currently
// valid for the given time. Validity boundaries are explicit (notBefore/notAfter/validNow/daysToExpiry).
func certDetail(cert *x509.Certificate, protocol uint16, host string, now time.Time) (map[string]any, bool) {
	sum := sha256.Sum256(cert.Raw)
	validNow := !now.Before(cert.NotBefore) && !now.After(cert.NotAfter)
	days := int(cert.NotAfter.Sub(now).Hours() / 24)
	selfSigned := cert.CheckSignatureFrom(cert) == nil || cert.Issuer.String() == cert.Subject.String()
	hostnameErr := cert.VerifyHostname(host)
	return map[string]any{
		"subject":         cert.Subject.String(),
		"issuer":          cert.Issuer.String(),
		"notBefore":       cert.NotBefore.UTC().Format(time.RFC3339),
		"notAfter":        cert.NotAfter.UTC().Format(time.RFC3339),
		"protocol":        tls.VersionName(protocol),
		"sha256":          hex.EncodeToString(sum[:]),
		"selfSigned":      selfSigned,
		"hostnameMatch":   hostnameErr == nil,
		"daysToExpiry":    days,
		"validNow":        validNow,
		"expiredOrNotYet": !validNow,
	}, validNow
}

func tlsMetadata(resp *http.Response, finalURL, host string) []Record {
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return []Record{metaRecord(finalURL, host, CatTLS, "certificate", MetaNotObserved, false, "", map[string]any{"reason": "no TLS (plaintext request)"}, nil, "no TLS connection", "TLS")}
	}
	cert := resp.TLS.PeerCertificates[0]
	detail, validNow := certDetail(cert, resp.TLS.Version, host, time.Now())
	return []Record{metaRecord(finalURL, host, CatTLS, "certificate", MetaObserved, true, "", detail, boolPtr(validNow), "TLS peer certificate", "TLS")}
}

func hstsMetadata(finalURL, host, value string, https bool) Record {
	if value == "" {
		detail := map[string]any{"reason": "strict-transport-security header absent"}
		if !https {
			detail["reason"] = "plaintext request or no HSTS header"
		}
		return metaRecord(finalURL, host, CatHSTS, "strict-transport-security", MetaNotObserved, false, "", detail, nil, "HSTS not observed in this response", "HEADER")
	}
	detail := map[string]any{"raw": truncate(telemetry.RedactString(value), 200)}
	maxAge := -1
	includeSub := false
	preload := false
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		low := strings.ToLower(part)
		switch {
		case strings.HasPrefix(low, "max-age="):
			if n, err := strconv.Atoi(strings.TrimSpace(part[len("max-age="):])); err == nil {
				maxAge = n
			}
		case low == "includesubdomains":
			includeSub = true
		case low == "preload":
			preload = true
		}
	}
	detail["maxAge"] = maxAge
	detail["includeSubDomains"] = includeSub
	detail["preload"] = preload
	return metaRecord(finalURL, host, CatHSTS, "strict-transport-security", MetaObserved, true, "", detail, nil, "HSTS header "+truncate(value, 120), "HEADER")
}

func corsMetadata(resp *http.Response, finalURL, host string) *Record {
	acao := resp.Header.Get("access-control-allow-origin")
	acac := resp.Header.Get("access-control-allow-credentials")
	acam := resp.Header.Get("access-control-allow-methods")
	acah := resp.Header.Get("access-control-allow-headers")
	if acao == "" && acac == "" && acam == "" && acah == "" {
		r := metaRecord(finalURL, host, CatCORS, "cors", MetaNotObserved, false, "", map[string]any{"limitation": "observed without an Origin header; reflective CORS is not tested"}, nil, "no CORS headers present", "HEADER")
		return &r
	}
	wildcard := acao == "*"
	credentials := strings.EqualFold(strings.TrimSpace(acac), "true")
	status := MetaObserved
	consistent := true
	if wildcard && credentials {
		status = MetaInconsistent
		consistent = false
	}
	r := metaRecord(finalURL, host, CatCORS, "cors", status, true, acao, map[string]any{
		"allowOrigin":      acao,
		"allowCredentials": credentials,
		"allowMethods":     acam,
		"allowHeaders":     acah,
		"wildcard":         wildcard,
	}, boolPtr(consistent), "CORS response headers", "HEADER")
	return &r
}

func cookieMetadata(resp *http.Response, finalURL, host string) []Record {
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return []Record{metaRecord(finalURL, host, CatCookie, "set-cookie", MetaNotObserved, false, "", map[string]any{"limitation": "no Set-Cookie in this response"}, nil, "no cookies set", "HEADER")}
	}
	var out []Record
	for _, c := range cookies {
		sameSite := "Default"
		switch c.SameSite {
		case http.SameSiteLaxMode:
			sameSite = "Lax"
		case http.SameSiteStrictMode:
			sameSite = "Strict"
		case http.SameSiteNoneMode:
			sameSite = "None"
		}
		// The cookie VALUE is never recorded.
		detail := map[string]any{
			"secure":   c.Secure,
			"httpOnly": c.HttpOnly,
			"sameSite": sameSite,
			"domain":   c.Domain,
			"path":     c.Path,
			"maxAge":   c.MaxAge,
		}
		out = append(out, metaRecord(finalURL, host, CatCookie, c.Name, MetaObserved, true, "", detail, nil, "Set-Cookie attributes for cookie "+c.Name, "HEADER"))
	}
	return out
}

func contentTypeMetadata(resp *http.Response, finalURL, host, body string) Record {
	declared := resp.Header.Get("Content-Type")
	sniffed := sniffContentType(body)
	consistent := true
	if declared != "" && sniffed != "other" {
		consistent = strings.Contains(strings.ToLower(declared), sniffed)
	}
	status := MetaObserved
	if declared == "" {
		status = MetaNotObserved
	}
	if !consistent {
		status = MetaInconsistent
	}
	detail := map[string]any{"declared": declared, "sniffed": sniffed, "consistent": consistent}
	return metaRecord(finalURL, host, CatContentType, "content-type", status, declared != "", declared, detail, boolPtr(consistent), "declared vs observed body type", "CONTENT")
}

func sniffContentType(body string) string {
	s := strings.TrimSpace(body)
	s = strings.TrimPrefix(s, "\ufeff")
	low := strings.ToLower(s)
	switch {
	case strings.HasPrefix(low, "{") || strings.HasPrefix(low, "["):
		return "json"
	case strings.HasPrefix(low, "<!doctype html") || strings.HasPrefix(low, "<html") || strings.HasPrefix(low, "<!doctype"):
		return "html"
	case s == "":
		return "empty"
	default:
		return "other"
	}
}
