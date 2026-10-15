package discovery

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/reconnexus/workers/internal/matching"
	"github.com/reconnexus/workers/internal/telemetry"
)

// builtinSecretScan analyses eligible artifacts for potential secrets. It is strictly read-only and
// never persists raw matched values: findings carry only a redacted snippet and a keyed HMAC
// fingerprint. It never verifies credentials and never follows references from a match.
type builtinSecretScan struct{}

func (builtinSecretScan) Name() string            { return "builtin-secret-scan" }
func (builtinSecretScan) Kind() string            { return "SECRET_SCAN" }
func (builtinSecretScan) Capability() string      { return "SECRET_SCAN" }
func (builtinSecretScan) NetworkBehavior() string { return "ACTIVE" }

type secretRule struct {
	id         string
	category   string
	confidence float64
	high       bool
	group      int
	entropy    bool
	minEntropy float64
	re         *regexp.Regexp
}

// secretRules is a maintained, high-signal rule set. Patterns are intentionally specific; the
// single heuristic (entropy) rule is marked low-confidence and suppressed on overlap.
var secretRules = []secretRule{
	{id: "aws-access-key-id", category: "CLOUD_CREDENTIAL", confidence: 0.95, high: true, group: 0, re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{id: "aws-secret-access-key", category: "CLOUD_CREDENTIAL", confidence: 0.9, high: true, group: 1, re: regexp.MustCompile(`(?i)aws[^\n]{0,20}?(?:secret|access)[^\n]{0,20}?['"]([A-Za-z0-9/+=]{40})['"]`)},
	{id: "google-api-key", category: "API_KEY", confidence: 0.95, high: true, group: 0, re: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
	{id: "slack-token", category: "API_KEY", confidence: 0.9, high: true, group: 0, re: regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)},
	{id: "github-token", category: "API_KEY", confidence: 0.9, high: true, group: 0, re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
	{id: "stripe-secret-key", category: "API_KEY", confidence: 0.9, high: true, group: 0, re: regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24,}\b`)},
	{id: "private-key", category: "PRIVATE_KEY", confidence: 0.95, high: true, group: 0, re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----`)},
	// A bare `SK` + 32 hex is far too generic (it matches hashes and generated ids). Twilio keys are
	// only reported when a Twilio-ish context token appears nearby.
	{id: "twilio-api-key", category: "API_KEY", confidence: 0.85, high: true, group: 1, re: regexp.MustCompile(`(?i)(?:twilio|account[_-]?sid|auth[_-]?token|api[_-]?key)[^\n]{0,40}?\b(SK[0-9a-fA-F]{32})\b`)},
	{id: "sendgrid-api-key", category: "API_KEY", confidence: 0.9, high: true, group: 0, re: regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b`)},
	{id: "npm-token", category: "API_KEY", confidence: 0.9, high: true, group: 0, re: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{id: "azure-storage-account-key", category: "CLOUD_CREDENTIAL", confidence: 0.9, high: true, group: 1, re: regexp.MustCompile(`(?i)AccountKey=([A-Za-z0-9+/=]{88})`)},
	{id: "database-connection-string", category: "DATABASE_URL", confidence: 0.9, high: true, group: 0, re: regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s'"]*:[^\s'"@]+@[^\s'"]+`)},
	// Assignment keywords are common in configuration/UI code; require the value to look random.
	{id: "oauth-client-secret", category: "OAUTH_SECRET", confidence: 0.85, high: true, group: 1, entropy: true, minEntropy: 3.5, re: regexp.MustCompile(`(?i)(?:client[_-]?secret|oauth[_-]?secret)\s*[:=]\s*['"]([A-Za-z0-9_\-]{16,})['"]`)},
	{id: "webhook-signing-secret", category: "WEBHOOK_SECRET", confidence: 0.8, high: true, group: 1, entropy: true, minEntropy: 3.5, re: regexp.MustCompile(`(?i)(?:whsec_|webhook[_-]?secret|signing[_-]?secret)\s*[:=]?\s*['"]?([A-Za-z0-9_\-]{16,})`)},
	{id: "embedded-credentials", category: "PASSWORD", confidence: 0.6, high: false, group: 0, re: regexp.MustCompile(`\bhttps?://[^/\s:@'"]+:[^/\s:@'"]+@`)},
	{id: "password-assignment", category: "PASSWORD", confidence: 0.5, high: false, group: 1, entropy: true, minEntropy: 3.5, re: regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"\s]{6,})['"]`)},
	{id: "jwt-token", category: "BEARER_TOKEN", confidence: 0.7, high: false, group: 0, entropy: true, minEntropy: 3.5, re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)},
	{id: "bearer-token", category: "BEARER_TOKEN", confidence: 0.6, high: false, group: 1, entropy: true, minEntropy: 3.5, re: regexp.MustCompile(`(?i)bearer\s+([A-Za-z0-9._\-]{20,})`)},
	{id: "generic-high-entropy", category: "GENERIC_HIGH_ENTROPY", confidence: 0.5, high: false, group: 1, entropy: true, minEntropy: 3.5, re: regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|token)\s*[:=]\s*['"]([A-Za-z0-9_\-]{20,64})['"]`)},
}

// placeholderTokens suppress obvious non-secrets. Words here appear in UI/config strings that a
// generic assignment rule would otherwise flag (e.g. `password = 'required'`), so they are treated
// as placeholders rather than candidates.
var placeholderTokens = []string{
	"example", "placeholder", "changeme", "change_me", "dummy", "your_", "your-", "xxxxxx", "aaaaaa",
	"<", "${", "{{", "redacted", "fake",
	"required", "invalid", "undefined", "sample", "todo", "lorem", "password",
}

const (
	maxSecretMatchesPerRule = 200
)

func (builtinSecretScan) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{Coverage: Coverage{}}
	urls := job.Inputs.ArtifactURLs
	if len(urls) == 0 {
		res.StatusOverride = StatusSkipped
		res.Diagnostics = append(res.Diagnostics, "no eligible artifacts to scan")
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
		maxBytes = 4 * 1024 * 1024
	}
	key := []byte(os.Getenv("RECONNEXUS_HMAC_KEY"))
	suppressed := suppressedRules()
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
			recs, ok := scanArtifact(ctx, client, pc.Limiter, raw, maxBytes, key, suppressed)
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

func suppressedRules() map[string]bool {
	out := map[string]bool{}
	for _, r := range strings.Split(os.Getenv("RECONNEXUS_SECRET_SUPPRESS_RULES"), ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			out[r] = true
		}
	}
	return out
}

func scanArtifact(ctx context.Context, client *http.Client, limiter *rateLimiter, raw string, maxBytes int, key []byte, suppressed map[string]bool) ([]Record, bool) {
	canon, err := matching.CanonicalURL(raw)
	if err != nil {
		return artifactRecord(raw, "", SecretArtifactAnalysisFailed, 0, 0, false, "invalid artifact URL"), false
	}
	host, _, _ := matching.HostAndPort(canon)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, canon, nil)
	if err != nil {
		return artifactRecord(canon, host, SecretArtifactAnalysisFailed, 0, 0, false, "request build failed"), false
	}
	req.Header.Set("User-Agent", "reconnexus/0.7 (+https://github.com/anomalyco/opencode)")
	resp, derr := doRequest(ctx, client, limiter, req)
	if derr != nil {
		return artifactRecord(canon, host, SecretArtifactAnalysisFailed, 0, 0, len(key) > 0, telemetry.RedactString(derr.Error())), false
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return artifactRecord(canon, host, SecretArtifactSkipped, 0, 0, len(key) > 0, ""), false
	}
	body, truncated, _ := readBounded(resp.Body, maxBytes)

	findings := scanText(body, canon, host, key, suppressed)
	status := SecretArtifactAnalyzed
	if truncated {
		status = SecretArtifactOversized
	}
	out := artifactRecord(canon, host, status, len(findings), len(body), len(key) > 0, "")
	out = append(out, findings...)
	return out, true
}

func artifactRecord(url, host, status string, findings, rawBytes int, hmacKeyed bool, errMsg string) []Record {
	return []Record{{
		Type:     TypeSecretScanArtifact,
		URL:      url,
		Host:     host,
		Provider: "builtin-secret-scan",
		Source:   "secret-scan",
		SecretScan: &SecretScanArtifactInfo{
			ArtifactURL:   url,
			Host:          host,
			Status:        status,
			FindingsCount: findings,
			RawBytes:      rawBytes,
			HMACKeyed:     hmacKeyed,
			Error:         errMsg,
		},
	}}
}

type rawMatch struct {
	rule  *secretRule
	start int
	end   int
	value string
}

// scanText applies the rule set, suppresses placeholders/overlaps, and returns redacted findings.
func scanText(content, artifactURL, host string, key []byte, suppressed map[string]bool) []Record {
	var kept []rawMatch
	for ri := range secretRules {
		rule := &secretRules[ri]
		idxs := rule.re.FindAllStringSubmatchIndex(content, maxSecretMatchesPerRule)
		for _, m := range idxs {
			g := rule.group
			if 2*g+1 >= len(m) || m[2*g] < 0 {
				continue
			}
			start, end := m[2*g], m[2*g+1]
			value := content[start:end]
			// Placeholders are retained so the suppression is observable. For everything else, the
			// entropy gate drops low-entropy values (config flags, form-validation strings) that a
			// weak assignment rule would otherwise report as false positives.
			if rule.entropy && !isPlaceholder(value) && shannon(value) < rule.minEntropy {
				continue
			}
			// Suppress generic matches that overlap an already-kept (more specific) match.
			if rule.entropy && overlaps(kept, start, end) {
				continue
			}
			kept = append(kept, rawMatch{rule: rule, start: start, end: end, value: value})
		}
	}

	// Deduplicate identical rule+value matches, counting occurrences.
	type agg struct {
		match       rawMatch
		occurrences int
	}
	order := []string{}
	byKey := map[string]*agg{}
	for _, m := range kept {
		k := m.rule.id + "\x00" + m.value
		if a, ok := byKey[k]; ok {
			a.occurrences++
			continue
		}
		byKey[k] = &agg{match: m, occurrences: 1}
		order = append(order, k)
	}

	var out []Record
	for _, k := range order {
		a := byKey[k]
		m := a.match
		status := SecretCandidate
		conf := m.rule.confidence
		reason := ""
		if suppressed[m.rule.id] {
			status = SecretSuppressed
			reason = "rule suppressed by configuration"
		} else if isPlaceholder(m.value) {
			status = SecretSuppressed
			reason = "placeholder/example value"
		} else if m.rule.high {
			status = SecretHighConf
		}
		fp := ""
		if len(key) > 0 {
			mac := hmac.New(sha256.New, key)
			mac.Write([]byte(m.rule.id + "|" + m.value))
			fp = hex.EncodeToString(mac.Sum(nil))[:32]
		}
		out = append(out, Record{
			Type:     TypeSecretCandidate,
			URL:      artifactURL,
			Host:     host,
			Provider: "builtin-secret-scan",
			Source:   "secret-scan",
			Secret: &SecretCandidateInfo{
				RuleID:            m.rule.id,
				Category:          m.rule.category,
				Status:            status,
				Confidence:        conf,
				ArtifactURL:       artifactURL,
				Host:              host,
				Location:          lineCol(content, m.start),
				RedactedSnippet:   redactSnippet(content, m.start, m.end, m.value, m.rule.id, m.rule.category == "PRIVATE_KEY"),
				Fingerprint:       fp,
				Occurrences:       a.occurrences,
				Rationale:         "matched rule " + m.rule.id,
				SuppressionReason: reason,
			},
		})
	}
	return out
}

func overlaps(kept []rawMatch, start, end int) bool {
	for _, k := range kept {
		if start < k.end && k.start < end {
			return true
		}
	}
	return false
}

func isPlaceholder(v string) bool {
	low := strings.ToLower(v)
	for _, p := range placeholderTokens {
		if strings.Contains(low, p) {
			return true
		}
	}
	return false
}

// redactSnippet returns a snippet scoped to the line containing the match, so no token is ever cut
// in half. Every rule match found in the snippet is replaced, the raw value is removed, and the
// global redactor runs last. Private keys and over-long (e.g. minified) lines fall back to a
// context-free marker so no part of a key body or neighbouring secret can leak.
func redactSnippet(content string, start, end int, value, ruleID string, sensitiveBody bool) string {
	if sensitiveBody {
		return "[REDACTED:" + ruleID + "]"
	}
	lineStart := strings.LastIndexByte(content[:start], '\n') + 1
	lineEnd := len(content)
	if i := strings.IndexByte(content[end:], '\n'); i >= 0 {
		lineEnd = end + i
	}
	if lineEnd-lineStart > 240 {
		return "[REDACTED:" + ruleID + "]"
	}
	snippet := content[lineStart:lineEnd]
	if value != "" {
		snippet = strings.ReplaceAll(snippet, value, "[REDACTED]")
	}
	snippet = redactAllRuleMatches(snippet)
	snippet = telemetry.RedactString(snippet)
	return truncate(snippet, 240)
}

// redactAllRuleMatches replaces any rule match within a snippet, so a neighbouring secret on the
// same line cannot survive redaction.
func redactAllRuleMatches(s string) string {
	for i := range secretRules {
		s = secretRules[i].re.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}

func lineCol(content string, offset int) string {
	if offset > len(content) {
		offset = len(content)
	}
	line := 1
	last := 0
	for i := 0; i < offset; i++ {
		if content[i] == '\n' {
			line++
			last = i + 1
		}
	}
	return intToStr(line) + ":" + intToStr(offset-last+1)
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
