package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reconnexus/workers/internal/scope"
)

func secScanPolicy() scope.Policy {
	p := testPolicy("PASSIVE", "ACTIVE_HTTP", "SECRET_SCAN")
	p.InScope.IPs = []string{"127.0.0.1"}
	return p
}

func secScanJob(urls []string, opts ...func(*Job)) Job {
	j := Job{
		SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "09", JobKey: "09",
		Kind: "SECRET_SCAN", Provider: "builtin-secret-scan", Policy: secScanPolicy(),
		Limits: scope.Limits{MaxConcurrency: 4, RequestsPerSecond: 20, CrawlDepth: 1, MaxRuntimeSeconds: 30, MaxArtifactBytes: 1 << 20},
		Inputs: Inputs{ArtifactURLs: urls},
	}
	for _, o := range opts {
		o(&j)
	}
	return j
}

func secretFindings(res Result) []*SecretCandidateInfo {
	var out []*SecretCandidateInfo
	for _, r := range res.Records {
		if r.Type == TypeSecretCandidate && r.Secret != nil {
			out = append(out, r.Secret)
		}
	}
	return out
}

func findSecret(res Result, ruleID string) *SecretCandidateInfo {
	for _, f := range secretFindings(res) {
		if f.RuleID == ruleID {
			return f
		}
	}
	return nil
}

// The synthetic secrets below are fixtures only and are never real credentials.
const (
	rawAWSKey  = "AKIAABCDEFGHIJKLMNOP"
	rawDBURL   = "postgres://admin:S3cr3tP4ss@db.internal:5432/app"
	rawJWT     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
	rawGeneric = "Xy9Kq2Lm7Pz4Rt6Wv8Bn0Cd3Ef5Gh1"
	rawKeyBody = "MIIEowIBAAKCAQEA" // start of a fake private-key body
)

func jsWithSecrets() string {
	return "const a='" + rawAWSKey + "';\n" +
		"const b='" + rawAWSKey + "';\n" + // duplicate of a → one finding, occurrences=2
		"const db='" + rawDBURL + "';\n" +
		"const pk='-----BEGIN RSA PRIVATE KEY-----\n" + rawKeyBody + "\n-----END RSA PRIVATE KEY-----';\n" +
		"const jwt='" + rawJWT + "';\n" +
		"const cfg={password:'your_password_here'};\n" +
		"const gen={token:'" + rawGeneric + "'};\n"
}

// activeSecretRules returns the non-suppressed rule ids scanText reports for a blob.
func activeSecretRules(text string) map[string]bool {
	out := map[string]bool{}
	for _, r := range scanText(text, "https://example.com/a.js", "example.com", nil, nil) {
		if r.Type == TypeSecretCandidate && r.Secret != nil && r.Secret.Status != SecretSuppressed {
			out[r.Secret.RuleID] = true
		}
	}
	return out
}

// Regression: the weak assignment/entropy rules must not flag ordinary values that appear in
// minified JavaScript (ids, form-validation strings, repeated characters).
func TestSecretScanDoesNotFlagBenignValues(t *testing.T) {
	benign := map[string]string{
		"bare SK hash without context": "const id='SK0123456789abcdef0123456789abcdef';",
		"low-entropy password":         "const cfg={password:'required'};",
		"numeric password":             "const cfg={password:'123456789'};",
		"repeated-char bearer":         "req.setHeader('Authorization','Bearer aaaaaaaaaaaaaaaaaaaaaaaa');",
		"placeholder client secret":    "const o={client_secret:'xxxxxxxxxxxxxxxx'};",
		"repeated-char webhook":        "const w={signing_secret:'aaaaaaaaaaaaaaaaaaaa'};",
		"example embedded creds":       "const u='https://user:password@example.com/';",
	}
	for name, text := range benign {
		if got := activeSecretRules(text); len(got) != 0 {
			t.Errorf("%s: expected no finding, got %v", name, keysOfBool(got))
		}
	}
}

// Regression: a Twilio key IS still detected when a Twilio-ish context token is present.
func TestSecretScanTwilioRequiresContext(t *testing.T) {
	key := "SK0123456789abcdef0123456789abcdef"
	if got := activeSecretRules("const auth_token = '" + key + "';"); !got["twilio-api-key"] {
		t.Errorf("expected twilio-api-key with context, got %v", keysOfBool(got))
	}
	if got := activeSecretRules("const id = '" + key + "';"); got["twilio-api-key"] {
		t.Errorf("bare SK value without context must not be flagged: %v", keysOfBool(got))
	}
}

func TestSecretScanDetectsAndRedacts(t *testing.T) {
	t.Setenv("RECONNEXUS_HMAC_KEY", "test-key-material-123")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, jsWithSecrets())
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})

	res, err := Run(context.Background(), secScanJob([]string{srv.URL + "/app.js"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusSucceeded {
		t.Fatalf("status=%s diag=%v", res.Status, res.Diagnostics)
	}

	aws := findSecret(res, "aws-access-key-id")
	if aws == nil || aws.Status != SecretHighConf {
		t.Fatalf("expected aws HIGH_CONFIDENCE, got %+v", aws)
	}
	if aws.Occurrences != 2 {
		t.Errorf("expected 2 occurrences collapsed into one finding, got %d", aws.Occurrences)
	}
	if aws.Fingerprint == "" {
		t.Errorf("expected a keyed fingerprint")
	}
	if findSecret(res, "private-key") == nil || findSecret(res, "database-connection-string") == nil {
		t.Errorf("missing private-key / db-connection findings")
	}
	if p := findSecret(res, "password-assignment"); p == nil || p.Status != SecretSuppressed {
		t.Errorf("expected placeholder password to be SUPPRESSED, got %+v", p)
	}
	if g := findSecret(res, "generic-high-entropy"); g == nil {
		t.Errorf("expected a generic high-entropy candidate")
	}

	// RELEASE GATE: the raw secret values must never appear anywhere in the worker output.
	blob, _ := json.Marshal(res)
	for _, raw := range []string{rawAWSKey, rawDBURL, rawJWT, rawGeneric, rawKeyBody, "S3cr3tP4ss"} {
		if bytes.Contains(blob, []byte(raw)) {
			t.Fatalf("raw secret value leaked into worker output")
		}
	}
	for _, f := range secretFindings(res) {
		if !strings.Contains(f.RedactedSnippet, "[REDACTED") && f.RuleID != "generic-high-entropy" {
			// generic-high-entropy also redacts; keep a soft check
			if !strings.Contains(f.RedactedSnippet, "[REDACTED") {
				t.Errorf("finding %s snippet not redacted: %q", f.RuleID, f.RedactedSnippet)
			}
		}
	}
	// The private key snippet must not contain any part of the key body.
	pk := findSecret(res, "private-key")
	if strings.Contains(pk.RedactedSnippet, rawKeyBody) {
		t.Fatalf("private key body leaked into snippet")
	}
}

func TestSecretScanSuppressionByRule(t *testing.T) {
	t.Setenv("RECONNEXUS_SECRET_SUPPRESS_RULES", "aws-access-key-id")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "const a='"+rawAWSKey+"';")
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), secScanJob([]string{srv.URL + "/a.js"}), nil)
	aws := findSecret(res, "aws-access-key-id")
	if aws == nil || aws.Status != SecretSuppressed || aws.SuppressionReason == "" {
		t.Fatalf("expected SUPPRESSED by config, got %+v", aws)
	}
}

func TestSecretScanNoKeyNoFingerprint(t *testing.T) {
	t.Setenv("RECONNEXUS_HMAC_KEY", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "const a='"+rawAWSKey+"';")
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), secScanJob([]string{srv.URL + "/a.js"}), nil)
	aws := findSecret(res, "aws-access-key-id")
	if aws == nil || aws.Fingerprint != "" {
		t.Fatalf("without a key the fingerprint must be empty, got %+v", aws)
	}
	for _, r := range res.Records {
		if r.Type == TypeSecretScanArtifact && r.SecretScan.HMACKeyed {
			t.Errorf("hmacKeyed should be false without a key")
		}
	}
}

func TestSecretScanOversized(t *testing.T) {
	t.Setenv("RECONNEXUS_HMAC_KEY", "k")
	big := "const x='" + rawAWSKey + "';\n" + strings.Repeat("// padding\n", 5000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, big) }))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), secScanJob([]string{srv.URL + "/big.js"}, func(j *Job) { j.Limits.MaxArtifactBytes = 256 }), nil)
	var status string
	for _, r := range res.Records {
		if r.Type == TypeSecretScanArtifact {
			status = r.SecretScan.Status
		}
	}
	if status != SecretArtifactOversized {
		t.Fatalf("expected OVERSIZED, got %q", status)
	}
}

func TestSecretScanUnicodeAndMalformed(t *testing.T) {
	t.Setenv("RECONNEXUS_HMAC_KEY", "k")
	payload := []byte("const s='" + rawAWSKey + "';\xff\xfe\x00garbage\xc3\x28")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) }))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), secScanJob([]string{srv.URL + "/m.js"}), nil)
	if res.Status != StatusSucceeded {
		t.Fatalf("malformed bytes should not crash the scan: %s", res.Status)
	}
	if findSecret(res, "aws-access-key-id") == nil {
		t.Errorf("expected detection despite malformed surrounding bytes")
	}
}

func TestSecretScanAnalysisFailedAndSkipped(t *testing.T) {
	t.Setenv("RECONNEXUS_HMAC_KEY", "k")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/404.js" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(500)
	}))
	base := srv.URL
	srv.Close() // connection refused → ANALYSIS_FAILED
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), secScanJob([]string{base + "/boom.js"}), nil)
	var status string
	for _, r := range res.Records {
		if r.Type == TypeSecretScanArtifact {
			status = r.SecretScan.Status
		}
	}
	if status != SecretArtifactAnalysisFailed {
		t.Fatalf("expected ANALYSIS_FAILED, got %q", status)
	}
	if res.Coverage.Failed != 1 {
		t.Errorf("coverage.failed=%d want 1", res.Coverage.Failed)
	}
}

func TestSecretScanOutOfScopeSkipped(t *testing.T) {
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	res, _ := Run(context.Background(), secScanJob([]string{"http://evil.other.net/app.js"}), nil)
	if res.Coverage.Skipped != 1 {
		t.Fatalf("skipped=%d want 1", res.Coverage.Skipped)
	}
}

func TestSecretScanCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()
	withResolver(t, funcResolver{fn: resolveExampleTo("127.0.0.1")})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(80 * time.Millisecond); cancel() }()
	res, _ := Run(ctx, secScanJob([]string{srv.URL + "/x.js"}, func(j *Job) { j.RequestTimeoutMs = 5000 }), nil)
	if res.Status != StatusCancelled {
		t.Fatalf("status=%s want CANCELLED", res.Status)
	}
}

func TestSecretScanBlockedWithoutCapability(t *testing.T) {
	p := secScanPolicy()
	p.Authorization.Capabilities = []string{"ACTIVE_HTTP"}
	job := secScanJob([]string{"http://example.com/a.js"})
	job.Policy = p
	res, _ := Run(context.Background(), job, nil)
	if res.Status != StatusBlocked {
		t.Fatalf("status=%s want BLOCKED", res.Status)
	}
}
