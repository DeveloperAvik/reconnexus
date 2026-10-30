package discovery

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reconnexus/workers/internal/scope"
)

const nucleiSample = `{"template-id":"git-config","info":{"name":"Git Config","severity":"medium","description":"exposed","tags":["exposure","git"],"reference":["https://ex.test/r"]},"type":"http","host":"https://www.example.com","matched-at":"https://www.example.com/.git/config","extracted-results":["token=ghp_abcdefghijklmnopqrstuvwxyz0123456789"]}
{"template-id":"git-config","info":{"name":"Git Config","severity":"medium"},"type":"http","host":"https://www.example.com","matched-at":"https://www.example.com/.git/config"}
{"template-id":"tech-detect","info":{"name":"Tech","severity":"info","tags":"tech,nginx","reference":"https://a.test,https://b.test"},"type":"http","host":"https://www.example.com","matched-at":"https://www.example.com/","matcher-name":"nginx"}
{"template-id":"offsite","info":{"name":"Off","severity":"high"},"type":"http","host":"https://evil.other.test","matched-at":"https://evil.other.test/x"}
{"template-id":"weird","info":{"name":"W","severity":"banana"},"type":"http","host":"https://www.example.com","matched-at":"https://www.example.com/w"}
not json
`

func nucleiEngine() *scope.Engine {
	p := testPolicy("ACTIVE_TEMPLATE_CHECK")
	return scope.NewEngine(&p)
}

func TestParseNucleiJSONL(t *testing.T) {
	recs, diag := parseNucleiJSONL(nucleiSample, nucleiEngine())
	if len(recs) != 3 {
		t.Fatalf("records = %d, want 3 (dedupe, off-scope and malformed dropped): %+v", len(recs), recs)
	}
	if len(diag) != 2 {
		t.Fatalf("diagnostics = %v", diag)
	}
	git := recs[0].Template
	if git.Severity != "MEDIUM" || recs[0].Host != "www.example.com" || len(git.Tags) != 2 {
		t.Fatalf("unexpected git record: %+v", git)
	}
	if strings.Contains(git.Extracted[0], "ghp_abcdefghijklmnopqrstuvwxyz0123456789") {
		t.Fatalf("extracted value not redacted: %q", git.Extracted[0])
	}
	tech := recs[1].Template
	if tech.Severity != "INFO" || len(tech.Tags) != 2 || len(tech.References) != 2 || tech.MatcherName != "nginx" {
		t.Fatalf("string-form tags/reference not handled: %+v", tech)
	}
	if recs[2].Template.Severity != "INFO" {
		t.Fatalf("unknown severity must fall back to INFO: %+v", recs[2].Template)
	}
}

func TestNucleiArgvAlwaysExcludesIntrusiveTags(t *testing.T) {
	argv := strings.Join(nucleiArgv("exposure", scope.Limits{RequestsPerSecond: 3.7, MaxConcurrency: 50}), " ")
	for _, want := range []string{"-ni", "-duc", "-rate-limit 3", "-c 10", "-tags exposure", "-etags dos,fuzz,intrusive,bruteforce"} {
		if !strings.Contains(argv, want) {
			t.Errorf("argv missing %q: %s", want, argv)
		}
	}
	if def := strings.Join(nucleiArgv("", scope.Limits{}), " "); !strings.Contains(def, "-tags "+defaultTemplateTags) || !strings.Contains(def, "-rate-limit 1") {
		t.Errorf("defaults not applied: %s", def)
	}
}

func TestValidateTemplateTags(t *testing.T) {
	for _, ok := range []string{"", "exposure", "exposure,misconfig", "wp-plugin,cve_2021"} {
		if err := validateTemplateTags(ok); err != nil {
			t.Errorf("validateTemplateTags(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"-config", "a,-b", "A", "a b", "a;b", "a,,b", ","} {
		if err := validateTemplateTags(bad); err == nil {
			t.Errorf("validateTemplateTags(%q) accepted", bad)
		}
	}
}

func fakeNuclei(t *testing.T, out string, exit int) string {
	t.Helper()
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.jsonl")
	if err := os.WriteFile(outPath, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo '[INF] Nuclei Engine Version: v3.4.1' >&2; exit 0; fi\ncat >/dev/null\ncat '" + outPath + "'\nexit " + string(rune('0'+exit)) + "\n"
	bin := filepath.Join(dir, "nuclei")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin
}

func templateJob(bin string, caps ...string) Job {
	if len(caps) == 0 {
		caps = []string{"ACTIVE_TEMPLATE_CHECK"}
	}
	return Job{
		SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "16", JobKey: "16",
		Kind: "TEMPLATE_CHECK", Provider: "nuclei", Policy: testPolicy(caps...), BinaryPath: bin,
		Limits: scope.Limits{MaxConcurrency: 4, RequestsPerSecond: 20, CrawlDepth: 1, MaxRuntimeSeconds: 30, MaxArtifactBytes: 1 << 20},
		Inputs: Inputs{URLs: []string{"https://www.example.com"}},
	}
}

func TestNucleiProviderEndToEnd(t *testing.T) {
	res, _ := Run(context.Background(), templateJob(fakeNuclei(t, nucleiSample, 0)), nil)
	if res.Status != StatusSucceeded || len(res.Records) != 3 || res.ProviderVersion != "3.4.1" {
		t.Fatalf("status=%s records=%d version=%s diag=%v", res.Status, len(res.Records), res.ProviderVersion, res.Diagnostics)
	}
}

func TestNucleiProviderBlockedSkippedFailedUnavailable(t *testing.T) {
	bin := fakeNuclei(t, nucleiSample, 0)
	if res, _ := Run(context.Background(), templateJob(bin, "ACTIVE_HTTP"), nil); res.Status != StatusBlocked {
		t.Fatalf("without capability: status=%s", res.Status)
	}
	job := templateJob(bin)
	job.Inputs.URLs = []string{"https://evil.other.test"}
	if res, _ := Run(context.Background(), job, nil); res.Status != StatusSkipped {
		t.Fatalf("out of scope: status=%s", res.Status)
	}
	job = templateJob(bin)
	job.Inputs.TemplateTags = "-config"
	if res, _ := Run(context.Background(), job, nil); res.Status != StatusFailed {
		t.Fatalf("bad tags: status=%s", res.Status)
	}
	if res, _ := Run(context.Background(), templateJob(fakeNuclei(t, "", 1)), nil); res.Status != StatusFailed {
		t.Fatalf("non-zero exit: status=%s", res.Status)
	}
	missing := templateJob("")
	t.Setenv("PATH", t.TempDir())
	if res, _ := Run(context.Background(), missing, nil); res.Status != StatusSourceUnavailable {
		t.Fatalf("missing binary: status=%s", res.Status)
	}
}

// A line shaped like real nuclei 3.x output: it carries the full request and response, which the
// parser must never copy into a record.
const nucleiRealLine = `{"template":"http/exposures/configs/git-config.yaml","template-id":"git-config","info":{"name":"Git Configuration - Detect","author":["pdteam"],"tags":["config","git","exposure","vuln"],"description":"Git configuration was detected.","severity":"medium","classification":{"cve-id":null,"cvss-score":5.3}},"type":"http","host":"www.example.com","port":"443","scheme":"https","url":"https://www.example.com","matched-at":"https://www.example.com/.git/config","request":"GET /.git/config HTTP/1.1\r\nCookie: session=SECRETSESSIONVALUE\r\n\r\n","response":"HTTP/1.0 200 OK\r\n\r\nurl = https://user:SECRETPASSWORD@example.com/r.git","ip":"93.184.216.34","curl-command":"curl -H 'Cookie: session=SECRETSESSIONVALUE'","matcher-status":true}`

func TestParseNucleiRealOutputShapeNeverCarriesRequestOrResponse(t *testing.T) {
	recs, diag := parseNucleiJSONL(nucleiRealLine+"\n", nucleiEngine())
	if len(recs) != 1 || len(diag) != 0 {
		t.Fatalf("records=%d diag=%v", len(recs), diag)
	}
	b, err := json.Marshal(recs[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"SECRETSESSIONVALUE", "SECRETPASSWORD", "curl", "HTTP/1.1"} {
		if strings.Contains(string(b), leaked) {
			t.Fatalf("record leaks %q: %s", leaked, b)
		}
	}
	if recs[0].Template.Severity != "MEDIUM" || recs[0].Host != "www.example.com" {
		t.Fatalf("unexpected record: %+v", recs[0].Template)
	}
}
