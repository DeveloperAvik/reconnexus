package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/reconnexus/workers/internal/adapters"
	"github.com/reconnexus/workers/internal/scope"
	"github.com/reconnexus/workers/internal/telemetry"
)

// defaultTemplateTags selects detection-oriented templates: exposed files and panels,
// misconfigurations and technology detection. None of them submit credentials or attack payloads.
const defaultTemplateTags = "exposure,misconfig,tech,panel"

// excludedTemplateTags are always passed to nuclei and cannot be removed by a job. Templates that
// carry any of them are intrusive, send attack payloads, try credentials, or need out-of-band
// callbacks, none of which this platform's authorization model covers.
const excludedTemplateTags = "dos,fuzz,intrusive,bruteforce,brute-force,default-login,oast,rce,sqli,xss,ssrf,lfi,kev"

const (
	maxExtractedValues = 5
	maxExtractedLen    = 200
	maxNucleiHosts     = 500
)

var templateTagsRe = regexp.MustCompile(`^[a-z0-9_-]+(,[a-z0-9_-]+)*$`)

// validateTemplateTags accepts "" (default tags) or a comma-separated list of tag names. Nothing
// that starts with "-" is accepted, so a tag can never become a scanner flag.
func validateTemplateTags(tags string) error {
	if tags == "" {
		return nil
	}
	if len(tags) > 256 || !templateTagsRe.MatchString(tags) {
		return fmt.Errorf("tags must be comma-separated names of lowercase letters, digits, '_' and '-'")
	}
	for _, t := range strings.Split(tags, ",") {
		if strings.HasPrefix(t, "-") {
			return fmt.Errorf("tag %q may not start with '-'", t)
		}
	}
	return nil
}

// nucleiProvider runs nuclei over in-scope web origins with a restricted, detection-only template
// selection. Template updates and the out-of-band (interactsh) service are disabled, and a match
// whose URL leaves scope is discarded.
type nucleiProvider struct{}

func (nucleiProvider) Name() string            { return "nuclei" }
func (nucleiProvider) Kind() string            { return "TEMPLATE_CHECK" }
func (nucleiProvider) Capability() string      { return "ACTIVE_TEMPLATE_CHECK" }
func (nucleiProvider) NetworkBehavior() string { return "ACTIVE_TEMPLATE" }

func nucleiArgv(tags string, limits scope.Limits) []string {
	if tags == "" {
		tags = defaultTemplateTags
	}
	rate := int(limits.RequestsPerSecond)
	if rate < 1 {
		rate = 1
	}
	conc := limits.MaxConcurrency
	if conc <= 0 || conc > 10 {
		conc = 10
	}
	return []string{
		"-jsonl", "-silent", "-nc", "-duc", "-ni",
		"-timeout", "10", "-retries", "0", "-max-host-error", "10",
		"-rate-limit", strconv.Itoa(rate), "-c", strconv.Itoa(conc),
		"-tags", tags, "-etags", excludedTemplateTags,
	}
}

func (nucleiProvider) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{}
	urls := job.Inputs.URLs
	if len(urls) > maxNucleiHosts {
		urls = urls[:maxNucleiHosts]
	}

	bin := job.BinaryPath
	if bin == "" {
		found, err := exec.LookPath("nuclei")
		if err != nil {
			res.StatusOverride = StatusSourceUnavailable
			res.Coverage.Unavailable = len(urls)
			res.Diagnostics = append(res.Diagnostics, `binary "nuclei" not found on PATH`)
			return res, nil
		}
		bin = found
	}
	if vr, err := adapters.Run(ctx, []string{bin, "-version"}, adapters.RunOptions{Timeout: 15 * time.Second}); err == nil && !vr.TimedOut {
		res.ProviderVersion = extractVersion(vr.Stdout + "\n" + vr.Stderr)
	}

	argv := append([]string{bin}, nucleiArgv(job.Inputs.TemplateTags, job.Limits)...)
	timeoutMs := 900000
	if job.TimeoutMs > 0 {
		timeoutMs = job.TimeoutMs
	}
	maxBytes := 32 * 1024 * 1024
	if job.MaxOutputBytes > 0 {
		maxBytes = job.MaxOutputBytes
	}
	run, err := adapters.Run(ctx, argv, adapters.RunOptions{Timeout: defaultTimeout(timeoutMs), MaxBytes: maxBytes, Dir: job.WorkDir, Input: strings.Join(urls, "\n") + "\n"})
	exec := &Execution{Argv: redactArgv(argv)}
	res.Execution = exec
	res.Coverage.Attempted = len(urls)
	if err != nil {
		exec.SpawnError = err.Error()
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = len(urls)
		res.Diagnostics = append(res.Diagnostics, "provider spawn failed: "+err.Error())
		return res, nil
	}
	exec.ExitCode = intPtr(run.ExitCode)
	exec.DurationMs = run.Duration.Milliseconds()
	exec.StdoutBytes, exec.StderrBytes = len(run.Stdout), len(run.Stderr)
	exec.Truncated, exec.TimedOut = run.Truncated, run.TimedOut
	if run.TimedOut || run.ExitCode != 0 {
		exec.ExitDescription = "timed out"
		if !run.TimedOut {
			exec.ExitDescription = "non-zero exit " + strconv.Itoa(run.ExitCode)
		}
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = len(urls)
		res.Diagnostics = append(res.Diagnostics, "nuclei "+exec.ExitDescription+": "+truncate(strings.TrimSpace(run.Stderr), 300))
		return res, nil
	}
	if run.Truncated {
		res.Diagnostics = append(res.Diagnostics, "provider output was truncated at the configured limit")
	}

	records, diag := parseNucleiJSONL(run.Stdout, pc.Engine)
	res.Records = records
	res.Diagnostics = append(res.Diagnostics, diag...)
	res.Coverage.Succeeded = len(urls)
	if len(records) == 0 {
		res.Diagnostics = append(res.Diagnostics, "no template matches (exit 0); this is not proof the targets are free of the issues the templates look for")
	}
	return res, nil
}

type nucleiLine struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string          `json:"name"`
		Severity    string          `json:"severity"`
		Description string          `json:"description"`
		Tags        json.RawMessage `json:"tags"`
		Reference   json.RawMessage `json:"reference"`
	} `json:"info"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	MatchedAt        string   `json:"matched-at"`
	MatcherName      string   `json:"matcher-name"`
	ExtractedResults []string `json:"extracted-results"`
}

// stringList reads a JSON value that nuclei emits either as an array of strings or as a single
// (possibly comma-separated) string.
func stringList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	var one string
	if json.Unmarshal(raw, &one) == nil && one != "" {
		return strings.Split(one, ",")
	}
	return nil
}

func normalizeTemplateSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return strings.ToUpper(strings.TrimSpace(s))
	default:
		return "INFO"
	}
}

// parseNucleiJSONL converts nuclei -jsonl output into TEMPLATE_FINDING records. Matches whose URL
// is out of scope are discarded, extracted values are redacted and truncated, and the request and
// response (which nuclei can include) are never read.
func parseNucleiJSONL(stdout string, engine *scope.Engine) ([]Record, []string) {
	var records []Record
	var diag []string
	seen := map[string]struct{}{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var l nucleiLine
		if err := json.Unmarshal([]byte(line), &l); err != nil || l.TemplateID == "" {
			diag = append(diag, "discarded malformed nuclei line: "+truncate(line, 80))
			continue
		}
		at := l.MatchedAt
		if at == "" {
			at = l.Host
		}
		host := hostOfMatch(at)
		if host == "" {
			diag = append(diag, "discarded nuclei match without a usable URL: "+l.TemplateID)
			continue
		}
		if engine != nil && strings.HasPrefix(at, "http") {
			if d := engine.Check(scope.Request{Kind: "URL", Value: at, Capability: "ACTIVE_TEMPLATE_CHECK"}); !d.Allowed {
				diag = append(diag, "discarded out-of-scope nuclei match: "+truncate(at, 80))
				continue
			}
		}
		key := l.TemplateID + "\x00" + at + "\x00" + l.MatcherName
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		extracted := make([]string, 0, maxExtractedValues)
		for _, e := range l.ExtractedResults {
			if len(extracted) == maxExtractedValues {
				break
			}
			extracted = append(extracted, truncate(telemetry.RedactString(e), maxExtractedLen))
		}
		records = append(records, Record{
			Type: TypeTemplateFinding, Host: host, URL: at, Provider: "nuclei", Source: "nuclei",
			Template: &TemplateInfo{
				TemplateID: l.TemplateID, Name: l.Info.Name, Severity: normalizeTemplateSeverity(l.Info.Severity),
				Description: truncate(l.Info.Description, 500), Tags: stringList(l.Info.Tags), References: stringList(l.Info.Reference),
				MatcherName: l.MatcherName, Extracted: extracted, TemplateType: l.Type, Confidence: 0.7,
			},
		})
	}
	return records, diag
}

// hostOfMatch returns the lowercase hostname of a matched URL, or of a bare host:port.
func hostOfMatch(at string) string {
	raw := at
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
