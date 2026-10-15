package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/reconnexus/workers/internal/adapters"
	"github.com/reconnexus/workers/internal/matching"
	"github.com/reconnexus/workers/internal/scope"
	"github.com/reconnexus/workers/internal/telemetry"
)

// Provider executes a discovery job and returns normalized records.
type Provider interface {
	Name() string
	Kind() string
	Capability() string
	NetworkBehavior() string
	Run(ctx context.Context, pc ProviderContext) (ProviderResult, error)
}

// ProviderContext is passed to a provider at execution time.
type ProviderContext struct {
	Job    Job
	Engine *scope.Engine
	Logger *telemetry.Logger
}

// ProviderResult is what a provider returns.
type ProviderResult struct {
	Records         []Record
	Coverage        Coverage
	Diagnostics     []string
	Execution       *Execution
	ProviderVersion string
	// StatusOverride, when set, replaces the derived status.
	StatusOverride string
}

var labelRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// normalizeHost canonicalizes and validates a hostname; returns ok=false for anything that
// is not a plausible DNS name (including IP literals).
func normalizeHost(raw string) (string, bool) {
	h := matching.CanonicalHost(raw)
	if h == "" || len(h) > 253 {
		return "", false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return "", false
	}
	if !strings.Contains(h, ".") {
		return "", false
	}
	for _, label := range strings.Split(h, ".") {
		if !labelRe.MatchString(label) {
			return "", false
		}
	}
	return h, true
}

// dedupeHosts normalizes and deduplicates hostnames, preserving first-seen order.
func dedupeHosts(lines []string) (hosts []string, diagnostics []string) {
	seen := map[string]struct{}{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Some tools emit "host:port"; strip the port.
		if i := strings.LastIndex(line, ":"); i > 0 && !strings.Contains(line, "]") {
			// only strip when the suffix is all digits
			if isAllDigits(line[i+1:]) {
				line = line[:i]
			}
		}
		h, ok := normalizeHost(line)
		if !ok {
			diagnostics = append(diagnostics, "discarded non-hostname line: "+truncate(line, 80))
			continue
		}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		hosts = append(hosts, h)
	}
	return hosts, diagnostics
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// externalProvider runs an external binary via structured argv.
type externalProvider struct {
	name, kind, capability, networkBehavior string
	versionArgs                             []string
	buildArgv                               func(job Job) ([]string, error)
	parse                                   func(stdout string) ([]Record, []string)
	usesStdin                               bool
	stdin                                   func(job Job) string
	defaultTimeoutMs                        int
	defaultMaxBytes                         int
}

func (p *externalProvider) Name() string            { return p.name }
func (p *externalProvider) Kind() string            { return p.kind }
func (p *externalProvider) Capability() string      { return p.capability }
func (p *externalProvider) NetworkBehavior() string { return p.networkBehavior }

func (p *externalProvider) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{Coverage: Coverage{}}

	bin := job.BinaryPath
	if bin == "" {
		found, err := exec.LookPath(p.name)
		if err != nil {
			res.StatusOverride = StatusSourceUnavailable
			res.Coverage.Unavailable = 1
			res.Diagnostics = append(res.Diagnostics, fmt.Sprintf("binary %q not found on PATH", p.name))
			return res, nil
		}
		bin = found
	}

	version := "unknown"
	if len(p.versionArgs) > 0 {
		if vr, err := adapters.Run(ctx, append([]string{bin}, p.versionArgs...), adapters.RunOptions{Timeout: 10 * defaultTimeout(p.defaultTimeoutMs)}); err == nil && !vr.TimedOut && vr.ExitCode == 0 {
			version = extractVersion(vr.Stdout + "\n" + vr.Stderr)
		}
	}

	argv, err := p.buildArgv(job)
	if err != nil {
		res.StatusOverride = StatusFailed
		res.Diagnostics = append(res.Diagnostics, "invalid job inputs: "+err.Error())
		return res, nil
	}
	fullArgv := append([]string{bin}, argv...)

	timeoutMs := p.defaultTimeoutMs
	if job.TimeoutMs > 0 {
		timeoutMs = job.TimeoutMs
	}
	maxBytes := p.defaultMaxBytes
	if job.MaxOutputBytes > 0 {
		maxBytes = job.MaxOutputBytes
	}

	opts := adapters.RunOptions{Timeout: defaultTimeout(timeoutMs), MaxBytes: maxBytes, Dir: job.WorkDir}
	if p.usesStdin {
		opts.Input = p.stdin(job)
	}
	run, err := adapters.Run(ctx, fullArgv, opts)
	if err != nil {
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "provider spawn failed: "+err.Error())
		res.Execution = &Execution{Argv: redactArgv(fullArgv), SpawnError: err.Error()}
		return res, nil
	}

	exec := &Execution{
		Argv:        redactArgv(fullArgv),
		ExitCode:    intPtr(run.ExitCode),
		DurationMs:  run.Duration.Milliseconds(),
		StdoutBytes: len(run.Stdout),
		StderrBytes: len(run.Stderr),
		Truncated:   run.Truncated,
		TimedOut:    run.TimedOut,
	}
	res.Execution = exec
	res.ProviderVersion = version

	switch {
	case run.TimedOut:
		exec.ExitDescription = "timed out"
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "provider timed out")
		return res, nil
	case run.ExitCode != 0:
		exec.ExitDescription = "non-zero exit " + fmt.Sprint(run.ExitCode)
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "provider exited non-zero: "+truncate(strings.TrimSpace(run.Stderr), 400))
		return res, nil
	}

	records, diag := p.parse(run.Stdout)
	res.Records = records
	res.Diagnostics = append(res.Diagnostics, diag...)
	if run.Truncated {
		res.Diagnostics = append(res.Diagnostics, "provider output was truncated at the configured limit")
	}
	// A zero exit code with no parsed records is a *successful empty result*, which must be
	// distinguishable from a failure, a timeout, or a malformed response. Record why it was empty
	// so an analyst does not read silence as coverage.
	if len(records) == 0 {
		if strings.TrimSpace(run.Stdout) == "" {
			res.Diagnostics = append(res.Diagnostics, "provider returned 0 records (exit 0); no output — the source may hold no data for this input")
		} else {
			res.Diagnostics = append(res.Diagnostics, "provider returned 0 usable records (exit 0); output present but did not parse")
		}
	}
	res.Coverage.Succeeded = 1
	return res, nil
}

func intPtr(v int) *int { return &v }

func defaultTimeout(ms int) time.Duration { return time.Duration(ms) * time.Millisecond }

// redactArgv masks obviously sensitive argv values in the execution record.
func redactArgv(argv []string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		out[i] = telemetry.RedactString(a)
	}
	return out
}

var versionRe = regexp.MustCompile(`\bv?(\d+\.\d+\.\d+(?:[-+][\w.]+)?)`)

func extractVersion(s string) string {
	if m := versionRe.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return "unknown"
}

// --- Parsers ---

func parseHostLines(stdout string) ([]Record, []string) {
	lines := strings.Split(stdout, "\n")
	hosts, diag := dedupeHosts(lines)
	records := make([]Record, 0, len(hosts))
	for _, h := range hosts {
		records = append(records, Record{
			Type:     TypeHostObservation,
			Host:     h,
			Status:   HostDiscovered,
			Source:   "passive",
			Provider: "external",
		})
	}
	return records, diag
}

// dnsxJSONLine is a subset of dnsx -json output.
type dnsxJSONLine struct {
	Host       string   `json:"host"`
	A          []string `json:"a"`
	AAAA       []string `json:"aaaa"`
	CNAME      []string `json:"cname"`
	MX         []string `json:"mx"`
	NS         []string `json:"ns"`
	TXT        []string `json:"txt"`
	StatusCode string   `json:"status_code"`
}

func parseDnsx(stdout string) ([]Record, []string) {
	var records []Record
	var diag []string
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var l dnsxJSONLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			diag = append(diag, "discarded malformed dnsx line: "+truncate(line, 80))
			continue
		}
		name, ok := normalizeHost(l.Host)
		if !ok {
			diag = append(diag, "discarded dnsx record with invalid host: "+truncate(l.Host, 80))
			continue
		}
		status := l.StatusCode
		if status == "" {
			status = "NOERROR"
		}
		add := func(rt string, vals []string) {
			for _, v := range vals {
				records = append(records, Record{Type: TypeDNSRecord, Name: name, RecordType: rt, Value: v, Status: status})
			}
		}
		add("A", l.A)
		add("AAAA", l.AAAA)
		add("CNAME", l.CNAME)
		add("MX", l.MX)
		add("NS", l.NS)
		add("TXT", l.TXT)
	}
	return records, diag
}
