// katana external crawler integration (opt-in).

package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/reconnexus/workers/internal/matching"
)

// katanaProvider wraps the katana crawler (opt-in; see docs). It runs with redirects disabled and
// a scope regex, and every returned URL is re-checked against the scope policy.
type katanaProvider struct{}

func (katanaProvider) Name() string            { return "katana" }
func (katanaProvider) Kind() string            { return "URL_COLLECTION" }
func (katanaProvider) Capability() string      { return "CRAWL" }
func (katanaProvider) NetworkBehavior() string { return "ACTIVE" }

func (katanaProvider) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	inner := &externalProvider{
		name: "katana", kind: "URL_COLLECTION", capability: "CRAWL", networkBehavior: "ACTIVE",
		versionArgs: []string{"-version"},
		buildArgv: func(job Job) ([]string, error) {
			if len(job.Inputs.SeedURLs) == 0 {
				return nil, errors.New("seedUrls required")
			}
			depth := job.Inputs.CrawlDepth
			if depth <= 0 {
				depth = defaultCrawlDepth
			}
			conc := job.Limits.MaxConcurrency
			if conc <= 0 {
				conc = 10
			}
			timeout := job.RequestTimeoutMs / 1000
			if timeout <= 0 {
				timeout = 10
			}
			argv := []string{"-u", job.Inputs.SeedURLs[0], "-d", fmt.Sprint(depth), "-c", fmt.Sprint(conc), "-timeout", fmt.Sprint(timeout), "-jsonl", "-silent", "-nc", "-dr"}
			if re := scopeRegex(job); re != "" {
				argv = append(argv, "-cs", re)
			}
			return argv, nil
		},
		parse:            parseKatanaJSONL,
		defaultTimeoutMs: 600000,
		defaultMaxBytes:  64 * 1024 * 1024,
	}
	pr, err := inner.Run(ctx, pc)
	if err != nil {
		return pr, err
	}
	return filterExternal(ctx, pc, pr, "katana", "CRAWL", MethodCrawl), nil
}

func scopeRegex(job Job) string {
	var parts []string
	for _, d := range job.Policy.InScope.Domains {
		parts = append(parts, regexp.QuoteMeta(d.Value))
	}
	for _, h := range job.Policy.InScope.Hosts {
		parts = append(parts, regexp.QuoteMeta(h))
	}
	if len(parts) == 0 {
		return ""
	}
	return "(?:^|\\.)(?:" + strings.Join(parts, "|") + ")$"
}

type katanaLine struct {
	Request struct {
		Endpoint string `json:"endpoint"`
		Method   string `json:"method"`
	} `json:"request"`
	Response struct {
		StatusCode int `json:"status_code"`
	} `json:"response"`
}

func parseKatanaJSONL(stdout string) ([]Record, []string) {
	var records []Record
	var diagnostics []string
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var l katanaLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			diagnostics = append(diagnostics, "discarded malformed katana line: "+truncate(line, 80))
			continue
		}
		ep := strings.TrimSpace(l.Request.Endpoint)
		if ep == "" {
			continue
		}
		canon, err := matching.CanonicalURL(ep)
		if err != nil {
			diagnostics = append(diagnostics, "discarded non-http katana endpoint: "+truncate(ep, 80))
			continue
		}
		records = append(records, Record{Type: "URL_PLACEHOLDER", URL: ep, CanonicalURL: canon})
	}
	return records, diagnostics
}
