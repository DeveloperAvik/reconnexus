package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

// builtinGithubLeaks searches GitHub's public code search API for mentions of the target domain
// in public repositories. Like rdapProvider and builtinCTLogs, the request target is a
// third-party service, never the target itself, so it uses a plain HTTP client with no scope
// check. GitHub's code search API requires an authenticated token; without one this provider
// reports SOURCE_UNAVAILABLE rather than failing, the same way nmap/nuclei report an unavailable
// binary.
type builtinGithubLeaks struct{}

func (builtinGithubLeaks) Name() string            { return "builtin-github-leaks" }
func (builtinGithubLeaks) Kind() string            { return "GITHUB_LEAK_SEARCH" }
func (builtinGithubLeaks) Capability() string      { return "GITHUB_LEAK_SEARCH" }
func (builtinGithubLeaks) NetworkBehavior() string { return "PASSIVE" }

const githubTokenEnv = "RECONNEXUS_GITHUB_TOKEN"

type githubSearchResponse struct {
	Items []githubSearchItem `json:"items"`
}

type githubSearchItem struct {
	Path       string  `json:"path"`
	SHA        string  `json:"sha"`
	HTMLURL    string  `json:"html_url"`
	Score      float64 `json:"score"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	TextMatches []struct {
		Fragment string `json:"fragment"`
	} `json:"text_matches"`
}

func (builtinGithubLeaks) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	domain := pc.Job.Inputs.RootDomain
	res := ProviderResult{}
	if domain == "" {
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "rootDomain is required for GitHub leak search")
		return res, nil
	}
	token := os.Getenv(githubTokenEnv)
	if token == "" {
		res.StatusOverride = StatusSourceUnavailable
		res.Coverage.Unavailable = 1
		res.Diagnostics = append(res.Diagnostics, "GitHub API token not configured (set "+githubTokenEnv+")")
		return res, nil
	}
	base := pc.Job.GithubAPIBase
	if base == "" {
		base = os.Getenv("RECONNEXUS_GITHUB_API_BASE")
	}
	if base == "" {
		base = "https://api.github.com"
	}
	timeoutMs := 20000
	if pc.Job.TimeoutMs > 0 {
		timeoutMs = pc.Job.TimeoutMs
	}
	client := &http.Client{Timeout: time.Duration(timeoutMs) * time.Millisecond}

	target := fmt.Sprintf("%s/search/code?q=%s&per_page=20", base, url.QueryEscape("\""+domain+"\""))
	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if rerr != nil {
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "cannot build request: "+rerr.Error())
		return res, nil
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.text-match+json")
	req.Header.Set("User-Agent", "reconnexus/0.20 (+https://github.com/anomalyco/opencode)")

	res.Coverage.Attempted = 1
	resp, derr := client.Do(req)
	if derr != nil {
		res.StatusOverride = StatusSourceUnavailable
		res.Coverage.Unavailable = 1
		res.Diagnostics = append(res.Diagnostics, "GitHub search request failed: "+derr.Error())
		return res, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		res.StatusOverride = StatusSourceUnavailable
		res.Coverage.Unavailable = 1
		res.Diagnostics = append(res.Diagnostics, fmt.Sprintf("GitHub search returned HTTP %d", resp.StatusCode))
		return res, nil
	}
	body, _, rerr2 := readBounded(resp.Body, 8*1024*1024)
	if rerr2 != nil {
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "GitHub search response read failed: "+rerr2.Error())
		return res, nil
	}
	var parsed githubSearchResponse
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "GitHub search response could not be parsed: "+err.Error())
		return res, nil
	}

	key := []byte(os.Getenv(hmacKeyEnv))
	suppressed := suppressedRules()
	var records []Record
	for _, item := range parsed.Items {
		fragment := ""
		if len(item.TextMatches) > 0 {
			fragment = item.TextMatches[0].Fragment
		}
		evidence := truncate(redactAllRuleMatches(fragment), 300)
		records = append(records, Record{
			Type: TypeGithubCodeMatch, URL: item.HTMLURL, Host: domain, Provider: "builtin-github-leaks", Source: "github",
			GithubMatch: &GithubCodeMatchInfo{
				Query: domain, Repository: item.Repository.FullName, Path: item.Path, SHA: item.SHA, Score: item.Score,
				Evidence: evidence, EvidenceType: "CODE_MATCH",
			},
		})
		for _, tm := range item.TextMatches {
			records = append(records, scanText(tm.Fragment, item.HTMLURL, domain, key, suppressed)...)
		}
	}
	res.Records = records
	res.Coverage.Succeeded = 1
	if len(records) == 0 {
		res.Diagnostics = append(res.Diagnostics, "no public GitHub code mentions found")
	}
	return res, nil
}
