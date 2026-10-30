package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// builtinWaybackDiff compares the Wayback Machine's CDX index for the target domain against the
// URLs this scan has already observed, to surface paths that were once archived returning a
// successful response but are not linked anywhere this scan's own crawl reached — candidates for
// a forgotten-but-possibly-still-live endpoint. Like rdapProvider/builtinCTLogs/
// builtinGithubLeaks, the request target is a third-party archive, never the target itself, so
// it uses a plain HTTP client with no scope check. This is never a live check: a diffed path is
// not requested again here, only compared against what was already observed, so its confidence
// is capped accordingly.
type builtinWaybackDiff struct{}

func (builtinWaybackDiff) Name() string            { return "builtin-wayback-diff" }
func (builtinWaybackDiff) Kind() string            { return "WAYBACK_DIFF" }
func (builtinWaybackDiff) Capability() string      { return "WAYBACK_DIFF" }
func (builtinWaybackDiff) NetworkBehavior() string { return "PASSIVE" }

const maxWaybackDiffRecords = 100

func (builtinWaybackDiff) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	domain := pc.Job.Inputs.RootDomain
	res := ProviderResult{}
	if domain == "" {
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "rootDomain is required for Wayback diffing")
		return res, nil
	}
	base := pc.Job.WaybackAPIBase
	if base == "" {
		base = os.Getenv("RECONNEXUS_WAYBACK_BASE")
	}
	if base == "" {
		base = "https://web.archive.org"
	}
	timeoutMs := 30000
	if pc.Job.TimeoutMs > 0 {
		timeoutMs = pc.Job.TimeoutMs
	}
	client := &http.Client{Timeout: time.Duration(timeoutMs) * time.Millisecond}

	target := fmt.Sprintf("%s/cdx/search/cdx?url=%s&output=json&fl=timestamp,original,statuscode,mimetype&collapse=urlkey&limit=5000",
		base, url.QueryEscape(domain+"/*"))
	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if rerr != nil {
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "cannot build request: "+rerr.Error())
		return res, nil
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "reconnexus/0.20 (+https://github.com/anomalyco/opencode)")

	res.Coverage.Attempted = 1
	resp, derr := client.Do(req)
	if derr != nil {
		res.StatusOverride = StatusSourceUnavailable
		res.Coverage.Unavailable = 1
		res.Diagnostics = append(res.Diagnostics, "Wayback CDX request failed: "+derr.Error())
		return res, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		res.StatusOverride = StatusSourceUnavailable
		res.Coverage.Unavailable = 1
		res.Diagnostics = append(res.Diagnostics, fmt.Sprintf("Wayback CDX returned HTTP %d", resp.StatusCode))
		return res, nil
	}
	body, _, rerr2 := readBounded(resp.Body, 16*1024*1024)
	if rerr2 != nil {
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "Wayback CDX response read failed: "+rerr2.Error())
		return res, nil
	}

	var rows [][]string
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "Wayback CDX response could not be parsed: "+err.Error())
		return res, nil
	}
	if len(rows) == 0 {
		res.Coverage.Succeeded = 1
		res.Diagnostics = append(res.Diagnostics, "Wayback CDX returned no archived captures")
		return res, nil
	}

	observed := map[string]bool{}
	for _, u := range pc.Job.Inputs.URLs {
		observed[canonicalPathKey(u)] = true
	}

	var records []Record
	seen := map[string]bool{}
	for _, row := range rows[1:] { // rows[0] is the ["timestamp","original","statuscode","mimetype"] header
		if len(row) < 4 {
			continue
		}
		timestamp, original, statusCode, mimeType := row[0], row[1], row[2], row[3]
		if statusCode != "200" {
			continue
		}
		key := canonicalPathKey(original)
		if key == "" || observed[key] || seen[key] {
			continue
		}
		seen[key] = true
		records = append(records, Record{
			Type: TypeWaybackDiff, URL: original, Host: domain, Provider: "builtin-wayback-diff", Source: "wayback",
			WaybackDiff: &WaybackDiffInfo{
				FirstSeen: timestamp, LastStatus: 200, MimeType: mimeType, Confidence: 0.5,
				Evidence:     "archived by the Wayback Machine returning HTTP 200, but not observed by this scan's own crawl",
				EvidenceType: "NOT_CURRENTLY_OBSERVED",
			},
		})
		if len(records) >= maxWaybackDiffRecords {
			break
		}
	}
	res.Records = records
	res.Coverage.Succeeded = 1
	if len(records) == 0 {
		res.Diagnostics = append(res.Diagnostics, "no archived path differs from what this scan already observed")
	}
	return res, nil
}

// canonicalPathKey reduces a URL to host+path (lowercased, no scheme/query/fragment, no
// trailing slash except for the root) so Wayback's own URL and this scan's crawled URL can be
// compared regardless of query-string or scheme differences.
func canonicalPathKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	return strings.ToLower(u.Hostname()) + path
}
