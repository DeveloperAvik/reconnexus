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

// builtinCTLogs discovers subdomain candidates from Certificate Transparency logs via crt.sh's
// JSON API. Like rdapProvider, the request target is a shared third-party research service, not
// the authorized target, so it uses a plain HTTP client with no scope check — the same basis
// subfinder/amass/assetfinder (external passive tools) already run on. Discovered names are
// candidates only: they are revalidated against scope, like any other passive discovery output,
// the first time anything would actually act on them (DNS resolution, HTTP probing).
type builtinCTLogs struct{}

func (builtinCTLogs) Name() string            { return "builtin-ctlogs" }
func (builtinCTLogs) Kind() string            { return "SUBDOMAINS" }
func (builtinCTLogs) Capability() string      { return "PASSIVE" }
func (builtinCTLogs) NetworkBehavior() string { return "PASSIVE" }

type crtShEntry struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

func (builtinCTLogs) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	domain := pc.Job.Inputs.RootDomain
	if domain == "" {
		res := ProviderResult{}
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "rootDomain is required for CT log discovery")
		return res, nil
	}

	base := pc.Job.CtLogBaseURL
	if base == "" {
		base = os.Getenv("RECONNEXUS_CTLOG_BASE")
	}
	if base == "" {
		base = "https://crt.sh"
	}
	timeoutMs := 20000
	if pc.Job.TimeoutMs > 0 {
		timeoutMs = pc.Job.TimeoutMs
	}
	client := &http.Client{Timeout: time.Duration(timeoutMs) * time.Millisecond}

	target := fmt.Sprintf("%s/?q=%s&output=json", base, url.QueryEscape("%."+domain))
	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if rerr != nil {
		res := ProviderResult{}
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "cannot build request: "+rerr.Error())
		return res, nil
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "reconnexus/0.20 (+https://github.com/anomalyco/opencode)")

	res := ProviderResult{Coverage: Coverage{Attempted: 1}}
	resp, derr := client.Do(req)
	if derr != nil {
		res.StatusOverride = StatusSourceUnavailable
		res.Coverage.Unavailable = 1
		res.Diagnostics = append(res.Diagnostics, "crt.sh request failed: "+derr.Error())
		return res, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		res.StatusOverride = StatusSourceUnavailable
		res.Coverage.Unavailable = 1
		res.Diagnostics = append(res.Diagnostics, fmt.Sprintf("crt.sh returned HTTP %d", resp.StatusCode))
		return res, nil
	}
	body, _, rerr2 := readBounded(resp.Body, 16*1024*1024)
	if rerr2 != nil {
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "crt.sh response read failed: "+rerr2.Error())
		return res, nil
	}

	var entries []crtShEntry
	if err := json.Unmarshal([]byte(body), &entries); err != nil {
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "crt.sh response could not be parsed: "+err.Error())
		return res, nil
	}

	var lines []string
	for _, e := range entries {
		for _, raw := range strings.Split(e.CommonName+"\n"+e.NameValue, "\n") {
			raw = strings.TrimPrefix(strings.TrimSpace(raw), "*.")
			if raw == "" {
				continue
			}
			lines = append(lines, raw)
		}
	}
	hosts, diag := dedupeHosts(lines)
	res.Diagnostics = append(res.Diagnostics, diag...)

	var records []Record
	for _, h := range hosts {
		if h != domain && !strings.HasSuffix(h, "."+domain) {
			continue
		}
		records = append(records, Record{Type: TypeHostObservation, Host: h, Status: HostDiscovered, Source: "passive", Provider: "builtin-ctlogs"})
	}
	res.Records = records
	res.Coverage.Succeeded = 1
	if len(records) == 0 {
		res.Diagnostics = append(res.Diagnostics, "no in-scope hostnames found in CT log certificates")
	}
	return res, nil
}
