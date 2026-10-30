package discovery

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/reconnexus/workers/internal/scope"
	"github.com/reconnexus/workers/internal/telemetry"
)

var registry = map[string]Provider{}

func register(p Provider) { registry[p.Name()] = p }

func init() {
	register(&externalProvider{
		name: "subfinder", kind: "SUBDOMAINS", capability: "PASSIVE", networkBehavior: "PASSIVE",
		versionArgs: []string{"-version"},
		buildArgv: func(job Job) ([]string, error) {
			if job.Inputs.RootDomain == "" {
				return nil, fmt.Errorf("rootDomain required")
			}
			return []string{"-d", job.Inputs.RootDomain, "-silent"}, nil
		},
		parse:            parseHostLines,
		defaultTimeoutMs: 600000,
		defaultMaxBytes:  16 * 1024 * 1024,
	})
	register(&externalProvider{
		name: "assetfinder", kind: "SUBDOMAINS", capability: "PASSIVE", networkBehavior: "PASSIVE",
		buildArgv: func(job Job) ([]string, error) {
			if job.Inputs.RootDomain == "" {
				return nil, fmt.Errorf("rootDomain required")
			}
			return []string{"--subs-only", job.Inputs.RootDomain}, nil
		},
		parse:            parseHostLines,
		defaultTimeoutMs: 300000,
		defaultMaxBytes:  8 * 1024 * 1024,
	})
	register(&externalProvider{
		name: "amass", kind: "SUBDOMAINS", capability: "PASSIVE", networkBehavior: "PASSIVE",
		versionArgs: []string{"-version"},
		buildArgv: func(job Job) ([]string, error) {
			if job.Inputs.RootDomain == "" {
				return nil, fmt.Errorf("rootDomain required")
			}
			return []string{"enum", "-passive", "-d", job.Inputs.RootDomain, "-silent"}, nil
		},
		parse:            parseHostLines,
		defaultTimeoutMs: 900000,
		defaultMaxBytes:  32 * 1024 * 1024,
	})
	register(&externalProvider{
		name: "dnsx", kind: "DNS", capability: "DNS", networkBehavior: "ACTIVE",
		versionArgs: []string{"-version"},
		buildArgv: func(job Job) ([]string, error) {
			return []string{"-json", "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-silent"}, nil
		},
		usesStdin:        true,
		stdin:            func(job Job) string { return strings.Join(job.Inputs.Names, "\n") },
		parse:            parseDnsx,
		defaultTimeoutMs: 300000,
		defaultMaxBytes:  16 * 1024 * 1024,
	})
	register(builtinDNS{})
	register(builtinHTTP{})
	register(mockProvider{})
	register(offlineIPMeta{})
	register(rdapProvider{})
	register(builtinCrawler{})
	register(builtinStatic{})
	register(newGauProvider())
	register(newWaybackProvider())
	register(katanaProvider{})
	register(mockURLProvider{})
	register(builtinJSProvider{})
	register(builtinAPIProvider{})
	register(builtinSecurityMeta{})
	register(builtinSecretScan{})
	register(builtinTakeover{})
	register(builtinLoginFinder{})
	register(nmapProvider{})
	register(nucleiProvider{})
	register(builtinContent{})
	register(builtinCloudStorage{})
	register(builtinCorsRedirect{})
	register(builtinEmailSecurity{})
}

// Run executes a discovery job and returns a truthful result. An error is returned only
// for an internal failure; provider problems are encoded in the result status.
func Run(ctx context.Context, job Job, logger *telemetry.Logger) (Result, error) {
	if logger == nil {
		logger = telemetry.New(nil, telemetry.Info)
	}
	engine := scope.NewEngine(&job.Policy)
	engine.AllowRestrictedAddress = job.AllowRestrictedAddresses

	base := Result{
		SchemaVersion:   1,
		Provider:        job.Provider,
		ProviderVersion: "unknown",
		Diagnostics:     []string{},
		Records:         []Record{},
	}

	prov, ok := registry[job.Provider]
	if !ok {
		base.Status = StatusBlocked
		base.Coverage.Attempted = 1
		base.Coverage.Skipped = 1
		base.Diagnostics = append(base.Diagnostics, "unknown provider: "+job.Provider)
		return finalizeResult(base), nil
	}
	if k := prov.Kind(); k != "" && k != job.Kind {
		base.Status = StatusFailed
		base.Coverage.Attempted = 1
		base.Coverage.Failed = 1
		base.Diagnostics = append(base.Diagnostics, fmt.Sprintf("provider %s does not support kind %s", job.Provider, job.Kind))
		return finalizeResult(base), nil
	}
	requiredCap := prov.Capability()
	if requiredCap != "" && !capAllowed(job.Policy, requiredCap) {
		base.Status = StatusBlocked
		base.Coverage.Attempted = 1
		base.Coverage.Skipped = 1
		base.Diagnostics = append(base.Diagnostics, fmt.Sprintf("capability %s is not authorized by the policy", requiredCap))
		return finalizeResult(base), nil
	}

	// Scope-filter inputs. Discovered assets are never auto-authorized: every name that will
	// be actively resolved and every host through which an address is correlated must pass
	// an independent scope check here in the worker.
	skipped := 0
	filterCap := requiredCap
	if filterCap == "" {
		filterCap = "DNS"
	}
	switch job.Kind {
	case "SUBDOMAINS":
		if job.Inputs.RootDomain == "" {
			base.Status = StatusFailed
			base.Coverage.Attempted = 1
			base.Coverage.Failed = 1
			base.Diagnostics = append(base.Diagnostics, "rootDomain is required for subdomain discovery")
			return finalizeResult(base), nil
		}
		d := engine.Check(scope.Request{Kind: "DOMAIN", Value: job.Inputs.RootDomain, Capability: requiredCapOr(requiredCap, "PASSIVE")})
		if !d.Allowed {
			base.Status = StatusBlocked
			base.Coverage.Attempted = 1
			base.Coverage.Skipped = 1
			base.Diagnostics = append(base.Diagnostics, "root domain is not authorized: "+d.Reason)
			return finalizeResult(base), nil
		}
	case "DNS":
		names := make([]string, 0, len(job.Inputs.Names))
		for _, n := range job.Inputs.Names {
			d := engine.Check(scope.Request{Kind: "HOST", Value: n, Capability: filterCap})
			if d.Allowed {
				names = append(names, n)
			} else {
				skipped++
			}
		}
		addrs := make([]AddressInput, 0, len(job.Inputs.Addresses))
		for _, a := range job.Inputs.Addresses {
			d := engine.Check(scope.Request{Kind: "HOST", Value: a.ViaHost, Capability: filterCap})
			if d.Allowed {
				addrs = append(addrs, a)
			} else {
				skipped++
			}
		}
		job.Inputs.Names = names
		job.Inputs.Addresses = addrs
		if len(names) == 0 && len(addrs) == 0 {
			base.Status = StatusSkipped
			base.Coverage.Attempted = skipped
			base.Coverage.Skipped = skipped
			base.Diagnostics = append(base.Diagnostics, "all inputs were out of scope; nothing resolved")
			return finalizeResult(base), nil
		}
	case "IP_METADATA":
		addrs := make([]AddressInput, 0, len(job.Inputs.Addresses))
		for _, a := range job.Inputs.Addresses {
			d := engine.Check(scope.Request{Kind: "HOST", Value: a.ViaHost, Capability: filterCap})
			if d.Allowed {
				addrs = append(addrs, a)
			} else {
				skipped++
			}
		}
		job.Inputs.Addresses = addrs
		if len(addrs) == 0 {
			base.Status = StatusSkipped
			base.Coverage.Attempted = skipped
			base.Coverage.Skipped = skipped
			base.Diagnostics = append(base.Diagnostics, "all addresses were out of scope; nothing correlated")
			return finalizeResult(base), nil
		}
	case "HTTP_PROBE":
		urls := make([]string, 0, len(job.Inputs.URLs))
		for _, u := range job.Inputs.URLs {
			d := engine.Check(scope.Request{Kind: "URL", Value: u, Capability: requiredCapOr(requiredCap, "ACTIVE_HTTP")})
			if d.Allowed {
				urls = append(urls, u)
			} else {
				skipped++
			}
		}
		job.Inputs.URLs = urls
		if len(urls) == 0 {
			base.Status = StatusSkipped
			base.Coverage.Attempted = skipped
			base.Coverage.Skipped = skipped
			base.Diagnostics = append(base.Diagnostics, "all HTTP targets were out of scope; nothing probed")
			return finalizeResult(base), nil
		}
	case "JS_ANALYSIS":
		js := make([]string, 0, len(job.Inputs.JSURLs))
		for _, u := range job.Inputs.JSURLs {
			d := engine.Check(scope.Request{Kind: "URL", Value: u, Capability: "JS_ANALYSIS"})
			if d.Allowed {
				js = append(js, u)
			} else {
				skipped++
			}
		}
		job.Inputs.JSURLs = js
		if len(js) == 0 {
			base.Status = StatusSkipped
			base.Coverage.Attempted = skipped
			base.Coverage.Skipped = skipped
			base.Diagnostics = append(base.Diagnostics, "all JavaScript URLs were out of scope; nothing analysed")
			return finalizeResult(base), nil
		}
	case "API_SPEC":
		specs := make([]string, 0, len(job.Inputs.SpecURLs))
		for _, u := range job.Inputs.SpecURLs {
			d := engine.Check(scope.Request{Kind: "URL", Value: u, Capability: "API_DISCOVERY"})
			if d.Allowed {
				specs = append(specs, u)
			} else {
				skipped++
			}
		}
		probes := make([]string, 0, len(job.Inputs.SpecProbeURLs))
		for _, u := range job.Inputs.SpecProbeURLs {
			d := engine.Check(scope.Request{Kind: "URL", Value: u, Capability: "API_DISCOVERY"})
			if d.Allowed {
				probes = append(probes, u)
			} else {
				skipped++
			}
		}
		job.Inputs.SpecURLs = specs
		job.Inputs.SpecProbeURLs = probes
		if len(specs) == 0 && len(probes) == 0 {
			base.Status = StatusSkipped
			base.Coverage.Attempted = skipped
			base.Coverage.Skipped = skipped
			base.Diagnostics = append(base.Diagnostics, "all API specification URLs were out of scope; nothing parsed")
			return finalizeResult(base), nil
		}
	case "SECURITY_META":
		urls := make([]string, 0, len(job.Inputs.URLs))
		for _, u := range job.Inputs.URLs {
			d := engine.Check(scope.Request{Kind: "URL", Value: u, Capability: "SECURITY_CHECKS"})
			if d.Allowed {
				urls = append(urls, u)
			} else {
				skipped++
			}
		}
		job.Inputs.URLs = urls
		if len(urls) == 0 {
			base.Status = StatusSkipped
			base.Coverage.Attempted = skipped
			base.Coverage.Skipped = skipped
			base.Diagnostics = append(base.Diagnostics, "all services were out of scope; no metadata collected")
			return finalizeResult(base), nil
		}
	case "TAKEOVER":
		urls := make([]string, 0, len(job.Inputs.URLs))
		for _, u := range job.Inputs.URLs {
			d := engine.Check(scope.Request{Kind: "URL", Value: u, Capability: "TAKEOVER_CHECK"})
			if d.Allowed {
				urls = append(urls, u)
			} else {
				skipped++
			}
		}
		job.Inputs.URLs = urls
		if len(urls) == 0 {
			base.Status = StatusSkipped
			base.Coverage.Attempted = skipped
			base.Coverage.Skipped = skipped
			base.Diagnostics = append(base.Diagnostics, "all hosts were out of scope; no takeover checks performed")
			return finalizeResult(base), nil
		}
	case "LOGIN_FINDER":
		urls := make([]string, 0, len(job.Inputs.URLs))
		for _, u := range job.Inputs.URLs {
			d := engine.Check(scope.Request{Kind: "URL", Value: u, Capability: requiredCapOr(requiredCap, "ACTIVE_HTTP")})
			if d.Allowed {
				urls = append(urls, u)
			} else {
				skipped++
			}
		}
		job.Inputs.URLs = urls
		if len(urls) == 0 {
			base.Status = StatusSkipped
			base.Coverage.Attempted = skipped
			base.Coverage.Skipped = skipped
			base.Diagnostics = append(base.Diagnostics, "all origins were out of scope; no interface checks performed")
			return finalizeResult(base), nil
		}
	case "CLOUD_STORAGE":
		cands := make([]CloudStorageCandidate, 0, len(job.Inputs.CloudCandidates))
		for _, c := range job.Inputs.CloudCandidates {
			d := engine.Check(scope.Request{Kind: "URL", Value: c.URL, Capability: requiredCapOr(requiredCap, "CLOUD_STORAGE_CHECK")})
			if d.Allowed {
				cands = append(cands, c)
			} else {
				skipped++
			}
		}
		job.Inputs.CloudCandidates = cands
		if len(cands) == 0 {
			base.Status = StatusSkipped
			base.Coverage.Attempted = skipped
			base.Coverage.Skipped = skipped
			base.Diagnostics = append(base.Diagnostics, "all candidates were out of scope; no cloud storage checks performed")
			return finalizeResult(base), nil
		}
	case "CONTENT_DISCOVERY":
		urls := make([]string, 0, len(job.Inputs.URLs))
		for _, u := range job.Inputs.URLs {
			d := engine.Check(scope.Request{Kind: "URL", Value: u, Capability: requiredCapOr(requiredCap, "CONTENT_DISCOVERY")})
			if d.Allowed {
				urls = append(urls, u)
			} else {
				skipped++
			}
		}
		job.Inputs.URLs = urls
		if len(urls) == 0 {
			base.Status = StatusSkipped
			base.Coverage.Attempted = skipped
			base.Coverage.Skipped = skipped
			base.Diagnostics = append(base.Diagnostics, "all origins were out of scope; no content discovery performed")
			return finalizeResult(base), nil
		}
	case "EMAIL_SECURITY":
		names := make([]string, 0, len(job.Inputs.Names))
		for _, n := range job.Inputs.Names {
			d := engine.Check(scope.Request{Kind: "HOST", Value: n, Capability: filterCap})
			if d.Allowed {
				names = append(names, n)
			} else {
				skipped++
			}
		}
		job.Inputs.Names = names
		if len(names) == 0 {
			base.Status = StatusSkipped
			base.Coverage.Attempted = skipped
			base.Coverage.Skipped = skipped
			base.Diagnostics = append(base.Diagnostics, "all domains were out of scope; no email security checks performed")
			return finalizeResult(base), nil
		}
	case "CORS_REDIRECT":
		urls := make([]string, 0, len(job.Inputs.URLs))
		for _, u := range job.Inputs.URLs {
			d := engine.Check(scope.Request{Kind: "URL", Value: u, Capability: requiredCapOr(requiredCap, "CORS_REDIRECT_CHECK")})
			if d.Allowed {
				urls = append(urls, u)
			} else {
				skipped++
			}
		}
		job.Inputs.URLs = urls
		cands := make([]RedirectCandidate, 0, len(job.Inputs.RedirectCandidates))
		for _, c := range job.Inputs.RedirectCandidates {
			d := engine.Check(scope.Request{Kind: "URL", Value: c.URL, Capability: requiredCapOr(requiredCap, "CORS_REDIRECT_CHECK")})
			if d.Allowed {
				cands = append(cands, c)
			} else {
				skipped++
			}
		}
		job.Inputs.RedirectCandidates = cands
		if len(urls) == 0 && len(cands) == 0 {
			base.Status = StatusSkipped
			base.Coverage.Attempted = skipped
			base.Coverage.Skipped = skipped
			base.Diagnostics = append(base.Diagnostics, "all targets were out of scope; no CORS or redirect checks performed")
			return finalizeResult(base), nil
		}
	case "PORT_SCAN":
		if err := validatePorts(job.Inputs.Ports); err != nil {
			base.Status = StatusFailed
			base.Coverage.Attempted = 1
			base.Coverage.Failed = 1
			base.Diagnostics = append(base.Diagnostics, "invalid port selection: "+err.Error())
			return finalizeResult(base), nil
		}
		// Each address is checked against the host it was reached through, with the address itself
		// passed for address-space classification, so a name that resolves to restricted space is
		// denied here regardless of what the control plane sent.
		addrs := make([]AddressInput, 0, len(job.Inputs.Addresses))
		for _, a := range job.Inputs.Addresses {
			if _, err := netip.ParseAddr(a.IP); err != nil {
				skipped++
				continue
			}
			d := engine.Check(scope.Request{Kind: "HOST", Value: a.ViaHost, Capability: requiredCapOr(requiredCap, "PORT_SCAN"), ResolvedAddresses: []string{a.IP}})
			if d.Allowed {
				addrs = append(addrs, a)
			} else {
				skipped++
			}
		}
		job.Inputs.Addresses = addrs
		if len(addrs) == 0 {
			base.Status = StatusSkipped
			base.Coverage.Attempted = skipped
			base.Coverage.Skipped = skipped
			base.Diagnostics = append(base.Diagnostics, "all addresses were out of scope; no ports scanned")
			return finalizeResult(base), nil
		}
	case "TEMPLATE_CHECK":
		if err := validateTemplateTags(job.Inputs.TemplateTags); err != nil {
			base.Status = StatusFailed
			base.Coverage.Attempted = 1
			base.Coverage.Failed = 1
			base.Diagnostics = append(base.Diagnostics, "invalid template tags: "+err.Error())
			return finalizeResult(base), nil
		}
		urls := make([]string, 0, len(job.Inputs.URLs))
		for _, u := range job.Inputs.URLs {
			d := engine.Check(scope.Request{Kind: "URL", Value: u, Capability: requiredCapOr(requiredCap, "ACTIVE_TEMPLATE_CHECK")})
			if d.Allowed {
				urls = append(urls, u)
			} else {
				skipped++
			}
		}
		job.Inputs.URLs = urls
		if len(urls) == 0 {
			base.Status = StatusSkipped
			base.Coverage.Attempted = skipped
			base.Coverage.Skipped = skipped
			base.Diagnostics = append(base.Diagnostics, "all targets were out of scope; no templates run")
			return finalizeResult(base), nil
		}
	case "SECRET_SCAN":
		arts := make([]string, 0, len(job.Inputs.ArtifactURLs))
		for _, u := range job.Inputs.ArtifactURLs {
			d := engine.Check(scope.Request{Kind: "URL", Value: u, Capability: "SECRET_SCAN"})
			if d.Allowed {
				arts = append(arts, u)
			} else {
				skipped++
			}
		}
		job.Inputs.ArtifactURLs = arts
		if len(arts) == 0 {
			base.Status = StatusSkipped
			base.Coverage.Attempted = skipped
			base.Coverage.Skipped = skipped
			base.Diagnostics = append(base.Diagnostics, "all artifacts were out of scope; nothing scanned")
			return finalizeResult(base), nil
		}
	case "URL_COLLECTION":
		// The mock provider has no capability and reads a fixture; skip input filtering for it.
		if requiredCap != "" {
			seeds := make([]string, 0, len(job.Inputs.SeedURLs))
			for _, u := range job.Inputs.SeedURLs {
				d := engine.Check(scope.Request{Kind: "URL", Value: u, Capability: requiredCap})
				if d.Allowed {
					seeds = append(seeds, u)
				} else {
					skipped++
				}
			}
			domains := make([]string, 0, len(job.Inputs.Domains))
			for _, dom := range job.Inputs.Domains {
				d := engine.Check(scope.Request{Kind: "DOMAIN", Value: dom, Capability: requiredCapOr(requiredCap, "PASSIVE")})
				if d.Allowed {
					domains = append(domains, dom)
				} else {
					skipped++
				}
			}
			job.Inputs.SeedURLs = seeds
			job.Inputs.Domains = domains
			if len(seeds) == 0 && len(domains) == 0 {
				base.Status = StatusSkipped
				base.Coverage.Attempted = skipped
				base.Coverage.Skipped = skipped
				base.Diagnostics = append(base.Diagnostics, "all URL-collection inputs were out of scope; nothing collected")
				return finalizeResult(base), nil
			}
		}
	}

	pc := ProviderContext{Job: job, Engine: engine, Logger: logger, Limiter: newRateLimiter(job.Limits.RequestsPerSecond)}
	pr, err := prov.Run(ctx, pc)
	if err != nil {
		base.Status = StatusFailed
		base.Coverage.Attempted = unitCount(job)
		base.Coverage.Failed = 1
		base.Diagnostics = append(base.Diagnostics, "internal provider error: "+err.Error())
		return finalizeResult(base), nil
	}

	base.Records = pr.Records
	base.Coverage = pr.Coverage
	base.Coverage.Skipped += skipped
	if base.Coverage.Attempted == 0 {
		base.Coverage.Attempted = unitCount(job)
	}
	base.Diagnostics = append(base.Diagnostics, pr.Diagnostics...)
	if pr.Execution != nil {
		base.Execution = *pr.Execution
	}
	if pr.ProviderVersion != "" {
		base.ProviderVersion = pr.ProviderVersion
	}

	base.Status = deriveStatus(ctx, pr, base.Coverage)
	// Normalize nil slices so the JSON contract (arrays, not null) is always satisfied.
	if base.Execution.Argv == nil {
		base.Execution.Argv = []string{}
	}
	if base.Records == nil {
		base.Records = []Record{}
	}
	if base.Diagnostics == nil {
		base.Diagnostics = []string{}
	}
	// Records carry nested slices and maps of their own; a nil one would marshal as null and
	// fail the control plane's schema validation for the entire run.
	NormalizeRecords(base.Records)
	logger.Info("discovery job finished", map[string]any{
		"scanId": job.ScanID, "provider": job.Provider, "kind": job.Kind, "status": base.Status, "records": len(base.Records),
	})
	return finalizeResult(base), nil
}

// finalizeResult guarantees the JSON shape required by the discovery contract on every return
// path, including early exits such as an unknown provider or an all-out-of-scope input set. Without
// this, a nil Execution.Argv marshals as null and the control plane rejects the entire result with
// a schema error that hides the real reason (for example, a stale worker binary).
func finalizeResult(r Result) Result {
	if r.Execution.Argv == nil {
		r.Execution.Argv = []string{}
	}
	if r.Records == nil {
		r.Records = []Record{}
	}
	if r.Diagnostics == nil {
		r.Diagnostics = []string{}
	}
	NormalizeRecords(r.Records)
	return r
}

func deriveStatus(ctx context.Context, pr ProviderResult, cov Coverage) string {
	if pr.StatusOverride != "" {
		return pr.StatusOverride
	}
	if ctx.Err() != nil {
		return StatusCancelled
	}
	if cov.Failed > 0 && cov.Succeeded > 0 {
		return StatusPartial
	}
	if cov.Failed > 0 && cov.Succeeded == 0 {
		return StatusFailed
	}
	return StatusSucceeded
}

func unitCount(job Job) int {
	switch job.Kind {
	case "SUBDOMAINS":
		return 1
	case "DNS":
		return len(job.Inputs.Names) + len(job.Inputs.Addresses)
	case "IP_METADATA":
		return len(job.Inputs.Addresses)
	case "HTTP_PROBE":
		return len(job.Inputs.URLs)
	case "URL_COLLECTION":
		n := len(job.Inputs.SeedURLs) + len(job.Inputs.Domains)
		if n == 0 {
			return 1
		}
		return n
	case "JS_ANALYSIS":
		return len(job.Inputs.JSURLs)
	case "API_SPEC":
		return len(job.Inputs.SpecURLs) + len(job.Inputs.SpecProbeURLs)
	case "SECURITY_META":
		return len(job.Inputs.URLs)
	case "SECRET_SCAN":
		return len(job.Inputs.ArtifactURLs)
	case "TAKEOVER":
		return len(job.Inputs.URLs)
	case "LOGIN_FINDER":
		return len(job.Inputs.URLs)
	case "PORT_SCAN":
		return len(job.Inputs.Addresses)
	case "TEMPLATE_CHECK":
		return len(job.Inputs.URLs)
	case "CONTENT_DISCOVERY":
		return len(job.Inputs.URLs)
	case "CLOUD_STORAGE":
		return len(job.Inputs.CloudCandidates)
	case "CORS_REDIRECT":
		return len(job.Inputs.URLs) + len(job.Inputs.RedirectCandidates)
	case "EMAIL_SECURITY":
		return len(job.Inputs.Names)
	}
	return 1
}

func capAllowed(p scope.Policy, cap string) bool {
	for _, c := range p.Authorization.Capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

func requiredCapOr(cap, fallback string) string {
	if cap == "" {
		return fallback
	}
	return cap
}

// Providers returns the registered provider names (for diagnostics/tests).
func Providers() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	return out
}
