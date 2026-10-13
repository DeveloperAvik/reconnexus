package discovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/reconnexus/workers/internal/matching"
)

// --- builtin-dns: forward and reverse DNS via the Go resolver ---

type builtinDNS struct{}

// hostResolver is the subset of *net.Resolver used by the built-in DNS provider. It is an
// interface so tests can inject a deterministic resolver.
type hostResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// resolverFactory builds a resolver for a job. Overridden in tests.
var resolverFactory = defaultResolverFactory

func defaultResolverFactory(job Job) hostResolver {
	if job.ResolverAddress != "" {
		addr := job.ResolverAddress
		return &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", addr)
			},
		}
	}
	return net.DefaultResolver
}

func (builtinDNS) Name() string            { return "builtin-dns" }
func (builtinDNS) Kind() string            { return "DNS" }
func (builtinDNS) Capability() string      { return "DNS" }
func (builtinDNS) NetworkBehavior() string { return "ACTIVE" }

func (builtinDNS) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{Coverage: Coverage{Attempted: len(job.Inputs.Names) + len(job.Inputs.Addresses)}}

	resolver := resolverFactory(job)

	wildcardAddrs := map[string]struct{}{}
	if job.Inputs.RootDomain != "" {
		if set, ok := detectWildcard(ctx, resolver, job.Inputs.RootDomain); ok {
			for a := range set {
				wildcardAddrs[a] = struct{}{}
			}
			res.Diagnostics = append(res.Diagnostics, fmt.Sprintf("wildcard DNS detected under %s (%d address(es))", job.Inputs.RootDomain, len(set)))
		}
	}

	concurrency := job.Limits.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 10
	}
	if concurrency > 64 {
		concurrency = 64
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for _, raw := range job.Inputs.Names {
		raw := raw
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			name, ok := normalizeHost(raw)
			if !ok {
				mu.Lock()
				res.Coverage.Failed++
				res.Diagnostics = append(res.Diagnostics, "invalid name skipped: "+truncate(raw, 80))
				mu.Unlock()
				return
			}
			cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			addrs, err := resolver.LookupHost(cctx, name)
			cname, _ := resolver.LookupCNAME(cctx, name)
			cancel()

			var local []Record
			status, errText := dnsStatus(err)
			if err != nil {
				mu.Lock()
				// NXDOMAIN is an authoritative answer, not a collection failure: the name was
				// resolved, and the answer is that it does not exist. Only a transport problem
				// (timeout, resolver error) leaves the host uncovered.
				if status == "NXDOMAIN" {
					res.Coverage.Succeeded++
				} else {
					res.Coverage.Failed++
				}
				mu.Unlock()
				local = append(local,
					Record{Type: TypeDNSRecord, Name: name, RecordType: "A", Status: status, Resolver: resolverLabel(job), Error: errText},
					Record{Type: TypeHostObservation, Host: name, Status: HostUnresolved, Source: "dns", Provider: "builtin-dns", Notes: errText},
				)
				mu.Lock()
				res.Records = append(res.Records, local...)
				mu.Unlock()
				return
			}
			if cname != "" && !strings.EqualFold(strings.TrimSuffix(cname, "."), name) {
				local = append(local, Record{Type: TypeDNSRecord, Name: name, RecordType: "CNAME", Value: strings.TrimSuffix(cname, "."), Status: "NOERROR", Resolver: resolverLabel(job)})
			}
			hostStatus := HostResolved
			for _, a := range addrs {
				rt := "A"
				if strings.Contains(a, ":") {
					rt = "AAAA"
				}
				local = append(local, Record{Type: TypeDNSRecord, Name: name, RecordType: rt, Value: a, Status: "NOERROR", Resolver: resolverLabel(job)})
				if _, isWild := wildcardAddrs[a]; isWild {
					hostStatus = HostWildcard
				}
			}
			local = append(local, Record{Type: TypeHostObservation, Host: name, Status: hostStatus, Addresses: addrs, Source: "dns", Provider: "builtin-dns"})
			mu.Lock()
			res.Records = append(res.Records, local...)
			res.Coverage.Succeeded++
			mu.Unlock()
		}()
	}
	wg.Wait()

	for _, ai := range job.Inputs.Addresses {
		cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		names, err := resolver.LookupAddr(cctx, ai.IP)
		cancel()
		if err != nil {
			status, errText := dnsStatus(err)
			// An address with no PTR record is a complete answer, not a failed lookup.
			if status == "NXDOMAIN" {
				res.Coverage.Succeeded++
			} else {
				res.Coverage.Failed++
			}
			res.Records = append(res.Records, Record{Type: TypeDNSRecord, Name: ai.IP, RecordType: "PTR", Status: status, Resolver: resolverLabel(job), Error: errText})
			continue
		}
		for _, n := range names {
			res.Records = append(res.Records, Record{Type: TypeDNSRecord, Name: ai.IP, RecordType: "PTR", Value: strings.TrimSuffix(n, "."), Status: "NOERROR", Resolver: resolverLabel(job)})
		}
		res.Coverage.Succeeded++
	}

	if len(res.Records) == 0 {
		res.Diagnostics = append(res.Diagnostics, "no names or addresses to resolve")
	}
	return res, nil
}

func resolverLabel(job Job) string {
	if job.ResolverAddress != "" {
		return job.ResolverAddress
	}
	return "system"
}

func dnsStatus(err error) (status, text string) {
	if err == nil {
		return "NOERROR", ""
	}
	var dnsErr *net.DNSError
	if ok := asDNSError(err, &dnsErr); ok {
		text = dnsErr.Err
		if dnsErr.IsNotFound {
			return "NXDOMAIN", text
		}
		if dnsErr.IsTimeout {
			return "TIMEOUT", text
		}
	}
	return "ERROR", err.Error()
}

func asDNSError(err error, target **net.DNSError) bool {
	for err != nil {
		if d, ok := err.(*net.DNSError); ok {
			*target = d
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func randomLabel() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// detectWildcard probes random labels under domain; returns the address set if any resolve.
func detectWildcard(ctx context.Context, resolver hostResolver, domain string) (map[string]struct{}, bool) {
	set := map[string]struct{}{}
	found := false
	for i := 0; i < 3; i++ {
		name := randomLabel() + "." + domain
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := resolver.LookupHost(cctx, name)
		cancel()
		if err == nil && len(addrs) > 0 {
			found = true
			for _, a := range addrs {
				set[a] = struct{}{}
			}
		}
	}
	return set, found
}

// --- mock: deterministic fixture-driven provider (builtin) ---

type mockProvider struct{}

func (mockProvider) Name() string            { return "mock" }
func (mockProvider) Kind() string            { return "" }
func (mockProvider) Capability() string      { return "" }
func (mockProvider) NetworkBehavior() string { return "NONE" }

type mockFixture struct {
	Hosts       []string        `json:"hosts"`
	DNSRecords  []mockDNSRecord `json:"dnsRecords"`
	IPMetadata  []mockIPMeta    `json:"ipMetadata"`
	SleepMs     int             `json:"sleepMs"`
	Version     string          `json:"version"`
	Status      string          `json:"status"`
	Diagnostics []string        `json:"diagnostics"`
}

type mockDNSRecord struct {
	Name       string `json:"name"`
	RecordType string `json:"recordType"`
	Value      string `json:"value"`
	TTL        *int   `json:"ttl"`
	Status     string `json:"status"`
}

type mockIPMeta struct {
	IP          string   `json:"ip"`
	Prefix      *string  `json:"prefix"`
	ASN         *int     `json:"asn"`
	ASNOrg      *string  `json:"asnOrg"`
	NetworkName *string  `json:"networkName"`
	Country     *string  `json:"country"`
	Confidence  float64  `json:"confidence"`
	Limitations []string `json:"limitations"`
}

func (mockProvider) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	res := ProviderResult{}
	if pc.Job.FixturePath == "" {
		res.StatusOverride = StatusFailed
		res.Diagnostics = append(res.Diagnostics, "mock provider requires fixturePath")
		return res, nil
	}
	raw, err := os.ReadFile(pc.Job.FixturePath)
	if err != nil {
		res.StatusOverride = StatusFailed
		res.Diagnostics = append(res.Diagnostics, "cannot read fixture: "+err.Error())
		return res, nil
	}
	var fx mockFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		res.StatusOverride = StatusFailed
		res.Diagnostics = append(res.Diagnostics, "invalid fixture json: "+err.Error())
		return res, nil
	}
	res.ProviderVersion = fx.Version
	res.Diagnostics = append(res.Diagnostics, fx.Diagnostics...)

	if fx.SleepMs > 0 {
		select {
		case <-ctx.Done():
			res.StatusOverride = StatusCancelled
			res.Diagnostics = append(res.Diagnostics, "cancelled during mock delay")
			return res, nil
		case <-time.After(time.Duration(fx.SleepMs) * time.Millisecond):
		}
	}

	hosts, diag := dedupeHosts(fx.Hosts)
	res.Diagnostics = append(res.Diagnostics, diag...)
	for _, h := range hosts {
		res.Records = append(res.Records, Record{Type: TypeHostObservation, Host: h, Status: HostDiscovered, Source: "mock", Provider: "mock"})
		res.Coverage.Succeeded++
	}
	for _, r := range fx.DNSRecords {
		status := r.Status
		if status == "" {
			status = "NOERROR"
		}
		res.Records = append(res.Records, Record{Type: TypeDNSRecord, Name: r.Name, RecordType: r.RecordType, Value: r.Value, TTL: r.TTL, Status: status, Resolver: "mock"})
		res.Coverage.Succeeded++
	}
	for _, m := range fx.IPMetadata {
		res.Records = append(res.Records, Record{Type: TypeIPMetadata, IP: m.IP, Prefix: m.Prefix, ASN: m.ASN, ASNOrg: m.ASNOrg, NetworkName: m.NetworkName, Country: m.Country, Source: "mock", Confidence: m.Confidence, Limitations: m.Limitations})
		res.Coverage.Succeeded++
	}
	if fx.Status != "" {
		res.StatusOverride = fx.Status
	}
	if res.Coverage.Attempted == 0 {
		res.Coverage.Attempted = res.Coverage.Succeeded + res.Coverage.Failed
	}
	return res, nil
}

// --- offline-ipmeta: fixture-driven IP metadata (builtin) ---

type offlineIPMeta struct{}

func (offlineIPMeta) Name() string            { return "offline-ipmeta" }
func (offlineIPMeta) Kind() string            { return "IP_METADATA" }
func (offlineIPMeta) Capability() string      { return "PASSIVE" }
func (offlineIPMeta) NetworkBehavior() string { return "PASSIVE" }

func (offlineIPMeta) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	res := ProviderResult{}
	if pc.Job.FixturePath == "" {
		res.StatusOverride = StatusFailed
		res.Diagnostics = append(res.Diagnostics, "offline-ipmeta requires fixturePath")
		return res, nil
	}
	raw, err := os.ReadFile(pc.Job.FixturePath)
	if err != nil {
		res.StatusOverride = StatusFailed
		res.Diagnostics = append(res.Diagnostics, "cannot read fixture: "+err.Error())
		return res, nil
	}
	var entries []mockIPMeta
	if err := json.Unmarshal(raw, &entries); err != nil {
		res.StatusOverride = StatusFailed
		res.Diagnostics = append(res.Diagnostics, "invalid fixture json: "+err.Error())
		return res, nil
	}
	byIP := map[string]mockIPMeta{}
	for _, e := range entries {
		byIP[e.IP] = e
	}
	for _, ai := range pc.Job.Inputs.Addresses {
		e, ok := byIP[ai.IP]
		if !ok {
			res.Coverage.Failed++
			res.Diagnostics = append(res.Diagnostics, "no offline metadata for "+ai.IP)
			continue
		}
		res.Records = append(res.Records, Record{Type: TypeIPMetadata, IP: e.IP, Prefix: e.Prefix, ASN: e.ASN, ASNOrg: e.ASNOrg, NetworkName: e.NetworkName, Country: e.Country, Source: "offline-ipmeta", Confidence: e.Confidence, Limitations: e.Limitations})
		res.Coverage.Succeeded++
	}
	return res, nil
}

// --- rdap: IP registration metadata via RDAP over HTTPS ---

type rdapProvider struct{}

func (rdapProvider) Name() string            { return "rdap" }
func (rdapProvider) Kind() string            { return "IP_METADATA" }
func (rdapProvider) Capability() string      { return "PASSIVE" }
func (rdapProvider) NetworkBehavior() string { return "PASSIVE" }

func (rdapProvider) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	base := pc.Job.RdapBaseURL
	if base == "" {
		base = os.Getenv("RECONNEXUS_RDAP_BASE")
	}
	if base == "" {
		base = "https://rdap.org"
	}
	timeoutMs := 15000
	if pc.Job.TimeoutMs > 0 {
		timeoutMs = pc.Job.TimeoutMs
	}
	client := &http.Client{Timeout: time.Duration(timeoutMs) * time.Millisecond}
	// RDAP registries are shared public services that throttle aggressively. Pacing the lookups
	// (and honoring Retry-After once) collects the registration data instead of a run of 429s.
	// The policy's request rate governs the authorized target, so it can only slow this down.
	interval := rdapMinInterval
	if rps := pc.Job.Limits.RequestsPerSecond; rps > 0 {
		if policyInterval := time.Duration(float64(time.Second) / rps); policyInterval > interval {
			interval = policyInterval
		}
	}
	res := ProviderResult{}
	for i, ai := range pc.Job.Inputs.Addresses {
		if _, ok := matching.ParseIP(ai.IP); !ok {
			res.Coverage.Failed++
			res.Diagnostics = append(res.Diagnostics, "invalid IP: "+ai.IP)
			continue
		}
		if i > 0 && !sleepCtx(ctx, interval) {
			res.Diagnostics = append(res.Diagnostics, "cancelled before all addresses were correlated")
			break
		}
		rec, retryAfter, diag := lookupRdap(ctx, client, base, ai.IP)
		if rec == nil && retryAfter > 0 {
			if !sleepCtx(ctx, retryAfter) {
				res.Diagnostics = append(res.Diagnostics, diag...)
				res.Coverage.Failed++
				break
			}
			rec, _, diag = lookupRdap(ctx, client, base, ai.IP)
		}
		res.Diagnostics = append(res.Diagnostics, diag...)
		if rec == nil {
			res.Coverage.Failed++
			continue
		}
		res.Records = append(res.Records, *rec)
		res.Coverage.Succeeded++
	}
	return res, nil
}

// rdapMinInterval is the fastest this provider will query a public RDAP service, regardless of
// the policy's request budget.
const rdapMinInterval = 500 * time.Millisecond

// rdapMaxRetryAfter bounds how long a single Retry-After may hold up the stage.
const rdapMaxRetryAfter = 10 * time.Second

// sleepCtx waits for d, reporting false if the context was cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// retryAfterDelay reads a Retry-After header (delay-seconds or HTTP-date), bounded.
func retryAfterDelay(h string, now time.Time) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	var d time.Duration
	if secs, err := strconv.Atoi(h); err == nil {
		d = time.Duration(secs) * time.Second
	} else if at, err := http.ParseTime(h); err == nil {
		d = at.Sub(now)
	}
	if d <= 0 {
		return 0
	}
	if d > rdapMaxRetryAfter {
		return rdapMaxRetryAfter
	}
	return d
}

// lookupRdap queries one address. A non-zero second return is how long the service asked the
// caller to wait before trying again.
func lookupRdap(ctx context.Context, client *http.Client, base, ip string) (*Record, time.Duration, []string) {
	url := strings.TrimRight(base, "/") + "/ip/" + ip
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, []string{"rdap request build failed: " + err.Error()}
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, []string{fmt.Sprintf("rdap lookup failed for %s: %v", ip, err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var retryAfter time.Duration
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			retryAfter = retryAfterDelay(resp.Header.Get("Retry-After"), time.Now())
			if retryAfter == 0 {
				retryAfter = rdapMinInterval * 4
			}
		}
		return nil, retryAfter, []string{fmt.Sprintf("rdap returned HTTP %d for %s", resp.StatusCode, ip)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, 0, []string{"rdap read failed: " + err.Error()}
	}
	// RFC 9083 §5.4 / RFC 8977: each cidr0_cidrs entry carries a `v4prefix` or `v6prefix`
	// string plus a `length`.
	var doc struct {
		Handle       string     `json:"handle"`
		Name         string     `json:"name"`
		Country      string     `json:"country"`
		StartAddress string     `json:"startAddress"`
		EndAddress   string     `json:"endAddress"`
		Cidr0        []rdapCidr `json:"cidr0_cidrs"`
		Entities     []struct {
			VcardArray []any    `json:"vcardArray"`
			Roles      []string `json:"roles"`
		} `json:"entities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, 0, []string{fmt.Sprintf("rdap response for %s could not be parsed: %v", ip, err)}
	}
	rec := &Record{Type: TypeIPMetadata, IP: ip, Source: "rdap", Confidence: 0.6, Limitations: []string{}}
	if doc.Name != "" {
		rec.NetworkName = strPtr(doc.Name)
	}
	if doc.Country != "" {
		rec.Country = strPtr(doc.Country)
	}
	if p := prefixFromCidr0(doc.Cidr0); p != "" {
		rec.Prefix = strPtr(p)
	} else {
		rec.Limitations = append(rec.Limitations, "prefix not stated in the RDAP response")
	}
	if org := orgFromEntities(doc.Entities); org != "" {
		rec.ASNOrg = strPtr(org)
	}
	// RDAP IP responses do not carry a routable ASN in a standard field.
	if rec.ASN == nil {
		rec.Limitations = append(rec.Limitations, "ASN not established from RDAP IP response")
	}
	return rec, 0, nil
}

// prefixFromCidr0 returns the registered CIDR block as stated by the registry. A prefix length
// is never inferred from the start address: an unstated prefix is reported as a limitation
// instead of being fabricated.
// rdapCidr is one cidr0_cidrs entry (RFC 8977): a v4 or v6 prefix string plus its length.
type rdapCidr struct {
	V4Prefix string `json:"v4prefix"`
	V6Prefix string `json:"v6prefix"`
	Length   int    `json:"length"`
}

func prefixFromCidr0(cidrs []rdapCidr) string {
	for _, c := range cidrs {
		addr := c.V4Prefix
		maxLen := 32
		if addr == "" {
			addr = c.V6Prefix
			maxLen = 128
		}
		if addr == "" || c.Length <= 0 || c.Length > maxLen {
			continue
		}
		a, ok := matching.ParseIP(addr)
		if !ok {
			continue
		}
		if (maxLen == 32) != a.Is4() {
			continue
		}
		return fmt.Sprintf("%s/%d", a.String(), c.Length)
	}
	return ""
}

func orgFromEntities(entities []struct {
	VcardArray []any    `json:"vcardArray"`
	Roles      []string `json:"roles"`
}) string {
	for _, e := range entities {
		if len(e.VcardArray) < 2 {
			continue
		}
		props, ok := e.VcardArray[1].([]any)
		if !ok {
			continue
		}
		for _, p := range props {
			kv, ok := p.([]any)
			if !ok || len(kv) < 4 {
				continue
			}
			if name, _ := kv[0].(string); name == "fn" {
				if v, _ := kv[3].(string); v != "" {
					return v
				}
			}
		}
	}
	return ""
}

func strPtr(s string) *string { return &s }
