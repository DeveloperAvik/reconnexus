package discovery

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/reconnexus/workers/internal/scope"
)

// builtinEmailSecurity checks a domain's SPF and DMARC posture, and probes a small, fixed list of
// common DKIM selectors. All of it is read-only DNS TXT/MX lookups against the domain itself —
// never a connection to a mail server, and never an attempt to send mail.
type builtinEmailSecurity struct{}

func (builtinEmailSecurity) Name() string            { return "builtin-email-security" }
func (builtinEmailSecurity) Kind() string            { return "EMAIL_SECURITY" }
func (builtinEmailSecurity) Capability() string      { return "DNS" }
func (builtinEmailSecurity) NetworkBehavior() string { return "ACTIVE" }

// Email security statuses, shared across SPF/DMARC/DKIM (interpretation documented per category
// in packages/contracts/src/discovery.ts). DKIM's NOT_DETECTED is never proof DKIM is absent: it
// only means none of a fixed, common selector list resolved.
const (
	EmailSecurityStrong        = "STRONG"
	EmailSecurityWeak          = "WEAK"
	EmailSecurityAbsent        = "ABSENT"
	EmailSecurityMisconfigured = "MISCONFIGURED"
	EmailSecurityDetected      = "DETECTED"
	EmailSecurityNotDetected   = "NOT_DETECTED"
)

const (
	EmailCategorySPF   = "SPF"
	EmailCategoryDMARC = "DMARC"
	EmailCategoryDKIM  = "DKIM"
)

const maxEmailSecurityDomains = 10

// commonDKIMSelectors covers the selector conventions of the mail providers domains most often
// delegate to. A domain using a custom or rotated selector not in this list is not detected as
// having DKIM — that is an inconclusive result, not evidence DKIM is absent.
var commonDKIMSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "k2", "dkim", "mail", "smtp", "s1", "s2", "mandrill",
}

// emailResolver is the subset of *net.Resolver this provider needs. It is an interface so tests
// can inject a deterministic resolver, mirroring hostResolver for the DNS provider.
type emailResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

var emailResolverFactory = defaultEmailResolverFactory

func defaultEmailResolverFactory(job Job) emailResolver {
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

var spfAllRe = regexp.MustCompile(`(?i)(^|\s)([+\-~?]?)all(\s|$)`)

func (builtinEmailSecurity) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{Coverage: Coverage{}}
	domains := job.Inputs.Names
	if len(domains) > maxEmailSecurityDomains {
		domains = domains[:maxEmailSecurityDomains]
	}
	if len(domains) == 0 {
		res.StatusOverride = StatusSkipped
		res.Diagnostics = append(res.Diagnostics, "no domains to check")
		return res, nil
	}

	resolver := emailResolverFactory(job)
	var mu sync.Mutex
	var records []Record
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)

	for _, domain := range domains {
		domain := domain
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			local, outcome := checkEmailSecurity(ctx, resolver, pc, domain)
			mu.Lock()
			defer mu.Unlock()
			res.Coverage.Attempted++
			switch outcome {
			case interfaceHit, interfaceMiss:
				res.Coverage.Succeeded++
			case interfaceSkipped:
				res.Coverage.Skipped++
			default:
				res.Coverage.Failed++
			}
			records = append(records, local...)
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		res.StatusOverride = StatusCancelled
	}
	res.Records = records
	if len(records) == 0 {
		res.Diagnostics = append(res.Diagnostics, "no domain produced a classifiable result")
	}
	return res, nil
}

func checkEmailSecurity(ctx context.Context, resolver emailResolver, pc ProviderContext, domain string) ([]Record, interfaceResult) {
	d := pc.Engine.Check(scope.Request{Kind: "HOST", Value: domain, Capability: "DNS"})
	if !d.Allowed {
		return nil, interfaceSkipped
	}

	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	mxRecords, _ := resolver.LookupMX(cctx, domain)
	cancel()
	hasMX := len(mxRecords) > 0

	var out []Record
	if spf := checkSPF(ctx, resolver, domain, hasMX); spf != nil {
		out = append(out, Record{Type: TypeEmailSecurity, Host: domain, Provider: "builtin-email-security", Source: "email-security", EmailSecurity: spf})
	}
	if dmarc := checkDMARC(ctx, resolver, domain, hasMX); dmarc != nil {
		out = append(out, Record{Type: TypeEmailSecurity, Host: domain, Provider: "builtin-email-security", Source: "email-security", EmailSecurity: dmarc})
	}
	if dkim := checkDKIM(ctx, resolver, domain); dkim != nil {
		out = append(out, Record{Type: TypeEmailSecurity, Host: domain, Provider: "builtin-email-security", Source: "email-security", EmailSecurity: dkim})
	}
	if len(out) == 0 {
		return nil, interfaceFailed
	}
	return out, interfaceHit
}

func checkSPF(ctx context.Context, resolver emailResolver, domain string, hasMX bool) *EmailSecurityInfo {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	txts, _ := resolver.LookupTXT(cctx, domain)
	cancel()

	var spfRecords []string
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			spfRecords = append(spfRecords, t)
		}
	}
	detail := map[string]any{"hasMx": hasMX}
	switch {
	case len(spfRecords) == 0:
		return &EmailSecurityInfo{Category: EmailCategorySPF, Status: EmailSecurityAbsent, Confidence: 0.8, Detail: detail,
			Evidence: "no SPF (v=spf1) TXT record found", EvidenceType: "ABSENT"}
	case len(spfRecords) > 1:
		return &EmailSecurityInfo{Category: EmailCategorySPF, Status: EmailSecurityMisconfigured, Confidence: 0.9, Value: truncate(spfRecords[0], 300), Detail: detail,
			Evidence: fmt.Sprintf("%d SPF TXT records found; RFC 7208 requires exactly one, so SPF evaluation is undefined", len(spfRecords)), EvidenceType: "MULTIPLE_RECORDS"}
	}
	record := spfRecords[0]
	m := spfAllRe.FindAllStringSubmatch(record, -1)
	if len(m) == 0 {
		return &EmailSecurityInfo{Category: EmailCategorySPF, Status: EmailSecurityWeak, Confidence: 0.7, Value: truncate(record, 300), Detail: detail,
			Evidence: "SPF record present but has no 'all' mechanism; evaluation falls through with no explicit terminal policy", EvidenceType: "NO_ALL_MECHANISM"}
	}
	qualifier := m[len(m)-1][2]
	detail["allQualifier"] = qualifier
	switch qualifier {
	case "-":
		return &EmailSecurityInfo{Category: EmailCategorySPF, Status: EmailSecurityStrong, Confidence: 0.9, Value: truncate(record, 300), Detail: detail,
			Evidence: "SPF record ends in '-all' (hard fail for unlisted senders)", EvidenceType: "STRICT_ALL"}
	case "+":
		return &EmailSecurityInfo{Category: EmailCategorySPF, Status: EmailSecurityMisconfigured, Confidence: 0.9, Value: truncate(record, 300), Detail: detail,
			Evidence: "SPF record ends in '+all', explicitly permitting any sender to pass SPF", EvidenceType: "PERMISSIVE_ALL"}
	default: // "~" softfail or "?" neutral (qualifier == "" means bare "all", implicitly "+")
		return &EmailSecurityInfo{Category: EmailCategorySPF, Status: EmailSecurityWeak, Confidence: 0.8, Value: truncate(record, 300), Detail: detail,
			Evidence: fmt.Sprintf("SPF record ends in '%sall', which does not hard-fail unlisted senders", qualifier), EvidenceType: "WEAK_ALL"}
	}
}

var dmarcPolicyRe = regexp.MustCompile(`(?i)[;\s]p=(\w+)`)
var dmarcPctRe = regexp.MustCompile(`(?i)[;\s]pct=(\d+)`)

func checkDMARC(ctx context.Context, resolver emailResolver, domain string, hasMX bool) *EmailSecurityInfo {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	txts, _ := resolver.LookupTXT(cctx, "_dmarc."+domain)
	cancel()

	var dmarcRecords []string
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
			dmarcRecords = append(dmarcRecords, t)
		}
	}
	detail := map[string]any{"hasMx": hasMX}
	switch {
	case len(dmarcRecords) == 0:
		return &EmailSecurityInfo{Category: EmailCategoryDMARC, Status: EmailSecurityAbsent, Confidence: 0.8, Detail: detail,
			Evidence: "no DMARC (v=DMARC1) TXT record at _dmarc." + domain, EvidenceType: "ABSENT"}
	case len(dmarcRecords) > 1:
		return &EmailSecurityInfo{Category: EmailCategoryDMARC, Status: EmailSecurityMisconfigured, Confidence: 0.9, Value: truncate(dmarcRecords[0], 300), Detail: detail,
			Evidence: fmt.Sprintf("%d DMARC TXT records found at _dmarc.%s; exactly one is required", len(dmarcRecords), domain), EvidenceType: "MULTIPLE_RECORDS"}
	}
	record := dmarcRecords[0]
	pm := dmarcPolicyRe.FindStringSubmatch(record)
	if len(pm) == 0 {
		return &EmailSecurityInfo{Category: EmailCategoryDMARC, Status: EmailSecurityMisconfigured, Confidence: 0.8, Value: truncate(record, 300), Detail: detail,
			Evidence: "DMARC record present but has no 'p' (policy) tag, which DMARC requires", EvidenceType: "MISSING_POLICY_TAG"}
	}
	policy := strings.ToLower(pm[1])
	detail["policy"] = policy
	if pct := dmarcPctRe.FindStringSubmatch(record); len(pct) > 0 {
		detail["pct"] = pct[1]
	}
	switch policy {
	case "reject", "quarantine":
		return &EmailSecurityInfo{Category: EmailCategoryDMARC, Status: EmailSecurityStrong, Confidence: 0.9, Value: truncate(record, 300), Detail: detail,
			Evidence: "DMARC policy is p=" + policy + " (enforced)", EvidenceType: "ENFORCED"}
	case "none":
		return &EmailSecurityInfo{Category: EmailCategoryDMARC, Status: EmailSecurityWeak, Confidence: 0.8, Value: truncate(record, 300), Detail: detail,
			Evidence: "DMARC policy is p=none (monitoring only; failing mail is not rejected or quarantined)", EvidenceType: "MONITOR_ONLY"}
	default:
		return &EmailSecurityInfo{Category: EmailCategoryDMARC, Status: EmailSecurityMisconfigured, Confidence: 0.7, Value: truncate(record, 300), Detail: detail,
			Evidence: "DMARC policy tag has an unrecognized value: " + truncate(policy, 40), EvidenceType: "UNKNOWN_POLICY"}
	}
}

func checkDKIM(ctx context.Context, resolver emailResolver, domain string) *EmailSecurityInfo {
	for _, selector := range commonDKIMSelectors {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		txts, _ := resolver.LookupTXT(cctx, selector+"._domainkey."+domain)
		cancel()
		for _, t := range txts {
			low := strings.ToLower(t)
			if strings.Contains(low, "v=dkim1") || strings.Contains(low, "p=") {
				return &EmailSecurityInfo{
					Category: EmailCategoryDKIM, Status: EmailSecurityDetected, Confidence: 0.8, Value: truncate(t, 300),
					Detail:       map[string]any{"selector": selector},
					Evidence:     "DKIM key record found at selector \"" + selector + "\"",
					EvidenceType: "SELECTOR_MATCH",
				}
			}
		}
	}
	return &EmailSecurityInfo{
		Category: EmailCategoryDKIM, Status: EmailSecurityNotDetected, Confidence: 0.3,
		Detail:       map[string]any{"selectorsTried": len(commonDKIMSelectors)},
		Evidence:     fmt.Sprintf("no DKIM record found at %d common selectors; this is not proof DKIM is absent, only that it does not use one of them", len(commonDKIMSelectors)),
		EvidenceType: "NO_COMMON_SELECTOR_MATCHED",
	}
}
