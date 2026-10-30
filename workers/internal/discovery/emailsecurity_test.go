package discovery

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/reconnexus/workers/internal/scope"
)

type fakeEmailResolver struct {
	mx  map[string][]*net.MX
	txt map[string][]string
}

func (f fakeEmailResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return f.mx[name], nil
}
func (f fakeEmailResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f.txt[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func withEmailResolver(t *testing.T, r emailResolver) {
	t.Helper()
	old := emailResolverFactory
	emailResolverFactory = func(Job) emailResolver { return r }
	t.Cleanup(func() { emailResolverFactory = old })
}

func emailSecurityPolicy(domain string) scope.Policy {
	return scope.Policy{
		SchemaVersion: 1,
		Authorization: scope.Authorization{
			Reference:    "test",
			AuthorizedBy: "test",
			ValidFrom:    time.Now().Add(-time.Hour).UTC(),
			ValidUntil:   time.Now().Add(time.Hour).UTC(),
			Capabilities: []string{"DNS"},
		},
		InScope: scope.InScope{Domains: []scope.DomainRule{{Value: domain, IncludeSubdomains: true}}},
		Limits:  scope.Limits{MaxConcurrency: 4, MaxArtifactBytes: 256 * 1024},
	}
}

func runEmailSecurity(t *testing.T, domain string, r fakeEmailResolver) ProviderResult {
	t.Helper()
	withEmailResolver(t, r)
	job := Job{
		SchemaVersion: 1,
		Kind:          "EMAIL_SECURITY",
		Provider:      "builtin-email-security",
		Inputs:        Inputs{Names: []string{domain}},
		Limits:        scope.Limits{MaxConcurrency: 4},
		Policy:        emailSecurityPolicy(domain),
	}
	res, err := (builtinEmailSecurity{}).Run(context.Background(), ProviderContext{Job: job, Engine: scope.NewEngine(&job.Policy)})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return res
}

func recordFor(t *testing.T, res ProviderResult, category string) *EmailSecurityInfo {
	t.Helper()
	for _, r := range res.Records {
		if r.EmailSecurity != nil && r.EmailSecurity.Category == category {
			return r.EmailSecurity
		}
	}
	t.Fatalf("no %s record among %d records", category, len(res.Records))
	return nil
}

func TestSPFAbsentWhenNoRecord(t *testing.T) {
	res := runEmailSecurity(t, "example.com", fakeEmailResolver{})
	info := recordFor(t, res, EmailCategorySPF)
	if info.Status != EmailSecurityAbsent {
		t.Fatalf("info = %+v", info)
	}
}

func TestSPFStrictAllIsStrong(t *testing.T) {
	res := runEmailSecurity(t, "example.com", fakeEmailResolver{txt: map[string][]string{"example.com": {"v=spf1 include:_spf.example.com -all"}}})
	info := recordFor(t, res, EmailCategorySPF)
	if info.Status != EmailSecurityStrong {
		t.Fatalf("info = %+v", info)
	}
}

func TestSPFSoftFailIsWeak(t *testing.T) {
	res := runEmailSecurity(t, "example.com", fakeEmailResolver{txt: map[string][]string{"example.com": {"v=spf1 include:_spf.example.com ~all"}}})
	info := recordFor(t, res, EmailCategorySPF)
	if info.Status != EmailSecurityWeak {
		t.Fatalf("info = %+v", info)
	}
}

func TestSPFPermissiveAllIsMisconfigured(t *testing.T) {
	res := runEmailSecurity(t, "example.com", fakeEmailResolver{txt: map[string][]string{"example.com": {"v=spf1 +all"}}})
	info := recordFor(t, res, EmailCategorySPF)
	if info.Status != EmailSecurityMisconfigured {
		t.Fatalf("info = %+v", info)
	}
}

func TestSPFMultipleRecordsIsMisconfigured(t *testing.T) {
	res := runEmailSecurity(t, "example.com", fakeEmailResolver{txt: map[string][]string{"example.com": {"v=spf1 -all", "v=spf1 include:other.com -all"}}})
	info := recordFor(t, res, EmailCategorySPF)
	if info.Status != EmailSecurityMisconfigured || info.EvidenceType != "MULTIPLE_RECORDS" {
		t.Fatalf("info = %+v", info)
	}
}

func TestDMARCAbsentWhenNoRecord(t *testing.T) {
	res := runEmailSecurity(t, "example.com", fakeEmailResolver{})
	info := recordFor(t, res, EmailCategoryDMARC)
	if info.Status != EmailSecurityAbsent {
		t.Fatalf("info = %+v", info)
	}
}

func TestDMARCPolicyNoneIsWeak(t *testing.T) {
	res := runEmailSecurity(t, "example.com", fakeEmailResolver{txt: map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=none; pct=100"}}})
	info := recordFor(t, res, EmailCategoryDMARC)
	if info.Status != EmailSecurityWeak {
		t.Fatalf("info = %+v", info)
	}
}

func TestDMARCPolicyRejectIsStrong(t *testing.T) {
	res := runEmailSecurity(t, "example.com", fakeEmailResolver{txt: map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; pct=100"}}})
	info := recordFor(t, res, EmailCategoryDMARC)
	if info.Status != EmailSecurityStrong {
		t.Fatalf("info = %+v", info)
	}
}

func TestDKIMDetectedAtCommonSelector(t *testing.T) {
	res := runEmailSecurity(t, "example.com", fakeEmailResolver{txt: map[string][]string{
		"google._domainkey.example.com": {"v=DKIM1; k=rsa; p=MIGfMA0GCSq..."},
	}})
	info := recordFor(t, res, EmailCategoryDKIM)
	if info.Status != EmailSecurityDetected || info.Detail["selector"] != "google" {
		t.Fatalf("info = %+v", info)
	}
}

func TestDKIMNotDetectedIsLowConfidenceNotAbsence(t *testing.T) {
	res := runEmailSecurity(t, "example.com", fakeEmailResolver{})
	info := recordFor(t, res, EmailCategoryDKIM)
	if info.Status != EmailSecurityNotDetected || info.Confidence > 0.5 {
		t.Fatalf("info = %+v, want low-confidence NOT_DETECTED", info)
	}
}

func TestEmailSecurityRequiresCapability(t *testing.T) {
	withEmailResolver(t, fakeEmailResolver{})
	job := Job{
		SchemaVersion: 1,
		Kind:          "EMAIL_SECURITY",
		Provider:      "builtin-email-security",
		Inputs:        Inputs{Names: []string{"example.com"}},
		Limits:        scope.Limits{MaxConcurrency: 4},
		Policy: scope.Policy{
			SchemaVersion: 1,
			Authorization: scope.Authorization{
				Reference: "test", AuthorizedBy: "test",
				ValidFrom: time.Now().Add(-time.Hour).UTC(), ValidUntil: time.Now().Add(time.Hour).UTC(),
				Capabilities: []string{"PASSIVE"},
			},
			InScope: scope.InScope{Domains: []scope.DomainRule{{Value: "example.com", IncludeSubdomains: true}}},
		},
	}
	res, err := Run(context.Background(), job, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusBlocked {
		t.Fatalf("status = %s, want BLOCKED", res.Status)
	}
}

func TestEmailSecurityNoDomainsIsSkipped(t *testing.T) {
	withEmailResolver(t, fakeEmailResolver{})
	job := Job{
		SchemaVersion: 1,
		Kind:          "EMAIL_SECURITY",
		Provider:      "builtin-email-security",
		Inputs:        Inputs{},
		Limits:        scope.Limits{MaxConcurrency: 4},
		Policy:        emailSecurityPolicy("example.com"),
	}
	res, err := (builtinEmailSecurity{}).Run(context.Background(), ProviderContext{Job: job, Engine: scope.NewEngine(&job.Policy)})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusOverride != StatusSkipped {
		t.Fatalf("StatusOverride = %s, want SKIPPED", res.StatusOverride)
	}
}
