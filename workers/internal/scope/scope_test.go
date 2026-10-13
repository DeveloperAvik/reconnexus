package scope

import (
	"strings"
	"testing"
	"time"
)

func basePolicy() *Policy {
	return &Policy{
		SchemaVersion: 1,
		PolicyID:      "11111111-1111-1111-1111-111111111111",
		ProjectID:     "22222222-2222-2222-2222-222222222222",
		PolicyVersion: 1,
		Authorization: Authorization{
			Reference:    "AUTH-1",
			AuthorizedBy: "tester",
			ValidFrom:    time.Now().Add(-time.Hour),
			ValidUntil:   time.Now().Add(time.Hour),
			Capabilities: []string{"ACTIVE_HTTP", "DNS", "PASSIVE", "INTERNAL_NETWORK"},
		},
		InScope: InScope{
			Domains: []DomainRule{{Value: "example.com", IncludeSubdomains: true}},
			Hosts:   []string{"api.example.com"},
			IPs:     []string{"203.0.113.10"},
			CIDRs:   []string{"198.51.100.0/24"},
		},
		Exclusions: Exclusions{
			Hosts: []string{"admin.example.com"},
			Paths: []string{"/logout"},
		},
	}
}

func check(t *testing.T, e *Engine, req Request) Decision {
	t.Helper()
	return e.Check(req)
}

func TestAllowInScopeSubdomain(t *testing.T) {
	e := NewEngine(basePolicy())
	d := check(t, e, Request{Kind: "HOST", Value: "www.example.com", Capability: "ACTIVE_HTTP"})
	if !d.Allowed {
		t.Fatalf("expected allow, got %s: %s", d.Code, d.Reason)
	}
}

func TestDenyOutOfScope(t *testing.T) {
	e := NewEngine(basePolicy())
	d := check(t, e, Request{Kind: "HOST", Value: "evil.example.net", Capability: "ACTIVE_HTTP"})
	if d.Allowed || d.Code != CodeNotInScope {
		t.Fatalf("expected NOT_IN_SCOPE, got %+v", d)
	}
}

func TestExpiredAuthorization(t *testing.T) {
	p := basePolicy()
	p.Authorization.ValidUntil = time.Now().Add(-time.Minute)
	e := NewEngine(p)
	d := check(t, e, Request{Kind: "HOST", Value: "www.example.com", Capability: "ACTIVE_HTTP"})
	if d.Allowed || d.Code != CodeAuthorizationExpired {
		t.Fatalf("expected AUTHORIZATION_EXPIRED, got %+v", d)
	}
}

func TestCapabilityNotPermitted(t *testing.T) {
	e := NewEngine(basePolicy())
	d := check(t, e, Request{Kind: "HOST", Value: "www.example.com", Capability: "ACTIVE_TEMPLATE_CHECK"})
	if d.Allowed || d.Code != CodeCapabilityNotPermitted {
		t.Fatalf("expected CAPABILITY_NOT_PERMITTED, got %+v", d)
	}
}

func TestExclusionPrecedence(t *testing.T) {
	e := NewEngine(basePolicy())
	d := check(t, e, Request{Kind: "HOST", Value: "admin.example.com", Capability: "ACTIVE_HTTP"})
	if d.Allowed || d.Code != CodeExcluded {
		t.Fatalf("expected EXCLUDED, got %+v", d)
	}
}

func TestExcludedPath(t *testing.T) {
	e := NewEngine(basePolicy())
	d := check(t, e, Request{Kind: "URL", Value: "https://www.example.com/logout", Capability: "ACTIVE_HTTP"})
	if d.Allowed || d.Code != CodeExcludedPath {
		t.Fatalf("expected EXCLUDED_PATH, got %+v", d)
	}
}

func TestPrivateAddressBlockedByDefault(t *testing.T) {
	e := NewEngine(basePolicy())
	d := check(t, e, Request{Kind: "URL", Value: "http://127.0.0.1/", Capability: "ACTIVE_HTTP"})
	if d.Allowed {
		t.Fatalf("expected denial for loopback, got allow")
	}
}

func TestLoopbackBlockedEvenWithInternalCapability(t *testing.T) {
	// Restricted addresses remain denied unless the operator explicitly enables them.
	e := NewEngine(basePolicy())
	d := check(t, e, Request{Kind: "IP", Value: "127.0.0.1", Capability: "ACTIVE_HTTP"})
	if d.Allowed || d.Code != CodeRestrictedAddress {
		t.Fatalf("expected RESTRICTED_ADDRESS_SPACE, got %+v", d)
	}
}

func TestIPv4MappedLoopbackBlocked(t *testing.T) {
	e := NewEngine(basePolicy())
	d := check(t, e, Request{Kind: "IP", Value: "::ffff:127.0.0.1", Capability: "ACTIVE_HTTP"})
	if d.Allowed || d.Code != CodeRestrictedAddress {
		t.Fatalf("expected RESTRICTED_ADDRESS_SPACE for mapped loopback, got %+v", d)
	}
}

func TestMetadataAddressBlocked(t *testing.T) {
	e := NewEngine(basePolicy())
	d := check(t, e, Request{Kind: "IP", Value: "169.254.169.254", Capability: "ACTIVE_HTTP"})
	if d.Allowed {
		t.Fatalf("expected metadata address to be denied")
	}
}

func TestDNSToPrivateAddressBlocked(t *testing.T) {
	// Public name resolves to a private address => rebinding-style denial.
	e := NewEngine(basePolicy())
	d := check(t, e, Request{
		Kind: "HOST", Value: "www.example.com", Capability: "ACTIVE_HTTP",
		ResolvedAddresses: []string{"10.0.0.5"},
	})
	if d.Allowed || d.Code != CodeRestrictedAddress {
		t.Fatalf("expected RESTRICTED_ADDRESS_SPACE for resolved private addr, got %+v", d)
	}
}

func TestExplicitlyAuthorizedIPAllowed(t *testing.T) {
	e := NewEngine(basePolicy())
	// 203.0.113.10 is an in-scope IP; it is documentation/reserved but explicitly authorized.
	d := check(t, e, Request{Kind: "IP", Value: "203.0.113.10", Capability: "ACTIVE_HTTP"})
	if !d.Allowed {
		t.Fatalf("expected explicit in-scope IP to be allowed, got %+v", d)
	}
}

func TestCIDRMatch(t *testing.T) {
	e := NewEngine(basePolicy())
	d := check(t, e, Request{Kind: "IP", Value: "198.51.100.77", Capability: "DNS"})
	if !d.Allowed {
		t.Fatalf("expected CIDR allow, got %+v", d)
	}
}

func TestInvalidURL(t *testing.T) {
	e := NewEngine(basePolicy())
	d := check(t, e, Request{Kind: "URL", Value: "not a url", Capability: "ACTIVE_HTTP"})
	if d.Allowed || d.Code != CodeInvalidTarget {
		t.Fatalf("expected INVALID_TARGET, got %+v", d)
	}
}

func TestLoadPolicyRejectsUnknownCapability(t *testing.T) {
	doc := `{"schemaVersion":1,"policyId":"x","projectId":"y","policyVersion":1,
	"authorization":{"reference":"r","authorizedBy":"a","validFrom":"2020-01-01T00:00:00Z","validUntil":"2999-01-01T00:00:00Z","capabilities":["SUPER_POWERS"]},
	"inScope":{},"exclusions":{},"limits":{}}`
	_, err := LoadPolicy(strings.NewReader(doc))
	if err == nil {
		t.Fatal("expected error for unknown capability")
	}
}
