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

func TestIPv6RestrictedAddressesBlocked(t *testing.T) {
	cases := []struct {
		name string
		ip   string
	}{
		{"ipv6 loopback", "::1"},
		{"ipv6 link-local", "fe80::1"},
		{"ipv6 unique-local", "fd00::1"},
		{"ipv6 documentation/reserved", "2001:db8::1"},
		{"ipv4-mapped private", "::ffff:10.0.0.1"},
		{"ipv4-mapped link-local", "::ffff:169.254.1.1"},
	}
	e := NewEngine(basePolicy())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := check(t, e, Request{Kind: "IP", Value: tc.ip, Capability: "ACTIVE_HTTP"})
			if d.Allowed {
				t.Fatalf("expected %s to be denied, got allow", tc.ip)
			}
			if d.Code != CodeRestrictedAddress {
				t.Fatalf("expected RESTRICTED_ADDRESS_SPACE for %s, got %+v", tc.ip, d)
			}
		})
	}
}

func TestIPv6HostLiteralScope(t *testing.T) {
	// An IPv6 literal host outside the authorized IP set is not in scope.
	e := NewEngine(basePolicy())
	d := check(t, e, Request{Kind: "URL", Value: "http://[2001:db8::1]/", Capability: "ACTIVE_HTTP"})
	if d.Allowed {
		t.Fatalf("expected out-of-scope IPv6 literal to be denied, got allow")
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

// P2-1: an explicit in-scope IP/CIDR entry authorizes only documentation ranges. Every other
// restricted class additionally requires the INTERNAL_NETWORK capability AND the restricted-address
// override. These tests pin that policy for explicit IPs, CIDRs, URL literals and DNS answers.
func restrictedPolicy(withInternal bool) *Policy {
	p := basePolicy()
	caps := []string{"ACTIVE_HTTP", "DNS", "PASSIVE"}
	if withInternal {
		caps = append(caps, "INTERNAL_NETWORK")
	}
	p.Authorization.Capabilities = caps
	p.InScope.IPs = append(p.InScope.IPs, "127.0.0.1", "169.254.169.254", "169.254.1.1", "100.64.0.1", "::1", "fd00:ec2::254")
	p.InScope.CIDRs = append(p.InScope.CIDRs, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fe80::/10", "fd00::/8", "2001:db8::/32")
	return p
}

var explicitRestricted = []struct{ name, ip string }{
	{"loopback ip", "127.0.0.1"},
	{"metadata ip", "169.254.169.254"},
	{"link-local ip", "169.254.1.1"},
	{"cgnat ip", "100.64.0.1"},
	{"private 10/8 cidr", "10.20.30.40"},
	{"private 172.16/12 cidr", "172.16.5.5"},
	{"private 192.168/16 cidr", "192.168.1.1"},
	{"ipv6 loopback", "::1"},
	{"ipv6 metadata", "fd00:ec2::254"},
	{"ipv6 link-local cidr", "fe80::1"},
	{"ipv6 unique-local cidr", "fd00::1"},
	{"ipv4-mapped private", "::ffff:10.0.0.1"},
}

func TestExplicitRestrictedEntryDoesNotBypassCapabilityAndFlag(t *testing.T) {
	for _, tc := range explicitRestricted {
		for _, mode := range []struct {
			name     string
			internal bool
			flag     bool
		}{{"no capability, no flag", false, false}, {"capability only", true, false}, {"flag only", false, true}} {
			t.Run(tc.name+"/"+mode.name, func(t *testing.T) {
				e := NewEngine(restrictedPolicy(mode.internal))
				e.AllowRestrictedAddress = mode.flag
				for _, req := range []Request{
					{Kind: "IP", Value: tc.ip, Capability: "ACTIVE_HTTP"},
					{Kind: "URL", Value: "http://" + bracket(tc.ip) + "/", Capability: "ACTIVE_HTTP"},
					{Kind: "HOST", Value: "www.example.com", Capability: "ACTIVE_HTTP", ResolvedAddresses: []string{tc.ip}},
				} {
					d := e.Check(req)
					if d.Allowed || d.Code != CodeRestrictedAddress {
						t.Fatalf("%s %q: expected RESTRICTED_ADDRESS_SPACE, got %+v", req.Kind, req.Value, d)
					}
				}
			})
		}
	}
}

func TestExplicitRestrictedEntryAllowedWithCapabilityAndFlag(t *testing.T) {
	for _, tc := range explicitRestricted {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEngine(restrictedPolicy(true))
			e.AllowRestrictedAddress = true
			if d := e.Check(Request{Kind: "IP", Value: tc.ip, Capability: "ACTIVE_HTTP"}); !d.Allowed {
				t.Fatalf("expected allow with capability+flag for %s, got %+v", tc.ip, d)
			}
			// A DNS answer is judged on the address alone; the hostname's own scope still applies.
			if d := e.Check(Request{Kind: "HOST", Value: "www.example.com", Capability: "ACTIVE_HTTP", ResolvedAddresses: []string{tc.ip}}); !d.Allowed {
				t.Fatalf("expected resolved %s allowed with capability+flag, got %+v", tc.ip, d)
			}
		})
	}
}

func TestUnlistedRestrictedAddressDeniedEvenWithCapabilityAndFlag(t *testing.T) {
	// The override relaxes the address-class check only; it never grants scope.
	e := NewEngine(restrictedPolicy(true))
	e.AllowRestrictedAddress = true
	d := e.Check(Request{Kind: "IP", Value: "10.0.0.1", Capability: "ACTIVE_HTTP"})
	if !d.Allowed {
		t.Fatalf("listed 10/8 should be allowed, got %+v", d)
	}
	d = e.Check(Request{Kind: "IP", Value: "172.32.0.1", Capability: "ACTIVE_HTTP"}) // routable, unlisted
	if d.Allowed || d.Code != CodeNotInScope {
		t.Fatalf("expected NOT_IN_SCOPE for unlisted address, got %+v", d)
	}
	// Unlisted restricted space stays denied even with capability+flag, for literals and DNS answers
	// alike (this is what keeps DNS rebinding to an unlisted internal address blocked).
	for _, ip := range []string{"127.0.0.2", "169.254.169.253", "100.100.100.100", "fc00::1"} {
		for _, req := range []Request{
			{Kind: "IP", Value: ip, Capability: "ACTIVE_HTTP"},
			{Kind: "HOST", Value: "www.example.com", Capability: "ACTIVE_HTTP", ResolvedAddresses: []string{ip}},
		} {
			if d := e.Check(req); d.Allowed || d.Code != CodeRestrictedAddress {
				t.Fatalf("%s %q resolved=%v: expected RESTRICTED_ADDRESS_SPACE, got %+v", req.Kind, req.Value, req.ResolvedAddresses, d)
			}
		}
	}
}

func TestExplicitDocumentationRangesAllowedWithoutOverride(t *testing.T) {
	e := NewEngine(restrictedPolicy(false))
	for _, ip := range []string{"203.0.113.10", "198.51.100.77", "2001:db8::5"} {
		if d := e.Check(Request{Kind: "IP", Value: ip, Capability: "ACTIVE_HTTP"}); !d.Allowed {
			t.Fatalf("expected documentation address %s allowed, got %+v", ip, d)
		}
	}
	// Not explicitly listed => not documentation exemption nor in scope.
	if d := e.Check(Request{Kind: "IP", Value: "192.0.2.1", Capability: "ACTIVE_HTTP"}); d.Allowed {
		t.Fatalf("unlisted documentation address must not be allowed, got %+v", d)
	}
	// A DNS answer inside an explicit documentation CIDR is allowed.
	if d := e.Check(Request{Kind: "HOST", Value: "www.example.com", Capability: "ACTIVE_HTTP", ResolvedAddresses: []string{"198.51.100.9"}}); !d.Allowed {
		t.Fatalf("expected resolved documentation address allowed, got %+v", d)
	}
}

func TestNonDocumentationReservedNeedsOverrideEvenIfListed(t *testing.T) {
	p := restrictedPolicy(false)
	p.InScope.CIDRs = append(p.InScope.CIDRs, "240.0.0.0/4", "198.18.0.0/15", "0.0.0.0/8")
	e := NewEngine(p)
	for _, ip := range []string{"240.0.0.1", "198.18.0.1", "0.0.0.1"} {
		if d := e.Check(Request{Kind: "IP", Value: ip, Capability: "ACTIVE_HTTP"}); d.Allowed || d.Code != CodeRestrictedAddress {
			t.Fatalf("expected %s denied as restricted, got %+v", ip, d)
		}
	}
}

func TestExclusionStillBeatsExplicitRestrictedEntry(t *testing.T) {
	p := restrictedPolicy(true)
	p.Exclusions.IPs = []string{"10.0.0.99"}
	e := NewEngine(p)
	e.AllowRestrictedAddress = true
	if d := e.Check(Request{Kind: "IP", Value: "10.0.0.99", Capability: "ACTIVE_HTTP"}); d.Allowed || d.Code != CodeExcluded {
		t.Fatalf("expected EXCLUDED, got %+v", d)
	}
}

func bracket(ip string) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]"
	}
	return ip
}
