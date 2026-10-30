// Package scope implements independent, worker-side scope enforcement. It mirrors the
// TypeScript policy engine so a compromised or misconfigured control plane cannot cause a
// worker to send traffic outside the authorized scope. Worker-side checks are authoritative.
package scope

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/reconnexus/workers/internal/matching"
)

// Decision codes (kept identical to the TypeScript engine's ScopeDecisionCode).
const (
	CodeAllowed                = "ALLOWED"
	CodeAuthorizationExpired   = "AUTHORIZATION_EXPIRED"
	CodeAuthorizationNotYet    = "AUTHORIZATION_NOT_YET_VALID"
	CodeCapabilityNotPermitted = "CAPABILITY_NOT_PERMITTED"
	CodeNotInScope             = "NOT_IN_SCOPE"
	CodeExcluded               = "EXCLUDED"
	CodeExcludedPath           = "EXCLUDED_PATH"
	CodeRestrictedAddress      = "RESTRICTED_ADDRESS_SPACE"
	CodeDNSRebind              = "DNS_REBIND_DETECTED"
	CodeDNSResolutionFailed    = "DNS_RESOLUTION_FAILED"
	CodeInvalidTarget          = "INVALID_TARGET"
	CodeLimitExceeded          = "LIMIT_EXCEEDED"
)

// CapabilityInternalNetwork is the only capability that may ever reach restricted space.
const CapabilityInternalNetwork = "INTERNAL_NETWORK"

var AllCapabilities = map[string]bool{
	"PASSIVE": true, "DNS": true, "ACTIVE_HTTP": true, "CRAWL": true,
	"JS_ANALYSIS": true, "API_DISCOVERY": true, "SECRET_SCAN": true,
	"SECURITY_CHECKS": true, "ACTIVE_TEMPLATE_CHECK": true, "TAKEOVER_CHECK": true, "PORT_SCAN": true, "CONTENT_DISCOVERY": true,
	"INTERNAL_NETWORK": true,
}

type DomainRule struct {
	Value             string `json:"value"`
	IncludeSubdomains bool   `json:"includeSubdomains"`
}

type Authorization struct {
	Reference    string    `json:"reference"`
	AuthorizedBy string    `json:"authorizedBy"`
	ValidFrom    time.Time `json:"validFrom"`
	ValidUntil   time.Time `json:"validUntil"`
	Capabilities []string  `json:"capabilities"`
}

type InScope struct {
	Domains []DomainRule `json:"domains"`
	Hosts   []string     `json:"hosts"`
	IPs     []string     `json:"ips"`
	CIDRs   []string     `json:"cidrs"`
}

type Exclusions struct {
	Domains []DomainRule `json:"domains"`
	Hosts   []string     `json:"hosts"`
	IPs     []string     `json:"ips"`
	CIDRs   []string     `json:"cidrs"`
	Paths   []string     `json:"paths"`
}

type Limits struct {
	MaxConcurrency    int     `json:"maxConcurrency"`
	RequestsPerSecond float64 `json:"requestsPerSecond"`
	CrawlDepth        int     `json:"crawlDepth"`
	MaxRuntimeSeconds int     `json:"maxRuntimeSeconds"`
	MaxArtifactBytes  int     `json:"maxArtifactBytes"`
}

type Policy struct {
	SchemaVersion int           `json:"schemaVersion"`
	PolicyID      string        `json:"policyId"`
	ProjectID     string        `json:"projectId"`
	PolicyVersion int           `json:"policyVersion"`
	Authorization Authorization `json:"authorization"`
	InScope       InScope       `json:"inScope"`
	Exclusions    Exclusions    `json:"exclusions"`
	Limits        Limits        `json:"limits"`
}

type Request struct {
	Kind              string
	Value             string
	Capability        string
	Now               time.Time
	ResolvedAddresses []string
	IsRedirect        bool
}

type AddressDecision struct {
	Address string `json:"address"`
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

type Decision struct {
	Allowed          bool              `json:"allowed"`
	Code             string            `json:"code"`
	Reason           string            `json:"reason"`
	MatchedRule      string            `json:"matchedRule,omitempty"`
	AddressDecisions []AddressDecision `json:"addressDecisions,omitempty"`
}

// LoadPolicy decodes and validates a scope policy document.
func LoadPolicy(r io.Reader) (*Policy, error) {
	var p Policy
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	if p.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported policy schemaVersion %d", p.SchemaVersion)
	}
	if len(p.Authorization.Capabilities) == 0 {
		return nil, errors.New("policy authorizes no capabilities")
	}
	for _, c := range p.Authorization.Capabilities {
		if !AllCapabilities[c] {
			return nil, fmt.Errorf("unknown capability %q", c)
		}
	}
	if !p.Authorization.ValidUntil.After(p.Authorization.ValidFrom) {
		return nil, errors.New("authorization validUntil must be after validFrom")
	}
	return &p, nil
}

// Engine enforces a policy.
type Engine struct {
	Policy                 *Policy
	AllowRestrictedAddress bool
}

func NewEngine(p *Policy) *Engine { return &Engine{Policy: p} }

type target struct {
	host string
	ip   netip.Addr
	path string
	hasIP bool
}

func (e *Engine) resolveTarget(req Request) (target, *Decision) {
	switch req.Kind {
	case "URL":
		u, err := url.Parse(req.Value)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return target{}, &Decision{Allowed: false, Code: CodeInvalidTarget, Reason: "not a valid http(s) URL: " + req.Value}
		}
		host := matching.CanonicalHost(u.Hostname())
		t := target{host: host, path: matching.NormalizePath(u.EscapedPath())}
		if a, err := netip.ParseAddr(host); err == nil {
			t.ip = a.Unmap()
			t.hasIP = true
		}
		return t, nil
	case "HOST", "DOMAIN":
		host := matching.CanonicalHost(req.Value)
		if host == "" {
			return target{}, &Decision{Allowed: false, Code: CodeInvalidTarget, Reason: "empty host"}
		}
		t := target{host: host}
		if a, err := netip.ParseAddr(host); err == nil {
			t.ip = a.Unmap()
			t.hasIP = true
		}
		return t, nil
	case "IP":
		a, err := netip.ParseAddr(strings.TrimSpace(req.Value))
		if err != nil {
			return target{}, &Decision{Allowed: false, Code: CodeInvalidTarget, Reason: "not an IP literal: " + req.Value}
		}
		a = a.Unmap()
		return target{host: a.String(), ip: a, hasIP: true}, nil
	case "CIDR":
		return target{host: strings.ToLower(strings.TrimSpace(req.Value))}, nil
	default:
		return target{}, &Decision{Allowed: false, Code: CodeInvalidTarget, Reason: "unknown target kind " + req.Kind}
	}
}

// Check evaluates a request against the policy, applying all checks in order.
func (e *Engine) Check(req Request) Decision {
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	if now.Before(e.Policy.Authorization.ValidFrom) {
		return Decision{Allowed: false, Code: CodeAuthorizationNotYet, Reason: "authorization is not yet valid"}
	}
	if now.After(e.Policy.Authorization.ValidUntil) {
		return Decision{Allowed: false, Code: CodeAuthorizationExpired, Reason: "authorization has expired"}
	}
	if !contains(e.Policy.Authorization.Capabilities, req.Capability) {
		return Decision{Allowed: false, Code: CodeCapabilityNotPermitted, Reason: "capability " + req.Capability + " is not authorized"}
	}

	t, deny := e.resolveTarget(req)
	if deny != nil {
		return *deny
	}

	if d, excluded := e.matchExclusion(t); excluded {
		return d
	}

	// Address-space restrictions are evaluated before the positive match so a restricted
	// destination is reported as such; this is the stronger security signal.
	addresses := e.collectAddresses(t, req)
	decisions := make([]AddressDecision, 0, len(addresses))
	for _, addr := range addresses {
		ad := e.evaluateAddress(addr)
		decisions = append(decisions, ad)
		if !ad.Allowed {
			return Decision{Allowed: false, Code: CodeRestrictedAddress, Reason: "destination " + addr + " not permitted: " + ad.Reason, AddressDecisions: decisions}
		}
	}

	rule, reason, ok := e.matchInclusion(t)
	if !ok {
		return Decision{Allowed: false, Code: CodeNotInScope, Reason: "target " + t.host + " is not covered by the scope policy"}
	}
	if len(decisions) > 0 {
		return Decision{Allowed: true, Code: CodeAllowed, Reason: "in scope (" + reason + ")", MatchedRule: rule, AddressDecisions: decisions}
	}
	return Decision{Allowed: true, Code: CodeAllowed, Reason: "in scope (" + reason + ")", MatchedRule: rule}
}

func (e *Engine) collectAddresses(t target, req Request) []string {
	set := map[string]struct{}{}
	if t.hasIP {
		set[t.ip.String()] = struct{}{}
	}
	for _, a := range req.ResolvedAddresses {
		if parsed, err := netip.ParseAddr(a); err == nil {
			set[parsed.Unmap().String()] = struct{}{}
		} else {
			set[a] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}

func (e *Engine) evaluateAddress(address string) AddressDecision {
	a, ok := matching.ParseIP(address)
	if !ok {
		return AddressDecision{Address: address, Allowed: false, Reason: "not a parseable IP literal"}
	}
	cls := matching.ClassifyAddr(a)
	explicitlyAllowed := e.explicitlyAllowedIP(a)

	if cls.IsSpecial() {
		// Policy (P2-1, docs/threat-model/scope-enforcement.md "Restricted address space"):
		//   * documentation ranges (RFC 5737 / RFC 3849) listed in scope are allowed outright;
		//   * every other restricted class must be explicitly listed in inScope.ips/cidrs AND the
		//     policy must grant INTERNAL_NETWORK AND the restricted-address override must be set.
		// The override never opens unlisted restricted space, so a name rebinding to an unlisted
		// private/loopback/metadata address is always denied. Mirrors packages/scope-policy/src/engine.ts.
		if explicitlyAllowed && cls.IsDocumentation {
			return AddressDecision{Address: address, Allowed: true, Reason: "explicitly authorized in-scope documentation address"}
		}
		if !explicitlyAllowed {
			return AddressDecision{Address: address, Allowed: false, Reason: "restricted address space (" + strings.Join(cls.Categories(), ", ") + ") is not explicitly listed in inScope.ips/cidrs"}
		}
		if !e.AllowRestrictedAddress || !contains(e.Policy.Authorization.Capabilities, CapabilityInternalNetwork) {
			return AddressDecision{Address: address, Allowed: false, Reason: "restricted address space (" + strings.Join(cls.Categories(), ", ") + ") requires INTERNAL_NETWORK capability and a restricted-address override"}
		}
	}
	return AddressDecision{Address: address, Allowed: true, Reason: "routable public address"}
}

func (e *Engine) explicitlyAllowedIP(a netip.Addr) bool {
	au := a.Unmap()
	for _, s := range e.Policy.InScope.IPs {
		if p, ok := matching.ParseIP(s); ok && p.Unmap() == au {
			return true
		}
	}
	for _, s := range e.Policy.InScope.CIDRs {
		if p, err := netip.ParsePrefix(s); err == nil && p.Contains(au) {
			return true
		}
	}
	return false
}

func (e *Engine) matchExclusion(t target) (Decision, bool) {
	if t.hasIP {
		for _, s := range e.Policy.Exclusions.IPs {
			if p, err := netip.ParseAddr(s); err == nil && p.Unmap() == t.ip {
				return Decision{Allowed: false, Code: CodeExcluded, Reason: "IP " + t.ip.String() + " is excluded"}, true
			}
		}
		for _, s := range e.Policy.Exclusions.CIDRs {
			if p, err := netip.ParsePrefix(s); err == nil && p.Contains(t.ip) {
				return Decision{Allowed: false, Code: CodeExcluded, Reason: "IP " + t.ip.String() + " falls in excluded CIDR " + s}, true
			}
		}
	}
	for _, h := range e.Policy.Exclusions.Hosts {
		if strings.EqualFold(h, t.host) {
			return Decision{Allowed: false, Code: CodeExcluded, Reason: "host " + t.host + " is excluded"}, true
		}
	}
	for _, d := range e.Policy.Exclusions.Domains {
		if matching.MatchDomain(t.host, d.Value, d.IncludeSubdomains) || matching.IsSubdomainOf(t.host, d.Value) {
			return Decision{Allowed: false, Code: CodeExcluded, Reason: "host " + t.host + " is excluded by domain rule " + d.Value}, true
		}
	}
	for _, p := range e.Policy.Exclusions.Paths {
		if p != "" && t.path != "" && strings.HasPrefix(t.path, p) {
			return Decision{Allowed: false, Code: CodeExcludedPath, Reason: "path " + t.path + " is excluded by rule " + p}, true
		}
	}
	return Decision{}, false
}

func (e *Engine) matchInclusion(t target) (rule, reason string, ok bool) {
	if t.hasIP {
		for _, s := range e.Policy.InScope.IPs {
			if p, ok := matching.ParseIP(s); ok && p.Unmap() == t.ip {
				return "ip:" + s, "exact IP match", true
			}
		}
		for _, s := range e.Policy.InScope.CIDRs {
			if p, err := netip.ParsePrefix(s); err == nil && p.Contains(t.ip) {
				return "cidr:" + s, "CIDR match", true
			}
		}
		return "", "", false
	}
	for _, h := range e.Policy.InScope.Hosts {
		if strings.EqualFold(h, t.host) {
			return "host:" + h, "exact host match", true
		}
	}
	for _, d := range e.Policy.InScope.Domains {
		if matching.MatchDomain(t.host, d.Value, d.IncludeSubdomains) {
			suffix := ""
			if d.IncludeSubdomains {
				suffix = " (+subdomains)"
			}
			return "domain:" + d.Value + suffix, "domain match", true
		}
	}
	// Registrable-domain inference: a host whose eTLD+1 equals an authorized domain is in
	// scope. Mirrors the TypeScript engine exactly.
	if reg, ok := matching.RegistrableDomain(t.host); ok {
		for _, d := range e.Policy.InScope.Domains {
			if matching.CanonicalHost(d.Value) == reg {
				return "domain:" + d.Value, "registrable-domain match", true
			}
		}
	}
	return "", "", false
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
