// Package matching provides canonicalization primitives shared by worker-side scope
// enforcement. It mirrors packages/normalization in TypeScript and is verified against
// the same conformance fixtures (see test/fixtures/conformance and cmd/conformance).
package matching

import (
	"net/netip"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// CanonicalHost lowercases a host, strips a single trailing dot, and removes surrounding
// brackets from an IPv6 literal.
func CanonicalHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	h = strings.TrimSuffix(h, ".")
	return h
}

// IsIPLiteral reports whether host is a bare IP literal.
func IsIPLiteral(host string) bool {
	_, err := netip.ParseAddr(CanonicalHost(host))
	return err == nil
}

// RegistrableDomain returns the eTLD+1 using the Public Suffix List. It mirrors the
// TypeScript implementation's fallback: when the suffix is unknown, the last two labels
// are used when available.
func RegistrableDomain(host string) (string, bool) {
	h := CanonicalHost(host)
	if h == "" || IsIPLiteral(h) {
		return "", false
	}
	if domain, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil && domain != "" {
		return domain, true
	}
	labels := strings.Split(h, ".")
	nonEmpty := labels[:0]
	for _, l := range labels {
		if l != "" {
			nonEmpty = append(nonEmpty, l)
		}
	}
	if len(nonEmpty) >= 2 {
		return strings.Join(nonEmpty[len(nonEmpty)-2:], "."), true
	}
	return "", false
}

// PublicSuffix returns the public suffix (e.g. "co.uk"), or empty when unknown.
func PublicSuffix(host string) string {
	h := CanonicalHost(host)
	if h == "" || IsIPLiteral(h) {
		return ""
	}
	ps, _ := publicsuffix.PublicSuffix(h)
	return ps
}

// MatchDomain reports whether host matches the domain rule value (optionally including
// subdomains). Matching is label-boundary aware.
func MatchDomain(host, value string, includeSubdomains bool) bool {
	h := CanonicalHost(host)
	v := CanonicalHost(value)
	if h == v {
		return true
	}
	return includeSubdomains && strings.HasSuffix(h, "."+v)
}

// IsSubdomainOf reports whether candidate equals root or is a subdomain of it.
func IsSubdomainOf(candidate, root string) bool {
	c := CanonicalHost(candidate)
	r := CanonicalHost(root)
	return c == r || strings.HasSuffix(c, "."+r)
}
