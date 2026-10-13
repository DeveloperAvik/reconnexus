package matching

import (
	"net/netip"
	"sort"
)

// Classification mirrors classifyIp in packages/normalization/src/ip.ts.
type Classification struct {
	IsPrivate     bool
	IsLoopback    bool
	IsLinkLocal   bool
	IsUniqueLocal bool
	IsCGNAT       bool
	IsMulticast   bool
	IsUnspecified bool
	IsBroadcast   bool
	IsReserved    bool
	IsMetadata    bool
}

func (c Classification) IsSpecial() bool {
	return c.IsPrivate || c.IsLoopback || c.IsLinkLocal || c.IsCGNAT || c.IsMulticast ||
		c.IsUnspecified || c.IsBroadcast || c.IsReserved || c.IsMetadata
}

// Categories returns a sorted list of the category labels that apply.
func (c Classification) Categories() []string {
	pairs := []struct {
		on   bool
		name string
	}{
		{c.IsPrivate, "private"},
		{c.IsLoopback, "loopback"},
		{c.IsLinkLocal, "link-local"},
		{c.IsUniqueLocal, "unique-local"},
		{c.IsCGNAT, "cgnat"},
		{c.IsMulticast, "multicast"},
		{c.IsUnspecified, "unspecified"},
		{c.IsBroadcast, "broadcast"},
		{c.IsReserved, "reserved"},
		{c.IsMetadata, "metadata"},
	}
	out := make([]string, 0, 4)
	for _, p := range pairs {
		if p.on {
			out = append(out, p.name)
		}
	}
	sort.Strings(out)
	return out
}

// ParseIP parses an IPv4 or IPv6 literal without unwrapping IPv4-mapped addresses.
func ParseIP(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(trimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	return a, true
}

// CanonicalIP returns the canonical textual form of an IP literal.
func CanonicalIP(s string) (string, bool) {
	a, ok := ParseIP(s)
	if !ok {
		return "", false
	}
	return a.String(), true
}

// ClassifyAddr classifies an already-parsed address (unwrapping IPv4-mapped forms).
func ClassifyAddr(a netip.Addr) Classification {
	a = a.Unmap()
	is4 := a.Is4()

	var c Classification
	if is4 {
		c.IsLoopback = inPrefix(a, "127.0.0.0/8")
		c.IsLinkLocal = inPrefix(a, "169.254.0.0/16")
		c.IsPrivate = inPrefix(a, "10.0.0.0/8") ||
			inPrefix(a, "172.16.0.0/12") ||
			inPrefix(a, "192.168.0.0/16")
		c.IsCGNAT = inPrefix(a, "100.64.0.0/10")
		c.IsMulticast = inPrefix(a, "224.0.0.0/4")
		c.IsBroadcast = a == netip.MustParseAddr("255.255.255.255")
		c.IsReserved = inPrefix(a, "0.0.0.0/8") ||
			inPrefix(a, "192.0.0.0/24") ||
			inPrefix(a, "192.0.2.0/24") ||
			inPrefix(a, "198.18.0.0/15") ||
			inPrefix(a, "198.51.100.0/24") ||
			inPrefix(a, "203.0.113.0/24") ||
			inPrefix(a, "240.0.0.0/4")
		c.IsMetadata = a == netip.MustParseAddr("169.254.169.254")
	} else {
		c.IsLoopback = a == netip.MustParseAddr("::1")
		c.IsLinkLocal = inPrefix(a, "fe80::/10")
		c.IsUniqueLocal = inPrefix(a, "fc00::/7")
		c.IsPrivate = c.IsUniqueLocal
		c.IsMulticast = inPrefix(a, "ff00::/8")
		c.IsReserved = inPrefix(a, "2001:db8::/32")
		c.IsMetadata = a == netip.MustParseAddr("fd00:ec2::254")
	}
	c.IsUnspecified = a.IsUnspecified()
	return c
}

// ClassifyIP parses and classifies an IP literal.
func ClassifyIP(s string) (Classification, bool) {
	a, ok := ParseIP(s)
	if !ok {
		return Classification{}, false
	}
	return ClassifyAddr(a), true
}

// IPEqual reports whether two IP literals denote the same address after unwrapping.
func IPEqual(a, b netip.Addr) bool {
	return a.Unmap() == b.Unmap()
}

func inPrefix(a netip.Addr, cidr string) bool {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	return p.Contains(a)
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}
