package matching

import (
	"errors"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

// ErrUnsupportedScheme is returned for non-http(s) URLs.
var ErrUnsupportedScheme = errors.New("unsupported scheme")

// CanonicalURL returns a stable identity for an http(s) URL, matching the TypeScript
// `parseUrl(...).canonical`. Transformations that are applied:
//   - scheme and host lowercased;
//   - internationalized host converted to punycode;
//   - default ports (80/443) removed;
//   - RFC 3986 dot-segment removal in the path;
//   - fragment removed (not part of HTTP request identity).
//
// Transformations deliberately NOT applied: query parameters are neither sorted, removed,
// nor collapsed; the trailing slash is preserved; existing percent-encoding is preserved
// (no decoding); repeated parameters are kept in order.
func CanonicalURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", ErrUnsupportedScheme
	}
	hostRaw := u.Hostname()
	if hostRaw == "" {
		return "", errors.New("missing host")
	}
	host := canonicalHostASCII(hostRaw)

	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}

	escPath := u.EscapedPath()
	if escPath == "" {
		escPath = "/"
	}
	path := resolvePathWHATWG(escPath)

	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("://")
	if strings.Contains(host, ":") { // IPv6 literal
		b.WriteByte('[')
		b.WriteString(host)
		b.WriteByte(']')
	} else {
		b.WriteString(host)
	}
	if port != "" {
		b.WriteByte(':')
		b.WriteString(port)
	}
	b.WriteString(path)
	if u.RawQuery != "" {
		b.WriteByte('?')
		b.WriteString(u.RawQuery)
	}
	return b.String(), nil
}

func canonicalHostASCII(host string) string {
	lower := strings.ToLower(host)
	if _, err := netip.ParseAddr(lower); err == nil {
		return lower
	}
	if ascii, err := idna.Lookup.ToASCII(lower); err == nil && ascii != "" {
		return ascii
	}
	return lower
}

// HostAndPort extracts the canonical host and port for a URL.
func HostAndPort(raw string) (string, string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", false
	}
	h := u.Hostname()
	if h == "" {
		return "", "", false
	}
	return canonicalHostASCII(h), u.Port(), true
}

// NormalizePath exposes WHATWG-compatible path normalization so the scope engine performs path
// exclusion checks on the same canonical path as the TypeScript engine.
func NormalizePath(escaped string) string {
	return resolvePathWHATWG(escaped)
}

// resolvePathWHATWG applies URL Standard dot-segment removal to an escaped path, matching the
// behaviour of the WHATWG URL parser used by the TypeScript control plane. Critically, the
// single-dot segment is "." or "%2e" and the double-dot segment is "..", ".%2e", "%2e." or
// "%2e%2e" (case-insensitive); every other segment (including other percent-encodings) is preserved
// verbatim. This keeps scope path-exclusion checks and URL identity identical across languages.
func resolvePathWHATWG(escaped string) string {
	if !strings.HasPrefix(escaped, "/") {
		escaped = "/" + escaped
	}
	segments := strings.Split(escaped, "/")
	// The first element is the empty string before the leading slash.
	segments = segments[1:]

	out := make([]string, 0, len(segments))
	trailingSlash := false
	for i, seg := range segments {
		last := i == len(segments)-1
		switch {
		case isSingleDotSegment(seg):
			if last {
				trailingSlash = true
			}
		case isDoubleDotSegment(seg):
			if n := len(out); n > 0 && out[n-1] != ".." {
				out = out[:n-1]
			} else if n == 0 {
				// at root: dropping ".." leaves the root
			} else {
				out = append(out, seg)
			}
			if last {
				trailingSlash = true
			}
		default:
			out = append(out, seg)
			trailingSlash = false
		}
	}
	result := "/" + strings.Join(out, "/")
	if trailingSlash && !strings.HasSuffix(result, "/") {
		result += "/"
	}
	return result
}

func isSingleDotSegment(seg string) bool {
	return seg == "." || strings.EqualFold(seg, "%2e")
}

func isDoubleDotSegment(seg string) bool {
	switch {
	case seg == "..":
		return true
	case strings.EqualFold(seg, ".%2e"), strings.EqualFold(seg, "%2e."), strings.EqualFold(seg, "%2e%2e"):
		return true
	default:
		return false
	}
}
