package matching

import "testing"

var benchURLs = []string{
	"HTTP://Example.COM:80/Path?b=2&a=1#frag",
	"https://user.example.co.uk/a/../b/c?x=1&x=2&y=%2Fz",
	"http://example.com/%2e%2e/admin?next=https%3A%2F%2Fevil.test",
	"https://cdn.example.com/static/js/app.min.js?v=9f2c1a",
	"http://münchen.example.de/räume?q=tür",
	"https://example.com/a/b/c/d/e/f/g/../h/./i",
	"http://example.com//double//slash",
	"https://example.com:8443/path#fragment",
}

func BenchmarkCanonicalURL(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := CanonicalURL(benchURLs[i%len(benchURLs)]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNormalizePath(b *testing.B) {
	paths := []string{"/a/b/../c", "/%2e%2e/x", "/a/./b/../c/d", "//a//b", "/a/%2e/b"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = NormalizePath(paths[i%len(paths)])
	}
}
