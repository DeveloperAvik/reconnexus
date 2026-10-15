package discovery

import (
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// BenchmarkExtractScriptRefs measures the HTML <script src> scan over a large document. The scan is
// RE2 (linear time) and bounded by the response-size limit, so this records a baseline rather than
// chasing a target.
func BenchmarkExtractScriptRefs(b *testing.B) {
	base, _ := url.Parse("https://example.com/app/page/index.html")
	var sb strings.Builder
	for i := 0; i < 2000; i++ {
		sb.WriteString(`<script src="/assets/chunk-`)
		sb.WriteString(strconv.Itoa(i))
		sb.WriteString(strings.Repeat("x", 32))
		sb.WriteString(`.js"></script>`)
		sb.WriteString(`<a href="/page/`)
		sb.WriteString(strings.Repeat("y", 30))
		sb.WriteString(`">link</a>`)
	}
	body := sb.String()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if refs := extractScriptRefs(body, base); len(refs) != 2000 {
			b.Fatalf("expected 2000 deduped refs, got %d", len(refs))
		}
	}
}
