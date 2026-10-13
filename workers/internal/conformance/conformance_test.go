package conformance

import (
	"path/filepath"
	"reflect"
	"testing"
)

const fixtureDir = "../../../test/fixtures/conformance"

func strPtrEq(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func TestConformanceFixtures(t *testing.T) {
	dir, err := filepath.Abs(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Compute(dir)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}

	var domains domainFixture
	if err := readJSON(filepath.Join(dir, "domains.json"), &domains); err != nil {
		t.Fatal(err)
	}
	for i, c := range domains.Registrable {
		if !strPtrEq(got.Registrable[i].Result, c.Expected) {
			t.Errorf("registrable[%d] %q: got %v want %v", i, c.Host, deref(got.Registrable[i].Result), deref(c.Expected))
		}
	}
	for i, c := range domains.Suffix {
		if !strPtrEq(got.Suffix[i].Result, c.Expected) {
			t.Errorf("suffix[%d] %q: got %v want %v", i, c.Host, deref(got.Suffix[i].Result), deref(c.Expected))
		}
	}
	for i, c := range domains.Matching {
		if got.Matching[i].Result != c.Expected {
			t.Errorf("matching[%d] %q vs %q: got %v want %v", i, c.Host, c.Value, got.Matching[i].Result, c.Expected)
		}
	}

	var ips []IPCase
	if err := readJSON(filepath.Join(dir, "ips.json"), &ips); err != nil {
		t.Fatal(err)
	}
	for i, c := range ips {
		if !strPtrEq(got.IPs[i].Canonical, c.Canonical) {
			t.Errorf("ip[%d] %q canonical: got %v want %v", i, c.Input, deref(got.IPs[i].Canonical), deref(c.Canonical))
		}
		if !intPtrEq(got.IPs[i].Version, c.Version) {
			t.Errorf("ip[%d] %q version: got %v want %v", i, c.Input, derefInt(got.IPs[i].Version), derefInt(c.Version))
		}
		if !reflect.DeepEqual(got.IPs[i].Categories, c.Categories) {
			t.Errorf("ip[%d] %q categories: got %v want %v", i, c.Input, got.IPs[i].Categories, c.Categories)
		}
	}

	var urls []struct {
		Input    string  `json:"input"`
		Expected *string `json:"expected"`
	}
	if err := readJSON(filepath.Join(dir, "urls.json"), &urls); err != nil {
		t.Fatal(err)
	}
	for i, c := range urls {
		if !strPtrEq(got.URLs[i].Result, c.Expected) {
			t.Errorf("url[%d] %q: got %v want %v", i, c.Input, deref(got.URLs[i].Result), deref(c.Expected))
		}
	}

	expected, err := ExpectedScope(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got.Scope {
		exp, ok := expected[r.Name]
		if !ok {
			t.Errorf("unexpected scope case %q", r.Name)
			continue
		}
		if r.Allowed != exp.Expected.Allowed || r.Code != exp.Expected.Code {
			t.Errorf("scope %q: got {allowed:%v code:%s} want {allowed:%v code:%s}", r.Name, r.Allowed, r.Code, exp.Expected.Allowed, exp.Expected.Code)
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
func derefInt(i *int) any {
	if i == nil {
		return "<nil>"
	}
	return *i
}
func intPtrEq(a, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
