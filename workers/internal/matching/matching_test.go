package matching

import (
	"reflect"
	"testing"
)

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"www.example.co.uk": "example.co.uk",
		"a.b.example.com":   "example.com",
		"example.com":       "example.com",
		"site.github.io":    "site.github.io",
		"co.uk":             "co.uk",
		"foo.internal":      "foo.internal",
	}
	for host, want := range cases {
		got, ok := RegistrableDomain(host)
		if !ok || got != want {
			t.Errorf("RegistrableDomain(%q) = %q,%v want %q", host, got, ok, want)
		}
	}
	for _, host := range []string{"localhost", "127.0.0.1", "::1", ""} {
		if _, ok := RegistrableDomain(host); ok {
			t.Errorf("RegistrableDomain(%q) should have no registrable domain", host)
		}
	}
}

func TestMatchDomainBoundaries(t *testing.T) {
	cases := []struct {
		host, value string
		sub         bool
		want        bool
	}{
		{"app.example.com", "example.com", true, true},
		{"example.com", "example.com", false, true},
		{"app.example.com", "example.com", false, false},
		{"notexample.com", "example.com", true, false},
		{"example.com.evil.net", "example.com", true, false},
	}
	for _, c := range cases {
		if got := MatchDomain(c.host, c.value, c.sub); got != c.want {
			t.Errorf("MatchDomain(%q,%q,%v)=%v want %v", c.host, c.value, c.sub, got, c.want)
		}
	}
}

func TestCanonicalAndClassify(t *testing.T) {
	if got, ok := CanonicalIP("2001:DB8::1"); !ok || got != "2001:db8::1" {
		t.Errorf("CanonicalIP = %q,%v", got, ok)
	}
	if got, ok := CanonicalIP("::ffff:127.0.0.1"); !ok || got != "::ffff:127.0.0.1" {
		t.Errorf("CanonicalIP mapped = %q,%v", got, ok)
	}
	if _, ok := CanonicalIP("999.1.1.1"); ok {
		t.Errorf("expected invalid IP to fail")
	}

	c, ok := ClassifyIP("::ffff:127.0.0.1")
	if !ok || !c.IsLoopback {
		t.Errorf("mapped loopback should classify as loopback: %+v", c)
	}
	c, _ = ClassifyIP("fd00:ec2::254")
	want := []string{"metadata", "private", "unique-local"}
	if !reflect.DeepEqual(c.Categories(), want) {
		t.Errorf("fd00:ec2::254 categories = %v want %v", c.Categories(), want)
	}
	c, _ = ClassifyIP("8.8.8.8")
	if c.IsSpecial() {
		t.Errorf("8.8.8.8 should not be special")
	}
}
