package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The registry states the prefix; it is never inferred from the start address.
func TestPrefixFromCidr0(t *testing.T) {
	cases := []struct {
		name  string
		input []rdapCidr
		want  string
	}{
		{"v4", []rdapCidr{{V4Prefix: "13.108.0.0", Length: 14}}, "13.108.0.0/14"},
		{"v6", []rdapCidr{{V6Prefix: "2600:1400::", Length: 24}}, "2600:1400::/24"},
		{"no entries", nil, ""},
		{"missing length", []rdapCidr{{V4Prefix: "13.108.0.0"}}, ""},
		{"length out of range for v4", []rdapCidr{{V4Prefix: "13.108.0.0", Length: 40}}, ""},
		{"prefix is not an address", []rdapCidr{{V4Prefix: "not-an-ip", Length: 14}}, ""},
		{"family mismatch", []rdapCidr{{V4Prefix: "2600:1400::", Length: 24}}, ""},
		{"first usable entry wins", []rdapCidr{{V4Prefix: "bad", Length: 8}, {V4Prefix: "104.64.0.0", Length: 10}}, "104.64.0.0/10"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := prefixFromCidr0(c.input); got != c.want {
				t.Fatalf("prefixFromCidr0 = %q, want %q", got, c.want)
			}
		})
	}
}

func TestRetryAfterDelay(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		header string
		want   time.Duration
	}{
		{"", 0},
		{"3", 3 * time.Second},
		{" 2 ", 2 * time.Second},
		{"0", 0},
		{"-5", 0},
		{"900", rdapMaxRetryAfter},
		{"nonsense", 0},
		{now.Add(4 * time.Second).Format(http.TimeFormat), 4 * time.Second},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0},
	}
	for _, c := range cases {
		if got := retryAfterDelay(c.header, now); got != c.want {
			t.Errorf("retryAfterDelay(%q) = %v, want %v", c.header, got, c.want)
		}
	}
}

// A throttled lookup is retried once, and the record is built from the RDAP payload.
func TestRdapProviderRetriesOnThrottleAndParsesPayload(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{
			"handle": "NET-13-108-0-0-1",
			"name": "SALESF-3",
			"country": "US",
			"startAddress": "13.108.0.0",
			"endAddress": "13.111.255.255",
			"cidr0_cidrs": [{"v4prefix": "13.108.0.0", "length": 14}],
			"entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Salesforce, Inc."]]]}]
		}`))
	}))
	defer srv.Close()

	job := Job{
		Provider: "rdap",
		Kind:     "IP_METADATA",
		Policy:   testPolicy(),
		Limits:   testPolicy().Limits,
		Inputs:   Inputs{Addresses: []AddressInput{{IP: "13.111.14.190", ViaHost: "app.example.com"}}},
	}
	job.RdapBaseURL = srv.URL

	res, err := Run(context.Background(), job, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected the throttled lookup to be retried once, got %d call(s)", calls)
	}
	if res.Status != StatusSucceeded {
		t.Fatalf("status = %s (diagnostics: %v)", res.Status, res.Diagnostics)
	}
	if len(res.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(res.Records))
	}
	rec := res.Records[0]
	if rec.Type != TypeIPMetadata {
		t.Fatalf("type = %s", rec.Type)
	}
	if rec.Prefix == nil || *rec.Prefix != "13.108.0.0/14" {
		t.Errorf("prefix = %v, want 13.108.0.0/14", rec.Prefix)
	}
	if rec.ASNOrg == nil || *rec.ASNOrg != "Salesforce, Inc." {
		t.Errorf("asnOrg = %v, want Salesforce, Inc.", rec.ASNOrg)
	}
	if rec.NetworkName == nil || *rec.NetworkName != "SALESF-3" {
		t.Errorf("networkName = %v, want SALESF-3", rec.NetworkName)
	}
	if rec.ASN != nil {
		t.Errorf("asn = %v; an RDAP IP response does not state a routable ASN", rec.ASN)
	}
}
