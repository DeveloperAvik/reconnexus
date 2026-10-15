package discovery

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/reconnexus/workers/internal/scope"
)

const fixtures = "../../../test/fixtures/discovery"

func testPolicy(caps ...string) scope.Policy {
	if len(caps) == 0 {
		caps = []string{"PASSIVE", "DNS", "ACTIVE_HTTP"}
	}
	return scope.Policy{
		SchemaVersion: 1,
		PolicyID:      "11111111-1111-1111-1111-111111111111",
		ProjectID:     "22222222-2222-2222-2222-222222222222",
		PolicyVersion: 1,
		Authorization: scope.Authorization{
			Reference:    "TEST",
			AuthorizedBy: "test",
			ValidFrom:    time.Now().Add(-time.Hour),
			ValidUntil:   time.Now().Add(time.Hour),
			Capabilities: caps,
		},
		InScope: scope.InScope{
			Domains: []scope.DomainRule{{Value: "example.com", IncludeSubdomains: true}},
		},
		Limits: scope.Limits{MaxRuntimeSeconds: 60},
	}
}

func writeScript(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fake.sh")
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func fixture(name string) string {
	abs, _ := filepath.Abs(filepath.Join(fixtures, name))
	return abs
}

func hosts(records []Record) []string {
	var out []string
	for _, r := range records {
		if r.Type == TypeHostObservation {
			out = append(out, r.Host)
		}
	}
	return out
}

func TestMockSubdomainDiscoveryNormalization(t *testing.T) {
	job := Job{
		SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "02", JobKey: "02",
		Kind: "SUBDOMAINS", Provider: "mock", Policy: testPolicy(),
		Inputs: Inputs{RootDomain: "example.com"}, FixturePath: fixture("mock-subdomains.json"),
	}
	res, err := Run(context.Background(), job, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusSucceeded {
		t.Fatalf("status = %s, diagnostics=%v", res.Status, res.Diagnostics)
	}
	got := hosts(res.Records)
	want := []string{"a.example.com", "b.example.com", "dup.example.com", "x.example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("hosts = %v want %v", got, want)
	}
	if res.ProviderVersion != "9.9.9" {
		t.Fatalf("providerVersion = %q", res.ProviderVersion)
	}
}

func TestExternalProviderOutputNormalization(t *testing.T) {
	script := writeScript(t, "#!/bin/sh\nprintf 'a.example.com\\nB.EXAMPLE.COM.\\ninvalid host\\n10.0.0.1\\ndup.example.com\\ndup.example.com\\n'\n")
	job := Job{
		SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "02", JobKey: "02",
		Kind: "SUBDOMAINS", Provider: "subfinder", Policy: testPolicy(),
		Inputs: Inputs{RootDomain: "example.com"}, BinaryPath: script,
	}
	res, err := Run(context.Background(), job, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusSucceeded {
		t.Fatalf("status=%s diag=%v", res.Status, res.Diagnostics)
	}
	got := hosts(res.Records)
	if len(got) != 3 {
		t.Fatalf("expected 3 normalized hosts, got %v", got)
	}
	// argv is recorded as a structured array, never a shell string.
	joined := strings.Join(res.Execution.Argv, " ")
	if !strings.Contains(joined, "-d example.com -silent") {
		t.Fatalf("unexpected argv: %v", res.Execution.Argv)
	}
}

func TestMissingBinaryIsSourceUnavailable(t *testing.T) {
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", "")
	defer os.Setenv("PATH", oldPath)
	job := Job{
		SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "02", JobKey: "02",
		Kind: "SUBDOMAINS", Provider: "subfinder", Policy: testPolicy(),
		Inputs: Inputs{RootDomain: "example.com"},
	}
	res, err := Run(context.Background(), job, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusSourceUnavailable {
		t.Fatalf("status=%s want SOURCE_UNAVAILABLE", res.Status)
	}
	if res.Coverage.Unavailable != 1 {
		t.Fatalf("coverage.unavailable=%d", res.Coverage.Unavailable)
	}
}

func TestNonZeroExitIsFailureNotSuccess(t *testing.T) {
	script := writeScript(t, "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo v1.0.0; exit 0; fi\nexit 3\n")
	job := Job{SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "02", JobKey: "02",
		Kind: "SUBDOMAINS", Provider: "subfinder", Policy: testPolicy(),
		Inputs: Inputs{RootDomain: "example.com"}, BinaryPath: script}
	res, _ := Run(context.Background(), job, nil)
	if res.Status != StatusFailed {
		t.Fatalf("status=%s want FAILED", res.Status)
	}
	if res.Execution.ExitCode == nil || *res.Execution.ExitCode != 3 {
		t.Fatalf("exitCode=%v", res.Execution.ExitCode)
	}
}

func TestPartialOutputThenProcessFailureIsFailedNotPartialSuccess(t *testing.T) {
	// The tool prints a valid record, then crashes with a non-zero exit. The result must be FAILED
	// with the exit code captured; a crash is never converted into a partial success silently.
	script := writeScript(t, "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo v1.0.0; exit 0; fi\necho a.example.com\necho b.example.com\nexit 7\n")
	job := Job{SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "02", JobKey: "02",
		Kind: "SUBDOMAINS", Provider: "subfinder", Policy: testPolicy(),
		Inputs: Inputs{RootDomain: "example.com"}, BinaryPath: script}
	res, _ := Run(context.Background(), job, nil)
	if res.Status != StatusFailed {
		t.Fatalf("status=%s want FAILED", res.Status)
	}
	if res.Execution.ExitCode == nil || *res.Execution.ExitCode != 7 {
		t.Fatalf("exitCode=%v want 7", res.Execution.ExitCode)
	}
	// Partial output is not ingested as if the run had succeeded.
	if len(res.Records) != 0 {
		t.Fatalf("partial output must not be ingested on failure, got %d records", len(res.Records))
	}
	if len(res.Diagnostics) == 0 {
		t.Fatalf("expected a diagnostic explaining the failure")
	}
}

func TestTimeout(t *testing.T) {
	script := writeScript(t, "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo v1.0.0; exit 0; fi\nexec sleep 5\n")
	job := Job{SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "02", JobKey: "02",
		Kind: "SUBDOMAINS", Provider: "subfinder", Policy: testPolicy(),
		Inputs: Inputs{RootDomain: "example.com"}, BinaryPath: script, TimeoutMs: 300}
	res, _ := Run(context.Background(), job, nil)
	if res.Status != StatusFailed || !res.Execution.TimedOut {
		t.Fatalf("status=%s timedOut=%v", res.Status, res.Execution.TimedOut)
	}
}

func TestOutputLimitTruncation(t *testing.T) {
	script := writeScript(t, "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo v1.0.0; exit 0; fi\ni=0\nwhile [ $i -lt 20000 ]; do echo h$i.example.com; i=$((i+1)); done\n")
	job := Job{SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "02", JobKey: "02",
		Kind: "SUBDOMAINS", Provider: "subfinder", Policy: testPolicy(),
		Inputs: Inputs{RootDomain: "example.com"}, BinaryPath: script, MaxOutputBytes: 200}
	res, _ := Run(context.Background(), job, nil)
	if !res.Execution.Truncated {
		t.Fatalf("expected truncated execution, got %+v", res.Execution)
	}
	if res.Execution.StdoutBytes > 200 {
		t.Fatalf("stdout bytes %d exceeds limit", res.Execution.StdoutBytes)
	}
}

func TestCancellation(t *testing.T) {
	job := Job{SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "02", JobKey: "02",
		Kind: "SUBDOMAINS", Provider: "mock", Policy: testPolicy(),
		Inputs: Inputs{RootDomain: "example.com"}, FixturePath: fixture("mock-subdomains.json")}
	// Use a sleeping fixture.
	fx := fixture("mock-subdomains.json")
	_ = fx
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(80 * time.Millisecond); cancel() }()
	job.FixturePath = writeSleepFixture(t, 2000)
	res, _ := Run(ctx, job, nil)
	if res.Status != StatusCancelled {
		t.Fatalf("status=%s want CANCELLED (diag=%v)", res.Status, res.Diagnostics)
	}
}

func writeSleepFixture(t *testing.T, ms int) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "sleep.json")
	body := `{"hosts":["a.example.com"],"sleepMs":` + itoa(ms) + `}`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestDnsFilteringDropsOutOfScopeNames(t *testing.T) {
	// The fake dnsx echoes each stdin line back as a JSON record, so any out-of-scope name
	// would appear in the records if scope filtering failed.
	script := writeScript(t, "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo v1; exit 0; fi\nwhile IFS= read -r line; do\n  [ -z \"$line\" ] && continue\n  printf '{\"host\":\"%s\",\"a\":[\"93.184.216.34\"],\"status_code\":\"NOERROR\"}\\n' \"$line\"\ndone\n")
	job := Job{SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "03", JobKey: "03",
		Kind: "DNS", Provider: "dnsx", Policy: testPolicy(),
		Inputs: Inputs{Names: []string{"a.example.com", "evil.other.net", "b.example.com"}}, BinaryPath: script}
	res, _ := Run(context.Background(), job, nil)
	var names []string
	for _, r := range res.Records {
		names = append(names, r.Name)
	}
	for _, n := range names {
		if !strings.HasSuffix(n, ".example.com") {
			t.Fatalf("out-of-scope name leaked into records: %v", names)
		}
	}
	if res.Coverage.Skipped != 1 {
		t.Fatalf("coverage.skipped=%d want 1", res.Coverage.Skipped)
	}
}

func TestBlockedWhenCapabilityMissing(t *testing.T) {
	job := Job{SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "03", JobKey: "03",
		Kind: "DNS", Provider: "builtin-dns", Policy: testPolicy("PASSIVE"),
		Inputs: Inputs{Names: []string{"a.example.com"}}}
	res, _ := Run(context.Background(), job, nil)
	if res.Status != StatusBlocked {
		t.Fatalf("status=%s want BLOCKED", res.Status)
	}
}

func TestOfflineIpMetadataNormalization(t *testing.T) {
	job := Job{SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "03", JobKey: "03ip",
		Kind: "IP_METADATA", Provider: "offline-ipmeta", Policy: testPolicy(),
		Inputs:      Inputs{Addresses: []AddressInput{{IP: "203.0.113.10", ViaHost: "a.example.com"}}},
		FixturePath: fixture("offline-ipmeta.json")}
	res, _ := Run(context.Background(), job, nil)
	if res.Status != StatusSucceeded {
		t.Fatalf("status=%s diag=%v", res.Status, res.Diagnostics)
	}
	var found bool
	for _, r := range res.Records {
		if r.Type == TypeIPMetadata && r.IP == "203.0.113.10" {
			found = true
			if r.ASN == nil || *r.ASN != 64512 {
				t.Fatalf("asn=%v", r.ASN)
			}
			if r.Prefix == nil || *r.Prefix != "203.0.113.0/24" {
				t.Fatalf("prefix=%v", r.Prefix)
			}
		}
	}
	if !found {
		t.Fatal("no IP_METADATA record produced")
	}
}

func TestIpMetadataOutOfScopeSkipped(t *testing.T) {
	job := Job{SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "03", JobKey: "03ip",
		Kind: "IP_METADATA", Provider: "offline-ipmeta", Policy: testPolicy(),
		Inputs:      Inputs{Addresses: []AddressInput{{IP: "203.0.113.10", ViaHost: "evil.other.net"}}},
		FixturePath: fixture("offline-ipmeta.json")}
	res, _ := Run(context.Background(), job, nil)
	if res.Status != StatusSkipped {
		t.Fatalf("status=%s want SKIPPED", res.Status)
	}
	if res.Coverage.Skipped != 1 {
		t.Fatalf("skipped=%d", res.Coverage.Skipped)
	}
}

// --- builtin-dns with an injected resolver ---

type fakeResolver struct {
	hosts map[string][]string
	addrs map[string][]string
	cname map[string]string
	fail  map[string]error
}

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if err := f.fail[host]; err != nil {
		return nil, err
	}
	if a, ok := f.hosts[host]; ok {
		return a, nil
	}
	if a, ok := f.addrs[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}
func (f fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	return f.cname[host], nil
}
func (f fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	return f.addrs[addr], nil
}

func withResolver(t *testing.T, r hostResolver) {
	t.Helper()
	old := resolverFactory
	resolverFactory = func(Job) hostResolver { return r }
	t.Cleanup(func() { resolverFactory = old })
}

func TestResultJSONContract(t *testing.T) {
	// Every emitted result must satisfy the JSON contract: argv is an array (not null) and
	// every HOST_OBSERVATION carries a provider.
	withResolver(t, fakeResolver{hosts: map[string][]string{"a.example.com": {"93.184.216.34"}}})
	job := Job{SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "03", JobKey: "03",
		Kind: "DNS", Provider: "builtin-dns", Policy: testPolicy(),
		Inputs: Inputs{Names: []string{"a.example.com"}}}
	res, _ := Run(context.Background(), job, nil)
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), `"argv":null`) {
		t.Fatalf("argv must be an array, got null: %s", b)
	}
	for _, r := range res.Records {
		if r.Type == TypeHostObservation && r.Provider == "" {
			t.Fatalf("HOST_OBSERVATION missing provider: %+v", r)
		}
	}
}

func TestBuiltinDnsNxdomainAndTimeout(t *testing.T) {
	withResolver(t, fakeResolver{
		hosts: map[string][]string{"present.example.com": {"93.184.216.34"}},
		fail: map[string]error{
			"missing.example.com": &net.DNSError{Err: "no such host", Name: "missing.example.com", IsNotFound: true},
			"slow.example.com":    &net.DNSError{Err: "timeout", Name: "slow.example.com", IsTimeout: true},
		},
	})
	job := Job{SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "03", JobKey: "03",
		Kind: "DNS", Provider: "builtin-dns", Policy: testPolicy(),
		Inputs: Inputs{Names: []string{"present.example.com", "missing.example.com", "slow.example.com"}}}
	res, _ := Run(context.Background(), job, nil)
	statuses := map[string]string{}
	for _, r := range res.Records {
		if r.Type == TypeDNSRecord {
			statuses[r.Name] = r.Status
		}
	}
	if statuses["present.example.com"] != "NOERROR" {
		t.Errorf("present status=%q", statuses["present.example.com"])
	}
	if statuses["missing.example.com"] != "NXDOMAIN" {
		t.Errorf("missing status=%q want NXDOMAIN", statuses["missing.example.com"])
	}
	if statuses["slow.example.com"] != "TIMEOUT" {
		t.Errorf("slow status=%q want TIMEOUT", statuses["slow.example.com"])
	}
	if res.Status != StatusPartial {
		t.Errorf("status=%s want PARTIAL", res.Status)
	}
}

func TestBuiltinDnsWildcardDetection(t *testing.T) {
	// Every host resolves to the same wildcard address.
	withResolver(t, fakeResolver{
		hosts: map[string][]string{"a.example.com": {"93.184.216.34"}},
		addrs: map[string][]string{}, // unused
	})
	// Override to return the wildcard address for any random label.
	old := resolverFactory
	resolverFactory = func(Job) hostResolver { return wildcardResolver{} }
	t.Cleanup(func() { resolverFactory = old })

	job := Job{SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "03", JobKey: "03",
		Kind: "DNS", Provider: "builtin-dns", Policy: testPolicy(),
		Inputs: Inputs{RootDomain: "example.com", Names: []string{"a.example.com"}}}
	res, _ := Run(context.Background(), job, nil)
	var wild bool
	for _, r := range res.Records {
		if r.Type == TypeHostObservation && r.Host == "a.example.com" && r.Status == HostWildcard {
			wild = true
		}
	}
	if !wild {
		t.Fatalf("expected wildcard status; records=%+v diag=%v", res.Records, res.Diagnostics)
	}
}

type wildcardResolver struct{}

func (wildcardResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	return []string{"93.184.216.34"}, nil
}
func (wildcardResolver) LookupCNAME(_ context.Context, host string) (string, error)  { return host, nil }
func (wildcardResolver) LookupAddr(_ context.Context, addr string) ([]string, error) { return nil, nil }
