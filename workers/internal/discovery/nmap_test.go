package discovery

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/reconnexus/workers/internal/scope"
)

const nmapSampleXML = `<?xml version="1.0"?>
<nmaprun>
<host><status state="up"/><address addr="93.184.216.34" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9" extrainfo="protocol 2.0" conf="10"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="http" product="nginx" tunnel="ssl" conf="8"/></port>
<port protocol="tcp" portid="8080"><state state="closed"/></port>
<port protocol="udp" portid="53"><state state="open"/></port>
</ports></host>
<host><address addr="203.0.113.99" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host>
</nmaprun>`

func TestParseNmapXML(t *testing.T) {
	recs, diag, err := parseNmapXML(nmapSampleXML, map[string][]string{"93.184.216.34": {"a.example.com", "b.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	// 2 open tcp ports x 2 hosts; closed, udp and the unrequested address are dropped.
	if len(recs) != 4 {
		t.Fatalf("records = %d, want 4: %+v", len(recs), recs)
	}
	if len(diag) != 1 || !strings.Contains(diag[0], "not requested") {
		t.Fatalf("diagnostics = %v", diag)
	}
	r := recs[0]
	if r.Type != TypePortObservation || r.Host != "a.example.com" || r.Port.Port != 22 || r.Port.Product != "OpenSSH" || r.Port.Confidence != 1 || r.Port.TLS {
		t.Fatalf("unexpected first record: %+v %+v", r, r.Port)
	}
	if !recs[2].Port.TLS || recs[2].Port.Port != 443 {
		t.Fatalf("expected TLS on 443: %+v", recs[2].Port)
	}
}

func TestValidatePorts(t *testing.T) {
	for _, ok := range []string{"", "80", "80,443,8000-8100"} {
		if err := validatePorts(ok); err != nil {
			t.Errorf("validatePorts(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"0", "65536", "90-80", "1-3000", "80;id", "-p", "80,", "a"} {
		if err := validatePorts(bad); err == nil {
			t.Errorf("validatePorts(%q) accepted", bad)
		}
	}
}

func TestNmapArgvHasNoScriptsOrRawScans(t *testing.T) {
	argv := strings.Join(nmapArgv([]string{"93.184.216.34"}, "", false, 10), " ")
	for _, banned := range []string{"-sS", "-sU", "-O", "-A", "--script", "-sC"} {
		if strings.Contains(" "+argv+" ", " "+banned+" ") {
			t.Errorf("argv contains %s: %s", banned, argv)
		}
	}
	if !strings.Contains(argv, "--max-rate 10") || !strings.HasSuffix(argv, "93.184.216.34") {
		t.Errorf("unexpected argv: %s", argv)
	}
}

func fakeNmap(t *testing.T, xml string, exit int) string {
	t.Helper()
	dir := t.TempDir()
	xmlPath := filepath.Join(dir, "out.xml")
	if err := os.WriteFile(xmlPath, []byte(xml), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'Nmap version 7.95 ( https://nmap.org )'; exit 0; fi\ncat '" + xmlPath + "'\nexit " + string(rune('0'+exit)) + "\n"
	bin := filepath.Join(dir, "nmap")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin
}

func portScanJob(bin string, caps ...string) Job {
	if len(caps) == 0 {
		caps = []string{"PORT_SCAN"}
	}
	return Job{
		SchemaVersion: 1, ScanID: "s", ProjectID: "p", Stage: "15", JobKey: "15",
		Kind: "PORT_SCAN", Provider: "nmap", Policy: testPolicy(caps...), BinaryPath: bin,
		Limits: scope.Limits{MaxConcurrency: 4, RequestsPerSecond: 20, CrawlDepth: 1, MaxRuntimeSeconds: 30, MaxArtifactBytes: 1 << 20},
		Inputs: Inputs{Addresses: []AddressInput{{IP: "93.184.216.34", ViaHost: "www.example.com"}}},
	}
}

func TestNmapProviderEndToEnd(t *testing.T) {
	res, err := Run(context.Background(), portScanJob(fakeNmap(t, nmapSampleXML, 0)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusSucceeded || res.ProviderVersion != "7.95" {
		t.Fatalf("status=%s version=%s diag=%v", res.Status, res.ProviderVersion, res.Diagnostics)
	}
	if len(res.Records) != 2 || res.Coverage.Succeeded != 1 {
		t.Fatalf("records=%d coverage=%+v", len(res.Records), res.Coverage)
	}
}

func TestNmapProviderBlockedWithoutCapability(t *testing.T) {
	res, _ := Run(context.Background(), portScanJob(fakeNmap(t, nmapSampleXML, 0), "DNS"), nil)
	if res.Status != StatusBlocked || len(res.Records) != 0 {
		t.Fatalf("status=%s records=%d", res.Status, len(res.Records))
	}
}

func TestNmapProviderSkipsOutOfScopeAndRestrictedAddresses(t *testing.T) {
	job := portScanJob(fakeNmap(t, nmapSampleXML, 0))
	job.Inputs.Addresses = []AddressInput{
		{IP: "93.184.216.34", ViaHost: "evil.other.test"}, // host not in scope
		{IP: "10.0.0.5", ViaHost: "www.example.com"},      // restricted address space
		{IP: "not-an-ip", ViaHost: "www.example.com"},
	}
	res, _ := Run(context.Background(), job, nil)
	if res.Status != StatusSkipped || len(res.Records) != 0 {
		t.Fatalf("status=%s records=%d diag=%v", res.Status, len(res.Records), res.Diagnostics)
	}
}

func TestNmapProviderFailureAndMissingBinary(t *testing.T) {
	res, _ := Run(context.Background(), portScanJob(fakeNmap(t, "", 1)), nil)
	if res.Status != StatusFailed {
		t.Fatalf("status=%s", res.Status)
	}
	job := portScanJob("")
	t.Setenv("PATH", t.TempDir())
	res, _ = Run(context.Background(), job, nil)
	if res.Status != StatusSourceUnavailable {
		t.Fatalf("status=%s", res.Status)
	}
}

func TestNmapProviderRejectsBadPorts(t *testing.T) {
	job := portScanJob(fakeNmap(t, nmapSampleXML, 0))
	job.Inputs.Ports = "80;rm"
	res, _ := Run(context.Background(), job, nil)
	if res.Status != StatusFailed {
		t.Fatalf("status=%s", res.Status)
	}
}

// TestNmapProviderRealBinary drives the real nmap against a loopback listener. It is skipped when
// nmap is not installed. Loopback is restricted address space, so the policy lists it explicitly
// and grants INTERNAL_NETWORK, exactly as an operator authorizing an internal scan would.
func TestNmapProviderRealBinary(t *testing.T) {
	if _, err := exec.LookPath("nmap"); err != nil {
		t.Skip("nmap not installed")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	job := portScanJob("", "PORT_SCAN", "DNS", "INTERNAL_NETWORK")
	job.Policy.InScope.IPs = []string{"127.0.0.1"}
	job.Policy.InScope.Hosts = []string{"localhost"}
	job.AllowRestrictedAddresses = true
	job.Inputs = Inputs{Addresses: []AddressInput{{IP: "127.0.0.1", ViaHost: "localhost"}}, Ports: strconv.Itoa(port)}
	res, err := Run(context.Background(), job, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusSucceeded || len(res.Records) != 1 {
		t.Fatalf("status=%s records=%d diag=%v", res.Status, len(res.Records), res.Diagnostics)
	}
	if r := res.Records[0]; r.Port == nil || r.Port.Port != port || r.Port.State != "OPEN" || r.IP != "127.0.0.1" {
		t.Fatalf("unexpected record: %+v %+v", r, r.Port)
	}
}
