package discovery

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/reconnexus/workers/internal/adapters"
)

// defaultPortList is the bounded set scanned when a job names no ports: common web, remote-access,
// database, mail, directory and management services. It is explicit rather than "top N" so the
// scan is reproducible across nmap versions.
const defaultPortList = "21,22,23,25,53,80,81,110,111,135,139,143,389,443,445,465,587,993,995," +
	"1433,1521,2049,2375,2376,3000,3306,3389,5000,5432,5601,5672,5900,5985,6379,6443,7001," +
	"8000,8008,8080,8081,8443,8888,9000,9042,9090,9200,9300,10250,11211,15672,27017"

const (
	maxPortSpecCount = 2048
	nmapMaxHostTime  = "600s"
)

// nmapProvider runs nmap as a TCP connect scan with light service-version detection. It never
// uses NSE scripts, OS detection, or raw-packet scan types, so it needs no privileges and sends
// only complete TCP handshakes plus the version probes nmap uses to identify the service.
type nmapProvider struct{}

func (nmapProvider) Name() string            { return "nmap" }
func (nmapProvider) Kind() string            { return "PORT_SCAN" }
func (nmapProvider) Capability() string      { return "PORT_SCAN" }
func (nmapProvider) NetworkBehavior() string { return "ACTIVE" }

// validatePorts accepts "" (default list) or a comma-separated list of ports and ranges within
// 1-65535 totalling at most maxPortSpecCount ports. Anything else is rejected so a job can never
// smuggle scanner flags through the port selection.
func validatePorts(spec string) error {
	if spec == "" {
		return nil
	}
	total := 0
	for _, part := range strings.Split(spec, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 1 || a > 65535 {
			return fmt.Errorf("port %q is not in 1-65535", lo)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < a || b > 65535 {
				return fmt.Errorf("range %q is invalid", part)
			}
		}
		total += b - a + 1
		if total > maxPortSpecCount {
			return fmt.Errorf("more than %d ports requested", maxPortSpecCount)
		}
	}
	return nil
}

// nmapArgv builds the scan argv for one address family. Targets are validated IP literals, so
// none can begin with "-".
func nmapArgv(ips []string, ports string, ipv6 bool, maxRate float64) []string {
	if ports == "" {
		ports = defaultPortList
	}
	argv := []string{"-sT", "-Pn", "-n", "-sV", "--version-light", "--open", "-T3",
		"--max-retries", "1", "--host-timeout", nmapMaxHostTime, "-p", ports, "-oX", "-"}
	if maxRate > 0 {
		argv = append(argv, "--max-rate", strconv.Itoa(int(maxRate)))
	}
	if ipv6 {
		argv = append(argv, "-6")
	}
	return append(argv, ips...)
}

func (nmapProvider) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{}

	bin := job.BinaryPath
	if bin == "" {
		found, err := exec.LookPath("nmap")
		if err != nil {
			res.StatusOverride = StatusSourceUnavailable
			res.Coverage.Unavailable = len(job.Inputs.Addresses)
			res.Diagnostics = append(res.Diagnostics, `binary "nmap" not found on PATH`)
			return res, nil
		}
		bin = found
	}
	if vr, err := adapters.Run(ctx, []string{bin, "--version"}, adapters.RunOptions{Timeout: 10 * time.Second}); err == nil && !vr.TimedOut && vr.ExitCode == 0 {
		res.ProviderVersion = nmapVersion(vr.Stdout)
	}

	// Group the hosts that reached each address, and split by family: nmap needs -6 for IPv6.
	hostsByIP := map[string][]string{}
	var v4, v6 []string
	for _, a := range job.Inputs.Addresses {
		addr, err := netip.ParseAddr(a.IP)
		if err != nil {
			continue
		}
		ip := addr.Unmap().String()
		if _, seen := hostsByIP[ip]; !seen {
			if addr.Unmap().Is4() {
				v4 = append(v4, ip)
			} else {
				v6 = append(v6, ip)
			}
		}
		hostsByIP[ip] = append(hostsByIP[ip], a.ViaHost)
	}
	sort.Strings(v4)
	sort.Strings(v6)
	for _, hosts := range hostsByIP {
		sort.Strings(hosts)
	}

	timeoutMs := 900000
	if job.TimeoutMs > 0 {
		timeoutMs = job.TimeoutMs
	}
	maxBytes := 16 * 1024 * 1024
	if job.MaxOutputBytes > 0 {
		maxBytes = job.MaxOutputBytes
	}
	deadline := time.Now().Add(defaultTimeout(timeoutMs))

	failed := false
	for _, group := range []struct {
		ips  []string
		ipv6 bool
	}{{v4, false}, {v6, true}} {
		if len(group.ips) == 0 {
			continue
		}
		argv := append([]string{bin}, nmapArgv(group.ips, job.Inputs.Ports, group.ipv6, job.Limits.RequestsPerSecond)...)
		remaining := time.Until(deadline)
		if remaining <= 0 {
			res.Coverage.Failed += len(group.ips)
			res.Diagnostics = append(res.Diagnostics, "port scan deadline reached before all addresses were scanned")
			failed = true
			continue
		}
		run, err := adapters.Run(ctx, argv, adapters.RunOptions{Timeout: remaining, MaxBytes: maxBytes, Dir: job.WorkDir})
		exec := &Execution{Argv: redactArgv(argv)}
		res.Execution = exec
		if err != nil {
			exec.SpawnError = err.Error()
			res.Coverage.Failed += len(group.ips)
			res.Diagnostics = append(res.Diagnostics, "provider spawn failed: "+err.Error())
			failed = true
			continue
		}
		exec.ExitCode = intPtr(run.ExitCode)
		exec.DurationMs = run.Duration.Milliseconds()
		exec.StdoutBytes, exec.StderrBytes = len(run.Stdout), len(run.Stderr)
		exec.Truncated, exec.TimedOut = run.Truncated, run.TimedOut
		if run.TimedOut || run.ExitCode != 0 {
			exec.ExitDescription = "timed out"
			if !run.TimedOut {
				exec.ExitDescription = "non-zero exit " + strconv.Itoa(run.ExitCode)
			}
			res.Coverage.Failed += len(group.ips)
			res.Diagnostics = append(res.Diagnostics, "nmap "+exec.ExitDescription+": "+truncate(strings.TrimSpace(run.Stderr), 300))
			failed = true
			continue
		}
		if run.Truncated {
			res.Diagnostics = append(res.Diagnostics, "provider output was truncated at the configured limit; XML may be incomplete")
		}
		records, diag, err := parseNmapXML(run.Stdout, hostsByIP)
		res.Diagnostics = append(res.Diagnostics, diag...)
		if err != nil {
			res.Coverage.Failed += len(group.ips)
			res.Diagnostics = append(res.Diagnostics, "could not parse nmap XML: "+err.Error())
			failed = true
			continue
		}
		res.Records = append(res.Records, records...)
		res.Coverage.Succeeded += len(group.ips)
	}
	res.Coverage.Attempted = res.Coverage.Succeeded + res.Coverage.Failed
	if failed && res.Coverage.Succeeded == 0 {
		res.StatusOverride = StatusFailed
	}
	if len(res.Records) == 0 && !failed {
		res.Diagnostics = append(res.Diagnostics, "no open ports found among the scanned ports (exit 0); closed or filtered ports are not recorded")
	}
	return res, nil
}

var nmapVersionRe = regexp.MustCompile(`(?i)nmap version (\d+(?:\.\d+)+\w*)`)

// nmapVersion extracts "7.95" from "Nmap version 7.95 ( https://nmap.org )"; nmap releases are
// two-part, which the generic x.y.z extractor does not match.
func nmapVersion(out string) string {
	if m := nmapVersionRe.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return "unknown"
}

type nmapRun struct {
	Hosts []struct {
		Addresses []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			PortID   int    `xml:"portid,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name      string `xml:"name,attr"`
				Product   string `xml:"product,attr"`
				Version   string `xml:"version,attr"`
				ExtraInfo string `xml:"extrainfo,attr"`
				Tunnel    string `xml:"tunnel,attr"`
				Conf      int    `xml:"conf,attr"`
			} `xml:"service"`
		} `xml:"ports>port"`
	} `xml:"host"`
}

// parseNmapXML converts nmap -oX output into PORT_OBSERVATION records, one per (host, address,
// port) so each in-scope name that reached the address keeps its relationship. Addresses nmap
// reports that were not requested are discarded.
func parseNmapXML(stdout string, hostsByIP map[string][]string) ([]Record, []string, error) {
	var run nmapRun
	if err := xml.Unmarshal([]byte(stdout), &run); err != nil {
		return nil, nil, err
	}
	var records []Record
	var diag []string
	for _, h := range run.Hosts {
		ip := ""
		for _, a := range h.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				if addr, err := netip.ParseAddr(a.Addr); err == nil {
					ip = addr.Unmap().String()
				}
			}
		}
		hosts, requested := hostsByIP[ip]
		if !requested {
			diag = append(diag, "discarded nmap host that was not requested: "+truncate(ip, 64))
			continue
		}
		for _, p := range h.Ports {
			if p.Protocol != "tcp" || p.PortID < 1 || p.PortID > 65535 {
				continue
			}
			var state string
			switch p.State.State {
			case "open":
				state = "OPEN"
			case "open|filtered":
				state = "OPEN_FILTERED"
			case "filtered":
				state = "FILTERED"
			default:
				continue
			}
			conf := float64(p.Service.Conf) / 10
			if conf > 1 {
				conf = 1
			}
			info := &PortInfo{
				Port: p.PortID, Protocol: "tcp", State: state,
				Service: p.Service.Name, Product: p.Service.Product, Version: p.Service.Version,
				ExtraInfo: p.Service.ExtraInfo, TLS: p.Service.Tunnel == "ssl", Confidence: conf,
			}
			for _, host := range hosts {
				records = append(records, Record{Type: TypePortObservation, Host: host, IP: ip, Provider: "nmap", Source: "nmap", Port: info})
			}
		}
	}
	return records, diag, nil
}
