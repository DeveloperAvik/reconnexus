package adapters

import (
	"context"
	"os/exec"
	"regexp"
	"time"
)

// Provider describes an external tool invocation contract.
type Provider struct {
	Name              string
	Binary            string
	VersionArgs       []string
	Capabilities      []string
	NetworkBehavior   string
	SupportsCancel    bool
}

// Catalog is the fixed set of known providers. Binary paths default to PATH lookups;
// operators may override via configuration but cannot inject arbitrary argv.
var Catalog = []Provider{
	{Name: "subfinder", Binary: "subfinder", VersionArgs: []string{"-version"}, Capabilities: []string{"PASSIVE"}, NetworkBehavior: "PASSIVE", SupportsCancel: true},
	{Name: "amass", Binary: "amass", VersionArgs: []string{"-version"}, Capabilities: []string{"PASSIVE", "DNS"}, NetworkBehavior: "PASSIVE", SupportsCancel: true},
	{Name: "assetfinder", Binary: "assetfinder", VersionArgs: nil, Capabilities: []string{"PASSIVE"}, NetworkBehavior: "PASSIVE", SupportsCancel: true},
	{Name: "dnsx", Binary: "dnsx", VersionArgs: []string{"-version"}, Capabilities: []string{"DNS"}, NetworkBehavior: "ACTIVE", SupportsCancel: true},
	{Name: "httpx", Binary: "httpx", VersionArgs: []string{"-version"}, Capabilities: []string{"ACTIVE_HTTP"}, NetworkBehavior: "ACTIVE", SupportsCancel: true},
	{Name: "katana", Binary: "katana", VersionArgs: []string{"-version"}, Capabilities: []string{"CRAWL"}, NetworkBehavior: "ACTIVE", SupportsCancel: true},
	{Name: "gau", Binary: "gau", VersionArgs: []string{"--version"}, Capabilities: []string{"PASSIVE"}, NetworkBehavior: "PASSIVE", SupportsCancel: true},
	{Name: "waybackurls", Binary: "waybackurls", VersionArgs: nil, Capabilities: []string{"PASSIVE"}, NetworkBehavior: "PASSIVE", SupportsCancel: true},
	{Name: "mapcidr", Binary: "mapcidr", VersionArgs: []string{"-version"}, Capabilities: []string{"PASSIVE"}, NetworkBehavior: "NONE", SupportsCancel: true},
	{Name: "nmap", Binary: "nmap", VersionArgs: []string{"--version"}, Capabilities: []string{"PORT_SCAN"}, NetworkBehavior: "ACTIVE", SupportsCancel: true},
	{Name: "nuclei", Binary: "nuclei", VersionArgs: []string{"-version"}, Capabilities: []string{"SECURITY_CHECKS", "ACTIVE_TEMPLATE_CHECK"}, NetworkBehavior: "ACTIVE_TEMPLATE", SupportsCancel: true},
}

type HealthStatus string

const (
	HealthOK              HealthStatus = "OK"
	HealthMissing         HealthStatus = "MISSING"
	HealthFailedHealth    HealthStatus = "FAILED_HEALTHCHECK"
)

// HealthReport is the outcome of a provider health check.
type HealthReport struct {
	Name    string       `json:"name"`
	Status  HealthStatus `json:"status"`
	Version string       `json:"version,omitempty"`
	Path    string       `json:"path,omitempty"`
	Message string       `json:"message"`
}

var versionRe = regexp.MustCompile(`\bv?(\d+\.\d+\.\d+(?:[-+][\w.]+)?)`)

// CheckProvider locates the provider binary and runs its version probe if available.
func CheckProvider(ctx context.Context, p Provider) HealthReport {
	path, err := exec.LookPath(p.Binary)
	if err != nil {
		return HealthReport{Name: p.Name, Status: HealthMissing, Message: "binary " + p.Binary + " not found on PATH"}
	}
	if len(p.VersionArgs) == 0 {
		return HealthReport{Name: p.Name, Status: HealthOK, Path: path, Message: "binary present (no version probe)"}
	}
	res, runErr := Run(ctx, append([]string{path}, p.VersionArgs...), RunOptions{Timeout: 10 * time.Second, MaxBytes: 64 * 1024})
	if runErr != nil {
		return HealthReport{Name: p.Name, Status: HealthFailedHealth, Path: path, Message: runErr.Error()}
	}
	if res.TimedOut {
		return HealthReport{Name: p.Name, Status: HealthFailedHealth, Path: path, Message: "version probe timed out"}
	}
	if res.ExitCode != 0 {
		return HealthReport{Name: p.Name, Status: HealthFailedHealth, Path: path, Message: "version probe returned non-zero exit"}
	}
	version := "unknown"
	if m := versionRe.FindStringSubmatch(res.Stdout + "\n" + res.Stderr); m != nil {
		version = m[1]
	}
	return HealthReport{Name: p.Name, Status: HealthOK, Path: path, Version: version, Message: "healthy"}
}
