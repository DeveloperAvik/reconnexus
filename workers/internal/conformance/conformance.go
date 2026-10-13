// Package conformance computes scope/normalization results from the shared fixtures in
// test/fixtures/conformance. Both the Go and TypeScript engines are evaluated against the
// same fixtures, which is how cross-language agreement is enforced.
package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/reconnexus/workers/internal/matching"
	"github.com/reconnexus/workers/internal/scope"
)

type DomainCase struct {
	Host     string  `json:"host"`
	Expected *string `json:"expected"`
}

type MatchCase struct {
	Host              string `json:"host"`
	Value             string `json:"value"`
	IncludeSubdomains bool   `json:"includeSubdomains"`
	Expected          bool   `json:"expected"`
}

type domainFixture struct {
	Registrable []DomainCase `json:"registrable"`
	Suffix      []DomainCase `json:"suffix"`
	Matching    []MatchCase  `json:"matching"`
}

type IPCase struct {
	Input      string   `json:"input"`
	Canonical  *string  `json:"canonical"`
	Version    *int     `json:"version"`
	Categories []string `json:"categories"`
}

type ScopeCase struct {
	Name                  string   `json:"name"`
	Kind                  string   `json:"kind"`
	Value                 string   `json:"value"`
	Capability            string   `json:"capability"`
	ResolvedAddresses     []string `json:"resolvedAddresses"`
	IsRedirect            bool     `json:"isRedirect"`
	AuthorizationOverride *struct {
		ValidFrom  time.Time `json:"validFrom"`
		ValidUntil time.Time `json:"validUntil"`
	} `json:"authorizationOverride"`
	Expected struct {
		Allowed bool   `json:"allowed"`
		Code    string `json:"code"`
	} `json:"expected"`
}

type scopeFixture struct {
	Policy scope.Policy `json:"policy"`
	Now    time.Time    `json:"now"`
	Cases  []ScopeCase  `json:"cases"`
}

// Results mirrors the shape computed by the TypeScript conformance test.
type Results struct {
	Registrable []DomainResult `json:"registrable"`
	Suffix      []DomainResult `json:"suffix"`
	Matching    []MatchResult  `json:"matching"`
	IPs         []IPResult     `json:"ips"`
	Scope       []ScopeResult  `json:"scope"`
	URLs        []URLResult    `json:"urls"`
}

type URLResult struct {
	Input  string  `json:"input"`
	Result *string `json:"result"`
}

type DomainResult struct {
	Host   string  `json:"host"`
	Result *string `json:"result"`
}

type MatchResult struct {
	Host              string `json:"host"`
	Value             string `json:"value"`
	IncludeSubdomains bool   `json:"includeSubdomains"`
	Result            bool   `json:"result"`
}

type IPResult struct {
	Input      string   `json:"input"`
	Canonical  *string  `json:"canonical"`
	Version    *int     `json:"version"`
	Categories []string `json:"categories"`
}

type ScopeResult struct {
	Name    string `json:"name"`
	Allowed bool   `json:"allowed"`
	Code    string `json:"code"`
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Compute evaluates all fixtures under dir.
func Compute(dir string) (Results, error) {
	var res Results

	var domains domainFixture
	if err := readJSON(filepath.Join(dir, "domains.json"), &domains); err != nil {
		return res, fmt.Errorf("domains.json: %w", err)
	}
	for _, c := range domains.Registrable {
		r := DomainResult{Host: c.Host}
		if rd, ok := matching.RegistrableDomain(c.Host); ok {
			r.Result = &rd
		}
		res.Registrable = append(res.Registrable, r)
	}
	for _, c := range domains.Suffix {
		r := DomainResult{Host: c.Host}
		if ps := matching.PublicSuffix(c.Host); ps != "" {
			r.Result = &ps
		}
		res.Suffix = append(res.Suffix, r)
	}
	for _, c := range domains.Matching {
		res.Matching = append(res.Matching, MatchResult{
			Host:              c.Host,
			Value:             c.Value,
			IncludeSubdomains: c.IncludeSubdomains,
			Result:            matching.MatchDomain(c.Host, c.Value, c.IncludeSubdomains),
		})
	}

	var ips []IPCase
	if err := readJSON(filepath.Join(dir, "ips.json"), &ips); err != nil {
		return res, fmt.Errorf("ips.json: %w", err)
	}
	for _, c := range ips {
		out := IPResult{Input: c.Input, Categories: []string{}}
		if a, ok := matching.ParseIP(c.Input); ok {
			canon := a.String()
			out.Canonical = &canon
			v := 4
			if a.Is6() {
				v = 6
			}
			out.Version = &v
			out.Categories = matching.ClassifyAddr(a).Categories()
		}
		res.IPs = append(res.IPs, out)
	}

	var urls []struct {
		Input    string  `json:"input"`
		Expected *string `json:"expected"`
	}
	if err := readJSON(filepath.Join(dir, "urls.json"), &urls); err != nil {
		return res, fmt.Errorf("urls.json: %w", err)
	}
	for _, c := range urls {
		out := URLResult{Input: c.Input}
		if canon, err := matching.CanonicalURL(c.Input); err == nil {
			out.Result = &canon
		}
		res.URLs = append(res.URLs, out)
	}

	var sf scopeFixture
	if err := readJSON(filepath.Join(dir, "scope.json"), &sf); err != nil {
		return res, fmt.Errorf("scope.json: %w", err)
	}
	for _, c := range sf.Cases {
		policy := sf.Policy
		if c.AuthorizationOverride != nil {
			policy.Authorization.ValidFrom = c.AuthorizationOverride.ValidFrom
			policy.Authorization.ValidUntil = c.AuthorizationOverride.ValidUntil
		}
		engine := scope.NewEngine(&policy)
		d := engine.Check(scope.Request{
			Kind:              c.Kind,
			Value:             c.Value,
			Capability:        c.Capability,
			Now:               sf.Now,
			ResolvedAddresses: c.ResolvedAddresses,
			IsRedirect:        c.IsRedirect,
		})
		res.Scope = append(res.Scope, ScopeResult{Name: c.Name, Allowed: d.Allowed, Code: d.Code})
	}

	return res, nil
}

// ExpectedScope returns the expected decisions from the scope fixture for Go-side assertions.
func ExpectedScope(dir string) (map[string]ScopeCase, error) {
	var sf scopeFixture
	if err := readJSON(filepath.Join(dir, "scope.json"), &sf); err != nil {
		return nil, err
	}
	out := map[string]ScopeCase{}
	for _, c := range sf.Cases {
		out[c.Name] = c
	}
	return out, nil
}
