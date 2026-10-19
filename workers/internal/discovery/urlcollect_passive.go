// External passive URL providers (gau, waybackurls).

package discovery

import (
	"context"
	"errors"
	"strings"
)

// passiveURLProvider wraps an external passive tool (gau, waybackurls).
type passiveURLProvider struct {
	name      string
	buildArgv func(job Job) ([]string, error)
	input     func(job Job) string
}

func (p passiveURLProvider) Name() string            { return p.name }
func (p passiveURLProvider) Kind() string            { return "URL_COLLECTION" }
func (p passiveURLProvider) Capability() string      { return "PASSIVE" }
func (p passiveURLProvider) NetworkBehavior() string { return "PASSIVE" }

func (p passiveURLProvider) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	buildArgv := p.buildArgv
	if buildArgv == nil {
		buildArgv = func(Job) ([]string, error) { return nil, nil }
	}
	inner := &externalProvider{
		name: p.name, kind: "URL_COLLECTION", capability: "PASSIVE", networkBehavior: "PASSIVE",
		buildArgv: buildArgv, parse: parseURLPlaceholders, defaultTimeoutMs: 300000, defaultMaxBytes: 32 * 1024 * 1024,
	}
	if p.input != nil {
		inner.usesStdin = true
		inner.stdin = p.input
	}
	pr, err := inner.Run(ctx, pc)
	if err != nil {
		return pr, err
	}
	// Passively discovered URLs can be anywhere; keep only in-scope candidates.
	return filterExternal(ctx, pc, pr, p.name, "PASSIVE", MethodPassive), nil
}

// newGauProvider builds the gau passive provider.
func newGauProvider() Provider {
	return passiveURLProvider{
		name: "gau",
		buildArgv: func(job Job) ([]string, error) {
			if len(job.Inputs.Domains) == 0 {
				return nil, errors.New("gau requires at least one domain")
			}
			return []string{"--threads", "5", "--subs", job.Inputs.Domains[0]}, nil
		},
	}
}

// newWaybackProvider builds the waybackurls passive provider (reads domains on stdin).
func newWaybackProvider() Provider {
	return passiveURLProvider{
		name:  "waybackurls",
		input: func(job Job) string { return strings.Join(job.Inputs.Domains, "\n") },
	}
}
