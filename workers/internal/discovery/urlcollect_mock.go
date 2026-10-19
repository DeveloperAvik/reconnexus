// mock-url: fixture-driven provider for deterministic tests.

package discovery

import (
	"context"
	"encoding/json"
	"os"
)

type mockURLProvider struct{}

func (mockURLProvider) Name() string            { return "mock-url" }
func (mockURLProvider) Kind() string            { return "URL_COLLECTION" }
func (mockURLProvider) Capability() string      { return "" }
func (mockURLProvider) NetworkBehavior() string { return "NONE" }

func (mockURLProvider) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	res := ProviderResult{}
	if pc.Job.FixturePath == "" {
		res.StatusOverride = StatusFailed
		res.Diagnostics = append(res.Diagnostics, "mock-url requires fixturePath")
		return res, nil
	}
	raw, err := os.ReadFile(pc.Job.FixturePath)
	if err != nil {
		res.StatusOverride = StatusFailed
		res.Diagnostics = append(res.Diagnostics, "cannot read fixture: "+err.Error())
		return res, nil
	}
	var fx struct {
		Version string   `json:"version"`
		URLs    []string `json:"urls"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		res.StatusOverride = StatusFailed
		res.Diagnostics = append(res.Diagnostics, "invalid fixture json: "+err.Error())
		return res, nil
	}
	res.ProviderVersion = fx.Version
	for _, rawURL := range fx.URLs {
		canon, h, malformed := canonicalizeForRecord(rawURL)
		if malformed {
			res.Diagnostics = append(res.Diagnostics, "mock-url malformed URL: "+truncate(rawURL, 80))
			continue
		}
		res.Records = append(res.Records, buildURLRecord(rawURL, canon, h, MethodPassive, "mock-url", "fixture", 0, nil))
		res.Coverage.Succeeded++
	}
	return res, nil
}
