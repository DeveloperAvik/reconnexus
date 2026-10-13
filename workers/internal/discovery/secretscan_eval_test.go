package discovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type evalCase struct {
	Name string  `json:"name"`
	Rule *string `json:"rule"`
	Text string  `json:"text"`
}

// TestSecretDetectionEvaluation computes precision/recall/F1 against a small, hand-labeled synthetic
// corpus. This measures regression behaviour on a curated fixture set — it is NOT an estimate of
// real-world detection quality, and no such claim is made.
func TestSecretDetectionEvaluation(t *testing.T) {
	dir, _ := filepath.Abs("../../../test/fixtures/eval")
	raw, err := os.ReadFile(filepath.Join(dir, "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []evalCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}

	predictedRules := func(text string) map[string]bool {
		out := map[string]bool{}
		for _, r := range scanText(text, "https://example.com/a.js", "example.com", nil, nil) {
			if r.Type == TypeSecretCandidate && r.Secret != nil && r.Secret.Status != SecretSuppressed {
				out[r.Secret.RuleID] = true
			}
		}
		return out
	}

	tp, fp, fn := 0, 0, 0
	positives, negatives := 0, 0
	for _, c := range cases {
		got := predictedRules(c.Text)
		if c.Rule == nil {
			negatives++
			for rule := range got {
				t.Errorf("false positive on %q: rule %s", c.Name, rule)
				fp++
			}
			continue
		}
		positives++
		if got[*c.Rule] {
			tp++
		} else {
			t.Errorf("false negative on %q: expected %s, got %v", c.Name, *c.Rule, keysOfBool(got))
			fn++
		}
		for rule := range got {
			if rule != *c.Rule {
				t.Errorf("unexpected extra rule on %q: %s", c.Name, rule)
				fp++
			}
		}
	}

	precision := 1.0
	if tp+fp > 0 {
		precision = float64(tp) / float64(tp+fp)
	}
	recall := 1.0
	if tp+fn > 0 {
		recall = float64(tp) / float64(tp+fn)
	}
	f1 := 0.0
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}
	t.Logf("secret-detection evaluation: cases=%d positives=%d negatives=%d TP=%d FP=%d FN=%d", len(cases), positives, negatives, tp, fp, fn)
	t.Logf("precision=%.3f recall=%.3f f1=%.3f (curated fixture set; not real-world quality)", precision, recall, f1)
	if tp != positives || fp != 0 || fn != 0 {
		t.Fatalf("curated corpus expectation failed: all labeled cases must match (TP=%d/%d, FP=%d, FN=%d)", tp, positives, fp, fn)
	}
}

func keysOfBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
