package discovery

import (
	"sort"
	"testing"
)

func topCategory(cats []UrlClassification) string {
	if len(cats) == 0 {
		return ""
	}
	best := cats[0]
	for _, c := range cats[1:] {
		if c.Confidence > best.Confidence {
			best = c
		}
	}
	return best.Category
}

// labeled is a small, hand-labeled fixture set. It is deliberately modest: it validates
// regression safety, not a claim of real-world precision/recall.
var labeled = []struct {
	url  string
	want string
}{
	{"http://x/api/v1/users", "API_ENDPOINT"},
	{"http://x/graphql", "GRAPHQL"},
	{"http://x/app.js", "JAVASCRIPT"},
	{"http://x/static/site.css", "STATIC_ASSET"},
	{"http://x/login", "AUTHENTICATION"},
	{"http://x/signin", "AUTHENTICATION"},
	{"http://x/register", "REGISTRATION"},
	{"http://x/forgot-password", "PASSWORD_RECOVERY"},
	{"http://x/password/reset", "PASSWORD_RECOVERY"},
	{"http://x/logout", "SESSION"},
	{"http://x/admin/users", "ADMIN"},
	{"http://x/wp-admin/", "ADMIN"},
	{"http://x/docs/index", "DOCUMENTATION"},
	{"http://x/swagger.json", "API_SPEC"},
	{"http://x/upload", "UPLOAD"},
	{"http://x/files/report.zip", "DOWNLOAD"},
	{"http://x/search?q=hello", "SEARCH"},
	{"http://x/products?page=2", "PAGINATION"},
	{"http://x/products?filter=color", "FILTER"},
	{"http://x/redirect?url=http://evil", "REDIRECT"},
	{"http://x/export?type=csv", "EXPORT"},
	{"http://x/about", "HTML_PAGE"},
	{"http://x/index.php", "HTML_PAGE"},
	{"http://x/user/123?id=5", "HTML_PAGE"},
}

func TestClassifyURLFixturesAndConfusionMatrix(t *testing.T) {
	labels := map[string]bool{}
	for _, c := range labeled {
		labels[c.want] = true
	}
	labelList := make([]string, 0, len(labels))
	for l := range labels {
		labelList = append(labelList, l)
	}
	sort.Strings(labelList)

	matrix := map[string]map[string]int{} // want -> predicted -> count
	for _, l := range labelList {
		matrix[l] = map[string]int{}
	}
	correct := 0
	for _, c := range labeled {
		cats, _ := ClassifyURL(c.url)
		pred := topCategory(cats)
		matrix[c.want][pred]++
		if pred == c.want {
			correct++
		} else {
			t.Errorf("classify %q: top=%s want %s (%+v)", c.url, pred, c.want, cats)
		}
	}

	// Report the confusion matrix and metrics (no fabricated numbers).
	t.Logf("classification confusion matrix (want -> predicted):")
	rows := append([]string{"PREDICTED→"}, labelList...)
	_ = rows
	for _, want := range labelList {
		line := want + ":"
		for _, pred := range labelList {
			if n := matrix[want][pred]; n > 0 {
				line += " " + pred + "=" + itoa(n)
			}
		}
		t.Logf("  %s", line)
	}
	acc := float64(correct) / float64(len(labeled))
	t.Logf("labelled classification accuracy = %.3f (%d/%d)", acc, correct, len(labeled))
	if acc < 1.0 {
		t.Fatalf("accuracy %.3f below fixture expectation (fixtures are hand-labeled and expected to match)", acc)
	}
}

func TestParameterRoleInference(t *testing.T) {
	cases := map[string]string{
		"page":   "pagination",
		"q":      "search",
		"id":     "identifier",
		"url":    "redirect",
		"file":   "file_path",
		"token":  "auth_token",
		"filter": "filter",
	}
	for name, wantRole := range cases {
		_, params := ClassifyURL("http://x/p?" + name + "=1")
		if len(params) != 1 {
			t.Fatalf("param %q: expected 1 param, got %+v", name, params)
		}
		found := false
		for _, r := range params[0].Roles {
			if r.Role == wantRole {
				found = true
			}
		}
		if !found {
			t.Errorf("param %q: expected role %q, got %+v", name, wantRole, params[0].Roles)
		}
	}
	_, params := ClassifyURL("http://x/p?foo=1")
	if params[0].Roles[0].Role != "unknown" {
		t.Errorf("unknown param should be role 'unknown', got %+v", params[0].Roles)
	}
}

func TestClassifyDoesNotOverclaimFromRouteAlone(t *testing.T) {
	// "id"/"url"/"file" in a path are not vulnerability signals; classifications stay low
	// confidence and there is no finding/severity output at all.
	cats, params := ClassifyURL("http://x/item?id=5&url=/x")
	if len(cats) == 0 {
		t.Fatal("expected at least a fallback classification")
	}
	for _, c := range cats {
		if c.Confidence > 0.7 {
			t.Errorf("route-only classification should not be highly confident: %+v", c)
		}
	}
	if len(params) != 2 {
		t.Errorf("expected 2 parameters, got %+v", params)
	}
}
