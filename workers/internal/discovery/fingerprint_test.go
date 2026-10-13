package discovery

import (
	"strings"
	"testing"
)

func names(hits []TechDetails) []string {
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.Name)
	}
	return out
}

func has(hits []TechDetails, name string) bool {
	for _, h := range hits {
		if h.Name == name {
			return true
		}
	}
	return false
}

func TestFingerprintGenericPageHasNoFalsePositives(t *testing.T) {
	hits := Fingerprint(fingerprintInput{
		Headers: map[string]string{"content-type": "text/html"},
		Body:    strings.ToLower("<html><body><h1>Welcome</h1><p>We love react, docker and cloud.</p></body></html>"),
		Title:   "Welcome",
	})
	if len(hits) != 0 {
		t.Fatalf("generic content must not assert technologies, got %v", names(hits))
	}
}

func TestFingerprintServerHeader(t *testing.T) {
	hits := Fingerprint(fingerprintInput{Headers: map[string]string{"server": "nginx/1.25.3"}, Body: ""})
	if len(hits) != 1 || hits[0].Name != "nginx" {
		t.Fatalf("expected only nginx, got %v", names(hits))
	}
	if !strings.Contains(hits[0].Evidence, "nginx/1.25.3") {
		t.Errorf("evidence must cite the header value: %q", hits[0].Evidence)
	}
}

func TestFingerprintMultipleCompetingHypotheses(t *testing.T) {
	hits := Fingerprint(fingerprintInput{
		Headers: map[string]string{
			"server":        "nginx",
			"x-powered-by":  "PHP/8.1",
			"cf-ray":        "8a1b2c3d4e5f-LHR",
			"x-shopify-stage": "",
		},
		Body:    strings.ToLower("<html><body><div data-reactroot></div><link href=\"/wp-content/a.css\"></body></html>"),
		Cookies: []string{"phpsessid"},
	})
	for _, want := range []string{"nginx", "PHP", "Cloudflare", "React", "WordPress"} {
		if !has(hits, want) {
			t.Errorf("expected %q in %v", want, names(hits))
		}
	}
	// A specifically-marked WordPress page must not be misreported as Drupal/Joomla.
	if has(hits, "Drupal") || has(hits, "Joomla") {
		t.Errorf("unexpected CMS hypothesis: %v", names(hits))
	}
}

func TestFingerprintCmsDisambiguation(t *testing.T) {
	wp := Fingerprint(fingerprintInput{Headers: map[string]string{}, Body: "x wp-includes/ y"})
	if !has(wp, "WordPress") || has(wp, "Drupal") {
		t.Errorf("wordpress markers misclassified: %v", names(wp))
	}
	drupal := Fingerprint(fingerprintInput{Headers: map[string]string{"x-drupal-cache": "HIT"}, Body: ""})
	if !has(drupal, "Drupal") || has(drupal, "WordPress") {
		t.Errorf("drupal markers misclassified: %v", names(drupal))
	}
}

func TestFingerprintDocsAndDevServices(t *testing.T) {
	swagger := Fingerprint(fingerprintInput{Headers: map[string]string{}, Body: "swagger-ui bundle"})
	if !has(swagger, "Swagger UI") {
		t.Errorf("expected Swagger UI, got %v", names(swagger))
	}
	jenkins := Fingerprint(fingerprintInput{Headers: map[string]string{"x-jenkins": "2.4"}})
	if !has(jenkins, "Jenkins") {
		t.Errorf("expected Jenkins, got %v", names(jenkins))
	}
}

func TestFingerprintEvidenceAndConfidencePresent(t *testing.T) {
	hits := Fingerprint(fingerprintInput{Headers: map[string]string{"x-powered-by": "Express"}})
	if len(hits) != 1 || hits[0].Name != "Express" {
		t.Fatalf("expected Express, got %v", names(hits))
	}
	if hits[0].Evidence == "" || hits[0].Confidence <= 0 || hits[0].Category == "" || hits[0].EvidenceType == "" {
		t.Errorf("fingerprint must include evidence, category, type and confidence: %+v", hits[0])
	}
}
