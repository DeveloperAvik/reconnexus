package telemetry

import (
	"strings"
	"testing"
)

func TestRedactSensitiveKey(t *testing.T) {
	out := RedactValue(map[string]any{
		"api_key": "abcdef123456",
		"nested":  map[string]any{"password": "hunter2", "safe": "ok"},
	}).(map[string]any)
	if out["api_key"] != Redacted {
		t.Fatalf("expected api_key redacted, got %v", out["api_key"])
	}
	nested := out["nested"].(map[string]any)
	if nested["password"] != Redacted {
		t.Fatalf("expected nested password redacted, got %v", nested["password"])
	}
	if nested["safe"] != "ok" {
		t.Fatalf("expected safe value preserved, got %v", nested["safe"])
	}
}

func TestRedactValuePatterns(t *testing.T) {
	s := "token is eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	if got := RedactString(s); strings.Contains(got, "eyJzdWIi") {
		t.Fatalf("expected JWT redacted, got %q", got)
	}
	if got := RedactString("AKIAIOSFODNN7EXAMPLE"); !strings.Contains(got, Redacted) {
		t.Fatalf("expected AWS key redacted, got %q", got)
	}
	if got := RedactString("-----BEGIN RSA PRIVATE KEY-----"); !strings.Contains(got, Redacted) {
		t.Fatalf("expected private key redacted, got %q", got)
	}
}
