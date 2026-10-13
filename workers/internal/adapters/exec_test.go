package adapters

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunEcho(t *testing.T) {
	res, err := Run(context.Background(), []string{"/bin/echo", "hello world"}, RunOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d", res.ExitCode)
	}
	if strings.TrimSpace(res.Stdout) != "hello world" {
		t.Fatalf("unexpected stdout %q", res.Stdout)
	}
}

func TestRunNonZeroExit(t *testing.T) {
	res, err := Run(context.Background(), []string{"/bin/sh", "-c", "exit 7"}, RunOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode != 7 {
		t.Fatalf("expected exit 7, got %d", res.ExitCode)
	}
}

func TestRunTimeout(t *testing.T) {
	res, err := Run(context.Background(), []string{"/bin/sleep", "5"}, RunOptions{Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.TimedOut {
		t.Fatalf("expected timeout, got %+v", res)
	}
}

func TestRunOutputLimit(t *testing.T) {
	res, err := Run(context.Background(), []string{"/bin/sh", "-c", "yes abcdefghij | head -c 100000"}, RunOptions{Timeout: 5 * time.Second, MaxBytes: 100})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Stdout) > 100 {
		t.Fatalf("expected truncated output <= 100 bytes, got %d", len(res.Stdout))
	}
	if !res.Truncated {
		t.Fatalf("expected Truncated=true")
	}
}

func TestArgvPreventsShellInjection(t *testing.T) {
	// A value containing shell metacharacters must be treated as a literal argument.
	res, err := Run(context.Background(), []string{"/bin/echo", "a; touch /tmp/pwned"}, RunOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(res.Stdout) != "a; touch /tmp/pwned" {
		t.Fatalf("argument was not treated literally: %q", res.Stdout)
	}
}
