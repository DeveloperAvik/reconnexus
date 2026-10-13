// Command reconnexus-worker executes a single discovery job and prints a normalized JSON
// result on stdout. It enforces scope independently (worker-side) and never reports a
// provider as successful when it failed.
//
// Job input: a DiscoveryJob JSON document, read from stdin or --job <file>.
// Output: a DiscoveryResult JSON document on stdout; logs go to stderr.
//
// Exit codes: 0 ok, 2 usage, 3 blocked, 4 source unavailable, 5 failed, 130 cancelled.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/reconnexus/workers/internal/discovery"
	"github.com/reconnexus/workers/internal/telemetry"
)

func main() {
	jobFile := flag.String("job", "", "path to a job JSON file (otherwise read stdin)")
	flag.Parse()

	logger := telemetry.New(os.Stderr, telemetry.Info)

	raw, err := readInput(*jobFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "worker: "+err.Error())
		os.Exit(2)
	}
	var job discovery.Job
	if err := json.Unmarshal(raw, &job); err != nil {
		fmt.Fprintln(os.Stderr, "worker: invalid job JSON: "+err.Error())
		os.Exit(2)
	}
	if job.SchemaVersion != 1 {
		fmt.Fprintf(os.Stderr, "worker: unsupported job schemaVersion %d\n", job.SchemaVersion)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if job.TimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(job.TimeoutMs)*time.Millisecond+10*time.Second)
		defer cancel()
	}

	result, runErr := discovery.Run(ctx, job, logger)
	if runErr != nil {
		fmt.Fprintln(os.Stderr, "worker: internal error: "+runErr.Error())
		os.Exit(5)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "worker: cannot encode result: "+err.Error())
		os.Exit(5)
	}
	os.Exit(exitFor(result.Status))
}

func readInput(path string) ([]byte, error) {
	if path != "" {
		return os.ReadFile(path)
	}
	return io.ReadAll(io.LimitReader(os.Stdin, 8*1024*1024))
}

func exitFor(status string) int {
	switch status {
	case "SUCCEEDED", "PARTIAL", "SKIPPED":
		return 0
	case "BLOCKED":
		return 3
	case "SOURCE_UNAVAILABLE":
		return 4
	case "CANCELLED":
		return 130
	default:
		return 5
	}
}
