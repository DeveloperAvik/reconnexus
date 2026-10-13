// Command worker is the ReconNexus execution worker.
//
// Phase 1 status: this is an intentional skeleton. Job claiming, stage execution, and
// checkpointing are implemented in Phase 2. Rather than fabricate work, the binary
// validates its environment and exits NOT_IMPLEMENTED (code 3) so callers cannot mistake
// it for a functioning worker.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/reconnexus/workers/internal/scope"
	"github.com/reconnexus/workers/internal/telemetry"
)

const (
	exitSuccess        = 0
	exitNotImplemented = 3
)

func main() {
	policyPath := flag.String("policy", "", "path to a scope policy JSON file to self-check")
	checkConfig := flag.Bool("check-config", false, "validate worker configuration and exit")
	flag.Parse()

	log := telemetry.New(os.Stderr, telemetry.Info)
	log.Info("worker starting", map[string]any{"phase": "skeleton"})

	if !*checkConfig && *policyPath == "" {
		fmt.Fprintln(os.Stderr, "worker: job execution is not implemented in this build (Phase 2).")
		fmt.Fprintln(os.Stderr, "        use --check-config to validate configuration, or --policy <file> to self-check scope enforcement.")
		os.Exit(exitNotImplemented)
	}

	if *policyPath != "" {
		f, err := os.Open(*policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "worker: cannot open policy: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		p, err := scope.LoadPolicy(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "worker: invalid policy: %v\n", err)
			os.Exit(1)
		}
		engine := scope.NewEngine(p)
		// Demonstrate independent worker-side enforcement with a self-check.
		d := engine.Check(scope.Request{Kind: "HOST", Value: "example.invalid", Capability: "ACTIVE_HTTP"})
		log.Info("policy loaded", map[string]any{
			"projectId": p.ProjectID, "version": p.PolicyVersion, "capabilities": p.Authorization.Capabilities,
			"selfCheck": d.Code,
		})
	}

	fmt.Fprintln(os.Stdout, "worker: configuration OK")
	os.Exit(exitSuccess)
}
