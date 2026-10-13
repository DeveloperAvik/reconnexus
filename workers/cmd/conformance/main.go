// Command conformance evaluates the shared scope/normalization fixtures and prints the
// results as JSON. The TypeScript conformance test runs this binary and compares output,
// which is how cross-language agreement between the TS and Go scope engines is enforced.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/reconnexus/workers/internal/conformance"
)

func main() {
	dir := "test/fixtures/conformance"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "conformance: %v\n", err)
		os.Exit(1)
	}
	res, err := conformance.Compute(abs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "conformance: %v\n", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		fmt.Fprintf(os.Stderr, "conformance: %v\n", err)
		os.Exit(1)
	}
}
