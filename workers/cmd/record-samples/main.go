// Command record-samples prints one normalized record per record type as JSON. The TypeScript
// record-shape conformance test runs this binary and validates the output against
// DiscoveryRecordSchema, which is how the Go and TypeScript record contracts are kept in step.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/reconnexus/workers/internal/discovery"
)

func main() {
	records := discovery.SampleRecords()
	discovery.NormalizeRecords(records)
	out := struct {
		Types   []string           `json:"types"`
		Records []discovery.Record `json:"records"`
	}{Types: discovery.RecordTypes, Records: records}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "record-samples: %v\n", err)
		os.Exit(1)
	}
}
