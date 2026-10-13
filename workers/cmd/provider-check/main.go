// Command provider-check reports the health of external reconnaissance providers.
//
// Exit codes: 0 = all providers healthy; 1 = at least one provider missing or unhealthy.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/reconnexus/workers/internal/adapters"
	"github.com/reconnexus/workers/internal/telemetry"
)

func main() {
	jsonOut := flag.Bool("json", false, "emit JSON")
	flag.Parse()

	log := telemetry.New(os.Stderr, telemetry.Info)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	reports := make([]adapters.HealthReport, 0, len(adapters.Catalog))
	unhealthy := 0
	for _, p := range adapters.Catalog {
		r := adapters.CheckProvider(ctx, p)
		if r.Status != adapters.HealthOK {
			unhealthy++
		}
		reports = append(reports, r)
		log.Info("provider checked", map[string]any{"name": r.Name, "status": string(r.Status), "version": r.Version})
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"providers": reports, "unhealthy": unhealthy})
	} else {
		fmt.Println("Provider                 Status           Version    Path")
		for _, r := range reports {
			path := r.Path
			if path == "" {
				path = r.Message
			}
			version := r.Version
			if version == "" {
				version = "-"
			}
			fmt.Printf("%-24s %-16s %-10s %s\n", r.Name, r.Status, version, path)
		}
	}

	if unhealthy > 0 {
		os.Exit(1)
	}
}
