// Command laneboss-decisions is the Go implementation of `laneboss decisions`. The Python launcher forwards
// `laneboss decisions ...` here, unchanged, when LANEBOSS_DECISIONS_GO_BIN names this binary.
// Two packages share it: decisions (init, migrate, add, supersede, annotate, get, search, embed, egress, stats,
// verify, export, import, load) and decisionsrv (serve, ingest-lane, ingest-records and the org history parts).
package main

import (
	"os"

	"laneboss.io/laneboss/internal/decisions"
	"laneboss.io/laneboss/internal/decisionsrv"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve", "ingest-lane", "ingest-records", "hook-history", "history-worker", "capture-decision", "probe":
			os.Exit(decisionsrv.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
		}
	}
	os.Exit(decisions.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
